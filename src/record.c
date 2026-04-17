#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "pmi/event.h"
#include "pmi/output.h"
#include "pmi/perf_session.h"
#include "pmi/procfs.h"
#include "pmi/record.h"
#include "pmi/strutil.h"

#define PMI_MAX_TRACKED_TIDS 1024
#define PMI_THREAD_REFRESH_INTERVAL_MS 1000

static volatile sig_atomic_t g_stop;

struct record_runtime {
	struct pmi_record_options opts;
	struct pmi_event_list events;
	struct pmi_output_writer writer;
	struct pmi_perf_session sessions[PMI_MAX_TRACKED_TIDS];
	size_t session_count;
	pid_t target_pid;
	pid_t child_pid;
};

static void record_usage(FILE *stream)
{
	fprintf(stream,
		"usage: pmi record (-p <pid> | -t <tid> | -c <cmd>) -o <file> [options]\n"
		"\n"
		"options:\n"
		"  -p, --pid <pid>            attach to all threads in a process\n"
		"  -t, --tid <tid>            attach to one thread\n"
		"  -c, --cmd <cmd>            spawn and record a shell command\n"
		"  -o, --out <file>           write raw v3 samples to a file\n"
		"  -n, --period-insn <count>  sampling period in retired instructions\n"
		"                             default: 1000000\n"
		"  -e <raw-list>              raw PMU events, e.g. -e r0010,r0011\n"
		"                             may be repeated; only CPU PMU raw events are supported\n"
		"  -s, --stack <top|full>     function/stack mode; default: off\n"
		"                             raw output stores addresses; use report for symbols\n"
		"  -k, --kernel-stack <on|off>\n"
		"                             include kernel samples and kernel callchain, default: off\n"
		"      --write-mode <low-overhead|strict>\n"
		"                             userspace write policy, default: low-overhead\n"
		"                             low-overhead may drop userspace samples when writer is saturated\n"
		"      --debug-perf           print perf_session debug logs to stderr\n"
		"  -h, --help                 show this help\n"
		"\n"
		"examples:\n"
		"  pmi record -p 1234 -o out.pmi\n"
		"  pmi record -c './bench' -n 100000 -e r0010,r0011 -s full -o out.pmi\n");
}

static void record_debugf(const struct record_runtime *rt, const char *scope,
			  const char *fmt, ...)
{
	va_list ap;

	if (!rt || !rt->opts.debug_perf)
		return;

	fprintf(stderr, "[record][%s] ", scope);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

static void on_signal(int signo)
{
	(void)signo;
	g_stop = 1;
}

static bool session_exists(const struct record_runtime *rt, pid_t tid)
{
	size_t i;

	for (i = 0; i < rt->session_count; ++i) {
		if (rt->sessions[i].tid == tid)
			return true;
	}
	return false;
}

static uint64_t monotonic_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static int on_perf_sample(const struct pmi_perf_sample *sample, void *ctx)
{
	struct record_runtime *rt = ctx;
	struct pmi_output_sample out = { 0 };
	uint64_t top_ip = 0;
	size_t i;

	if (!sample)
		return 0;

	if (rt->opts.stack_mode == PMI_STACK_TOP) {
		top_ip = sample->ip;
	} else if (rt->opts.stack_mode == PMI_STACK_FULL) {
		if (sample->callchain_count > 0)
			top_ip = sample->callchain[0];
		else
			top_ip = sample->ip;
	}

	out.pid = sample->pid;
	out.tid = sample->tid;
	out.top_ip = top_ip;
	out.event_count = sample->event_count;
	memcpy(out.event_deltas, sample->event_deltas, sizeof(out.event_deltas));

	if (rt->opts.stack_mode == PMI_STACK_FULL && sample->callchain_count > 1) {
		for (i = 1; i < sample->callchain_count && out.stack_depth < PMI_MAX_STACK_DEPTH;
		     ++i)
			out.stack_ips[out.stack_depth++] = sample->callchain[i];
	}

	return pmi_output_enqueue_sample(&rt->writer, &out);
}

static int attach_tid(struct record_runtime *rt, pid_t tid)
{
	struct pmi_perf_session *session;
	int err;

	if (rt->session_count >= PMI_MAX_TRACKED_TIDS)
		return -ENOSPC;
	if (session_exists(rt, tid))
		return 0;

	session = &rt->sessions[rt->session_count];
	err = pmi_perf_session_open(session, tid, &rt->opts, &rt->events);
	if (err)
		return err;
	err = pmi_perf_session_enable(session);
	if (err) {
		pmi_perf_session_close(session);
		return err;
	}

	rt->session_count++;
	return 0;
}

static int attach_target_threads(struct record_runtime *rt, pid_t pid)
{
	struct pmi_tid_list tids;
	size_t i;
	int err;

	err = pmi_procfs_list_tids(pid, &tids);
	if (err)
		return err;
	for (i = 0; i < tids.count; ++i) {
		err = attach_tid(rt, tids.tids[i]);
		if (err)
			return err;
	}
	return 0;
}

static int spawn_command(const char *cmd, pid_t *pid_out)
{
	pid_t child;
	int status;

	child = fork();
	if (child < 0)
		return -errno;
	if (child == 0) {
		raise(SIGSTOP);
		execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
		_exit(127);
	}

	if (waitpid(child, &status, WUNTRACED) < 0)
		return -errno;
	*pid_out = child;
	return 0;
}

static int parse_pid_value(const char *text, pid_t *out)
{
	char *end = NULL;
	long value;

	if (!text || !out)
		return -EINVAL;

	value = strtol(text, &end, 10);
	if (!end || *end != '\0' || value <= 0 || value > INT_MAX)
		return -EINVAL;

	*out = (pid_t)value;
	return 0;
}

static int parse_u64_value(const char *text, uint64_t *out)
{
	char *end = NULL;

	if (!text || !out)
		return -EINVAL;

	*out = strtoull(text, &end, 10);
	if (!end || *end != '\0' || *out == 0)
		return -EINVAL;

	return 0;
}

static int append_raw_event_tokens(struct pmi_record_options *opts, const char *arg)
{
	char copy[PMI_MAX_LINE_LEN];
	char *cursor;
	char *token;

	if (!opts || !arg)
		return -EINVAL;
	if (strlen(arg) >= sizeof(copy))
		return -E2BIG;

	strcpy(copy, arg);
	cursor = copy;
	while ((token = strsep(&cursor, ",")) != NULL) {
		if (*token == '\0')
			return -EINVAL;
		if (opts->raw_event_count >= PMI_MAX_EVENTS - 1)
			return -E2BIG;
		if (pmi_copy_cstr(opts->raw_event_tokens[opts->raw_event_count],
				  sizeof(opts->raw_event_tokens[0]), token) != 0)
			return -E2BIG;
		opts->raw_event_count++;
	}

	return 0;
}

static int parse_stack_mode(const char *mode, enum pmi_stack_mode *out)
{
	if (strcmp(mode, "top") == 0) {
		*out = PMI_STACK_TOP;
		return 0;
	}
	if (strcmp(mode, "full") == 0) {
		*out = PMI_STACK_FULL;
		return 0;
	}
	return -EINVAL;
}

static int parse_onoff(const char *text, bool *out)
{
	if (strcmp(text, "on") == 0) {
		*out = true;
		return 0;
	}
	if (strcmp(text, "off") == 0) {
		*out = false;
		return 0;
	}
	return -EINVAL;
}

static int parse_write_mode(const char *text, enum pmi_write_mode *out)
{
	if (strcmp(text, "low-overhead") == 0) {
		*out = PMI_WRITE_LOW_OVERHEAD;
		return 0;
	}
	if (strcmp(text, "strict") == 0) {
		*out = PMI_WRITE_STRICT;
		return 0;
	}
	return -EINVAL;
}

static int parse_record_options(int argc, char **argv, struct pmi_record_options *opts)
{
	static const struct option long_options[] = {
		{ "pid", required_argument, NULL, 'p' },
		{ "tid", required_argument, NULL, 't' },
		{ "cmd", required_argument, NULL, 'c' },
		{ "out", required_argument, NULL, 'o' },
		{ "period-insn", required_argument, NULL, 'n' },
		{ "stack", required_argument, NULL, 's' },
		{ "kernel-stack", required_argument, NULL, 'k' },
		{ "write-mode", required_argument, NULL, 1002 },
		{ "debug-perf", no_argument, NULL, 1001 },
		{ "help", no_argument, NULL, 'h' },
		{ "event", required_argument, NULL, 1000 },
		{ 0, 0, 0, 0 },
	};
	int opt;

	memset(opts, 0, sizeof(*opts));
	opts->period = 1000000;
	opts->stack_mode = PMI_STACK_NONE;
	opts->write_mode = PMI_WRITE_LOW_OVERHEAD;
	opts->mmap_pages = 64;
	opts->poll_timeout_ms = 200;
	opterr = 0;
	optind = 1;

	while ((opt = getopt_long(argc, argv, "p:t:c:o:n:e:s:k:h", long_options,
				  NULL)) != -1) {
		switch (opt) {
		case 'p':
			if (parse_pid_value(optarg, &opts->pid) != 0) {
				fprintf(stderr, "invalid pid: %s\n", optarg);
				return -EINVAL;
			}
			break;
		case 't':
			if (parse_pid_value(optarg, &opts->tid) != 0) {
				fprintf(stderr, "invalid tid: %s\n", optarg);
				return -EINVAL;
			}
			break;
		case 'c':
			opts->cmd = optarg;
			break;
		case 'o':
			opts->output_path = optarg;
			break;
		case 'n':
			if (parse_u64_value(optarg, &opts->period) != 0) {
				fprintf(stderr, "invalid instruction period: %s\n",
					optarg);
				return -EINVAL;
			}
			break;
		case 'e':
			if (append_raw_event_tokens(opts, optarg) != 0) {
				fprintf(stderr, "invalid raw event list: %s\n", optarg);
				return -EINVAL;
			}
			break;
		case 's':
			if (parse_stack_mode(optarg, &opts->stack_mode) != 0) {
				fprintf(stderr, "invalid stack mode: %s\n", optarg);
				return -EINVAL;
			}
			break;
		case 'k':
			if (parse_onoff(optarg, &opts->capture_kernel_stack) != 0) {
				fprintf(stderr, "invalid kernel stack mode: %s\n",
					optarg);
				return -EINVAL;
			}
			break;
		case 1001:
			opts->debug_perf = true;
			break;
		case 1002:
			if (parse_write_mode(optarg, &opts->write_mode) != 0) {
				fprintf(stderr, "invalid write mode: %s\n", optarg);
				return -EINVAL;
			}
			break;
		case 'h':
			record_usage(stdout);
			return 2;
		case 1000:
			fprintf(stderr,
				"--event is no longer supported; use -e r0010,r0011\n");
			return -EINVAL;
		case '?':
		default:
			fprintf(stderr, "unknown record option: %s\n",
				optind > 0 && optind - 1 < argc ? argv[optind - 1] : "?");
			return -EINVAL;
		}
	}

	if (optind != argc) {
		fprintf(stderr, "unexpected positional argument: %s\n", argv[optind]);
		return -EINVAL;
	}
	if (!opts->output_path) {
		fprintf(stderr, "-o/--out is required\n");
		return -EINVAL;
	}
	if (!!opts->pid + !!opts->tid + !!opts->cmd != 1) {
		fprintf(stderr, "exactly one of -p, -t, or -c is required\n");
		return -EINVAL;
	}
	return 0;
}

static void close_runtime(struct record_runtime *rt)
{
	size_t i;
	int status;
	int output_err;
	uint64_t dropped_samples;

	for (i = 0; i < rt->session_count; ++i) {
		int err;

		err = pmi_perf_session_drain(&rt->sessions[i], on_perf_sample, rt);
		if (err)
			record_debugf(rt, "error",
				      "stage=close-drain tid=%d leader_fd=%d err=%d (%s)",
				      rt->sessions[i].tid,
				      rt->sessions[i].leader_fd, -err,
				      strerror(-err));
	}
	for (i = 0; i < rt->session_count; ++i) {
		if (rt->opts.debug_perf && rt->sessions[i].count_grew &&
		    rt->sessions[i].samples_seen == 0) {
			record_debugf(rt, "summary",
				      "tid=%d count_grew=yes samples_seen=%" PRIu64 " period=%" PRIu64 " last_leader=%" PRIu64 " enabled=%" PRIu64 " running=%" PRIu64,
				      rt->sessions[i].tid,
				      rt->sessions[i].samples_seen,
				      rt->sessions[i].sample_period,
				      rt->sessions[i].last_leader_count,
				      rt->sessions[i].last_time_enabled,
				      rt->sessions[i].last_time_running);
		}
	}
	for (i = 0; i < rt->session_count; ++i)
		pmi_perf_session_close(&rt->sessions[i]);
	dropped_samples = rt->writer.dropped_samples;
	output_err = pmi_output_close(&rt->writer);
	if (output_err)
		fprintf(stderr, "close output failed: %s\n", strerror(-output_err));
	if (dropped_samples > 0)
		fprintf(stderr, "record userspace dropped %" PRIu64 " samples\n",
			dropped_samples);
	if (rt->child_pid > 0) {
		kill(rt->child_pid, SIGTERM);
		waitpid(rt->child_pid, &status, WNOHANG);
	}
}

int pmi_record_main(int argc, char **argv)
{
	struct record_runtime rt;
	struct sigaction sa = { 0 };
	const char *raw_event_ptrs[PMI_MAX_EVENTS - 1];
	uint64_t next_refresh_ms = 0;
	size_t i;
	int err;

	memset(&rt, 0, sizeof(rt));
	g_stop = 0;
	err = parse_record_options(argc, argv, &rt.opts);
	if (err) {
		if (err == 2)
			return 0;
		record_usage(stderr);
		return 1;
	}

	if (rt.opts.cmd) {
		err = spawn_command(rt.opts.cmd, &rt.child_pid);
		if (err) {
			fprintf(stderr, "spawn command failed: %s\n", strerror(-err));
			return 1;
		}
		rt.target_pid = rt.child_pid;
	} else if (rt.opts.pid) {
		rt.target_pid = rt.opts.pid;
	} else {
		rt.target_pid = rt.opts.tid;
	}

	memset(&rt.events, 0, sizeof(rt.events));
	if (rt.opts.raw_event_count > 0) {
		for (i = 0; i < rt.opts.raw_event_count; ++i)
			raw_event_ptrs[i] = rt.opts.raw_event_tokens[i];
		err = pmi_event_list_resolve_raw_tokens(&rt.events, raw_event_ptrs,
							rt.opts.raw_event_count,
							"/sys/bus/event_source/devices");
		if (err) {
			fprintf(stderr, "event resolution failed: %s\n",
				rt.events.error[0] ? rt.events.error : strerror(-err));
			return 1;
		}
	}

	err = pmi_output_open(&rt.writer, rt.opts.output_path, &rt.events,
			      rt.opts.write_mode, rt.opts.debug_perf);
	if (err) {
		fprintf(stderr, "open output failed: %s\n", strerror(-err));
		return 1;
	}

	if (rt.opts.tid)
		err = attach_tid(&rt, rt.target_pid);
	else
		err = attach_target_threads(&rt, rt.target_pid);
	if (err) {
		fprintf(stderr, "attach failed: %s\n", strerror(-err));
		close_runtime(&rt);
		return 1;
	}

	if (rt.child_pid > 0)
		kill(rt.child_pid, SIGCONT);

	sa.sa_handler = on_signal;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	if (rt.opts.pid || rt.opts.cmd)
		next_refresh_ms = monotonic_ms() + PMI_THREAD_REFRESH_INTERVAL_MS;

	while (!g_stop) {
		struct pollfd fds[PMI_MAX_TRACKED_TIDS];
		uint64_t now_ms = monotonic_ms();
		nfds_t nfds = 0;
		int timeout_ms = rt.opts.poll_timeout_ms;
		int status;

		if ((rt.opts.pid || rt.opts.cmd) && next_refresh_ms > now_ms) {
			uint64_t wait_ms = next_refresh_ms - now_ms;

			if (wait_ms < (uint64_t)timeout_ms)
				timeout_ms = (int)wait_ms;
		} else if (rt.opts.pid || rt.opts.cmd) {
			timeout_ms = 0;
		}
		for (i = 0; i < rt.session_count; ++i) {
			fds[nfds].fd = rt.sessions[i].leader_fd;
			fds[nfds].events = POLLIN | POLLERR | POLLHUP;
			nfds++;
		}

		poll(fds, nfds, timeout_ms);
		for (i = 0; i < rt.session_count; ++i) {
			if ((fds[i].revents & (POLLIN | POLLERR | POLLHUP)) == 0)
				continue;
			err = pmi_perf_session_drain(&rt.sessions[i], on_perf_sample,
						     &rt);
			if (err) {
				record_debugf(&rt, "error",
					      "stage=drain tid=%d leader_fd=%d err=%d (%s)",
					      rt.sessions[i].tid,
					      rt.sessions[i].leader_fd, -err,
					      strerror(-err));
				g_stop = 1;
				break;
			}
		}
		if (g_stop)
			break;

		now_ms = monotonic_ms();
		if ((rt.opts.pid || rt.opts.cmd) && now_ms >= next_refresh_ms) {
			attach_target_threads(&rt, rt.target_pid);
			next_refresh_ms = now_ms + PMI_THREAD_REFRESH_INTERVAL_MS;
		}

		if (rt.child_pid > 0) {
			pid_t rc = waitpid(rt.child_pid, &status, WNOHANG);

			if (rc == rt.child_pid)
				g_stop = 1;
		}
	}

	close_runtime(&rt);
	return 0;
}

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "pmi/bpf_loader.h"
#include "pmi/event.h"
#include "pmi/joiner.h"
#include "pmi/output.h"
#include "pmi/perf_session.h"
#include "pmi/procfs.h"
#include "pmi/record.h"
#include "pmi/strutil.h"
#include "pmi/symbolizer.h"

#define PMI_MAX_TRACKED_TIDS 1024

static volatile sig_atomic_t g_stop;

struct record_runtime {
	struct pmi_record_options opts;
	struct pmi_event_list events;
	struct pmi_bpf_runtime bpf;
	struct pmi_joiner *joiner;
	struct pmi_output_writer writer;
	struct pmi_symbolizer *symbolizer;
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
		"  -o, --out <file>           write raw v2 samples to a file\n"
		"  -n, --period-insn <count>  sampling period in retired instructions\n"
		"                             default: 1000000\n"
		"  -e <raw-list>              raw PMU events, e.g. -e r0010,r0011\n"
		"                             may be repeated; only CPU PMU raw events are supported\n"
		"  -s, --stack <top|full>     stack mode; default: top\n"
		"  -k, --kernel-stack <on|off>\n"
		"                             capture kernel stack in BPF, default: off\n"
		"  -h, --help                 show this help\n"
		"\n"
		"examples:\n"
		"  pmi record -p 1234 -o out.pmi\n"
		"  pmi record -c './bench' -n 100000 -e r0010,r0011 -s full -o out.pmi\n");
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

static void normalize_symbol(char *symbol)
{
	char *plus;

	if (!symbol || symbol[0] == '\0' || strncmp(symbol, "0x", 2) == 0)
		return;

	plus = strstr(symbol, "+0x");
	if (plus)
		*plus = '\0';
}

static void format_stack_ips(const uint64_t *ips, size_t depth, char *out,
			     size_t out_cap)
{
	size_t i;
	size_t len = 0;
	bool wrote = false;

	if (!out || out_cap == 0)
		return;

	out[0] = '\0';
	for (i = 0; i < depth; ++i) {
		int written;

		if (ips[i] == 0)
			continue;
		written = snprintf(out + len, out_cap - len, "%s0x%" PRIx64,
				   wrote ? ";" : "", ips[i]);
		if (written < 0 || (size_t)written >= out_cap - len)
			break;
		len += (size_t)written;
		wrote = true;
	}

	if (!wrote)
		pmi_copy_cstr_trunc(out, out_cap, "-");
}

static int on_joined_sample(const struct pmi_joined_sample *sample, void *ctx)
{
	struct record_runtime *rt = ctx;
	char module[PMI_MAX_MODULE_LEN];
	char symbol[PMI_MAX_SYMBOL_LEN];
	char stack[PMI_MAX_STACK_TEXT_LEN];
	uint64_t ips[PMI_MAX_STACK_DEPTH] = { 0 };
	uint64_t ip;
	pid_t pid;

	if (!sample || sample->perf.event_count == 0)
		return 0;

	ip = sample->bpf.ip ? sample->bpf.ip : sample->perf.ip;
	pid = sample->perf.pid ? sample->perf.pid : (pid_t)sample->bpf.pid;
	pmi_copy_cstr_trunc(symbol, sizeof(symbol), ip ? "-" : "0x0");
	pmi_copy_cstr_trunc(stack, sizeof(stack), "-");

	if (ip) {
		pmi_symbolizer_symbolize_ip(rt->symbolizer, pid, ip, module,
					    sizeof(module), symbol,
					    sizeof(symbol));
		normalize_symbol(symbol);
	}

	if (rt->opts.stack_mode == PMI_STACK_FULL && sample->bpf.user_stack_id >= 0) {
		if (pmi_bpf_runtime_read_stack(&rt->bpf, sample->bpf.user_stack_id, ips,
					       PMI_MAX_STACK_DEPTH) == 0)
			format_stack_ips(ips, PMI_MAX_STACK_DEPTH, stack,
					sizeof(stack));
	}

	return pmi_output_write_sample(&rt->writer, sample, symbol, stack);
}

static int on_perf_sample(const struct pmi_perf_sample *sample, void *ctx)
{
	return pmi_joiner_push_perf(ctx, sample);
}

static int on_bpf_event(const struct pmi_bpf_event *event, void *ctx)
{
	return pmi_joiner_push_bpf(ctx, event);
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
	err = pmi_bpf_runtime_attach_session(&rt->bpf, session);
	if (err) {
		pmi_perf_session_close(session);
		return err;
	}
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
		{ "help", no_argument, NULL, 'h' },
		{ "event", required_argument, NULL, 1000 },
		{ 0, 0, 0, 0 },
	};
	int opt;

	memset(opts, 0, sizeof(*opts));
	opts->period = 1000000;
	opts->stack_mode = PMI_STACK_TOP;
	opts->mmap_pages = 8;
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

	if (rt->joiner) {
		pmi_bpf_runtime_poll(&rt->bpf, 0);
		for (i = 0; i < rt->session_count; ++i)
			pmi_perf_session_drain(&rt->sessions[i], on_perf_sample, rt->joiner);
		pmi_joiner_flush(rt->joiner);
	}
	for (i = 0; i < rt->session_count; ++i)
		pmi_perf_session_close(&rt->sessions[i]);
	pmi_joiner_destroy(rt->joiner);
	pmi_bpf_runtime_close(&rt->bpf);
	pmi_output_close(&rt->writer);
	pmi_symbolizer_destroy(rt->symbolizer);
	if (rt->child_pid > 0) {
		kill(rt->child_pid, SIGTERM);
		waitpid(rt->child_pid, &status, WNOHANG);
	}
}

int pmi_record_main(int argc, char **argv)
{
	struct record_runtime rt;
	struct sigaction sa = { 0 };
	struct pmi_bpf_config cfg;
	char bpf_obj_path[PATH_MAX];
	const char *raw_event_ptrs[PMI_MAX_EVENTS - 1];
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

	err = pmi_output_open(&rt.writer, rt.opts.output_path, rt.opts.period);
	if (err) {
		fprintf(stderr, "open output failed: %s\n", strerror(-err));
		return 1;
	}
	err = pmi_symbolizer_init(&rt.symbolizer);
	if (err) {
		fprintf(stderr, "symbolizer init failed: %s\n", strerror(-err));
		close_runtime(&rt);
		return 1;
	}
	err = pmi_joiner_init(&rt.joiner, on_joined_sample, &rt);
	if (err) {
		fprintf(stderr, "joiner init failed: %s\n", strerror(-err));
		close_runtime(&rt);
		return 1;
	}

	cfg.stack_mode = rt.opts.stack_mode;
	cfg.capture_kernel_stack = rt.opts.capture_kernel_stack ? 1 : 0;
	snprintf(bpf_obj_path, sizeof(bpf_obj_path), "build/bpf/pmi.bpf.o");
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	err = pmi_bpf_runtime_open(&rt.bpf, bpf_obj_path, &cfg, on_bpf_event,
				   rt.joiner);
	if (err) {
		fprintf(stderr, "bpf open failed: %s\n", strerror(-err));
		close_runtime(&rt);
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

	while (!g_stop) {
		struct pollfd fds[PMI_MAX_TRACKED_TIDS + 1];
		nfds_t nfds = 0;
		int status;
		int ring_fd = ring_buffer__epoll_fd(rt.bpf.ringbuf);

		if (ring_fd >= 0) {
			fds[nfds].fd = ring_fd;
			fds[nfds].events = POLLIN;
			nfds++;
		}
		for (i = 0; i < rt.session_count; ++i) {
			fds[nfds].fd = rt.sessions[i].leader_fd;
			fds[nfds].events = POLLIN;
			nfds++;
		}

		poll(fds, nfds, rt.opts.poll_timeout_ms);
		pmi_bpf_runtime_poll(&rt.bpf, 0);
		for (i = 0; i < rt.session_count; ++i)
			pmi_perf_session_drain(&rt.sessions[i], on_perf_sample, rt.joiner);

		if (rt.opts.pid || rt.opts.cmd)
			attach_target_threads(&rt, rt.target_pid);

		if (rt.child_pid > 0) {
			pid_t rc = waitpid(rt.child_pid, &status, WNOHANG);

			if (rc == rt.child_pid)
				g_stop = 1;
		}
	}

	close_runtime(&rt);
	return 0;
}

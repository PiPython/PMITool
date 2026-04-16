#define _GNU_SOURCE

#include <errno.h>
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

static int on_joined_sample(const struct pmi_joined_sample *sample, void *ctx)
{
	struct record_runtime *rt = ctx;
	struct pmi_joined_sample local = *sample;
	char module[PMI_MAX_MODULE_LEN] = "-";
	char symbol[PMI_MAX_SYMBOL_LEN] = "-";
	char folded[PMI_MAX_FOLDED_LEN] = "-";
	uint64_t ips[PMI_MAX_STACK_DEPTH] = { 0 };
	uint64_t ip = sample->bpf.ip ? sample->bpf.ip : sample->perf.ip;
	pid_t pid = sample->perf.pid ? sample->perf.pid : (pid_t)sample->bpf.pid;

	if (ip)
		pmi_symbolizer_symbolize_ip(rt->symbolizer, pid, ip, module,
					    sizeof(module), symbol,
					    sizeof(symbol));
	if (rt->opts.stack_mode == PMI_STACK_FULL && sample->bpf.user_stack_id >= 0) {
		if (pmi_bpf_runtime_read_stack(&rt->bpf, sample->bpf.user_stack_id, ips,
					       PMI_MAX_STACK_DEPTH) == 0) {
			pmi_symbolizer_symbolize_stack(rt->symbolizer, pid, ips,
						       PMI_MAX_STACK_DEPTH, folded,
						       sizeof(folded));
		} else {
			local.lost_flags |= PMI_LOST_STACK;
		}
	}

	return pmi_output_write_sample(&rt->writer, &local, module, symbol, folded);
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

static int parse_record_options(int argc, char **argv, struct pmi_record_options *opts)
{
	int i;

	memset(opts, 0, sizeof(*opts));
	opts->period = 1000000;
	opts->stack_mode = PMI_STACK_TOP;
	opts->mmap_pages = 8;
	opts->poll_timeout_ms = 200;

	for (i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc) {
			opts->pid = (pid_t)strtol(argv[++i], NULL, 10);
		} else if (strcmp(argv[i], "--tid") == 0 && i + 1 < argc) {
			opts->tid = (pid_t)strtol(argv[++i], NULL, 10);
		} else if (strcmp(argv[i], "--cmd") == 0 && i + 1 < argc) {
			opts->cmd = argv[++i];
		} else if (strcmp(argv[i], "--event") == 0 && i + 1 < argc) {
			if (opts->event_input_count >= PMI_MAX_EVENTS - 1)
				return -E2BIG;
			opts->event_inputs[opts->event_input_count++] = argv[++i];
		} else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
			opts->output_path = argv[++i];
		} else if (strcmp(argv[i], "--period-insn") == 0 && i + 1 < argc) {
			opts->period = strtoull(argv[++i], NULL, 10);
		} else if (strcmp(argv[i], "--stack") == 0 && i + 1 < argc) {
			const char *mode = argv[++i];

			if (strcmp(mode, "top") == 0)
				opts->stack_mode = PMI_STACK_TOP;
			else if (strcmp(mode, "full") == 0)
				opts->stack_mode = PMI_STACK_FULL;
			else
				return -EINVAL;
		} else if (strcmp(argv[i], "--kernel-stack") == 0 && i + 1 < argc) {
			const char *onoff = argv[++i];

			if (strcmp(onoff, "on") == 0)
				opts->capture_kernel_stack = true;
			else if (strcmp(onoff, "off") == 0)
				opts->capture_kernel_stack = false;
			else
				return -EINVAL;
		} else if (strcmp(argv[i], "--help") == 0) {
			fprintf(stdout,
				"usage: pmi record --pid <pid>|--tid <tid>|--cmd <cmd> "
				"[--event spec]... --out <file>\n");
			return 2;
		} else {
			return -EINVAL;
		}
	}

	if (!opts->output_path)
		return -EINVAL;
	if (!!opts->pid + !!opts->tid + !!opts->cmd != 1)
		return -EINVAL;
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
	int err;

	memset(&rt, 0, sizeof(rt));
	err = parse_record_options(argc, argv, &rt.opts);
	if (err) {
		if (err == 2)
			return 0;
		fprintf(stderr, "invalid record arguments\n");
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

	err = pmi_event_list_resolve(&rt.events, rt.opts.event_inputs,
				     rt.opts.event_input_count,
				     "/sys/bus/event_source/devices");
	if (err) {
		fprintf(stderr, "event resolution failed: %s\n", strerror(-err));
		return 1;
	}

	err = pmi_output_open(&rt.writer, rt.opts.output_path);
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

	if (rt.child_pid > 0) {
		kill(rt.child_pid, SIGCONT);
	}

	sa.sa_handler = on_signal;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	while (!g_stop) {
		struct pollfd fds[PMI_MAX_TRACKED_TIDS + 1];
		nfds_t nfds = 0;
		size_t i;
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
			pid_t waited = waitpid(rt.child_pid, &status, WNOHANG);

			if (waited == rt.child_pid)
				break;
		}
	}

	close_runtime(&rt);
	return 0;
}

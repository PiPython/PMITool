#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>

#include "pmi/bpf_loader.h"

struct ringbuf_dispatch_ctx {
	pmi_bpf_event_cb cb;
	void *cb_ctx;
};

static int on_ringbuf(void *ctx, void *data, size_t data_sz)
{
	struct ringbuf_dispatch_ctx *dispatch = ctx;

	if (data_sz < sizeof(struct pmi_bpf_event))
		return 0;
	return dispatch->cb((const struct pmi_bpf_event *)data, dispatch->cb_ctx);
}

int pmi_bpf_runtime_open(struct pmi_bpf_runtime *rt, const char *obj_path,
			 const struct pmi_bpf_config *cfg, pmi_bpf_event_cb cb,
			 void *ctx)
{
	struct ringbuf_dispatch_ctx *dispatch;
	__u32 zero = 0;
	int err;

	if (!rt || !obj_path || !cfg || !cb)
		return -EINVAL;

	memset(rt, 0, sizeof(*rt));
	rt->obj = bpf_object__open_file(obj_path, NULL);
	err = libbpf_get_error(rt->obj);
	if (err) {
		rt->obj = NULL;
		return err;
	}

	err = bpf_object__load(rt->obj);
	if (err)
		goto fail;

	rt->prog = bpf_object__find_program_by_name(rt->obj, "pmi_on_sample");
	if (!rt->prog) {
		err = -ENOENT;
		goto fail;
	}

	rt->ringbuf_map_fd = bpf_object__find_map_fd_by_name(rt->obj, "events");
	rt->stack_map_fd = bpf_object__find_map_fd_by_name(rt->obj, "stack_traces");
	rt->config_map_fd = bpf_object__find_map_fd_by_name(rt->obj, "config_map");
	if (rt->ringbuf_map_fd < 0 || rt->stack_map_fd < 0 || rt->config_map_fd < 0) {
		err = -ENOENT;
		goto fail;
	}

	err = bpf_map_update_elem(rt->config_map_fd, &zero, cfg, BPF_ANY);
	if (err) {
		err = -errno;
		goto fail;
	}

	dispatch = calloc(1, sizeof(*dispatch));
	if (!dispatch) {
		err = -ENOMEM;
		goto fail;
	}
	dispatch->cb = cb;
	dispatch->cb_ctx = ctx;
	rt->ringbuf_ctx = dispatch;

	rt->ringbuf = ring_buffer__new(rt->ringbuf_map_fd, on_ringbuf, dispatch, NULL);
	err = libbpf_get_error(rt->ringbuf);
	if (err) {
		rt->ringbuf = NULL;
		free(dispatch);
		rt->ringbuf_ctx = NULL;
		goto fail;
	}

	return 0;

fail:
	pmi_bpf_runtime_close(rt);
	return err;
}

int pmi_bpf_runtime_attach_session(struct pmi_bpf_runtime *rt,
				   struct pmi_perf_session *session)
{
	struct bpf_perf_event_opts opts;

	if (!rt || !session)
		return -EINVAL;

	memset(&opts, 0, sizeof(opts));
	opts.sz = sizeof(opts);
	opts.bpf_cookie = session->stream_id;

	session->link = bpf_program__attach_perf_event_opts(rt->prog,
							    session->leader_fd,
							    &opts);
	if (libbpf_get_error(session->link)) {
		int err = libbpf_get_error(session->link);

		session->link = NULL;
		return err;
	}
	return 0;
}

int pmi_bpf_runtime_poll(struct pmi_bpf_runtime *rt, int timeout_ms)
{
	if (!rt || !rt->ringbuf)
		return -EINVAL;
	return ring_buffer__poll(rt->ringbuf, timeout_ms);
}

int pmi_bpf_runtime_read_stack(struct pmi_bpf_runtime *rt, int stack_id,
			       uint64_t *ips, size_t depth)
{
	if (!rt || !ips || depth == 0)
		return -EINVAL;
	if (stack_id < 0)
		return -ENOENT;
	if (bpf_map_lookup_elem(rt->stack_map_fd, &stack_id, ips) != 0)
		return -errno;
	return 0;
}

void pmi_bpf_runtime_close(struct pmi_bpf_runtime *rt)
{
	if (!rt)
		return;
	if (rt->ringbuf) {
		ring_buffer__free(rt->ringbuf);
	}
	free(rt->ringbuf_ctx);
	if (rt->obj)
		bpf_object__close(rt->obj);
	memset(rt, 0, sizeof(*rt));
}

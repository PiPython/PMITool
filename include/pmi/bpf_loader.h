#ifndef PMI_BPF_LOADER_H
#define PMI_BPF_LOADER_H

#include <stddef.h>
#include <stdint.h>

#include <bpf/libbpf.h>

#include "pmi/perf_session.h"
#include "pmi/shared.h"

struct pmi_bpf_runtime {
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct ring_buffer *ringbuf;
	void *ringbuf_ctx;
	int ringbuf_map_fd;
	int stack_map_fd;
	int config_map_fd;
};

typedef int (*pmi_bpf_event_cb)(const struct pmi_bpf_event *event, void *ctx);

int pmi_bpf_runtime_open(struct pmi_bpf_runtime *rt, const char *obj_path,
			 const struct pmi_bpf_config *cfg, pmi_bpf_event_cb cb,
			 void *ctx);
int pmi_bpf_runtime_attach_session(struct pmi_bpf_runtime *rt,
				   struct pmi_perf_session *session);
int pmi_bpf_runtime_poll(struct pmi_bpf_runtime *rt, int timeout_ms);
int pmi_bpf_runtime_read_stack(struct pmi_bpf_runtime *rt, int stack_id,
			       uint64_t *ips, size_t depth);
void pmi_bpf_runtime_close(struct pmi_bpf_runtime *rt);

#endif

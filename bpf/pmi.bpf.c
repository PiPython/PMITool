#include <linux/bpf.h>
#include <linux/types.h>
#include <asm/bpf_perf_event.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "pmi/shared.h"

struct bpf_perf_event_data_kern {
	bpf_user_pt_regs_t regs;
	__u64 sample_period;
	__u64 addr;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, __u64[PMI_MAX_STACK_DEPTH]);
} stack_traces SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct pmi_bpf_config);
} config_map SEC(".maps");

SEC("perf_event")
int pmi_on_sample(struct bpf_perf_event_data_kern *ctx)
{
	struct pmi_bpf_config *cfg;
	struct pmi_bpf_event *event;
	__u32 zero = 0;
	__u64 pid_tgid;

	cfg = bpf_map_lookup_elem(&config_map, &zero);
	if (!cfg)
		return 0;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	__builtin_memset(event, 0, sizeof(*event));
	pid_tgid = bpf_get_current_pid_tgid();
	event->pid = pid_tgid >> 32;
	event->tid = (__u32)pid_tgid;
	event->cpu = bpf_get_smp_processor_id();
	event->time_ns = bpf_ktime_get_ns();
	event->attach_cookie = bpf_get_attach_cookie(ctx);
	event->ip = PT_REGS_IP(&ctx->regs);
	event->user_stack_id = -1;
	event->kernel_stack_id = -1;
	bpf_get_current_comm(event->comm, sizeof(event->comm));

	if (cfg->stack_mode == PMI_STACK_FULL)
		event->user_stack_id =
			bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
	if (cfg->capture_kernel_stack)
		event->kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);

	bpf_ringbuf_submit(event, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

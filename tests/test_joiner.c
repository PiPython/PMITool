#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pmi/joiner.h"

#define CHECK(cond)                                                             \
	do {                                                                    \
		if (!(cond)) {                                                   \
			fprintf(stderr, "CHECK failed at %s:%d: %s\n",           \
				__FILE__, __LINE__, #cond);                    \
			exit(1);                                                \
		}                                                               \
	} while (0)

struct test_state {
	struct pmi_joined_sample sample;
	size_t seen;
};

static int on_sample(const struct pmi_joined_sample *sample, void *ctx)
{
	struct test_state *state = ctx;

	state->sample = *sample;
	state->seen++;
	return 0;
}

int main(void)
{
	struct pmi_joiner *joiner;
	struct pmi_perf_sample perf = {
		.time_ns = 100,
		.stream_id = 7,
		.pid = 1000,
		.tid = 1001,
		.cpu = 1,
	};
	struct pmi_bpf_event bpf = {
		.time_ns = 105,
		.attach_cookie = 7,
		.pid = 1000,
		.tid = 1001,
		.cpu = 1,
		.ip = 0x55,
	};
	struct test_state state = { 0 };
	int err;

	err = pmi_joiner_init(&joiner, on_sample, &state);
	CHECK(err == 0);
	err = pmi_joiner_push_bpf(joiner, &bpf);
	CHECK(err == 0);
	err = pmi_joiner_push_perf(joiner, &perf);
	CHECK(err == 0);
	CHECK(state.seen == 1);
	CHECK(state.sample.perf.stream_id == 7);
	CHECK(state.sample.bpf.attach_cookie == 7);
	CHECK((state.sample.lost_flags & PMI_LOST_JOIN_MISMATCH) == 0);

	pmi_joiner_destroy(joiner);

	memset(&state, 0, sizeof(state));
	err = pmi_joiner_init(&joiner, on_sample, &state);
	CHECK(err == 0);
	err = pmi_joiner_push_perf(joiner, &perf);
	CHECK(err == 0);
	err = pmi_joiner_flush(joiner);
	CHECK(err == 0);
	CHECK(state.seen == 1);
	CHECK(state.sample.bpf.user_stack_id == -1);
	CHECK(state.sample.bpf.kernel_stack_id == -1);

	pmi_joiner_destroy(joiner);

	memset(&state, 0, sizeof(state));
	bpf.attach_cookie = 0;
	err = pmi_joiner_init(&joiner, on_sample, &state);
	CHECK(err == 0);
	err = pmi_joiner_push_bpf(joiner, &bpf);
	CHECK(err == 0);
	err = pmi_joiner_push_perf(joiner, &perf);
	CHECK(err == 0);
	CHECK(state.seen == 1);
	CHECK(state.sample.perf.tid == perf.tid);
	CHECK(state.sample.bpf.tid == bpf.tid);
	CHECK((state.sample.lost_flags & PMI_LOST_JOIN_MISMATCH) == 0);

	pmi_joiner_destroy(joiner);
	return 0;
}

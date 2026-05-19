#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "pmi/joiner.h"

#define PMI_JOINER_QUEUE_DEPTH 64
#define PMI_JOINER_MAX_STREAMS 1024
#define PMI_TIME_SKEW_NS (10ULL * 1000ULL * 1000ULL)

struct pmi_perf_queue {
	struct pmi_perf_sample items[PMI_JOINER_QUEUE_DEPTH];
	size_t count;
};

struct pmi_bpf_queue {
	struct pmi_bpf_event items[PMI_JOINER_QUEUE_DEPTH];
	size_t count;
};

struct pmi_stream_state {
	uint64_t stream_id;
	struct pmi_perf_queue perfq;
	struct pmi_bpf_queue bpfq;
};

struct pmi_joiner {
	struct pmi_stream_state streams[PMI_JOINER_MAX_STREAMS];
	size_t stream_count;
	pmi_joined_sample_cb cb;
	void *cb_ctx;
};

static uint64_t perf_stream_id(const struct pmi_perf_sample *sample)
{
	return sample->stream_id;
}

static uint64_t bpf_stream_id(const struct pmi_bpf_event *event)
{
	return event->attach_cookie;
}

static struct pmi_stream_state *find_stream(struct pmi_joiner *joiner,
					    uint64_t stream_id, bool create)
{
	size_t i;

	for (i = 0; i < joiner->stream_count; ++i) {
		if (joiner->streams[i].stream_id == stream_id)
			return &joiner->streams[i];
	}
	if (!create)
		return NULL;
	if (joiner->stream_count >= PMI_JOINER_MAX_STREAMS)
		return NULL;
	joiner->streams[joiner->stream_count].stream_id = stream_id;
	return &joiner->streams[joiner->stream_count++];
}

static int emit_joined(struct pmi_joiner *joiner,
		       const struct pmi_perf_sample *perf,
		       const struct pmi_bpf_event *bpf, unsigned int lost_flags)
{
	struct pmi_joined_sample sample;

	memset(&sample, 0, sizeof(sample));
	sample.bpf.user_stack_id = -1;
	sample.bpf.kernel_stack_id = -1;
	if (perf)
		sample.perf = *perf;
	if (bpf)
		sample.bpf = *bpf;
	sample.lost_flags = lost_flags;
	return joiner->cb(&sample, joiner->cb_ctx);
}

static void pop_perf(struct pmi_perf_queue *queue, struct pmi_perf_sample *out)
{
	*out = queue->items[0];
	memmove(&queue->items[0], &queue->items[1],
		(queue->count - 1) * sizeof(queue->items[0]));
	queue->count--;
}

static void pop_bpf(struct pmi_bpf_queue *queue, struct pmi_bpf_event *out)
{
	*out = queue->items[0];
	memmove(&queue->items[0], &queue->items[1],
		(queue->count - 1) * sizeof(queue->items[0]));
	queue->count--;
}

static int merge_stream(struct pmi_joiner *joiner, struct pmi_stream_state *stream)
{
	while (stream->perfq.count > 0 && stream->bpfq.count > 0) {
		struct pmi_perf_sample perf;
		struct pmi_bpf_event bpf;
		unsigned int lost = 0;
		uint64_t t0, t1, diff;

		pop_perf(&stream->perfq, &perf);
		pop_bpf(&stream->bpfq, &bpf);

		t0 = perf.time_ns;
		t1 = bpf.time_ns;
		diff = (t0 > t1) ? (t0 - t1) : (t1 - t0);
		lost |= perf.lost_flags;
		if (diff > PMI_TIME_SKEW_NS || perf.tid != (pid_t)bpf.tid)
			lost |= PMI_LOST_JOIN_MISMATCH;
		if (perf.event_count > 0 &&
		    perf.events[0].time_enabled != perf.events[0].time_running)
			lost |= PMI_LOST_MULTIPLEXED;

		if (emit_joined(joiner, &perf, &bpf, lost))
			return -1;
	}
	return 0;
}

int pmi_joiner_init(struct pmi_joiner **joiner, pmi_joined_sample_cb cb, void *ctx)
{
	struct pmi_joiner *out;

	if (!joiner || !cb)
		return -EINVAL;

	out = calloc(1, sizeof(*out));
	if (!out)
		return -ENOMEM;

	out->cb = cb;
	out->cb_ctx = ctx;
	*joiner = out;
	return 0;
}

void pmi_joiner_destroy(struct pmi_joiner *joiner)
{
	free(joiner);
}

int pmi_joiner_push_perf(struct pmi_joiner *joiner,
			 const struct pmi_perf_sample *sample)
{
	struct pmi_stream_state *stream;

	if (!joiner || !sample)
		return -EINVAL;

	stream = find_stream(joiner, perf_stream_id(sample), true);
	if (!stream)
		return -ENOSPC;

	if (stream->perfq.count >= PMI_JOINER_QUEUE_DEPTH) {
		struct pmi_perf_sample old;

		pop_perf(&stream->perfq, &old);
		if (emit_joined(joiner, &old, NULL, old.lost_flags | PMI_LOST_BPF))
			return -1;
	}

	stream->perfq.items[stream->perfq.count++] = *sample;
	return merge_stream(joiner, stream);
}

int pmi_joiner_push_bpf(struct pmi_joiner *joiner,
			const struct pmi_bpf_event *event)
{
	struct pmi_stream_state *stream;

	if (!joiner || !event)
		return -EINVAL;

	stream = find_stream(joiner, bpf_stream_id(event), true);
	if (!stream)
		return -ENOSPC;

	if (stream->bpfq.count >= PMI_JOINER_QUEUE_DEPTH) {
		struct pmi_bpf_event old;

		pop_bpf(&stream->bpfq, &old);
		if (emit_joined(joiner, NULL, &old, PMI_LOST_PERF))
			return -1;
	}

	stream->bpfq.items[stream->bpfq.count++] = *event;
	return merge_stream(joiner, stream);
}

int pmi_joiner_flush(struct pmi_joiner *joiner)
{
	size_t i;

	if (!joiner)
		return -EINVAL;

	for (i = 0; i < joiner->stream_count; ++i) {
		struct pmi_stream_state *stream = &joiner->streams[i];

		if (merge_stream(joiner, stream))
			return -1;

		while (stream->perfq.count > 0) {
			struct pmi_perf_sample perf;

			pop_perf(&stream->perfq, &perf);
			if (emit_joined(joiner, &perf, NULL,
					perf.lost_flags | PMI_LOST_BPF))
				return -1;
		}

		while (stream->bpfq.count > 0) {
			struct pmi_bpf_event bpf;

			pop_bpf(&stream->bpfq, &bpf);
			if (emit_joined(joiner, NULL, &bpf, PMI_LOST_PERF))
				return -1;
		}
	}

	return 0;
}

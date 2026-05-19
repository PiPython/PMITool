#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "pmi/output.h"

#define PMI_COL_TYPE_WIDTH 4
#define PMI_COL_SEQ_WIDTH 10
#define PMI_COL_INSN_WIDTH 16
#define PMI_COL_PID_WIDTH 8
#define PMI_COL_TID_WIDTH 8
#define PMI_COL_EVENTS_WIDTH 24
#define PMI_COL_TOP_WIDTH 32

static void sanitize_field(const char *src, char *dst, size_t cap)
{
	size_t i, j = 0;

	if (!dst || cap == 0)
		return;

	if (!src) {
		dst[0] = '\0';
		return;
	}

	for (i = 0; src[i] != '\0' && j + 1 < cap; ++i) {
		char c = src[i];

		if (c == '\t' || c == '\n' || c == '\r')
			c = ' ';
		dst[j++] = c;
	}
	dst[j] = '\0';
}

static struct pmi_output_prev_state *find_prev_state(struct pmi_output_writer *writer,
						     pid_t tid)
{
	size_t i;

	for (i = 0; i < writer->prev_count; ++i) {
		if (writer->prev[i].valid && writer->prev[i].tid == tid)
			return &writer->prev[i];
	}
	if (writer->prev_count >= PMI_OUTPUT_MAX_TIDS)
		return NULL;

	writer->prev[writer->prev_count].tid = tid;
	writer->prev[writer->prev_count].valid = true;
	writer->prev[writer->prev_count].event_count = 0;
	memset(writer->prev[writer->prev_count].values, 0,
	       sizeof(writer->prev[writer->prev_count].values));
	return &writer->prev[writer->prev_count++];
}

static uint64_t compute_delta(struct pmi_output_writer *writer,
			      const struct pmi_perf_sample *sample,
			      struct pmi_output_prev_state *prev, size_t slot)
{
	uint64_t current;
	uint64_t delta;

	if (!sample || !prev || slot >= sample->event_count)
		return 0;

	current = sample->events[slot].value;
	if (slot < prev->event_count) {
		uint64_t prior = prev->values[slot];

		if (current >= prior) {
			delta = current - prior;
		} else {
			delta = current;
			if (writer->debug_perf) {
				fprintf(stderr,
					"[output][delta] tid=%d slot=%zu current=%" PRIu64 " prev=%" PRIu64 " regression; using current\n",
					sample->tid, slot, current, prior);
			}
		}
	} else {
		delta = current;
	}

	prev->values[slot] = current;
	return delta;
}

static int format_custom_events(const struct pmi_perf_sample *sample,
				const uint64_t *deltas, char *buf, size_t cap)
{
	size_t i;
	size_t len = 0;
	bool wrote = false;

	if (!buf || cap == 0)
		return -EINVAL;

	for (i = 1; i < sample->event_count; ++i) {
		const char *name = sample->event_names[i][0] ?
					   sample->event_names[i] :
					   "event";
		int written;

		written = snprintf(buf + len, cap - len, "%s%s=%" PRIu64,
				   wrote ? "," : "", name, deltas[i]);
		if (written < 0 || (size_t)written >= cap - len)
			return -E2BIG;
		len += (size_t)written;
		wrote = true;
	}

	if (!wrote) {
		if (cap < 2)
			return -E2BIG;
		buf[0] = '-';
		buf[1] = '\0';
	}

	return 0;
}

int pmi_output_open(struct pmi_output_writer *writer, const char *path,
		    uint64_t period_insn)
{
	if (!writer || !path || period_insn == 0)
		return -EINVAL;

	memset(writer, 0, sizeof(*writer));
	writer->fp = fopen(path, "w");
	if (!writer->fp)
		return -errno;

	writer->period_insn = period_insn;
	fprintf(writer->fp, "# pmi raw v3\n");
	fprintf(writer->fp,
		"%-*s\t%-*s\t%-*s\t%-*s\t%-*s\t%-*s\t%-*s\t%s\n",
		PMI_COL_TYPE_WIDTH, "type", PMI_COL_SEQ_WIDTH, "seq",
		PMI_COL_INSN_WIDTH, "insn_delta", PMI_COL_PID_WIDTH, "pid",
		PMI_COL_TID_WIDTH, "tid", PMI_COL_EVENTS_WIDTH, "events",
		PMI_COL_TOP_WIDTH, "top", "stack");
	return 0;
}

int pmi_output_write_sample(struct pmi_output_writer *writer,
			    const struct pmi_perf_sample *sample,
			    const char *top, const char *stack)
{
	char safe_top[PMI_MAX_SYMBOL_LEN];
	char safe_stack[PMI_MAX_STACK_TEXT_LEN];
	char events[PMI_MAX_FOLDED_LEN];
	struct pmi_output_prev_state *prev;
	uint64_t deltas[PMI_MAX_EVENTS] = { 0 };
	uint64_t seq;
	uint64_t insn_delta = 0;
	pid_t pid;
	pid_t tid;
	size_t i;
	int err;

	if (!writer || !writer->fp || !sample)
		return -EINVAL;

	pid = sample->pid;
	tid = sample->tid;
	prev = find_prev_state(writer, tid);
	if (!prev)
		return -ENOSPC;
	for (i = 0; i < sample->event_count; ++i)
		deltas[i] = compute_delta(writer, sample, prev, i);
	prev->event_count = sample->event_count;
	insn_delta = sample->event_count > 0 ? deltas[0] : 0;

	sanitize_field(top && top[0] ? top : "-", safe_top, sizeof(safe_top));
	sanitize_field(stack && stack[0] ? stack : "-", safe_stack,
		       sizeof(safe_stack));
	err = format_custom_events(sample, deltas, events, sizeof(events));
	if (err)
		return err;

	seq = ++writer->seq;

	if (fprintf(writer->fp,
		    "%-*s\t%-*" PRIu64 "\t%-*" PRIu64 "\t%-*d\t%-*d\t%-*s\t%-*s\t%s\n",
		    PMI_COL_TYPE_WIDTH, "S", PMI_COL_SEQ_WIDTH, seq,
		    PMI_COL_INSN_WIDTH, insn_delta, PMI_COL_PID_WIDTH, pid,
		    PMI_COL_TID_WIDTH, tid, PMI_COL_EVENTS_WIDTH, events,
		    PMI_COL_TOP_WIDTH, safe_top, safe_stack) < 0)
		return -EIO;

	return ferror(writer->fp) ? -EIO : 0;
}

void pmi_output_close(struct pmi_output_writer *writer)
{
	if (writer && writer->fp)
		fclose(writer->fp);
}

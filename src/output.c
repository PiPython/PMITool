#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "pmi/output.h"

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

int pmi_output_open(struct pmi_output_writer *writer, const char *path,
		    const struct pmi_event_list *events)
{
	size_t i;

	if (!writer || !path)
		return -EINVAL;
	if (events && events->count > PMI_MAX_EVENTS - 1)
		return -E2BIG;

	memset(writer, 0, sizeof(*writer));
	writer->fp = fopen(path, "w");
	if (!writer->fp)
		return -errno;

	if (events) {
		writer->event_count = events->count;
		for (i = 0; i < events->count; ++i) {
			sanitize_field(events->items[i].name, writer->event_names[i],
				       sizeof(writer->event_names[i]));
		}
	}
	fprintf(writer->fp, "# pmi raw v3\n");
	fprintf(writer->fp, "type\tseq\tinsn_delta\tpid\ttid");
	for (i = 0; i < writer->event_count; ++i)
		fprintf(writer->fp, "\t%s", writer->event_names[i]);
	fprintf(writer->fp, "\ttop\tstack\n");
	return 0;
}

int pmi_output_write_sample(struct pmi_output_writer *writer,
			    const struct pmi_perf_sample *sample,
			    const char *top, const char *stack)
{
	char safe_top[PMI_MAX_SYMBOL_LEN];
	char safe_stack[PMI_MAX_STACK_TEXT_LEN];
	struct pmi_output_prev_state *prev;
	uint64_t deltas[PMI_MAX_EVENTS] = { 0 };
	uint64_t seq;
	uint64_t insn_delta = 0;
	pid_t pid;
	pid_t tid;
	size_t i;

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

	seq = ++writer->seq;

	if (fprintf(writer->fp, "S\t%" PRIu64 "\t%" PRIu64 "\t%d\t%d",
		    seq, insn_delta, pid, tid) < 0)
		return -EIO;
	for (i = 0; i < writer->event_count; ++i) {
		uint64_t value = 0;

		if (i + 1 < sample->event_count)
			value = deltas[i + 1];
		if (fprintf(writer->fp, "\t%" PRIu64, value) < 0)
			return -EIO;
	}
	if (fprintf(writer->fp, "\t%s\t%s\n", safe_top, safe_stack) < 0)
		return -EIO;

	return ferror(writer->fp) ? -EIO : 0;
}

void pmi_output_close(struct pmi_output_writer *writer)
{
	if (writer && writer->fp)
		fclose(writer->fp);
}

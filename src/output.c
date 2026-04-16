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
#define PMI_COL_IP_WIDTH 18
#define PMI_COL_SYMBOL_WIDTH 32
#define PMI_COL_EVENTS_WIDTH 24

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

static int format_custom_events(const struct pmi_joined_sample *sample, char *buf,
				size_t cap)
{
	size_t i;
	size_t len = 0;
	bool wrote = false;

	if (!buf || cap == 0)
		return -EINVAL;

	for (i = 0; i < sample->perf.event_count; ++i) {
		const char *name = sample->perf.event_names[i][0] ?
					   sample->perf.event_names[i] :
					   "event";
		int written;

		if (strcmp(name, "instructions") == 0)
			continue;
		written = snprintf(buf + len, cap - len, "%s%s=%" PRIu64,
				   wrote ? "," : "", name,
				   (uint64_t)sample->perf.events[i].value);
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

static uint64_t find_instruction_total(const struct pmi_joined_sample *sample)
{
	size_t i;

	for (i = 0; i < sample->perf.event_count; ++i) {
		if (strcmp(sample->perf.event_names[i], "instructions") == 0)
			return sample->perf.events[i].value;
	}

	if (sample->perf.event_count > 0)
		return sample->perf.events[0].value;
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
	fprintf(writer->fp, "# pmi raw v2\n");
	fprintf(writer->fp,
		"%-*s\t%-*s\t%-*s\t%-*s\t%-*s\t%-*s\t%-*s\t%-*s\t%-*s\t%s\n",
		PMI_COL_TYPE_WIDTH, "type", PMI_COL_SEQ_WIDTH, "seq",
		PMI_COL_INSN_WIDTH, "insn_total", PMI_COL_INSN_WIDTH,
		"insn_expected", PMI_COL_PID_WIDTH, "pid", PMI_COL_TID_WIDTH,
		"tid", PMI_COL_IP_WIDTH, "ip", PMI_COL_SYMBOL_WIDTH, "symbol",
		PMI_COL_EVENTS_WIDTH, "events", "stack");
	return 0;
}

int pmi_output_write_sample(struct pmi_output_writer *writer,
			    const struct pmi_joined_sample *sample,
			    const char *symbol, const char *stack)
{
	char safe_symbol[PMI_MAX_SYMBOL_LEN];
	char safe_stack[PMI_MAX_STACK_TEXT_LEN];
	char events[PMI_MAX_FOLDED_LEN];
	char ip_text[32];
	uint64_t seq;
	uint64_t insn_total = 0;
	uint64_t insn_expected;
	uint64_t ip;
	pid_t pid;
	pid_t tid;
	int err;

	if (!writer || !writer->fp || !sample)
		return -EINVAL;

	ip = sample->bpf.ip ? sample->bpf.ip : sample->perf.ip;
	pid = sample->perf.pid ? sample->perf.pid : (pid_t)sample->bpf.pid;
	tid = sample->perf.tid ? sample->perf.tid : (pid_t)sample->bpf.tid;
	insn_total = find_instruction_total(sample);

	sanitize_field(symbol && symbol[0] ? symbol : "-", safe_symbol,
		       sizeof(safe_symbol));
	sanitize_field(stack && stack[0] ? stack : "-", safe_stack,
		       sizeof(safe_stack));
	err = format_custom_events(sample, events, sizeof(events));
	if (err)
		return err;
	snprintf(ip_text, sizeof(ip_text), "0x%" PRIx64, ip);

	seq = ++writer->seq;
	insn_expected = seq * writer->period_insn;

	if (fprintf(writer->fp,
		    "%-*s\t%-*" PRIu64 "\t%-*" PRIu64 "\t%-*" PRIu64 "\t%-*d\t%-*d\t%-*s\t%-*s\t%-*s\t%s\n",
		    PMI_COL_TYPE_WIDTH, "S", PMI_COL_SEQ_WIDTH, seq,
		    PMI_COL_INSN_WIDTH, insn_total, PMI_COL_INSN_WIDTH,
		    insn_expected, PMI_COL_PID_WIDTH, pid, PMI_COL_TID_WIDTH, tid,
		    PMI_COL_IP_WIDTH, ip_text, PMI_COL_SYMBOL_WIDTH, safe_symbol,
		    PMI_COL_EVENTS_WIDTH, events, safe_stack) < 0)
		return -EIO;

	return ferror(writer->fp) ? -EIO : 0;
}

void pmi_output_close(struct pmi_output_writer *writer)
{
	if (writer && writer->fp)
		fclose(writer->fp);
}

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

static int write_custom_events(FILE *fp, const struct pmi_joined_sample *sample)
{
	size_t i;
	bool wrote = false;

	for (i = 0; i < sample->perf.event_count; ++i) {
		const char *name = sample->perf.event_names[i][0] ?
					   sample->perf.event_names[i] :
					   "event";

		if (strcmp(name, "instructions") == 0)
			continue;
		if (wrote && fputc(',', fp) == EOF)
			return -EIO;
		if (fprintf(fp, "%s=%" PRIu64, name,
			    (uint64_t)sample->perf.events[i].value) < 0)
			return -EIO;
		wrote = true;
	}

	if (!wrote && fputc('-', fp) == EOF)
		return -EIO;

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
		"type\tseq\tinsn_total\tinsn_expected\tpid\ttid\tip\tsymbol\tevents\tstack\n");
	return 0;
}

int pmi_output_write_sample(struct pmi_output_writer *writer,
			    const struct pmi_joined_sample *sample,
			    const char *symbol, const char *stack)
{
	char safe_symbol[PMI_MAX_SYMBOL_LEN];
	char safe_stack[PMI_MAX_STACK_TEXT_LEN];
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

	seq = ++writer->seq;
	insn_expected = seq * writer->period_insn;

	if (fprintf(writer->fp,
		    "S\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%d\t%d\t0x%" PRIx64
		    "\t%s\t",
		    seq, insn_total, insn_expected, pid, tid, ip, safe_symbol) < 0)
		return -EIO;

	err = write_custom_events(writer->fp, sample);
	if (err)
		return err;

	if (fprintf(writer->fp, "\t%s\n", safe_stack) < 0)
		return -EIO;

	return ferror(writer->fp) ? -EIO : 0;
}

void pmi_output_close(struct pmi_output_writer *writer)
{
	if (writer && writer->fp)
		fclose(writer->fp);
}

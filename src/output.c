#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "pmi/output.h"

static void sanitize_field(const char *src, char *dst, size_t cap)
{
	size_t i, j = 0;

	if (!src || !dst || cap == 0)
		return;

	for (i = 0; src[i] != '\0' && j + 1 < cap; ++i) {
		char c = src[i];

		if (c == '\t' || c == '\n' || c == '\r')
			c = ' ';
		dst[j++] = c;
	}
	dst[j] = '\0';
}

int pmi_output_open(struct pmi_output_writer *writer, const char *path)
{
	if (!writer || !path)
		return -EINVAL;

	writer->fp = fopen(path, "w");
	if (!writer->fp)
		return -errno;

	fprintf(writer->fp, "# pmi raw v1\n");
	return 0;
}

int pmi_output_write_sample(struct pmi_output_writer *writer,
			    const struct pmi_joined_sample *sample,
			    const char *module, const char *symbol,
			    const char *folded_stack)
{
	char comm[PMI_COMM_LEN];
	char safe_module[PMI_MAX_MODULE_LEN];
	char safe_symbol[PMI_MAX_SYMBOL_LEN];
	char safe_stack[PMI_MAX_FOLDED_LEN];
	size_t i;

	if (!writer || !writer->fp || !sample)
		return -EINVAL;

	sanitize_field(sample->bpf.comm[0] ? sample->bpf.comm : sample->perf.comm,
		       comm, sizeof(comm));
	sanitize_field(module ? module : "-", safe_module, sizeof(safe_module));
	sanitize_field(symbol ? symbol : "-", safe_symbol, sizeof(safe_symbol));
	sanitize_field(folded_stack ? folded_stack : "-", safe_stack,
		       sizeof(safe_stack));

		fprintf(writer->fp,
			"S\t%" PRIu64 "\t%d\t%d\t%u\t%" PRIu64 "\t%u\t0x%" PRIx64
			"\t%d\t%d\t%s\t%s\t%s\t",
			(uint64_t)(sample->perf.time_ns ? sample->perf.time_ns :
				   sample->bpf.time_ns),
			sample->perf.pid ? sample->perf.pid : (pid_t)sample->bpf.pid,
			sample->perf.tid ? sample->perf.tid : (pid_t)sample->bpf.tid,
			(sample->perf.stream_id || sample->perf.pid) ? sample->perf.cpu :
								       sample->bpf.cpu,
			(uint64_t)(sample->perf.stream_id ? sample->perf.stream_id :
				   sample->bpf.attach_cookie),
			sample->lost_flags,
			(uint64_t)(sample->bpf.ip ? sample->bpf.ip : sample->perf.ip),
			sample->bpf.user_stack_id, sample->bpf.kernel_stack_id, comm,
			safe_module, safe_symbol);

		for (i = 0; i < sample->perf.event_count; ++i) {
			const struct pmi_event_value *v = &sample->perf.events[i];

			if (i != 0) {
				fputc(',', writer->fp);
			}
			fprintf(writer->fp, "%s@%" PRIu64 "=%" PRIu64 "/%" PRIu64 "/%" PRIu64,
				sample->perf.event_names[i][0] ? sample->perf.event_names[i] :
								 "event",
				(uint64_t)v->id, (uint64_t)v->value,
				(uint64_t)v->time_enabled, (uint64_t)v->time_running);
		}

	fprintf(writer->fp, "\t%s\n", safe_stack);
	return ferror(writer->fp) ? -EIO : 0;
}

void pmi_output_close(struct pmi_output_writer *writer)
{
	if (writer && writer->fp)
		fclose(writer->fp);
}

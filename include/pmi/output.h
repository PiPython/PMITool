#ifndef PMI_OUTPUT_H
#define PMI_OUTPUT_H

#include <stdio.h>
#include <stdint.h>

#include "pmi/perf_session.h"

struct pmi_output_writer {
	FILE *fp;
	uint64_t seq;
	uint64_t period_insn;
};

int pmi_output_open(struct pmi_output_writer *writer, const char *path,
		    uint64_t period_insn);
int pmi_output_write_sample(struct pmi_output_writer *writer,
			    const struct pmi_perf_sample *sample,
			    const char *top, const char *stack);
void pmi_output_close(struct pmi_output_writer *writer);

#endif

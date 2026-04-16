#ifndef PMI_OUTPUT_H
#define PMI_OUTPUT_H

#include <stdio.h>

#include "pmi/joiner.h"

struct pmi_output_writer {
	FILE *fp;
};

int pmi_output_open(struct pmi_output_writer *writer, const char *path);
int pmi_output_write_sample(struct pmi_output_writer *writer,
			    const struct pmi_joined_sample *sample,
			    const char *module, const char *symbol,
			    const char *folded_stack);
void pmi_output_close(struct pmi_output_writer *writer);

#endif

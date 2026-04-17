#ifndef PMI_OUTPUT_H
#define PMI_OUTPUT_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "pmi/perf_session.h"

#define PMI_OUTPUT_MAX_TIDS 1024

struct pmi_output_prev_state {
	pid_t tid;
	bool valid;
	uint64_t values[PMI_MAX_EVENTS];
	size_t event_count;
};

struct pmi_output_writer {
	FILE *fp;
	uint64_t seq;
	bool debug_perf;
	char event_names[PMI_MAX_EVENTS - 1][PMI_MAX_EVENT_NAME];
	size_t event_count;
	struct pmi_output_prev_state prev[PMI_OUTPUT_MAX_TIDS];
	size_t prev_count;
};

int pmi_output_open(struct pmi_output_writer *writer, const char *path,
		    const struct pmi_event_list *events);
int pmi_output_write_sample(struct pmi_output_writer *writer,
			    const struct pmi_perf_sample *sample,
			    const char *top, const char *stack);
void pmi_output_close(struct pmi_output_writer *writer);

#endif

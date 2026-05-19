#ifndef PMI_RECORD_H
#define PMI_RECORD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "pmi/shared.h"

struct pmi_record_options {
	pid_t pid;
	pid_t tid;
	const char *cmd;
	const char *output_path;
	uint64_t period;
	enum pmi_stack_mode stack_mode;
	bool capture_kernel_stack;
	bool debug_perf;
	int mmap_pages;
	int poll_timeout_ms;
	char raw_event_tokens[PMI_MAX_EVENTS - 1][PMI_MAX_EVENT_NAME];
	size_t raw_event_count;
};

struct pmi_report_options {
	const char *input_path;
	size_t limit;
	enum {
		PMI_REPORT_OVERVIEW = 0,
		PMI_REPORT_SAMPLES = 1,
	} mode;
};

int pmi_record_main(int argc, char **argv);
int pmi_report_main(int argc, char **argv);

#endif

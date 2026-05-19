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
	int mmap_pages;
	int poll_timeout_ms;
	char *event_inputs[PMI_MAX_EVENTS - 1];
	size_t event_input_count;
};

struct pmi_report_options {
	const char *input_path;
	size_t limit;
};

int pmi_record_main(int argc, char **argv);
int pmi_report_main(int argc, char **argv);

#endif

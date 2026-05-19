#ifndef PMI_RECORD_H
#define PMI_RECORD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "pmi/shared.h"

enum pmi_write_mode {
	PMI_WRITE_LOW_OVERHEAD = 0,
	PMI_WRITE_STRICT = 1,
};

/* record 侧只保留真正影响采样行为的选项，符号化等重活统一放到 report。 */
struct pmi_record_options {
	pid_t pid;
	pid_t tid;
	const char *cmd;
	const char *output_path;
	uint64_t period;
	enum pmi_stack_mode stack_mode;
	enum pmi_write_mode write_mode;
	bool capture_kernel_stack;
	bool debug_perf;
	int mmap_pages;
	int poll_timeout_ms;
	char raw_event_tokens[PMI_MAX_EVENTS - 1][PMI_MAX_EVENT_NAME];
	size_t raw_event_count;
};

/* report 侧既承担文本报表，也承担 visual HTML 的离线生成。 */
struct pmi_report_options {
	const char *input_path;
	const char *output_path;
	size_t limit;
	size_t window_samples;
	bool saw_window_samples;
	pid_t tids[1024];
	size_t tid_count;
	enum {
		PMI_REPORT_OVERVIEW = 0,
		PMI_REPORT_SAMPLES = 1,
		PMI_REPORT_VISUAL = 2,
	} mode;
};

int pmi_record_main(int argc, char **argv);
int pmi_report_main(int argc, char **argv);

#endif

#ifndef PMI_SHARED_H
#define PMI_SHARED_H

#include <linux/types.h>

#define PMI_COMM_LEN 16
#define PMI_MAX_EVENT_NAME 64
#define PMI_MAX_PMU_NAME 64
#define PMI_MAX_EVENTS 8
#define PMI_MAX_STACK_DEPTH 127
#define PMI_MAX_SYMBOL_LEN 256
#define PMI_MAX_MODULE_LEN 256
#define PMI_MAX_FOLDED_LEN 2048
#define PMI_MAX_STACK_TEXT_LEN 4096
#define PMI_MAX_LINE_LEN 4096

enum pmi_stack_mode {
	PMI_STACK_NONE = 0,
	PMI_STACK_TOP = 1,
	PMI_STACK_FULL = 2,
};

enum pmi_lost_flags {
	PMI_LOST_NONE = 0,
	PMI_LOST_PERF = 1U << 0,
};

struct pmi_event_value {
	__u64 id;
	__u64 value;
	__u64 time_enabled;
	__u64 time_running;
};

#endif

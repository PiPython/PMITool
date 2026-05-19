#ifndef PMI_EVENT_H
#define PMI_EVENT_H

#include <limits.h>
#include <linux/perf_event.h>
#include <stddef.h>
#include <stdint.h>

#include "pmi/shared.h"

struct pmi_event_spec {
	char name[PMI_MAX_EVENT_NAME];
	char pmu[PMI_MAX_PMU_NAME];
	uint32_t type;
	uint64_t config;
	uint64_t config1;
	uint64_t config2;
};

struct pmi_event_list {
	char sysfs_root[PATH_MAX];
	struct pmi_event_spec items[PMI_MAX_EVENTS - 1];
	size_t count;
};

int pmi_event_list_resolve(struct pmi_event_list *list, char *const *inputs,
			   size_t count, const char *sysfs_root);

#endif

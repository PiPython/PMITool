#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pmi/event.h"

#define CHECK(cond)                                                             \
	do {                                                                    \
		if (!(cond)) {                                                   \
			fprintf(stderr, "CHECK failed at %s:%d: %s\n",           \
				__FILE__, __LINE__, #cond);                    \
			exit(1);                                                \
		}                                                               \
	} while (0)

int main(void)
{
	struct pmi_event_list list;
	const char *alias_inputs[] = { "l1d_cache" };
	const char *raw_inputs[] = { "armv8_pmuv3_0/event=0x08,opcode=0x3/" };
	const char *raw_tokens[] = { "r0010", "r0011" };
	const char *bad_tokens[] = { "0010" };
	int err;

	err = pmi_event_list_resolve(&list, alias_inputs, 1, "fixtures/sysfs_cpu_pmu");
	CHECK(err == 0);
	CHECK(list.count == 1);
	CHECK(strcmp(list.items[0].name, "l1d_cache") == 0);
	CHECK(strcmp(list.items[0].pmu, "armv8_pmuv3_0") == 0);
	CHECK(list.items[0].config == 0x4);
	CHECK(list.items[0].config1 == 0x2);

	err = pmi_event_list_resolve(&list, raw_inputs, 1, "fixtures/sysfs_cpu_pmu");
	CHECK(err == 0);
	CHECK(list.count == 1);
	CHECK(list.items[0].config == 0x08);
	CHECK(list.items[0].config1 == 0x3);

	err = pmi_event_list_resolve_raw_tokens(&list, raw_tokens, 2,
						"fixtures/sysfs_cpu_pmu");
	CHECK(err == 0);
	CHECK(list.count == 2);
	CHECK(strcmp(list.items[0].name, "r0010") == 0);
	CHECK(strcmp(list.items[0].pmu, "armv8_pmuv3_0") == 0);
	CHECK(list.items[0].config == 0x10);
	CHECK(strcmp(list.items[1].name, "r0011") == 0);
	CHECK(list.items[1].config == 0x11);

	err = pmi_event_list_resolve_raw_tokens(&list, bad_tokens, 1,
						"fixtures/sysfs_cpu_pmu");
	CHECK(err == -EINVAL);
	CHECK(strstr(list.error, "invalid raw event token") != NULL);

	err = pmi_event_list_resolve_raw_tokens(&list, raw_tokens, 1,
						"fixtures/sysfs_no_cpu_pmu");
	CHECK(err == -ENODEV);
	CHECK(strstr(list.error, "real CPU PMU") != NULL);

	return 0;
}

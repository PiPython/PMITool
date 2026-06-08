#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pmi/perf_session.h"
#include "pmi/record.h"

#define CHECK(cond)                                                             \
	do {                                                                    \
		if (!(cond)) {                                                   \
			fprintf(stderr, "CHECK failed at %s:%d: %s\n",           \
				__FILE__, __LINE__, #cond);                    \
			exit(1);                                                \
		}                                                               \
	} while (0)

static void check_cpu_set(const char *text, const int *expected, size_t expected_count)
{
	int cpus[PMI_MAX_RECORD_TARGETS];
	size_t count = 0;
	size_t i;
	int err;

	memset(cpus, 0, sizeof(cpus));
	err = pmi_record_parse_cpu_set(text, cpus,
				       sizeof(cpus) / sizeof(cpus[0]), &count);
	CHECK(err == 0);
	CHECK(count == expected_count);
	for (i = 0; i < expected_count; ++i)
		CHECK(cpus[i] == expected[i]);
}

static void check_bad_cpu_set(const char *text)
{
	int cpus[PMI_MAX_RECORD_TARGETS];
	size_t count = 0;

	CHECK(pmi_record_parse_cpu_set(text, cpus,
				       sizeof(cpus) / sizeof(cpus[0]), &count) != 0);
}

int main(void)
{
	const int cpus_1_4[] = { 1, 2, 3, 4 };
	const int cpus_mixed[] = { 0, 2, 3, 4, 7 };
	const int cpus_dedup[] = { 1, 2, 3 };
	struct pmi_perf_target tid_target = {
		.type = PMI_PERF_TARGET_TID,
		.tid = 123,
		.cpu = -1,
	};
	struct pmi_perf_target cpu_target = {
		.type = PMI_PERF_TARGET_CPU,
		.tid = -1,
		.cpu = 3,
	};
	struct pmi_perf_open_args args;

	check_cpu_set("1-4", cpus_1_4, sizeof(cpus_1_4) / sizeof(cpus_1_4[0]));
	check_cpu_set("0,2-4,7", cpus_mixed,
		      sizeof(cpus_mixed) / sizeof(cpus_mixed[0]));
	check_cpu_set("1,2,1,2-3", cpus_dedup,
		      sizeof(cpus_dedup) / sizeof(cpus_dedup[0]));

	check_bad_cpu_set("");
	check_bad_cpu_set("1,,2");
	check_bad_cpu_set("-1");
	check_bad_cpu_set("1,-2");
	check_bad_cpu_set("4-1");
	check_bad_cpu_set("abc");
	check_bad_cpu_set("1-a");
	check_bad_cpu_set("1 ");
	check_bad_cpu_set(" 1");

	args = pmi_perf_target_open_args(tid_target);
	CHECK(args.pid == 123);
	CHECK(args.cpu == -1);

	args = pmi_perf_target_open_args(cpu_target);
	CHECK(args.pid == -1);
	CHECK(args.cpu == 3);

	return 0;
}

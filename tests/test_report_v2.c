#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pmi/record.h"

#define CHECK(cond)                                                             \
	do {                                                                    \
		if (!(cond)) {                                                   \
			fprintf(stderr, "CHECK failed at %s:%d: %s\n",           \
				__FILE__, __LINE__, #cond);                    \
			exit(1);                                                \
		}                                                               \
	} while (0)

__attribute__((noinline)) static void report_fixture_target(void)
{
	__asm__ __volatile__("" ::: "memory");
}

int main(void)
{
	char input_path[] = "/tmp/pmi-report-input-XXXXXX";
	char output_path[] = "/tmp/pmi-report-output-XXXXXX";
	char line[1024];
	char output[2048] = { 0 };
	char stack_field[128];
	char symbol_field[64];
	char *argv[] = { "report", "-i", input_path, "-l", "10", NULL };
	FILE *fp;
	int input_fd;
	int output_fd;
	int saved_stdout;
	int err;
	uint64_t ip = (uint64_t)(uintptr_t)&report_fixture_target;

	snprintf(stack_field, sizeof(stack_field), "0x%llx",
		 (unsigned long long)ip);
	snprintf(symbol_field, sizeof(symbol_field), "0x%llx",
		 (unsigned long long)ip);

	input_fd = mkstemp(input_path);
	CHECK(input_fd >= 0);
	fp = fdopen(input_fd, "w");
	CHECK(fp != NULL);
	fprintf(fp, "# pmi raw v2\n");
	fprintf(fp, "S\t1\t1000000\t1000000\t%d\t%d\t0x%llx\tleaf\tr0010=3,r0011=5\t-\n",
		getpid(), getpid(), (unsigned long long)ip);
	fprintf(fp,
		"S\t2\t2000000\t2000000\t%d\t%d\t0x%llx\t%s\tr0010=7\t%s\n",
		getpid(), getpid(), (unsigned long long)ip, symbol_field,
		stack_field);
	fclose(fp);

	output_fd = mkstemp(output_path);
	CHECK(output_fd >= 0);
	saved_stdout = dup(STDOUT_FILENO);
	CHECK(saved_stdout >= 0);
	fflush(stdout);
	CHECK(dup2(output_fd, STDOUT_FILENO) >= 0);
	close(output_fd);

	err = pmi_report_main(5, argv);
	fflush(stdout);
	CHECK(dup2(saved_stdout, STDOUT_FILENO) >= 0);
	close(saved_stdout);
	CHECK(err == 0);

	fp = fopen(output_path, "r");
	CHECK(fp != NULL);
	while (fgets(line, sizeof(line), fp) != NULL)
		strncat(output, line, sizeof(output) - strlen(output) - 1);
	fclose(fp);

	CHECK(strstr(output, "samples") != NULL);
	CHECK(strstr(output, "leaf") != NULL);
	CHECK(strstr(output, "report_fixture_target") != NULL);
	CHECK(strstr(output, "r0010=3") != NULL);
	CHECK(strstr(output, "r0011=5") != NULL);
	CHECK(strstr(output, "r0010=7") != NULL);

	unlink(input_path);
	unlink(output_path);
	return 0;
}

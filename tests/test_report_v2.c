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

__attribute__((noinline)) static void report_fixture_parent(void)
{
	__asm__ __volatile__("" ::: "memory");
}

int main(void)
{
	char input_path[] = "/tmp/pmi-report-input-XXXXXX";
	char output_overview_path[] = "/tmp/pmi-report-overview-XXXXXX";
	char output_samples_path[] = "/tmp/pmi-report-samples-XXXXXX";
	char line[1024];
	char output[4096] = { 0 };
	char samples_output[4096] = { 0 };
	char stack_field[128];
	char top_field[64];
	char *overview_argv[] = { "report", "-i", input_path, "-l", "10", NULL };
	char *samples_argv[] = { "report", "-i", input_path, "-m", "samples", NULL };
	FILE *fp;
	int input_fd;
	int output_fd;
	int samples_output_fd;
	int saved_stdout;
	int err;
	uint64_t parent_ip = (uint64_t)(uintptr_t)&report_fixture_parent;

	snprintf(stack_field, sizeof(stack_field), "0x%llx",
		 (unsigned long long)parent_ip);
	snprintf(top_field, sizeof(top_field), "%s", "report_fixture_leaf");

	input_fd = mkstemp(input_path);
	CHECK(input_fd >= 0);
	fp = fdopen(input_fd, "w");
	CHECK(fp != NULL);
	fprintf(fp, "# pmi raw v3\n");
	fprintf(fp,
		"type\tseq\tinsn_delta\tpid\ttid\tevents\ttop\tstack\n");
	fprintf(fp, "S\t1\t1000000\t%d\t%d\tr0010=3,r0011=5\tleaf\t-\n",
		getpid(), getpid());
	fprintf(fp,
		"S\t2\t100\t%d\t%d\tr0010=7\t%s\t%s\n",
		getpid(), getpid(), top_field, stack_field);
	fclose(fp);

	output_fd = mkstemp(output_overview_path);
	CHECK(output_fd >= 0);
	saved_stdout = dup(STDOUT_FILENO);
	CHECK(saved_stdout >= 0);
	fflush(stdout);
	CHECK(dup2(output_fd, STDOUT_FILENO) >= 0);
	close(output_fd);

	err = pmi_report_main(5, overview_argv);
	fflush(stdout);
	CHECK(dup2(saved_stdout, STDOUT_FILENO) >= 0);
	close(saved_stdout);
	CHECK(err == 0);

	fp = fopen(output_overview_path, "r");
	CHECK(fp != NULL);
	while (fgets(line, sizeof(line), fp) != NULL)
		strncat(output, line, sizeof(output) - strlen(output) - 1);
	fclose(fp);

	CHECK(strstr(output, "samples") != NULL);
	CHECK(strstr(output, "insn_delta") != NULL);
	CHECK(strstr(output, "top") != NULL);
	CHECK(strstr(output, "leaf") != NULL);
	CHECK(strstr(output, "report_fixture_leaf") != NULL);
	CHECK(strstr(output, "full stacks") != NULL);
	CHECK(strstr(output, "report_fixture_leaf;report_fixture_parent") != NULL);
	CHECK(strstr(output, "1000000") != NULL);
	CHECK(strstr(output, "100") != NULL);
	CHECK(strstr(output, "r0010=3") != NULL);
	CHECK(strstr(output, "r0011=5") != NULL);
	CHECK(strstr(output, "r0010=7") != NULL);

	samples_output_fd = mkstemp(output_samples_path);
	CHECK(samples_output_fd >= 0);
	saved_stdout = dup(STDOUT_FILENO);
	CHECK(saved_stdout >= 0);
	fflush(stdout);
	CHECK(dup2(samples_output_fd, STDOUT_FILENO) >= 0);
	close(samples_output_fd);

	err = pmi_report_main(5, samples_argv);
	fflush(stdout);
	CHECK(dup2(saved_stdout, STDOUT_FILENO) >= 0);
	close(saved_stdout);
	CHECK(err == 0);

	fp = fopen(output_samples_path, "r");
	CHECK(fp != NULL);
	while (fgets(line, sizeof(line), fp) != NULL)
		strncat(samples_output, line, sizeof(samples_output) - strlen(samples_output) - 1);
	fclose(fp);

	CHECK(strstr(samples_output, "seq") != NULL);
	CHECK(strstr(samples_output, "insn_delta") != NULL);
	CHECK(strstr(samples_output, "leaf") != NULL);
	CHECK(strstr(samples_output, "report_fixture_leaf;report_fixture_parent") != NULL);
	CHECK(strstr(samples_output, "r0010=7") != NULL);

	unlink(input_path);
	unlink(output_overview_path);
	unlink(output_samples_path);
	return 0;
}

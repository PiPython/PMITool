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

__attribute__((noinline)) static void report_fixture_extremely_long_named_function_for_alignment_testing(void)
{
	__asm__ __volatile__("" ::: "memory");
}

int main(void)
{
	char input_path[] = "/tmp/pmi-report-input-XXXXXX";
	char output_overview_path[] = "/tmp/pmi-report-overview-XXXXXX";
	char output_samples_path[] = "/tmp/pmi-report-samples-XXXXXX";
	char output_visual_path[] = "/tmp/pmi-report-visual-XXXXXX";
	char line[1024];
	char output[16384] = { 0 };
	char samples_output[16384] = { 0 };
	char visual_output[32768] = { 0 };
	char stack_field[128];
	char mangled_top[64];
	char long_top_field[64];
	char long_stack_field[1024];
	char *overview_argv[] = { "report", "-i", input_path, "-l", "10", "-t",
				  "202", NULL };
	char *samples_argv[] = { "report", "-i", input_path, "-m", "samples",
				 "-t", "202", NULL };
	char *visual_argv[] = { "report", "-i", input_path, "-m", "visual",
				"-o", output_visual_path, "-l", "2", "-t",
				"202", NULL };
	char *visual_bad_argv[] = { "report", "-i", input_path, "-m", "visual",
				    NULL };
	char *visual_window_argv[] = { "report", "-i", input_path, "-m", "visual",
				       "-o", output_visual_path, "-w", "2", NULL };
	FILE *fp;
	int input_fd;
	int output_fd;
	int samples_output_fd;
	int visual_output_fd;
	int saved_stdout;
	int saved_stderr;
	int err;
	uint64_t parent_ip = (uint64_t)(uintptr_t)&report_fixture_parent;
	uint64_t long_top_ip =
		(uint64_t)(uintptr_t)&report_fixture_extremely_long_named_function_for_alignment_testing;
	size_t offset = 0;
	int i;

	snprintf(stack_field, sizeof(stack_field), "0x%llx",
		 (unsigned long long)parent_ip);
	snprintf(mangled_top, sizeof(mangled_top), "%s", "_ZN3foo3barEi");
	snprintf(long_top_field, sizeof(long_top_field), "0x%llx",
		 (unsigned long long)long_top_ip);
	long_stack_field[0] = '\0';
	for (i = 0; i < 20; ++i) {
		offset += (size_t)snprintf(long_stack_field + offset,
					   sizeof(long_stack_field) - offset,
					   "%s0x%llx", i ? ";" : "",
					   (unsigned long long)parent_ip);
	}

	input_fd = mkstemp(input_path);
	CHECK(input_fd >= 0);
	fp = fdopen(input_fd, "w");
	CHECK(fp != NULL);
	fprintf(fp, "# pmi raw v3\n");
	fprintf(fp,
		"type\tseq\tinsn_delta\tpid\ttid\tr0010\tr0011\ttop\tstack\n");
	fprintf(fp, "S\t1\t1000000\t%d\t%d\t3\t5\tleaf\t-\n",
		getpid(), 101);
	fprintf(fp,
		"S\t2\t100\t%d\t%d\t7\t0\t%s\t%s\n",
		getpid(), 202, mangled_top, stack_field);
	fprintf(fp,
		"S\t3\t200\t%d\t%d\t9\t11\t%s\t%s\n",
		getpid(), 202, long_top_field, long_stack_field);
	fclose(fp);

	output_fd = mkstemp(output_overview_path);
	CHECK(output_fd >= 0);
	saved_stdout = dup(STDOUT_FILENO);
	CHECK(saved_stdout >= 0);
	fflush(stdout);
	CHECK(dup2(output_fd, STDOUT_FILENO) >= 0);
	close(output_fd);

	err = pmi_report_main(7, overview_argv);
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
	CHECK(strstr(output, "leaf") == NULL);
	CHECK(strstr(output, "foo::bar(int)") != NULL);
	CHECK(strstr(output, long_top_field) == NULL);
	CHECK(strstr(output, "full stacks") != NULL);
	CHECK(strstr(output, "foo::bar(int);report_fixture_parent") != NULL);
	CHECK(strstr(output, "1000000") == NULL);
	CHECK(strstr(output, "100") != NULL);
	CHECK(strstr(output, "200") != NULL);
	CHECK(strstr(output, "r0010") != NULL);
	CHECK(strstr(output, "r0011") != NULL);
	CHECK(strchr(output, '\t') == NULL);
	CHECK(strstr(output, "samples  insn_delta") != NULL);
	CHECK(strstr(output, "-------") != NULL);
	CHECK(strstr(output, "...") != NULL);
	CHECK(strstr(output, "leaf") == NULL);

	samples_output_fd = mkstemp(output_samples_path);
	CHECK(samples_output_fd >= 0);
	saved_stdout = dup(STDOUT_FILENO);
	CHECK(saved_stdout >= 0);
	fflush(stdout);
	CHECK(dup2(samples_output_fd, STDOUT_FILENO) >= 0);
	close(samples_output_fd);

	err = pmi_report_main(7, samples_argv);
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
	CHECK(strstr(samples_output, "r0010") != NULL);
	CHECK(strstr(samples_output, "r0011") != NULL);
	CHECK(strchr(samples_output, '\t') == NULL);
	CHECK(strstr(samples_output, "seq  pid") != NULL);
	CHECK(strstr(samples_output, "-------") != NULL);
	CHECK(strstr(samples_output, "leaf") == NULL);
	CHECK(strstr(samples_output, "foo::bar(int);report_fixture_parent") != NULL);
	CHECK(strstr(samples_output, long_top_field) == NULL);
	CHECK(strstr(samples_output, "...") != NULL);

	visual_output_fd = mkstemp(output_visual_path);
	CHECK(visual_output_fd >= 0);
	close(visual_output_fd);

	err = pmi_report_main(11, visual_argv);
	CHECK(err == 0);

	fp = fopen(output_visual_path, "r");
	CHECK(fp != NULL);
	while (fgets(line, sizeof(line), fp) != NULL)
		strncat(visual_output, line,
			sizeof(visual_output) - strlen(visual_output) - 1);
	fclose(fp);

	CHECK(strstr(visual_output, "<!doctype html>") != NULL);
	CHECK(strstr(visual_output, "const reportData =") != NULL);
	CHECK(strstr(visual_output, "tid-select") != NULL);
	CHECK(strstr(visual_output, "phase-heatmap") != NULL);
	CHECK(strstr(visual_output, "phase-detail") != NULL);
	CHECK(strstr(visual_output, "阶段热条图") != NULL);
	CHECK(strstr(visual_output, "阶段热点榜") != NULL);
	CHECK(strstr(visual_output, "该阶段热点榜") != NULL);
	CHECK(strstr(visual_output, "该阶段 full stacks") != NULL);
	CHECK(strstr(visual_output, "\"r0010\"") != NULL);
	CHECK(strstr(visual_output, "\"r0011\"") != NULL);
	CHECK(strstr(visual_output, "foo::bar(int)") != NULL);
	CHECK(strstr(visual_output, mangled_top) == NULL);
	CHECK(strstr(visual_output, long_top_field) == NULL);
	CHECK(strstr(visual_output, stack_field) == NULL);
	CHECK(strstr(visual_output, "windowSamples") == NULL);
	CHECK(strstr(visual_output, "overview-canvas") == NULL);
	CHECK(strstr(visual_output, "detail-frame") == NULL);
	CHECK(strstr(visual_output, "全量概览") == NULL);
	CHECK(strstr(visual_output, "细节散点图") == NULL);
	CHECK(strstr(visual_output, "当前区间逐 Sample 折线图") == NULL);
	CHECK(strstr(visual_output, "requestAnimationFrame") == NULL);

	saved_stderr = dup(STDERR_FILENO);
	CHECK(saved_stderr >= 0);
	visual_output_fd = open("/dev/null", O_WRONLY);
	CHECK(visual_output_fd >= 0);
	CHECK(dup2(visual_output_fd, STDERR_FILENO) >= 0);
	close(visual_output_fd);
	err = pmi_report_main(5, visual_bad_argv);
	CHECK(dup2(saved_stderr, STDERR_FILENO) >= 0);
	close(saved_stderr);
	CHECK(err == 1);

	saved_stderr = dup(STDERR_FILENO);
	CHECK(saved_stderr >= 0);
	visual_output_fd = open("/dev/null", O_WRONLY);
	CHECK(visual_output_fd >= 0);
	CHECK(dup2(visual_output_fd, STDERR_FILENO) >= 0);
	close(visual_output_fd);
	err = pmi_report_main(9, visual_window_argv);
	CHECK(dup2(saved_stderr, STDERR_FILENO) >= 0);
	close(saved_stderr);
	CHECK(err == 1);

	unlink(input_path);
	unlink(output_overview_path);
	unlink(output_samples_path);
	unlink(output_visual_path);
	return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pmi/output.h"

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
	char path[] = "/tmp/pmi-output-v2-XXXXXX";
	struct pmi_output_writer writer;
	struct pmi_joined_sample sample;
	FILE *fp;
	char header[64];
	char line[512];
	int fd;
	int err;

	fd = mkstemp(path);
	CHECK(fd >= 0);
	close(fd);

	memset(&sample, 0, sizeof(sample));
	sample.bpf.user_stack_id = -1;
	sample.bpf.kernel_stack_id = -1;
	sample.perf.pid = 11;
	sample.perf.tid = 22;
	sample.perf.ip = 0x1234;
	sample.perf.event_count = 3;
	sample.perf.events[0].value = 1000000;
	sample.perf.events[1].value = 7;
	sample.perf.events[2].value = 9;
	strcpy(sample.perf.event_names[0], "instructions");
	strcpy(sample.perf.event_names[1], "r0010");
	strcpy(sample.perf.event_names[2], "r0011");

	err = pmi_output_open(&writer, path, 1000000);
	CHECK(err == 0);
	err = pmi_output_write_sample(&writer, &sample, "hot_func",
				      "0x1234;0x2345");
	CHECK(err == 0);
	pmi_output_close(&writer);

	fp = fopen(path, "r");
	CHECK(fp != NULL);
	CHECK(fgets(header, sizeof(header), fp) != NULL);
	CHECK(strcmp(header, "# pmi raw v2\n") == 0);
	CHECK(fgets(line, sizeof(line), fp) != NULL);
	CHECK(strcmp(line,
		     "S\t1\t1000000\t1000000\t11\t22\t0x1234\thot_func\tr0010=7,r0011=9\t0x1234;0x2345\n") ==
	      0);
	fclose(fp);
	unlink(path);
	return 0;
}

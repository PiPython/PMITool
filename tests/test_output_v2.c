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

static char *next_field(char **cursor)
{
	char *field = strsep(cursor, "\t");
	char *end;

	if (!field)
		return NULL;
	while (*field == ' ')
		field++;
	end = field + strlen(field);
	while (end > field && (end[-1] == ' ' || end[-1] == '\n')) {
		end[-1] = '\0';
		end--;
	}
	return field;
}

int main(void)
{
	char path[] = "/tmp/pmi-output-v3-XXXXXX";
	struct pmi_output_writer writer;
	struct pmi_perf_sample sample1;
	struct pmi_perf_sample sample2;
	struct pmi_perf_sample sample3;
	FILE *fp;
	char header[64];
	char columns[256];
	char line[512];
	char *cursor;
	int fd;
	int err;

	fd = mkstemp(path);
	CHECK(fd >= 0);
	close(fd);

	memset(&sample1, 0, sizeof(sample1));
	sample1.pid = 11;
	sample1.tid = 22;
	sample1.event_count = 3;
	sample1.events[0].value = 1000000;
	sample1.events[1].value = 7;
	sample1.events[2].value = 9;
	strcpy(sample1.event_names[0], "instructions");
	strcpy(sample1.event_names[1], "r0010");
	strcpy(sample1.event_names[2], "r0011");

	memset(&sample2, 0, sizeof(sample2));
	sample2.pid = 11;
	sample2.tid = 22;
	sample2.event_count = 3;
	sample2.events[0].value = 1000100;
	sample2.events[1].value = 10;
	sample2.events[2].value = 15;
	strcpy(sample2.event_names[0], "instructions");
	strcpy(sample2.event_names[1], "r0010");
	strcpy(sample2.event_names[2], "r0011");

	memset(&sample3, 0, sizeof(sample3));
	sample3.pid = 11;
	sample3.tid = 33;
	sample3.event_count = 3;
	sample3.events[0].value = 500;
	sample3.events[1].value = 2;
	sample3.events[2].value = 4;
	strcpy(sample3.event_names[0], "instructions");
	strcpy(sample3.event_names[1], "r0010");
	strcpy(sample3.event_names[2], "r0011");

	err = pmi_output_open(&writer, path, 1000000);
	CHECK(err == 0);
	err = pmi_output_write_sample(&writer, &sample1, "hot_func", "0x2345");
	CHECK(err == 0);
	err = pmi_output_write_sample(&writer, &sample2, "hot_func", "0x3345");
	CHECK(err == 0);
	err = pmi_output_write_sample(&writer, &sample3, "other_func", "-");
	CHECK(err == 0);
	pmi_output_close(&writer);

	fp = fopen(path, "r");
	CHECK(fp != NULL);
	CHECK(fgets(header, sizeof(header), fp) != NULL);
	CHECK(strcmp(header, "# pmi raw v3\n") == 0);
	CHECK(fgets(columns, sizeof(columns), fp) != NULL);
	cursor = columns;
	CHECK(strcmp(next_field(&cursor), "type") == 0);
	CHECK(strcmp(next_field(&cursor), "seq") == 0);
	CHECK(strcmp(next_field(&cursor), "insn_delta") == 0);
	CHECK(strcmp(next_field(&cursor), "pid") == 0);
	CHECK(strcmp(next_field(&cursor), "tid") == 0);
	CHECK(strcmp(next_field(&cursor), "events") == 0);
	CHECK(strcmp(next_field(&cursor), "top") == 0);
	CHECK(strcmp(next_field(&cursor), "stack") == 0);
	CHECK(fgets(line, sizeof(line), fp) != NULL);
	cursor = line;
	CHECK(strcmp(next_field(&cursor), "S") == 0);
	CHECK(strcmp(next_field(&cursor), "1") == 0);
	CHECK(strcmp(next_field(&cursor), "1000000") == 0);
	CHECK(strcmp(next_field(&cursor), "11") == 0);
	CHECK(strcmp(next_field(&cursor), "22") == 0);
	CHECK(strcmp(next_field(&cursor), "r0010=7,r0011=9") == 0);
	CHECK(strcmp(next_field(&cursor), "hot_func") == 0);
	CHECK(strcmp(next_field(&cursor), "0x2345") == 0);
	CHECK(fgets(line, sizeof(line), fp) != NULL);
	cursor = line;
	CHECK(strcmp(next_field(&cursor), "S") == 0);
	CHECK(strcmp(next_field(&cursor), "2") == 0);
	CHECK(strcmp(next_field(&cursor), "100") == 0);
	CHECK(strcmp(next_field(&cursor), "11") == 0);
	CHECK(strcmp(next_field(&cursor), "22") == 0);
	CHECK(strcmp(next_field(&cursor), "r0010=3,r0011=6") == 0);
	CHECK(strcmp(next_field(&cursor), "hot_func") == 0);
	CHECK(strcmp(next_field(&cursor), "0x3345") == 0);
	CHECK(fgets(line, sizeof(line), fp) != NULL);
	cursor = line;
	CHECK(strcmp(next_field(&cursor), "S") == 0);
	CHECK(strcmp(next_field(&cursor), "3") == 0);
	CHECK(strcmp(next_field(&cursor), "500") == 0);
	CHECK(strcmp(next_field(&cursor), "11") == 0);
	CHECK(strcmp(next_field(&cursor), "33") == 0);
	CHECK(strcmp(next_field(&cursor), "r0010=2,r0011=4") == 0);
	CHECK(strcmp(next_field(&cursor), "other_func") == 0);
	CHECK(strcmp(next_field(&cursor), "-") == 0);
	fclose(fp);
	unlink(path);
	return 0;
}

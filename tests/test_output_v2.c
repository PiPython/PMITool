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
	struct pmi_perf_sample sample;
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

	memset(&sample, 0, sizeof(sample));
	sample.pid = 11;
	sample.tid = 22;
	sample.ip = 0x1234;
	sample.event_count = 3;
	sample.events[0].value = 1000000;
	sample.events[1].value = 7;
	sample.events[2].value = 9;
	strcpy(sample.event_names[0], "instructions");
	strcpy(sample.event_names[1], "r0010");
	strcpy(sample.event_names[2], "r0011");

	err = pmi_output_open(&writer, path, 1000000);
	CHECK(err == 0);
	err = pmi_output_write_sample(&writer, &sample, "hot_func", "0x2345");
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
	CHECK(strcmp(next_field(&cursor), "insn_total") == 0);
	CHECK(strcmp(next_field(&cursor), "insn_expected") == 0);
	CHECK(strcmp(next_field(&cursor), "pid") == 0);
	CHECK(strcmp(next_field(&cursor), "tid") == 0);
	CHECK(strcmp(next_field(&cursor), "top") == 0);
	CHECK(strcmp(next_field(&cursor), "events") == 0);
	CHECK(strcmp(next_field(&cursor), "stack") == 0);
	CHECK(fgets(line, sizeof(line), fp) != NULL);
	cursor = line;
	CHECK(strcmp(next_field(&cursor), "S") == 0);
	CHECK(strcmp(next_field(&cursor), "1") == 0);
	CHECK(strcmp(next_field(&cursor), "1000000") == 0);
	CHECK(strcmp(next_field(&cursor), "1000000") == 0);
	CHECK(strcmp(next_field(&cursor), "11") == 0);
	CHECK(strcmp(next_field(&cursor), "22") == 0);
	CHECK(strcmp(next_field(&cursor), "hot_func") == 0);
	CHECK(strcmp(next_field(&cursor), "r0010=7,r0011=9") == 0);
	CHECK(strcmp(next_field(&cursor), "0x2345") == 0);
	fclose(fp);
	unlink(path);
	return 0;
}

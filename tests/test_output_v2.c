#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pmi/event.h"
#include "pmi/output.h"
#include "pmi/record.h"

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
	char no_event_path[] = "/tmp/pmi-output-v3-no-events-XXXXXX";
	struct pmi_output_writer writer;
	struct pmi_output_writer no_event_writer;
	struct pmi_event_list event_list;
	struct pmi_output_sample sample1;
	struct pmi_output_sample sample2;
	struct pmi_output_sample sample3;
	struct pmi_output_sample no_event_sample;
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

	memset(&event_list, 0, sizeof(event_list));
	event_list.count = 2;
	strcpy(event_list.items[0].name, "r0010");
	strcpy(event_list.items[1].name, "r0011");

	memset(&sample1, 0, sizeof(sample1));
	sample1.pid = 11;
	sample1.tid = 22;
	sample1.top_ip = 0x1234;
	sample1.stack_depth = 2;
	sample1.stack_ips[0] = 0x2234;
	sample1.stack_ips[1] = 0x3234;
	sample1.event_count = 3;
	sample1.event_deltas[0] = 1000000;
	sample1.event_deltas[1] = 7;
	sample1.event_deltas[2] = 9;

	memset(&sample2, 0, sizeof(sample2));
	sample2.pid = 11;
	sample2.tid = 22;
	sample2.top_ip = 0x1334;
	sample2.event_count = 3;
	sample2.event_deltas[0] = 100;
	sample2.event_deltas[1] = 3;
	sample2.event_deltas[2] = 6;

	memset(&sample3, 0, sizeof(sample3));
	sample3.pid = 11;
	sample3.tid = 33;
	sample3.event_count = 3;
	sample3.event_deltas[0] = 500;
	sample3.event_deltas[1] = 2;
	sample3.event_deltas[2] = 4;

	err = pmi_output_open(&writer, path, &event_list, PMI_WRITE_STRICT, false);
	CHECK(err == 0);
	err = pmi_output_enqueue_sample(&writer, &sample1);
	CHECK(err == 0);
	err = pmi_output_enqueue_sample(&writer, &sample2);
	CHECK(err == 0);
	err = pmi_output_enqueue_sample(&writer, &sample3);
	CHECK(err == 0);
	err = pmi_output_close(&writer);
	CHECK(err == 0);

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
	CHECK(strcmp(next_field(&cursor), "r0010") == 0);
	CHECK(strcmp(next_field(&cursor), "r0011") == 0);
	CHECK(strcmp(next_field(&cursor), "top") == 0);
	CHECK(strcmp(next_field(&cursor), "stack") == 0);

	CHECK(fgets(line, sizeof(line), fp) != NULL);
	cursor = line;
	CHECK(strcmp(next_field(&cursor), "S") == 0);
	CHECK(strcmp(next_field(&cursor), "1") == 0);
	CHECK(strcmp(next_field(&cursor), "1000000") == 0);
	CHECK(strcmp(next_field(&cursor), "11") == 0);
	CHECK(strcmp(next_field(&cursor), "22") == 0);
	CHECK(strcmp(next_field(&cursor), "7") == 0);
	CHECK(strcmp(next_field(&cursor), "9") == 0);
	CHECK(strcmp(next_field(&cursor), "0x1234") == 0);
	CHECK(strcmp(next_field(&cursor), "0x2234;0x3234") == 0);

	CHECK(fgets(line, sizeof(line), fp) != NULL);
	cursor = line;
	CHECK(strcmp(next_field(&cursor), "S") == 0);
	CHECK(strcmp(next_field(&cursor), "2") == 0);
	CHECK(strcmp(next_field(&cursor), "100") == 0);
	CHECK(strcmp(next_field(&cursor), "11") == 0);
	CHECK(strcmp(next_field(&cursor), "22") == 0);
	CHECK(strcmp(next_field(&cursor), "3") == 0);
	CHECK(strcmp(next_field(&cursor), "6") == 0);
	CHECK(strcmp(next_field(&cursor), "0x1334") == 0);
	CHECK(strcmp(next_field(&cursor), "-") == 0);

	CHECK(fgets(line, sizeof(line), fp) != NULL);
	cursor = line;
	CHECK(strcmp(next_field(&cursor), "S") == 0);
	CHECK(strcmp(next_field(&cursor), "3") == 0);
	CHECK(strcmp(next_field(&cursor), "500") == 0);
	CHECK(strcmp(next_field(&cursor), "11") == 0);
	CHECK(strcmp(next_field(&cursor), "33") == 0);
	CHECK(strcmp(next_field(&cursor), "2") == 0);
	CHECK(strcmp(next_field(&cursor), "4") == 0);
	CHECK(strcmp(next_field(&cursor), "-") == 0);
	CHECK(strcmp(next_field(&cursor), "-") == 0);
	fclose(fp);
	unlink(path);

	fd = mkstemp(no_event_path);
	CHECK(fd >= 0);
	close(fd);

	memset(&no_event_sample, 0, sizeof(no_event_sample));
	no_event_sample.pid = 99;
	no_event_sample.tid = 99;
	no_event_sample.event_count = 1;
	no_event_sample.event_deltas[0] = 42;

	err = pmi_output_open(&no_event_writer, no_event_path, NULL,
			      PMI_WRITE_STRICT, false);
	CHECK(err == 0);
	err = pmi_output_enqueue_sample(&no_event_writer, &no_event_sample);
	CHECK(err == 0);
	err = pmi_output_close(&no_event_writer);
	CHECK(err == 0);

	fp = fopen(no_event_path, "r");
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
	CHECK(strcmp(next_field(&cursor), "top") == 0);
	CHECK(strcmp(next_field(&cursor), "stack") == 0);
	CHECK(fgets(line, sizeof(line), fp) != NULL);
	cursor = line;
	CHECK(strcmp(next_field(&cursor), "S") == 0);
	CHECK(strcmp(next_field(&cursor), "1") == 0);
	CHECK(strcmp(next_field(&cursor), "42") == 0);
	CHECK(strcmp(next_field(&cursor), "99") == 0);
	CHECK(strcmp(next_field(&cursor), "99") == 0);
	CHECK(strcmp(next_field(&cursor), "-") == 0);
	CHECK(strcmp(next_field(&cursor), "-") == 0);
	fclose(fp);
	unlink(no_event_path);
	return 0;
}

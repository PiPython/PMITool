#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/perf_event.h>

#include "pmi/perf_session.h"

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
	unsigned char payload[256];
	unsigned char *cursor = payload;
	struct pmi_perf_sample sample;
	const uint64_t sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID |
				     PERF_SAMPLE_TIME | PERF_SAMPLE_CPU |
				     PERF_SAMPLE_READ | PERF_SAMPLE_STREAM_ID;
	uint64_t ip = 0x1234;
	uint32_t pid = 11, tid = 22, cpu = 3, reserved = 0;
	uint64_t time_ns = 55;
	uint64_t nr = 2, enabled = 100, running = 90;
	uint64_t value0 = 1000, id0 = 1, value1 = 2000, id1 = 2;
	uint64_t stream_id = 99;
	int err;

	memcpy(cursor, &ip, sizeof(ip));
	cursor += sizeof(ip);
	memcpy(cursor, &pid, sizeof(pid));
	memcpy(cursor + sizeof(pid), &tid, sizeof(tid));
	cursor += sizeof(pid) + sizeof(tid);
	memcpy(cursor, &time_ns, sizeof(time_ns));
	cursor += sizeof(time_ns);
	memcpy(cursor, &stream_id, sizeof(stream_id));
	cursor += sizeof(stream_id);
	memcpy(cursor, &cpu, sizeof(cpu));
	memcpy(cursor + sizeof(cpu), &reserved, sizeof(reserved));
	cursor += sizeof(cpu) + sizeof(reserved);
	memcpy(cursor, &nr, sizeof(nr));
	cursor += sizeof(nr);
	memcpy(cursor, &enabled, sizeof(enabled));
	memcpy(cursor + sizeof(enabled), &running, sizeof(running));
	cursor += sizeof(enabled) + sizeof(running);
	memcpy(cursor, &value0, sizeof(value0));
	memcpy(cursor + sizeof(value0), &id0, sizeof(id0));
	cursor += sizeof(value0) + sizeof(id0);
	memcpy(cursor, &value1, sizeof(value1));
	memcpy(cursor + sizeof(value1), &id1, sizeof(id1));
	cursor += sizeof(value1) + sizeof(id1);

	err = pmi_perf_decode_sample(payload, (size_t)(cursor - payload), sample_type,
				     &sample);
	CHECK(err == 0);
	CHECK(sample.ip == ip);
	CHECK(sample.pid == (pid_t)pid);
	CHECK(sample.tid == (pid_t)tid);
	CHECK(sample.time_ns == time_ns);
	CHECK(sample.cpu == cpu);
	CHECK(sample.stream_id == stream_id);
	CHECK(sample.event_count == 2);
	CHECK(sample.events[0].id == id0);
	CHECK(sample.events[0].value == value0);
	CHECK(sample.events[0].time_enabled == enabled);
	CHECK(sample.events[0].time_running == running);
	CHECK(sample.events[1].id == id1);
	CHECK(sample.events[1].value == value1);

	return 0;
}

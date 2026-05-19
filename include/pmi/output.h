#ifndef PMI_OUTPUT_H
#define PMI_OUTPUT_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "pmi/perf_session.h"

#define PMI_OUTPUT_QUEUE_CAPACITY 4096

/* 这是从采样热路径复制出来的轻量对象，避免 writer 线程再回看 perf 结构。 */
struct pmi_output_sample {
	pid_t pid;
	pid_t tid;
	uint64_t top_ip;
	uint64_t stack_ips[PMI_MAX_STACK_DEPTH];
	uint64_t event_deltas[PMI_MAX_EVENTS];
	size_t stack_depth;
	size_t event_count;
};

/* writer 线程负责批量 TSV 落盘，主线程只做入队，尽量少阻塞采样。 */
struct pmi_output_writer {
	FILE *fp;
	char *file_buffer;
	pthread_t thread;
	pthread_mutex_t mutex;
	pthread_cond_t not_empty;
	pthread_cond_t not_full;
	uint64_t seq;
	uint64_t dropped_samples;
	int worker_err;
	bool debug_perf;
	bool closing;
	bool thread_started;
	enum pmi_write_mode write_mode;
	char event_names[PMI_MAX_EVENTS - 1][PMI_MAX_EVENT_NAME];
	size_t event_count;
	size_t head;
	size_t tail;
	size_t count;
	struct pmi_output_sample *queue;
};

int pmi_output_open(struct pmi_output_writer *writer, const char *path,
		    const struct pmi_event_list *events, enum pmi_write_mode write_mode,
		    bool debug_perf);
int pmi_output_enqueue_sample(struct pmi_output_writer *writer,
			      const struct pmi_output_sample *sample);
int pmi_output_close(struct pmi_output_writer *writer);

#endif

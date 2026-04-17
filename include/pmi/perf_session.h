#ifndef PMI_PERF_SESSION_H
#define PMI_PERF_SESSION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "pmi/event.h"
#include "pmi/record.h"
#include "pmi/shared.h"

struct pmi_perf_sample {
	uint64_t time_ns;
	uint64_t stream_id;
	uint64_t ip;
	pid_t pid;
	pid_t tid;
	uint32_t cpu;
	char comm[PMI_COMM_LEN];
	struct pmi_event_value events[PMI_MAX_EVENTS];
	char event_names[PMI_MAX_EVENTS][PMI_MAX_EVENT_NAME];
	uint64_t callchain[PMI_MAX_STACK_DEPTH];
	size_t event_count;
	size_t callchain_count;
	unsigned int lost_flags;
};

struct pmi_perf_group_snapshot {
	struct pmi_event_value events[PMI_MAX_EVENTS];
	size_t event_count;
};

struct pmi_opened_event {
	char name[PMI_MAX_EVENT_NAME];
	int fd;
	uint64_t id;
	uint32_t type;
	uint64_t config;
};

struct pmi_perf_session {
	pid_t tid;
	int leader_fd;
	void *mmap_base;
	size_t mmap_len;
	uint64_t stream_id;
	uint64_t sample_type;
	char comm[PMI_COMM_LEN];
	bool debug_perf;
	bool pending_lost;
	uint64_t sample_period;
	uint64_t empty_drains;
	uint64_t samples_seen;
	uint64_t last_leader_count;
	uint64_t last_sample_leader_count;
	uint64_t last_time_enabled;
	uint64_t last_time_running;
	uint64_t missing_periods_reported;
	bool count_grew;
	struct pmi_opened_event events[PMI_MAX_EVENTS];
	size_t event_count;
};

typedef int (*pmi_perf_sample_cb)(const struct pmi_perf_sample *sample, void *ctx);

int pmi_perf_session_open(struct pmi_perf_session *session, pid_t tid,
			  const struct pmi_record_options *opts,
			  const struct pmi_event_list *events);
int pmi_perf_session_enable(struct pmi_perf_session *session);
int pmi_perf_session_drain(struct pmi_perf_session *session, pmi_perf_sample_cb cb,
			   void *ctx);
int pmi_perf_decode_sample(const void *data, size_t len, uint64_t sample_type,
			   struct pmi_perf_sample *sample);
int pmi_perf_parse_group_read(const void *data, size_t len,
			      struct pmi_perf_group_snapshot *snapshot);
void pmi_perf_session_close(struct pmi_perf_session *session);

#endif

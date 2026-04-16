#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <asm/unistd.h>
#include <errno.h>
#include <linux/perf_event.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "pmi/perf_session.h"
#include "pmi/procfs.h"
#include "pmi/strutil.h"

#define PMI_PERF_BUFFER_PAGES 8

static int sys_perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu,
			       int group_fd, unsigned long flags)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static int copy_from_ring(void *dst, size_t cap, const char *base, size_t size,
			  uint64_t offset, size_t len)
{
	size_t begin = offset % size;

	if (len > cap)
		return -E2BIG;
	if (begin + len <= size) {
		memcpy(dst, base + begin, len);
		return 0;
	}
	memcpy(dst, base + begin, size - begin);
	memcpy((char *)dst + (size - begin), base, len - (size - begin));
	return 0;
}

static void fill_sample_names(struct pmi_perf_session *session,
			      struct pmi_perf_sample *sample)
{
	size_t i, j;

	for (i = 0; i < sample->event_count; ++i) {
		snprintf(sample->event_names[i], sizeof(sample->event_names[i]),
			 "event%zu", i);
		for (j = 0; j < session->event_count; ++j) {
			if (session->events[j].id == sample->events[i].id) {
				snprintf(sample->event_names[i],
					 sizeof(sample->event_names[i]), "%s",
					 session->events[j].name);
				break;
			}
		}
	}
}

static int open_event(int group_fd, pid_t tid, const struct perf_event_attr *tmpl,
		      struct pmi_opened_event *opened)
{
	struct perf_event_attr attr = *tmpl;

	opened->fd = sys_perf_event_open(&attr, tid, -1, group_fd, 0);
	if (opened->fd < 0)
		return -errno;
	if (ioctl(opened->fd, PERF_EVENT_IOC_ID, &opened->id) != 0) {
		close(opened->fd);
		opened->fd = -1;
		return -errno;
	}
	return 0;
}

int pmi_perf_decode_sample(const void *data, size_t len, uint64_t sample_type,
			   struct pmi_perf_sample *sample)
{
	const unsigned char *cursor = data;
	const unsigned char *end = cursor + len;
	uint64_t nr, time_enabled = 0, time_running = 0;
	size_t i;

	memset(sample, 0, sizeof(*sample));

	if (sample_type & PERF_SAMPLE_IP) {
		if ((size_t)(end - cursor) < sizeof(uint64_t))
			return -EINVAL;
		memcpy(&sample->ip, cursor, sizeof(uint64_t));
		cursor += sizeof(uint64_t);
	}

	if (sample_type & PERF_SAMPLE_TID) {
		uint32_t pid, tid;

		if ((size_t)(end - cursor) < sizeof(uint32_t) * 2)
			return -EINVAL;
		memcpy(&pid, cursor, sizeof(pid));
		memcpy(&tid, cursor + sizeof(pid), sizeof(tid));
		sample->pid = (pid_t)pid;
		sample->tid = (pid_t)tid;
		cursor += sizeof(uint32_t) * 2;
	}

	if (sample_type & PERF_SAMPLE_TIME) {
		if ((size_t)(end - cursor) < sizeof(uint64_t))
			return -EINVAL;
		memcpy(&sample->time_ns, cursor, sizeof(uint64_t));
		cursor += sizeof(uint64_t);
	}

	if (sample_type & PERF_SAMPLE_ADDR) {
		if ((size_t)(end - cursor) < sizeof(uint64_t))
			return -EINVAL;
		cursor += sizeof(uint64_t);
	}

	if (sample_type & PERF_SAMPLE_ID) {
		if ((size_t)(end - cursor) < sizeof(uint64_t))
			return -EINVAL;
		cursor += sizeof(uint64_t);
	}

	if (sample_type & PERF_SAMPLE_STREAM_ID) {
		if ((size_t)(end - cursor) < sizeof(uint64_t))
			return -EINVAL;
		memcpy(&sample->stream_id, cursor, sizeof(uint64_t));
		cursor += sizeof(uint64_t);
	}

	if (sample_type & PERF_SAMPLE_CPU) {
		uint32_t cpu, reserved;

		if ((size_t)(end - cursor) < sizeof(uint32_t) * 2)
			return -EINVAL;
		memcpy(&cpu, cursor, sizeof(cpu));
		memcpy(&reserved, cursor + sizeof(cpu), sizeof(reserved));
		(void)reserved;
		sample->cpu = cpu;
		cursor += sizeof(uint32_t) * 2;
	}

	if (sample_type & PERF_SAMPLE_PERIOD) {
		if ((size_t)(end - cursor) < sizeof(uint64_t))
			return -EINVAL;
		cursor += sizeof(uint64_t);
	}

	if (sample_type & PERF_SAMPLE_READ) {
		if ((size_t)(end - cursor) < sizeof(uint64_t))
			return -EINVAL;
		memcpy(&nr, cursor, sizeof(nr));
		cursor += sizeof(uint64_t);

		if ((size_t)(end - cursor) < sizeof(uint64_t) * 2)
			return -EINVAL;
		memcpy(&time_enabled, cursor, sizeof(uint64_t));
		memcpy(&time_running, cursor + sizeof(uint64_t), sizeof(uint64_t));
		cursor += sizeof(uint64_t) * 2;

		if (nr > PMI_MAX_EVENTS)
			nr = PMI_MAX_EVENTS;
		sample->event_count = (size_t)nr;
		for (i = 0; i < sample->event_count; ++i) {
			if ((size_t)(end - cursor) < sizeof(uint64_t) * 2)
				return -EINVAL;
			memcpy(&sample->events[i].value, cursor, sizeof(uint64_t));
			memcpy(&sample->events[i].id, cursor + sizeof(uint64_t),
			       sizeof(uint64_t));
			sample->events[i].time_enabled = time_enabled;
			sample->events[i].time_running = time_running;
			cursor += sizeof(uint64_t) * 2;
		}
	}

	if (sample_type & PERF_SAMPLE_CALLCHAIN) {
		uint64_t nr_callchain;

		if ((size_t)(end - cursor) < sizeof(uint64_t))
			return -EINVAL;
		memcpy(&nr_callchain, cursor, sizeof(uint64_t));
		cursor += sizeof(uint64_t) + nr_callchain * sizeof(uint64_t);
		if (cursor > end)
			return -EINVAL;
	}

	return 0;
}

int pmi_perf_session_open(struct pmi_perf_session *session, pid_t tid,
			  const struct pmi_record_options *opts,
			  const struct pmi_event_list *events)
{
	struct perf_event_attr leader = {
		.size = sizeof(struct perf_event_attr),
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_INSTRUCTIONS,
		.sample_period = opts->period ? opts->period : 1000000,
		.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID |
			       PERF_SAMPLE_TIME | PERF_SAMPLE_CPU |
			       PERF_SAMPLE_READ | PERF_SAMPLE_STREAM_ID,
		.read_format = PERF_FORMAT_GROUP | PERF_FORMAT_ID |
			       PERF_FORMAT_TOTAL_TIME_ENABLED |
			       PERF_FORMAT_TOTAL_TIME_RUNNING,
		.disabled = 1,
		.exclude_hv = 1,
		.exclude_guest = 1,
		.exclude_kernel = opts->capture_kernel_stack ? 0 : 1,
		.wakeup_events = 1,
	};
	size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
	size_t pages = (size_t)(opts->mmap_pages > 0 ? opts->mmap_pages :
					 PMI_PERF_BUFFER_PAGES);
	size_t i;
	int err;

	memset(session, 0, sizeof(*session));
	session->tid = tid;
	for (i = 0; i < PMI_MAX_EVENTS; ++i)
		session->events[i].fd = -1;

	snprintf(session->events[0].name, sizeof(session->events[0].name),
		 "instructions");
	session->events[0].type = PERF_TYPE_HARDWARE;
	session->events[0].config = PERF_COUNT_HW_INSTRUCTIONS;
	err = open_event(-1, tid, &leader, &session->events[0]);
	if (err)
		goto fail;
	session->leader_fd = session->events[0].fd;
	session->event_count = 1;

	for (i = 0; i < events->count; ++i) {
		struct perf_event_attr sibling = {
			.size = sizeof(struct perf_event_attr),
			.type = events->items[i].type,
			.config = events->items[i].config,
			.config1 = events->items[i].config1,
			.config2 = events->items[i].config2,
			.read_format = leader.read_format,
			.exclude_hv = leader.exclude_hv,
			.exclude_guest = leader.exclude_guest,
			.exclude_kernel = leader.exclude_kernel,
		};

		snprintf(session->events[session->event_count].name,
			 sizeof(session->events[session->event_count].name), "%s",
			 events->items[i].name);
		session->events[session->event_count].type = sibling.type;
		session->events[session->event_count].config = sibling.config;
		err = open_event(session->leader_fd, tid, &sibling,
				 &session->events[session->event_count]);
		if (err)
			goto fail;
		session->event_count++;
	}

	if (ioctl(session->leader_fd, PERF_EVENT_IOC_ID, &session->stream_id) != 0) {
		err = -errno;
		goto fail;
	}

	session->mmap_len = page_size * (pages + 1);
	session->mmap_base = mmap(NULL, session->mmap_len, PROT_READ | PROT_WRITE,
				  MAP_SHARED, session->leader_fd, 0);
	if (session->mmap_base == MAP_FAILED) {
		session->mmap_base = NULL;
		err = -errno;
		goto fail;
	}

	if (pmi_procfs_read_comm(tid, session->comm))
		snprintf(session->comm, sizeof(session->comm), "%d", tid);
	return 0;

fail:
	pmi_perf_session_close(session);
	return err;
}

int pmi_perf_session_enable(struct pmi_perf_session *session)
{
	if (!session)
		return -EINVAL;
	if (ioctl(session->leader_fd, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP) != 0)
		return -errno;
	if (ioctl(session->leader_fd, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP) != 0)
		return -errno;
	return 0;
}

int pmi_perf_session_drain(struct pmi_perf_session *session, pmi_perf_sample_cb cb,
			   void *ctx)
{
	struct perf_event_mmap_page *meta;
	const char *data;
	uint64_t head, tail, size;
	int err = 0;

	if (!session || !session->mmap_base || !cb)
		return -EINVAL;

	meta = session->mmap_base;
	data = (const char *)session->mmap_base + sysconf(_SC_PAGESIZE);
	size = meta->data_size;
	head = __atomic_load_n(&meta->data_head, __ATOMIC_ACQUIRE);
	tail = meta->data_tail;

	while (tail < head) {
		struct perf_event_header hdr;
		unsigned char stack_buf[PMI_MAX_LINE_LEN];

		err = copy_from_ring(&hdr, sizeof(hdr), data, size, tail, sizeof(hdr));
		if (err)
			break;
		if (hdr.size > sizeof(stack_buf)) {
			err = -E2BIG;
			break;
		}
		err = copy_from_ring(stack_buf, sizeof(stack_buf), data, size, tail,
				     hdr.size);
		if (err)
			break;

		if (hdr.type == PERF_RECORD_SAMPLE) {
			struct pmi_perf_sample sample;

			err = pmi_perf_decode_sample(stack_buf + sizeof(hdr),
						     hdr.size - sizeof(hdr),
						     ((struct perf_event_attr){
							      .sample_type =
								      PERF_SAMPLE_IP |
								      PERF_SAMPLE_TID |
								      PERF_SAMPLE_TIME |
								      PERF_SAMPLE_CPU |
								      PERF_SAMPLE_READ |
								      PERF_SAMPLE_STREAM_ID,
						      })
							     .sample_type,
						     &sample);
			if (err)
				break;
			pmi_copy_cstr_trunc(sample.comm, sizeof(sample.comm),
					    session->comm);
			sample.lost_flags = session->pending_lost ? PMI_LOST_PERF : 0;
			session->pending_lost = false;
			fill_sample_names(session, &sample);
			err = cb(&sample, ctx);
			if (err)
				break;
		} else if (hdr.type == PERF_RECORD_LOST) {
			session->pending_lost = true;
		}

		tail += hdr.size;
	}

	__atomic_store_n(&meta->data_tail, tail, __ATOMIC_RELEASE);
	return err;
}

void pmi_perf_session_close(struct pmi_perf_session *session)
{
	size_t i;

	if (!session)
		return;
	if (session->link)
		bpf_link__destroy(session->link);
	if (session->mmap_base)
		munmap(session->mmap_base, session->mmap_len);
	for (i = 0; i < session->event_count; ++i) {
		if (session->events[i].fd >= 0)
			close(session->events[i].fd);
	}
	memset(session, 0, sizeof(*session));
}

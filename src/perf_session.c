#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <asm/unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/perf_event.h>
#include <stdbool.h>
#include <stdarg.h>
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

static void perf_debugf(const struct pmi_perf_session *session,
			const char *scope, const char *fmt, ...)
{
	va_list ap;

	if (!session || !session->debug_perf)
		return;

	fprintf(stderr, "[perf][%s] ", scope);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

static const char *perf_record_type_name(uint32_t type)
{
	switch (type) {
	case PERF_RECORD_MMAP:
		return "mmap";
	case PERF_RECORD_LOST:
		return "lost";
	case PERF_RECORD_COMM:
		return "comm";
	case PERF_RECORD_EXIT:
		return "exit";
	case PERF_RECORD_THROTTLE:
		return "throttle";
	case PERF_RECORD_UNTHROTTLE:
		return "unthrottle";
	case PERF_RECORD_FORK:
		return "fork";
	case PERF_RECORD_READ:
		return "read";
	case PERF_RECORD_SAMPLE:
		return "sample";
	default:
		return "other";
	}
}

static int perf_decode_error(const struct pmi_perf_session *session,
			     const unsigned char *cursor, const void *data,
			     const unsigned char *end, size_t len,
			     uint64_t sample_type, const char *field)
{
	const unsigned char *start = data;

	perf_debugf(session, "error",
		    "tid=%d stage=decode field=%s len=%zu consumed=%zu remain=%zu sample_type=0x%" PRIx64 " err=EINVAL",
		    session ? session->tid : -1, field, len,
		    (size_t)(cursor - start), (size_t)(end - cursor), sample_type);
	return -EINVAL;
}

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
		if (i < session->event_count) {
			pmi_copy_cstr_trunc(sample->event_names[i],
					    sizeof(sample->event_names[i]),
					    session->events[i].name);
		} else {
			snprintf(sample->event_names[i], sizeof(sample->event_names[i]),
				 "event%zu", i);
		}
		for (j = 0; j < session->event_count; ++j) {
			if (session->events[j].id == sample->events[i].id) {
				if (j != i) {
					perf_debugf(session, "read",
						    "tid=%d slot=%zu sample_id=%" PRIu64 " expected_slot=%zu expected_id=%" PRIu64 " resolved_name=%s id mismatch",
						    session->tid, i,
						    (uint64_t)sample->events[i].id, j,
						    (uint64_t)session->events[j].id,
						    session->events[j].name);
				}
				pmi_copy_cstr_trunc(sample->event_names[i],
						    sizeof(sample->event_names[i]),
						    session->events[j].name);
				break;
			}
		}
		perf_debugf(session, "read",
			    "tid=%d slot=%zu sample_id=%" PRIu64 " expected_id=%" PRIu64 " resolved_name=%s value=%" PRIu64,
			    session->tid, i, (uint64_t)sample->events[i].id,
			    i < session->event_count ? (uint64_t)session->events[i].id : 0,
			    sample->event_names[i], (uint64_t)sample->events[i].value);
	}
}

static int open_event(struct pmi_perf_session *session, int group_fd, pid_t tid,
		      const struct perf_event_attr *tmpl,
		      struct pmi_opened_event *opened)
{
	struct perf_event_attr attr = *tmpl;

	opened->fd = sys_perf_event_open(&attr, tid, -1, group_fd, 0);
	if (opened->fd < 0) {
		perf_debugf(session, "error",
			    "tid=%d stage=open group_fd=%d type=%u config=0x%" PRIx64 " config1=0x%" PRIx64 " config2=0x%" PRIx64 " period=%" PRIu64 " sample_type=0x%" PRIx64 " read_format=0x%" PRIx64 " errno=%d (%s)",
			    tid, group_fd, attr.type, (uint64_t)attr.config,
			    (uint64_t)attr.config1, (uint64_t)attr.config2,
			    (uint64_t)attr.sample_period,
			    (uint64_t)attr.sample_type,
			    (uint64_t)attr.read_format, errno, strerror(errno));
		return -errno;
	}
	if (ioctl(opened->fd, PERF_EVENT_IOC_ID, &opened->id) != 0) {
		perf_debugf(session, "error",
			    "tid=%d stage=event-id fd=%d errno=%d (%s)",
			    tid, opened->fd, errno, strerror(errno));
		close(opened->fd);
		opened->fd = -1;
		return -errno;
	}
	return 0;
}

static int pmi_perf_decode_sample_impl(const struct pmi_perf_session *session,
				       const void *data, size_t len,
				       uint64_t sample_type,
				       struct pmi_perf_sample *sample)
{
	const unsigned char *cursor = data;
	const unsigned char *end = cursor + len;
	uint64_t nr, time_enabled = 0, time_running = 0;
	size_t i;

	memset(sample, 0, sizeof(*sample));

	if (sample_type & PERF_SAMPLE_IP) {
		if ((size_t)(end - cursor) < sizeof(uint64_t))
			return perf_decode_error(session, cursor, data, end, len,
						 sample_type, "PERF_SAMPLE_IP");
		memcpy(&sample->ip, cursor, sizeof(uint64_t));
		cursor += sizeof(uint64_t);
	}

	if (sample_type & PERF_SAMPLE_TID) {
		uint32_t pid, tid;

		if ((size_t)(end - cursor) < sizeof(uint32_t) * 2)
			return perf_decode_error(session, cursor, data, end, len,
						 sample_type, "PERF_SAMPLE_TID");
		memcpy(&pid, cursor, sizeof(pid));
		memcpy(&tid, cursor + sizeof(pid), sizeof(tid));
		sample->pid = (pid_t)pid;
		sample->tid = (pid_t)tid;
		cursor += sizeof(uint32_t) * 2;
	}

	if (sample_type & PERF_SAMPLE_TIME) {
		if ((size_t)(end - cursor) < sizeof(uint64_t))
			return perf_decode_error(session, cursor, data, end, len,
						 sample_type, "PERF_SAMPLE_TIME");
		memcpy(&sample->time_ns, cursor, sizeof(uint64_t));
		cursor += sizeof(uint64_t);
	}

	if (sample_type & PERF_SAMPLE_ADDR) {
		if ((size_t)(end - cursor) < sizeof(uint64_t))
			return perf_decode_error(session, cursor, data, end, len,
						 sample_type, "PERF_SAMPLE_ADDR");
		cursor += sizeof(uint64_t);
	}

	if (sample_type & PERF_SAMPLE_ID) {
		if ((size_t)(end - cursor) < sizeof(uint64_t))
			return perf_decode_error(session, cursor, data, end, len,
						 sample_type, "PERF_SAMPLE_ID");
		cursor += sizeof(uint64_t);
	}

	if (sample_type & PERF_SAMPLE_STREAM_ID) {
		if ((size_t)(end - cursor) < sizeof(uint64_t))
			return perf_decode_error(session, cursor, data, end, len,
						 sample_type, "PERF_SAMPLE_STREAM_ID");
		memcpy(&sample->stream_id, cursor, sizeof(uint64_t));
		cursor += sizeof(uint64_t);
	}

	if (sample_type & PERF_SAMPLE_CPU) {
		uint32_t cpu, reserved;

		if ((size_t)(end - cursor) < sizeof(uint32_t) * 2)
			return perf_decode_error(session, cursor, data, end, len,
						 sample_type, "PERF_SAMPLE_CPU");
		memcpy(&cpu, cursor, sizeof(cpu));
		memcpy(&reserved, cursor + sizeof(cpu), sizeof(reserved));
		(void)reserved;
		sample->cpu = cpu;
		cursor += sizeof(uint32_t) * 2;
	}

	if (sample_type & PERF_SAMPLE_PERIOD) {
		if ((size_t)(end - cursor) < sizeof(uint64_t))
			return perf_decode_error(session, cursor, data, end, len,
						 sample_type, "PERF_SAMPLE_PERIOD");
		cursor += sizeof(uint64_t);
	}

	if (sample_type & PERF_SAMPLE_READ) {
		if ((size_t)(end - cursor) < sizeof(uint64_t))
			return perf_decode_error(session, cursor, data, end, len,
						 sample_type, "PERF_SAMPLE_READ.nr");
		memcpy(&nr, cursor, sizeof(nr));
		cursor += sizeof(uint64_t);

		if ((size_t)(end - cursor) < sizeof(uint64_t) * 2)
			return perf_decode_error(session, cursor, data, end, len,
						 sample_type, "PERF_SAMPLE_READ.time");
		memcpy(&time_enabled, cursor, sizeof(uint64_t));
		memcpy(&time_running, cursor + sizeof(uint64_t), sizeof(uint64_t));
		cursor += sizeof(uint64_t) * 2;

		perf_debugf(session, "read",
			    "tid=%d nr=%" PRIu64 " enabled=%" PRIu64 " running=%" PRIu64,
			    session ? session->tid : -1, nr, time_enabled, time_running);

		if (nr > PMI_MAX_EVENTS)
			nr = PMI_MAX_EVENTS;
		sample->event_count = (size_t)nr;
		for (i = 0; i < sample->event_count; ++i) {
			if ((size_t)(end - cursor) < sizeof(uint64_t) * 2)
				return perf_decode_error(session, cursor, data, end, len,
							 sample_type, "PERF_SAMPLE_READ.value");
			memcpy(&sample->events[i].value, cursor, sizeof(uint64_t));
			memcpy(&sample->events[i].id, cursor + sizeof(uint64_t),
			       sizeof(uint64_t));
			sample->events[i].time_enabled = time_enabled;
			sample->events[i].time_running = time_running;
			perf_debugf(session, "read",
				    "tid=%d slot=%zu sample_id=%" PRIu64 " value=%" PRIu64,
				    session ? session->tid : -1, i,
				    (uint64_t)sample->events[i].id,
				    (uint64_t)sample->events[i].value);
			cursor += sizeof(uint64_t) * 2;
		}
	}

	if (sample_type & PERF_SAMPLE_CALLCHAIN) {
		uint64_t nr_callchain;

		if ((size_t)(end - cursor) < sizeof(uint64_t))
			return perf_decode_error(session, cursor, data, end, len,
						 sample_type, "PERF_SAMPLE_CALLCHAIN.nr");
		memcpy(&nr_callchain, cursor, sizeof(uint64_t));
		cursor += sizeof(uint64_t) + nr_callchain * sizeof(uint64_t);
		if (cursor > end)
			return perf_decode_error(session, cursor, data, end, len,
						 sample_type, "PERF_SAMPLE_CALLCHAIN.frames");
	}

	return 0;
}

int pmi_perf_decode_sample(const void *data, size_t len, uint64_t sample_type,
			   struct pmi_perf_sample *sample)
{
	return pmi_perf_decode_sample_impl(NULL, data, len, sample_type, sample);
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
	session->debug_perf = opts->debug_perf;
	for (i = 0; i < PMI_MAX_EVENTS; ++i)
		session->events[i].fd = -1;

	snprintf(session->events[0].name, sizeof(session->events[0].name),
		 "instructions");
	session->events[0].type = PERF_TYPE_HARDWARE;
	session->events[0].config = PERF_COUNT_HW_INSTRUCTIONS;
	err = open_event(session, -1, tid, &leader, &session->events[0]);
	if (err)
		goto fail;
	session->leader_fd = session->events[0].fd;
	session->event_count = 1;
	perf_debugf(session, "open",
		    "tid=%d opened slot=0 name=%s fd=%d id=%" PRIu64 " type=%u config=0x%" PRIx64,
		    tid, session->events[0].name, session->events[0].fd,
		    (uint64_t)session->events[0].id, session->events[0].type,
		    (uint64_t)session->events[0].config);

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
		err = open_event(session, session->leader_fd, tid, &sibling,
				 &session->events[session->event_count]);
		if (err)
			goto fail;
		perf_debugf(session, "open",
			    "tid=%d opened slot=%zu name=%s fd=%d id=%" PRIu64 " type=%u config=0x%" PRIx64,
			    tid, session->event_count,
			    session->events[session->event_count].name,
			    session->events[session->event_count].fd,
			    (uint64_t)session->events[session->event_count].id,
			    session->events[session->event_count].type,
			    (uint64_t)session->events[session->event_count].config);
		session->event_count++;
	}

	if (ioctl(session->leader_fd, PERF_EVENT_IOC_ID, &session->stream_id) != 0) {
		err = -errno;
		perf_debugf(session, "error",
			    "tid=%d stage=stream-id fd=%d errno=%d (%s)",
			    tid, session->leader_fd, errno, strerror(errno));
		goto fail;
	}

	session->mmap_len = page_size * (pages + 1);
	session->mmap_base = mmap(NULL, session->mmap_len, PROT_READ | PROT_WRITE,
				  MAP_SHARED, session->leader_fd, 0);
	if (session->mmap_base == MAP_FAILED) {
		session->mmap_base = NULL;
		err = -errno;
		perf_debugf(session, "error",
			    "tid=%d stage=mmap fd=%d mmap_len=%zu errno=%d (%s)",
			    tid, session->leader_fd, session->mmap_len, errno,
			    strerror(errno));
		goto fail;
	}

	if (pmi_procfs_read_comm(tid, session->comm)) {
		snprintf(session->comm, sizeof(session->comm), "%d", tid);
		perf_debugf(session, "open",
			    "tid=%d comm-read failed; fallback comm=%s", tid,
			    session->comm);
	}
	return 0;

fail:
	pmi_perf_session_close(session);
	return err;
}

int pmi_perf_session_enable(struct pmi_perf_session *session)
{
	if (!session)
		return -EINVAL;
	if (ioctl(session->leader_fd, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP) != 0) {
		perf_debugf(session, "error",
			    "tid=%d stage=reset fd=%d errno=%d (%s)",
			    session->tid, session->leader_fd, errno, strerror(errno));
		return -errno;
	}
	if (ioctl(session->leader_fd, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP) != 0) {
		perf_debugf(session, "error",
			    "tid=%d stage=enable fd=%d errno=%d (%s)",
			    session->tid, session->leader_fd, errno, strerror(errno));
		return -errno;
	}
	perf_debugf(session, "enable", "tid=%d fd=%d group_events=%zu",
		    session->tid, session->leader_fd, session->event_count);
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
	perf_debugf(session, "drain",
		    "tid=%d head=%" PRIu64 " tail=%" PRIu64 " size=%" PRIu64,
		    session->tid, head, tail, size);

	while (tail < head) {
		struct perf_event_header hdr;
		unsigned char stack_buf[PMI_MAX_LINE_LEN];

		err = copy_from_ring(&hdr, sizeof(hdr), data, size, tail, sizeof(hdr));
		if (err) {
			perf_debugf(session, "error",
				    "tid=%d stage=copy-header tail=%" PRIu64 " err=%d (%s)",
				    session->tid, tail, -err, strerror(-err));
			break;
		}
		perf_debugf(session, "drain",
			    "tid=%d record=%s type=%u size=%u tail=%" PRIu64 " head=%" PRIu64,
			    session->tid, perf_record_type_name(hdr.type), hdr.type,
			    hdr.size, tail, head);
		if (hdr.size > sizeof(stack_buf)) {
			err = -E2BIG;
			perf_debugf(session, "error",
				    "tid=%d stage=record-size hdr_size=%u cap=%zu err=%d (%s)",
				    session->tid, hdr.size, sizeof(stack_buf), -err,
				    strerror(-err));
			break;
		}
		err = copy_from_ring(stack_buf, sizeof(stack_buf), data, size, tail,
				     hdr.size);
		if (err) {
			perf_debugf(session, "error",
				    "tid=%d stage=copy-record tail=%" PRIu64 " size=%u err=%d (%s)",
				    session->tid, tail, hdr.size, -err, strerror(-err));
			break;
		}

		if (hdr.type == PERF_RECORD_SAMPLE) {
			struct pmi_perf_sample sample;
			uint64_t sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID |
					       PERF_SAMPLE_TIME | PERF_SAMPLE_CPU |
					       PERF_SAMPLE_READ | PERF_SAMPLE_STREAM_ID;

			perf_debugf(session, "decode",
				    "tid=%d record=sample size=%u sample_type=0x%" PRIx64,
				    session->tid, hdr.size, sample_type);
			err = pmi_perf_decode_sample_impl(session,
						       stack_buf + sizeof(hdr),
						       hdr.size - sizeof(hdr),
						       sample_type, &sample);
			if (err) {
				perf_debugf(session, "error",
					    "tid=%d stage=decode record=sample size=%u err=%d (%s)",
					    session->tid, hdr.size, -err,
					    strerror(-err));
				break;
			}
			pmi_copy_cstr_trunc(sample.comm, sizeof(sample.comm),
					    session->comm);
			sample.lost_flags = session->pending_lost ? PMI_LOST_PERF : 0;
			session->pending_lost = false;
			perf_debugf(session, "decode",
				    "tid=%d sample pid=%d tid=%d cpu=%u stream=%" PRIu64 " ip=0x%" PRIx64 " event_count=%zu",
				    session->tid, sample.pid, sample.tid, sample.cpu,
				    sample.stream_id, sample.ip, sample.event_count);
			fill_sample_names(session, &sample);
			err = cb(&sample, ctx);
			if (err) {
				perf_debugf(session, "error",
					    "tid=%d stage=sample-callback err=%d",
					    session->tid, err);
				break;
			}
		} else if (hdr.type == PERF_RECORD_LOST) {
			session->pending_lost = true;
			perf_debugf(session, "lost",
				    "tid=%d record=lost size=%u", session->tid,
				    hdr.size);
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

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pmi/output.h"

#define PMI_OUTPUT_FILE_BUFFER_SIZE (1U << 20)
#define PMI_OUTPUT_STAGE_BUFFER_SIZE (1U << 16)
#define PMI_OUTPUT_BATCH_SIZE 64

/* raw 文件是 TSV，字段里不能直接带制表符或换行，否则 report 无法稳定解析。 */
static void sanitize_field(const char *src, char *dst, size_t cap)
{
	size_t i;
	size_t j = 0;

	if (!dst || cap == 0)
		return;

	if (!src) {
		dst[0] = '\0';
		return;
	}

	for (i = 0; src[i] != '\0' && j + 1 < cap; ++i) {
		char c = src[i];

		if (c == '\t' || c == '\n' || c == '\r')
			c = ' ';
		dst[j++] = c;
	}
	dst[j] = '\0';
}

/* full stack 模式下 raw 里只写地址尾帧，叶子地址单独放在 top_ip。 */
static size_t format_stack_ips(const struct pmi_output_sample *sample, char *out,
			       size_t out_cap)
{
	size_t i;
	size_t len = 0;
	bool wrote = false;

	if (!out || out_cap == 0)
		return 0;

	out[0] = '\0';
	for (i = 0; i < sample->stack_depth; ++i) {
		int written;

		if (sample->stack_ips[i] == 0)
			continue;
		written = snprintf(out + len, out_cap - len, "%s0x%" PRIx64,
				   wrote ? ";" : "", sample->stack_ips[i]);
		if (written < 0 || (size_t)written >= out_cap - len)
			break;
		len += (size_t)written;
		wrote = true;
	}

	if (!wrote)
		len = (size_t)snprintf(out, out_cap, "-");
	return len;
}

static int append_text(char *buf, size_t cap, size_t *len, const char *text)
{
	int written;

	written = snprintf(buf + *len, cap - *len, "%s", text);
	if (written < 0 || (size_t)written >= cap - *len)
		return -E2BIG;
	*len += (size_t)written;
	return 0;
}

static int append_uint64(char *buf, size_t cap, size_t *len, uint64_t value)
{
	int written;

	written = snprintf(buf + *len, cap - *len, "%" PRIu64, value);
	if (written < 0 || (size_t)written >= cap - *len)
		return -E2BIG;
	*len += (size_t)written;
	return 0;
}

static int append_int(char *buf, size_t cap, size_t *len, int value)
{
	int written;

	written = snprintf(buf + *len, cap - *len, "%d", value);
	if (written < 0 || (size_t)written >= cap - *len)
		return -E2BIG;
	*len += (size_t)written;
	return 0;
}

static int format_sample_line(struct pmi_output_writer *writer,
			      const struct pmi_output_sample *sample, char *line,
			      size_t line_cap, uint64_t seq, size_t *line_len)
{
	char top[PMI_MAX_SYMBOL_LEN];
	char stack[PMI_MAX_STACK_TEXT_LEN];
	size_t len = 0;
	size_t i;
	int err;

	if (!writer || !sample || !line || !line_len)
		return -EINVAL;

	/* record 阶段坚持只落地址，避免把符号化成本重新带回热路径。 */
	if (sample->top_ip != 0)
		snprintf(top, sizeof(top), "0x%" PRIx64, sample->top_ip);
	else
		snprintf(top, sizeof(top), "-");
	format_stack_ips(sample, stack, sizeof(stack));
	sanitize_field(top, top, sizeof(top));
	sanitize_field(stack, stack, sizeof(stack));

	err = append_text(line, line_cap, &len, "S\t");
	if (err)
		return err;
	err = append_uint64(line, line_cap, &len, seq);
	if (err)
		return err;
	err = append_text(line, line_cap, &len, "\t");
	if (err)
		return err;
	err = append_uint64(line, line_cap, &len,
			    sample->event_count > 0 ? sample->event_deltas[0] : 0);
	if (err)
		return err;
	err = append_text(line, line_cap, &len, "\t");
	if (err)
		return err;
	err = append_int(line, line_cap, &len, sample->pid);
	if (err)
		return err;
	err = append_text(line, line_cap, &len, "\t");
	if (err)
		return err;
	err = append_int(line, line_cap, &len, sample->tid);
	if (err)
		return err;
	for (i = 0; i < writer->event_count; ++i) {
		err = append_text(line, line_cap, &len, "\t");
		if (err)
			return err;
		err = append_uint64(line, line_cap, &len,
				    i + 1 < sample->event_count ?
					    sample->event_deltas[i + 1] :
					    0);
		if (err)
			return err;
	}
	err = append_text(line, line_cap, &len, "\t");
	if (err)
		return err;
	err = append_text(line, line_cap, &len, top);
	if (err)
		return err;
	err = append_text(line, line_cap, &len, "\t");
	if (err)
		return err;
	err = append_text(line, line_cap, &len, stack);
	if (err)
		return err;
	err = append_text(line, line_cap, &len, "\n");
	if (err)
		return err;

	*line_len = len;
	return 0;
}

static int flush_stage(FILE *fp, const char *buf, size_t len)
{
	if (len == 0)
		return 0;
	if (!fp || !buf)
		return -EINVAL;
	if (fwrite(buf, 1, len, fp) != len)
		return -EIO;
	return 0;
}

/* writer 线程是整个低开销化的核心：
 * - 主线程只负责入队
 * - writer 批量拼接 TSV 并集中写盘
 * 这样既减少热路径字符串格式化，也降低频繁 fwrite 的系统调用成本。
 */
static void *writer_thread_main(void *arg)
{
	struct pmi_output_writer *writer = arg;
	struct pmi_output_sample batch[PMI_OUTPUT_BATCH_SIZE];
	char stage[PMI_OUTPUT_STAGE_BUFFER_SIZE];
	size_t stage_len = 0;
	int err = 0;

	while (true) {
		size_t batch_count = 0;
		size_t i;

		pthread_mutex_lock(&writer->mutex);
		while (writer->count == 0 && !writer->closing && writer->worker_err == 0)
			pthread_cond_wait(&writer->not_empty, &writer->mutex);
		if (writer->worker_err != 0) {
			pthread_mutex_unlock(&writer->mutex);
			break;
		}
		if (writer->count == 0 && writer->closing) {
			pthread_mutex_unlock(&writer->mutex);
			break;
		}
		while (writer->count > 0 && batch_count < PMI_OUTPUT_BATCH_SIZE) {
			batch[batch_count++] = writer->queue[writer->head];
			writer->head = (writer->head + 1) % PMI_OUTPUT_QUEUE_CAPACITY;
			writer->count--;
		}
		pthread_cond_broadcast(&writer->not_full);
		pthread_mutex_unlock(&writer->mutex);

		for (i = 0; i < batch_count; ++i) {
			char line[PMI_MAX_STACK_TEXT_LEN + PMI_MAX_SYMBOL_LEN + 512];
			size_t line_len = 0;

			err = format_sample_line(writer, &batch[i], line, sizeof(line),
						 ++writer->seq, &line_len);
			if (err)
				break;
			if (stage_len + line_len > sizeof(stage)) {
				err = flush_stage(writer->fp, stage, stage_len);
				if (err)
					break;
				stage_len = 0;
			}
			memcpy(stage + stage_len, line, line_len);
			stage_len += line_len;
		}
		if (err)
			break;
		if (stage_len > 0) {
			err = flush_stage(writer->fp, stage, stage_len);
			if (err)
				break;
			stage_len = 0;
		}
	}

	if (err == 0 && stage_len > 0)
		err = flush_stage(writer->fp, stage, stage_len);
	if (err == 0 && writer->fp && fflush(writer->fp) != 0)
		err = -EIO;

	pthread_mutex_lock(&writer->mutex);
	if (err && writer->worker_err == 0)
		writer->worker_err = err;
	pthread_cond_broadcast(&writer->not_full);
	pthread_cond_broadcast(&writer->not_empty);
	pthread_mutex_unlock(&writer->mutex);
	return NULL;
}

int pmi_output_open(struct pmi_output_writer *writer, const char *path,
		    const struct pmi_event_list *events, enum pmi_write_mode write_mode,
		    bool debug_perf)
{
	size_t i;
	int err;
	char *file_buf;

	if (!writer || !path)
		return -EINVAL;
	if (events && events->count > PMI_MAX_EVENTS - 1)
		return -E2BIG;

	memset(writer, 0, sizeof(*writer));
	writer->debug_perf = debug_perf;
	writer->write_mode = write_mode;
	writer->fp = fopen(path, "w");
	if (!writer->fp)
		return -errno;

	file_buf = malloc(PMI_OUTPUT_FILE_BUFFER_SIZE);
	if (file_buf) {
		writer->file_buffer = file_buf;
		setvbuf(writer->fp, file_buf, _IOFBF, PMI_OUTPUT_FILE_BUFFER_SIZE);
	}

	writer->queue = calloc(PMI_OUTPUT_QUEUE_CAPACITY, sizeof(*writer->queue));
	if (!writer->queue) {
		fclose(writer->fp);
		writer->fp = NULL;
		return -ENOMEM;
	}
	if (pthread_mutex_init(&writer->mutex, NULL) != 0 ||
	    pthread_cond_init(&writer->not_empty, NULL) != 0 ||
	    pthread_cond_init(&writer->not_full, NULL) != 0) {
		free(writer->queue);
		writer->queue = NULL;
		free(writer->file_buffer);
		writer->file_buffer = NULL;
		fclose(writer->fp);
		writer->fp = NULL;
		return -EINVAL;
	}

	if (events) {
		/* 动态事件列的表头直接固定为用户输入顺序，report 也据此驱动解析。 */
		writer->event_count = events->count;
		for (i = 0; i < events->count; ++i) {
			sanitize_field(events->items[i].name, writer->event_names[i],
				       sizeof(writer->event_names[i]));
		}
	}
	fprintf(writer->fp, "# pmi raw v3\n");
	fprintf(writer->fp, "type\tseq\tinsn_delta\tpid\ttid");
	for (i = 0; i < writer->event_count; ++i)
		fprintf(writer->fp, "\t%s", writer->event_names[i]);
	fprintf(writer->fp, "\ttop\tstack\n");
	if (fflush(writer->fp) != 0)
		return -EIO;

	err = pthread_create(&writer->thread, NULL, writer_thread_main, writer);
	if (err != 0) {
		pthread_cond_destroy(&writer->not_full);
		pthread_cond_destroy(&writer->not_empty);
		pthread_mutex_destroy(&writer->mutex);
		free(writer->queue);
		writer->queue = NULL;
		free(writer->file_buffer);
		writer->file_buffer = NULL;
		fclose(writer->fp);
		writer->fp = NULL;
		return -err;
	}
	writer->thread_started = true;
	return 0;
}

int pmi_output_enqueue_sample(struct pmi_output_writer *writer,
			      const struct pmi_output_sample *sample)
{
	int err = 0;

	if (!writer || !sample || !writer->thread_started)
		return -EINVAL;

	pthread_mutex_lock(&writer->mutex);
	while (writer->count == PMI_OUTPUT_QUEUE_CAPACITY &&
	       writer->worker_err == 0 && !writer->closing) {
		if (writer->write_mode == PMI_WRITE_LOW_OVERHEAD) {
			/* low-overhead 模式优先保护业务线程，不让采样主线程因为写盘阻塞。 */
			writer->dropped_samples++;
			pthread_mutex_unlock(&writer->mutex);
			return 0;
		}
		pthread_cond_wait(&writer->not_full, &writer->mutex);
	}
	if (writer->worker_err != 0)
		err = writer->worker_err;
	else if (!writer->closing) {
		writer->queue[writer->tail] = *sample;
		writer->tail = (writer->tail + 1) % PMI_OUTPUT_QUEUE_CAPACITY;
		writer->count++;
		pthread_cond_signal(&writer->not_empty);
	}
	pthread_mutex_unlock(&writer->mutex);
	return err;
}

int pmi_output_close(struct pmi_output_writer *writer)
{
	int err = 0;

	if (!writer)
		return -EINVAL;

	if (writer->thread_started) {
		/* 关闭时先通知 writer 停止接新活，再 join 等它 flush 完队列。 */
		pthread_mutex_lock(&writer->mutex);
		writer->closing = true;
		pthread_cond_broadcast(&writer->not_empty);
		pthread_cond_broadcast(&writer->not_full);
		pthread_mutex_unlock(&writer->mutex);
		pthread_join(writer->thread, NULL);
	}

	if (writer->worker_err != 0)
		err = writer->worker_err;
	if (writer->fp && fclose(writer->fp) != 0 && err == 0)
		err = -EIO;
	free(writer->file_buffer);
	pthread_cond_destroy(&writer->not_full);
	pthread_cond_destroy(&writer->not_empty);
	pthread_mutex_destroy(&writer->mutex);
	free(writer->queue);
	memset(writer, 0, sizeof(*writer));
	return err;
}

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pmi/record.h"
#include "pmi/shared.h"
#include "pmi/strutil.h"
#include "pmi/symbolizer.h"

#define PMI_REPORT_MAX_FIELDS (PMI_MAX_EVENTS + 6)
#define PMI_REPORT_TOP_DISPLAY_WIDTH 48
#define PMI_REPORT_STACK_DISPLAY_WIDTH 96

struct sample_row {
	uint64_t seq;
	uint64_t insn_delta;
	pid_t pid;
	pid_t tid;
	uint64_t event_values[PMI_MAX_EVENTS - 1];
	size_t event_count;
	char top[PMI_MAX_SYMBOL_LEN];
	char stack[PMI_MAX_STACK_TEXT_LEN];
};

struct table_layout {
	size_t seq_w;
	size_t pid_w;
	size_t tid_w;
	size_t samples_w;
	size_t insn_w;
	size_t event_w[PMI_MAX_EVENTS - 1];
	size_t top_w;
	size_t stack_w;
};

struct report_schema {
	char event_names[PMI_MAX_EVENTS - 1][PMI_MAX_EVENT_NAME];
	size_t event_count;
};

struct report_entry {
	char top[PMI_MAX_SYMBOL_LEN];
	size_t sample_count;
	uint64_t insn_delta_total;
	uint64_t event_totals[PMI_MAX_EVENTS - 1];
};

struct stack_entry {
	char stack[PMI_MAX_STACK_TEXT_LEN];
	size_t sample_count;
	uint64_t insn_delta_total;
	uint64_t event_totals[PMI_MAX_EVENTS - 1];
};

struct parsed_sample {
	uint64_t seq;
	uint64_t insn_delta;
	pid_t pid;
	pid_t tid;
	uint64_t event_values[PMI_MAX_EVENTS - 1];
	size_t event_count;
	char top[PMI_MAX_SYMBOL_LEN];
	char stack[PMI_MAX_STACK_TEXT_LEN];
};

static void report_usage(FILE *stream)
{
	fprintf(stream,
		"usage: pmi report -i <file> [options]\n"
		"\n"
		"options:\n"
		"  -i, --input <file>           raw v3 sample file\n"
		"  -o, --output <file>          output HTML path for visual mode\n"
		"  -l, --limit <N>              max rows, default: 20\n"
		"  -m, --mode <overview|samples|visual>\n"
		"                               default: overview\n"
		"  -w, --window-samples <N>     samples per visual window, default: 200\n"
		"  -t, --tid <tid1,tid2,...>    filter samples by tid list\n"
		"  -h, --help                   show this help\n"
		"\n"
		"examples:\n"
		"  pmi report -i out.pmi\n"
		"  pmi report -i out.pmi -t 1234,5678 -m samples\n"
		"  pmi report -i out.pmi -m visual -o out.html -w 200\n");
}

static char *trim_field(char *field)
{
	char *end;

	if (!field)
		return NULL;

	while (*field == ' ' || *field == '\t')
		field++;
	if (*field == '\0')
		return field;

	end = field + strlen(field) - 1;
	while (end > field && (*end == ' ' || *end == '\t')) {
		*end = '\0';
		end--;
	}

	return field;
}

static bool has_symbol_text(const char *symbol)
{
	return symbol && symbol[0] != '\0' && strcmp(symbol, "-") != 0;
}

static bool is_tid_selected(const struct pmi_report_options *opts, pid_t tid)
{
	size_t i;

	if (!opts || opts->tid_count == 0)
		return true;
	for (i = 0; i < opts->tid_count; ++i) {
		if (opts->tids[i] == tid)
			return true;
	}
	return false;
}

static bool report_entry_tid_exists(const struct pmi_report_options *opts, pid_t tid)
{
	size_t i;

	for (i = 0; i < opts->tid_count; ++i) {
		if (opts->tids[i] == tid)
			return true;
	}
	return false;
}

static int parse_tid_list(struct pmi_report_options *opts, const char *arg)
{
	char copy[PMI_MAX_LINE_LEN];
	char *cursor;
	char *token;

	if (!opts || !arg)
		return -EINVAL;
	if (strlen(arg) >= sizeof(copy))
		return -E2BIG;

	strcpy(copy, arg);
	cursor = copy;
	while ((token = strsep(&cursor, ",")) != NULL) {
		char *end = NULL;
		long value;

		if (*token == '\0')
			return -EINVAL;
		value = strtol(token, &end, 10);
		if (!end || *end != '\0' || value <= 0)
			return -EINVAL;
		if (!report_entry_tid_exists(opts, (pid_t)value)) {
			if (opts->tid_count >= sizeof(opts->tids) / sizeof(opts->tids[0]))
				return -E2BIG;
			opts->tids[opts->tid_count++] = (pid_t)value;
		}
	}

	return 0;
}

static struct report_entry *find_or_add_report_entry(struct report_entry **entries,
						     size_t *count, size_t *cap,
						     const char *top)
{
	size_t i;

	for (i = 0; i < *count; ++i) {
		if (strcmp((*entries)[i].top, top) == 0)
			return &(*entries)[i];
	}

	if (*count == *cap) {
		size_t new_cap = *cap ? *cap * 2 : 64;
		struct report_entry *tmp;

		tmp = realloc(*entries, new_cap * sizeof(**entries));
		if (!tmp)
			return NULL;
		*entries = tmp;
		*cap = new_cap;
	}

	memset(&(*entries)[*count], 0, sizeof(**entries));
	pmi_copy_cstr_trunc((*entries)[*count].top, sizeof((*entries)[*count].top),
			    top);
	return &(*entries)[(*count)++];
}

static struct stack_entry *find_or_add_stack_entry(struct stack_entry **entries,
						   size_t *count, size_t *cap,
						   const char *stack)
{
	size_t i;

	for (i = 0; i < *count; ++i) {
		if (strcmp((*entries)[i].stack, stack) == 0)
			return &(*entries)[i];
	}

	if (*count == *cap) {
		size_t new_cap = *cap ? *cap * 2 : 64;
		struct stack_entry *tmp;

		tmp = realloc(*entries, new_cap * sizeof(**entries));
		if (!tmp)
			return NULL;
		*entries = tmp;
		*cap = new_cap;
	}

	memset(&(*entries)[*count], 0, sizeof(**entries));
	pmi_copy_cstr_trunc((*entries)[*count].stack,
			    sizeof((*entries)[*count].stack), stack);
	return &(*entries)[(*count)++];
}

static int compare_report_entry(const void *lhs, const void *rhs)
{
	const struct report_entry *a = lhs;
	const struct report_entry *b = rhs;

	if (a->sample_count < b->sample_count)
		return 1;
	if (a->sample_count > b->sample_count)
		return -1;
	return strcmp(a->top, b->top);
}

static int compare_stack_entry(const void *lhs, const void *rhs)
{
	const struct stack_entry *a = lhs;
	const struct stack_entry *b = rhs;

	if (a->sample_count < b->sample_count)
		return 1;
	if (a->sample_count > b->sample_count)
		return -1;
	return strcmp(a->stack, b->stack);
}

static void prettify_symbol(struct pmi_symbolizer *symbolizer, char *symbol,
			    size_t symbol_cap)
{
	char pretty[PMI_MAX_SYMBOL_LEN];

	if (!symbol || symbol[0] == '\0' || strcmp(symbol, "-") == 0)
		return;
	if (strncmp(symbol, "0x", 2) == 0)
		return;
	if (pmi_symbolizer_pretty_name(symbolizer, symbol, pretty, sizeof(pretty)) == 0)
		pmi_copy_cstr_trunc(symbol, symbol_cap, pretty);
}

static void resolve_symbol_or_hex(struct pmi_symbolizer *symbolizer, pid_t pid,
				  uint64_t ip, char *symbol, size_t symbol_cap)
{
	char module[PMI_MAX_MODULE_LEN];

	if (!symbol || symbol_cap == 0)
		return;

	snprintf(symbol, symbol_cap, "0x%" PRIx64, ip);
	if (!symbolizer || ip == 0)
		return;
	if (pmi_symbolizer_symbolize_ip(symbolizer, pid, ip, module, sizeof(module),
					symbol, symbol_cap) == 0)
		prettify_symbol(symbolizer, symbol, symbol_cap);
}

static void resolve_top_text(struct pmi_symbolizer *symbolizer, pid_t pid,
			     const char *raw_top, char *resolved,
			     size_t resolved_cap)
{
	uint64_t ip;

	if (!resolved || resolved_cap == 0)
		return;

	if (!raw_top || raw_top[0] == '\0' || strcmp(raw_top, "-") == 0) {
		pmi_copy_cstr_trunc(resolved, resolved_cap, "-");
		return;
	}
	if (strncmp(raw_top, "0x", 2) == 0) {
		ip = strtoull(raw_top, NULL, 0);
		resolve_symbol_or_hex(symbolizer, pid, ip, resolved, resolved_cap);
		return;
	}

	pmi_copy_cstr_trunc(resolved, resolved_cap, raw_top);
	prettify_symbol(symbolizer, resolved, resolved_cap);
}

static int append_stack_symbol(char *dst, size_t cap, const char *symbol)
{
	size_t len;
	int written;

	if (!dst || !symbol || symbol[0] == '\0')
		return -EINVAL;

	len = strlen(dst);
	written = snprintf(dst + len, cap - len, "%s%s", len ? ";" : "", symbol);
	if (written < 0 || (size_t)written >= cap - len)
		return -E2BIG;
	return 0;
}

static int build_symbolized_stack(struct pmi_symbolizer *symbolizer, pid_t pid,
				  const char *top, const char *raw_stack, char *out,
				  size_t out_cap)
{
	char stack_copy[PMI_MAX_STACK_TEXT_LEN];
	char resolved_top[PMI_MAX_SYMBOL_LEN];
	char *token;
	char *saveptr = NULL;

	if (!out || out_cap == 0)
		return -EINVAL;

	out[0] = '\0';
	if (has_symbol_text(top)) {
		resolve_top_text(symbolizer, pid, top, resolved_top,
				 sizeof(resolved_top));
		pmi_copy_cstr_trunc(out, out_cap, resolved_top);
	}
	if (!raw_stack || strcmp(raw_stack, "-") == 0)
		return 0;

	pmi_copy_cstr_trunc(stack_copy, sizeof(stack_copy), raw_stack);
	for (token = strtok_r(stack_copy, ";", &saveptr); token;
	     token = strtok_r(NULL, ";", &saveptr)) {
		uint64_t ip;
		char symbol[PMI_MAX_SYMBOL_LEN];

		if (*token == '\0')
			continue;
		ip = strtoull(token, NULL, 0);
		if (ip == 0)
			continue;
		resolve_symbol_or_hex(symbolizer, pid, ip, symbol, sizeof(symbol));
		if (append_stack_symbol(out, out_cap, symbol) != 0)
			break;
	}

	return 0;
}

static int file_printf(FILE *fp, const char *fmt, ...)
{
	va_list ap;
	int rc;

	va_start(ap, fmt);
	rc = vfprintf(fp, fmt, ap);
	va_end(ap);
	if (rc < 0)
		return -EIO;
	return 0;
}

static int file_puts_checked(FILE *fp, const char *text)
{
	if (!fp || !text)
		return -EINVAL;
	return fputs(text, fp) == EOF ? -EIO : 0;
}

static int json_write_escaped(FILE *fp, const char *text)
{
	const unsigned char *cursor = (const unsigned char *)(text ? text : "");

	if (fputc('"', fp) == EOF)
		return -EIO;
	for (; *cursor; ++cursor) {
		switch (*cursor) {
		case '\\':
			if (fputs("\\\\", fp) == EOF)
				return -EIO;
			break;
		case '"':
			if (fputs("\\\"", fp) == EOF)
				return -EIO;
			break;
		case '\n':
			if (fputs("\\n", fp) == EOF)
				return -EIO;
			break;
		case '\r':
			if (fputs("\\r", fp) == EOF)
				return -EIO;
			break;
		case '\t':
			if (fputs("\\t", fp) == EOF)
				return -EIO;
			break;
		case '<':
			if (fputs("\\u003c", fp) == EOF)
				return -EIO;
			break;
		case '>':
			if (fputs("\\u003e", fp) == EOF)
				return -EIO;
			break;
		case '&':
			if (fputs("\\u0026", fp) == EOF)
				return -EIO;
			break;
		default:
			if (fputc(*cursor, fp) == EOF)
				return -EIO;
			break;
		}
	}
	return fputc('"', fp) == EOF ? -EIO : 0;
}

static int parse_report_options(int argc, char **argv, struct pmi_report_options *opts)
{
	static const struct option long_options[] = {
		{ "input", required_argument, NULL, 'i' },
		{ "output", required_argument, NULL, 'o' },
		{ "limit", required_argument, NULL, 'l' },
		{ "mode", required_argument, NULL, 'm' },
		{ "window-samples", required_argument, NULL, 'w' },
		{ "tid", required_argument, NULL, 't' },
		{ "help", no_argument, NULL, 'h' },
		{ 0, 0, 0, 0 },
	};
	int opt;

	memset(opts, 0, sizeof(*opts));
	opts->limit = 20;
	opts->window_samples = 200;
	opts->mode = PMI_REPORT_OVERVIEW;
	opterr = 0;
	optind = 1;

	while ((opt = getopt_long(argc, argv, "i:o:l:m:w:t:h", long_options, NULL)) != -1) {
		switch (opt) {
		case 'i':
			opts->input_path = optarg;
			break;
		case 'o':
			opts->output_path = optarg;
			break;
		case 'l':
			opts->limit = strtoul(optarg, NULL, 10);
			break;
		case 'm':
			if (strcmp(optarg, "overview") == 0)
				opts->mode = PMI_REPORT_OVERVIEW;
			else if (strcmp(optarg, "samples") == 0)
				opts->mode = PMI_REPORT_SAMPLES;
			else if (strcmp(optarg, "visual") == 0)
				opts->mode = PMI_REPORT_VISUAL;
			else {
				fprintf(stderr, "invalid report mode: %s\n", optarg);
				return -EINVAL;
			}
			break;
		case 'w':
			opts->window_samples = strtoull(optarg, NULL, 10);
			break;
		case 't':
			if (parse_tid_list(opts, optarg) != 0) {
				fprintf(stderr, "invalid tid list: %s\n", optarg);
				return -EINVAL;
			}
			break;
		case 'h':
			report_usage(stdout);
			return 2;
		case '?':
		default:
			fprintf(stderr, "unknown report option: %s\n",
				optind > 0 && optind - 1 < argc ? argv[optind - 1] : "?");
			return -EINVAL;
		}
	}

	if (optind != argc) {
		fprintf(stderr, "unexpected positional argument: %s\n", argv[optind]);
		return -EINVAL;
	}
	if (!opts->input_path) {
		fprintf(stderr, "-i/--input is required\n");
		return -EINVAL;
	}
	if (opts->limit == 0) {
		fprintf(stderr, "limit must be greater than 0\n");
		return -EINVAL;
	}
	if (opts->window_samples == 0) {
		fprintf(stderr, "window size must be greater than 0\n");
		return -EINVAL;
	}
	if (opts->mode == PMI_REPORT_VISUAL && !opts->output_path) {
		fprintf(stderr, "-o/--output is required in visual mode\n");
		return -EINVAL;
	}

	return 0;
}

static int parse_tsv_fields(char *line, char **fields, size_t cap, size_t *count)
{
	char *cursor = line;
	char *field;

	*count = 0;
	while ((field = strsep(&cursor, "\t")) != NULL) {
		if (*count >= cap)
			return -E2BIG;
		field[strcspn(field, "\r\n")] = '\0';
		fields[*count] = trim_field(field);
		(*count)++;
	}

	return 0;
}

static int parse_header_line(char *line, struct report_schema *schema)
{
	char *fields[PMI_REPORT_MAX_FIELDS] = { 0 };
	size_t field_count = 0;
	size_t i;
	int err;

	if (!line || !schema)
		return -EINVAL;

	err = parse_tsv_fields(line, fields, PMI_REPORT_MAX_FIELDS, &field_count);
	if (err)
		return err;
	if (field_count < 7)
		return -EINVAL;
	if (strcmp(fields[0], "type") != 0 || strcmp(fields[1], "seq") != 0 ||
	    strcmp(fields[2], "insn_delta") != 0 || strcmp(fields[3], "pid") != 0 ||
	    strcmp(fields[4], "tid") != 0 ||
	    strcmp(fields[field_count - 2], "top") != 0 ||
	    strcmp(fields[field_count - 1], "stack") != 0)
		return -EINVAL;

	memset(schema, 0, sizeof(*schema));
	schema->event_count = field_count - 7;
	for (i = 0; i < schema->event_count; ++i) {
		pmi_copy_cstr_trunc(schema->event_names[i],
				    sizeof(schema->event_names[i]),
				    fields[5 + i]);
	}

	return 0;
}

static int parse_sample_line(char *line, const struct report_schema *schema,
			     struct parsed_sample *sample)
{
	char *fields[PMI_REPORT_MAX_FIELDS] = { 0 };
	size_t field_count = 0;
	size_t i;
	size_t top_idx;
	size_t stack_idx;
	int err;

	if (!line || !schema || !sample)
		return -EINVAL;
	if (line[0] == '#' || line[0] == '\0' || line[0] == '\n')
		return 1;

	err = parse_tsv_fields(line, fields, PMI_REPORT_MAX_FIELDS, &field_count);
	if (err)
		return err;
	if (field_count == 0 || strcmp(fields[0], "type") == 0)
		return 1;
	if (strcmp(fields[0], "S") != 0)
		return 1;
	if (field_count != schema->event_count + 7)
		return -EINVAL;

	memset(sample, 0, sizeof(*sample));
	sample->seq = strtoull(fields[1], NULL, 10);
	sample->insn_delta = strtoull(fields[2], NULL, 10);
	sample->pid = (pid_t)strtol(fields[3], NULL, 10);
	sample->tid = (pid_t)strtol(fields[4], NULL, 10);
	sample->event_count = schema->event_count;
	for (i = 0; i < schema->event_count; ++i)
		sample->event_values[i] = strtoull(fields[5 + i], NULL, 10);
	top_idx = 5 + schema->event_count;
	stack_idx = top_idx + 1;
	pmi_copy_cstr_trunc(sample->top, sizeof(sample->top), fields[top_idx]);
	pmi_copy_cstr_trunc(sample->stack, sizeof(sample->stack), fields[stack_idx]);
	return 0;
}

static size_t decimal_width_u64(uint64_t value)
{
	char text[32];
	int written;

	written = snprintf(text, sizeof(text), "%" PRIu64, value);
	return written > 0 ? (size_t)written : 1;
}

static size_t decimal_width_size(size_t value)
{
	char text[32];
	int written;

	written = snprintf(text, sizeof(text), "%zu", value);
	return written > 0 ? (size_t)written : 1;
}

static size_t decimal_width_pid(pid_t value)
{
	char text[32];
	int written;

	written = snprintf(text, sizeof(text), "%d", (int)value);
	return written > 0 ? (size_t)written : 1;
}

static size_t capped_text_width(const char *text, size_t max_width)
{
	size_t len;

	if (!text)
		return 1;
	len = strlen(text);
	return len < max_width ? len : max_width;
}

static void ellipsize_text(const char *src, size_t max_width, char *dst,
			   size_t dst_cap)
{
	size_t copy_len;

	if (!dst || dst_cap == 0)
		return;

	if (!src || src[0] == '\0')
		src = "-";
	if (max_width == 0) {
		dst[0] = '\0';
		return;
	}
	if (strlen(src) <= max_width) {
		pmi_copy_cstr_trunc(dst, dst_cap, src);
		return;
	}
	if (max_width <= 3) {
		copy_len = max_width < dst_cap - 1 ? max_width : dst_cap - 1;
		memcpy(dst, src, copy_len);
		dst[copy_len] = '\0';
		return;
	}

	copy_len = max_width - 3;
	if (copy_len > dst_cap - 4)
		copy_len = dst_cap - 4;
	memcpy(dst, src, copy_len);
	memcpy(dst + copy_len, "...", 3);
	dst[copy_len + 3] = '\0';
}

static void print_gap(void)
{
	printf("  ");
}

static void print_text_cell(const char *text, size_t width, size_t max_width)
{
	char clipped[PMI_MAX_STACK_TEXT_LEN];

	ellipsize_text(text, max_width, clipped, sizeof(clipped));
	printf("%-*s", (int)width, clipped);
}

static void print_u64_cell(uint64_t value, size_t width)
{
	printf("%*" PRIu64, (int)width, value);
}

static void print_size_cell(size_t value, size_t width)
{
	printf("%*zu", (int)width, value);
}

static void print_pid_cell(pid_t value, size_t width)
{
	printf("%*d", (int)width, (int)value);
}

static void print_separator_cell(size_t width)
{
	size_t i;

	for (i = 0; i < width; ++i)
		putchar('-');
}

static int append_sample_row(struct sample_row **rows, size_t *count, size_t *cap,
			     const struct parsed_sample *sample, const char *top,
			     const char *stack)
{
	struct sample_row *row;

	if (*count == *cap) {
		size_t new_cap = *cap ? *cap * 2 : 64;
		struct sample_row *tmp;

		tmp = realloc(*rows, new_cap * sizeof(**rows));
		if (!tmp)
			return -ENOMEM;
		*rows = tmp;
		*cap = new_cap;
	}

	row = &(*rows)[(*count)++];
	memset(row, 0, sizeof(*row));
	row->seq = sample->seq;
	row->insn_delta = sample->insn_delta;
	row->pid = sample->pid;
	row->tid = sample->tid;
	row->event_count = sample->event_count;
	memcpy(row->event_values, sample->event_values, sizeof(row->event_values));
	pmi_copy_cstr_trunc(row->top, sizeof(row->top), top);
	pmi_copy_cstr_trunc(row->stack, sizeof(row->stack), stack);
	return 0;
}

static int collect_symbolized_samples(FILE *fp, struct pmi_symbolizer *symbolizer,
				      const struct pmi_report_options *opts,
				      const struct report_schema *schema,
				      bool include_stack, struct sample_row **rows_out,
				      size_t *count_out)
{
	struct sample_row *rows = NULL;
	size_t count = 0;
	size_t cap = 0;
	char line[PMI_MAX_LINE_LEN];
	int err = 0;

	if (!fp || !rows_out || !count_out)
		return -EINVAL;

	while (fgets(line, sizeof(line), fp)) {
		struct parsed_sample sample;
		char resolved_top[PMI_MAX_SYMBOL_LEN];
		char symbolized_stack[PMI_MAX_STACK_TEXT_LEN];

		err = parse_sample_line(line, schema, &sample);
		if (err == 1)
			continue;
		if (err != 0)
			goto out;
		if (!is_tid_selected(opts, sample.tid))
			continue;

		resolve_top_text(symbolizer, sample.pid, sample.top, resolved_top,
				 sizeof(resolved_top));
		if (include_stack && strcmp(sample.stack, "-") != 0) {
			build_symbolized_stack(symbolizer, sample.pid, resolved_top,
					       sample.stack, symbolized_stack,
					       sizeof(symbolized_stack));
		} else {
			pmi_copy_cstr_trunc(symbolized_stack, sizeof(symbolized_stack),
					    "-");
		}

		err = append_sample_row(&rows, &count, &cap, &sample, resolved_top,
					symbolized_stack);
		if (err)
			goto out;
	}

	*rows_out = rows;
	*count_out = count;
	return 0;

out:
	free(rows);
	return err;
}

static void init_samples_layout(struct table_layout *layout,
				const struct report_schema *schema)
{
	size_t i;

	memset(layout, 0, sizeof(*layout));
	layout->seq_w = strlen("seq");
	layout->pid_w = strlen("pid");
	layout->tid_w = strlen("tid");
	layout->insn_w = strlen("insn_delta");
	layout->top_w = strlen("top");
	layout->stack_w = strlen("stack");
	for (i = 0; i < schema->event_count; ++i)
		layout->event_w[i] = strlen(schema->event_names[i]);
}

static void grow_samples_layout(struct table_layout *layout,
				const struct sample_row *rows, size_t count,
				const struct report_schema *schema)
{
	size_t i;
	size_t j;

	for (i = 0; i < count; ++i) {
		layout->seq_w = layout->seq_w > decimal_width_u64(rows[i].seq) ?
				layout->seq_w : decimal_width_u64(rows[i].seq);
		layout->pid_w = layout->pid_w > decimal_width_pid(rows[i].pid) ?
				layout->pid_w : decimal_width_pid(rows[i].pid);
		layout->tid_w = layout->tid_w > decimal_width_pid(rows[i].tid) ?
				layout->tid_w : decimal_width_pid(rows[i].tid);
		layout->insn_w = layout->insn_w > decimal_width_u64(rows[i].insn_delta) ?
				 layout->insn_w : decimal_width_u64(rows[i].insn_delta);
		layout->top_w = layout->top_w > capped_text_width(rows[i].top,
							  PMI_REPORT_TOP_DISPLAY_WIDTH) ?
				layout->top_w :
				capped_text_width(rows[i].top,
						 PMI_REPORT_TOP_DISPLAY_WIDTH);
		layout->stack_w =
			layout->stack_w > capped_text_width(rows[i].stack,
							    PMI_REPORT_STACK_DISPLAY_WIDTH) ?
			layout->stack_w :
			capped_text_width(rows[i].stack,
					 PMI_REPORT_STACK_DISPLAY_WIDTH);
		for (j = 0; j < schema->event_count; ++j) {
			size_t width = decimal_width_u64(rows[i].event_values[j]);

			if (layout->event_w[j] < width)
				layout->event_w[j] = width;
		}
	}
}

static void init_overview_layout(struct table_layout *layout,
				 const struct report_schema *schema)
{
	size_t i;

	memset(layout, 0, sizeof(*layout));
	layout->samples_w = strlen("samples");
	layout->insn_w = strlen("insn_delta");
	layout->top_w = strlen("top");
	layout->stack_w = strlen("stack");
	for (i = 0; i < schema->event_count; ++i)
		layout->event_w[i] = strlen(schema->event_names[i]);
}

static void grow_overview_layout(struct table_layout *layout,
				 const struct report_entry *entries, size_t count,
				 const struct report_schema *schema)
{
	size_t i;
	size_t j;

	for (i = 0; i < count; ++i) {
		layout->samples_w =
			layout->samples_w > decimal_width_size(entries[i].sample_count) ?
			layout->samples_w : decimal_width_size(entries[i].sample_count);
		layout->insn_w =
			layout->insn_w > decimal_width_u64(entries[i].insn_delta_total) ?
			layout->insn_w : decimal_width_u64(entries[i].insn_delta_total);
		layout->top_w = layout->top_w > capped_text_width(entries[i].top,
							  PMI_REPORT_TOP_DISPLAY_WIDTH) ?
				layout->top_w :
				capped_text_width(entries[i].top,
						 PMI_REPORT_TOP_DISPLAY_WIDTH);
		for (j = 0; j < schema->event_count; ++j) {
			size_t width = decimal_width_u64(entries[i].event_totals[j]);

			if (layout->event_w[j] < width)
				layout->event_w[j] = width;
		}
	}
}

static void grow_stack_layout(struct table_layout *layout,
			      const struct stack_entry *entries, size_t count,
			      const struct report_schema *schema)
{
	size_t i;
	size_t j;

	for (i = 0; i < count; ++i) {
		layout->samples_w =
			layout->samples_w > decimal_width_size(entries[i].sample_count) ?
			layout->samples_w : decimal_width_size(entries[i].sample_count);
		layout->insn_w =
			layout->insn_w > decimal_width_u64(entries[i].insn_delta_total) ?
			layout->insn_w : decimal_width_u64(entries[i].insn_delta_total);
		layout->stack_w =
			layout->stack_w > capped_text_width(entries[i].stack,
							    PMI_REPORT_STACK_DISPLAY_WIDTH) ?
			layout->stack_w :
			capped_text_width(entries[i].stack,
					 PMI_REPORT_STACK_DISPLAY_WIDTH);
		for (j = 0; j < schema->event_count; ++j) {
			size_t width = decimal_width_u64(entries[i].event_totals[j]);

			if (layout->event_w[j] < width)
				layout->event_w[j] = width;
		}
	}
}

static void print_samples_header(const struct table_layout *layout,
				 const struct report_schema *schema)
{
	size_t i;

	print_text_cell("seq", layout->seq_w, layout->seq_w);
	print_gap();
	print_text_cell("pid", layout->pid_w, layout->pid_w);
	print_gap();
	print_text_cell("tid", layout->tid_w, layout->tid_w);
	print_gap();
	print_text_cell("insn_delta", layout->insn_w, layout->insn_w);
	for (i = 0; i < schema->event_count; ++i) {
		print_gap();
		print_text_cell(schema->event_names[i], layout->event_w[i],
				layout->event_w[i]);
	}
	print_gap();
	print_text_cell("top", layout->top_w, layout->top_w);
	print_gap();
	print_text_cell("stack", layout->stack_w, layout->stack_w);
	putchar('\n');
}

static void print_samples_separator(const struct table_layout *layout,
				    const struct report_schema *schema)
{
	size_t i;

	print_separator_cell(layout->seq_w);
	print_gap();
	print_separator_cell(layout->pid_w);
	print_gap();
	print_separator_cell(layout->tid_w);
	print_gap();
	print_separator_cell(layout->insn_w);
	for (i = 0; i < schema->event_count; ++i) {
		print_gap();
		print_separator_cell(layout->event_w[i]);
	}
	print_gap();
	print_separator_cell(layout->top_w);
	print_gap();
	print_separator_cell(layout->stack_w);
	putchar('\n');
}

static void print_samples_row(const struct sample_row *row,
			      const struct table_layout *layout,
			      const struct report_schema *schema)
{
	size_t i;

	print_u64_cell(row->seq, layout->seq_w);
	print_gap();
	print_pid_cell(row->pid, layout->pid_w);
	print_gap();
	print_pid_cell(row->tid, layout->tid_w);
	print_gap();
	print_u64_cell(row->insn_delta, layout->insn_w);
	for (i = 0; i < schema->event_count; ++i) {
		print_gap();
		print_u64_cell(row->event_values[i], layout->event_w[i]);
	}
	print_gap();
	print_text_cell(row->top, layout->top_w, PMI_REPORT_TOP_DISPLAY_WIDTH);
	print_gap();
	print_text_cell(row->stack, layout->stack_w,
			PMI_REPORT_STACK_DISPLAY_WIDTH);
	putchar('\n');
}

static void print_overview_header(const struct table_layout *layout,
				  const struct report_schema *schema,
				  const char *last_column)
{
	size_t i;

	print_text_cell("samples", layout->samples_w, layout->samples_w);
	print_gap();
	print_text_cell("insn_delta", layout->insn_w, layout->insn_w);
	for (i = 0; i < schema->event_count; ++i) {
		print_gap();
		print_text_cell(schema->event_names[i], layout->event_w[i],
				layout->event_w[i]);
	}
	print_gap();
	if (strcmp(last_column, "top") == 0)
		print_text_cell(last_column, layout->top_w, layout->top_w);
	else
		print_text_cell(last_column, layout->stack_w, layout->stack_w);
	putchar('\n');
}

static void print_overview_separator(const struct table_layout *layout,
				     const struct report_schema *schema,
				     bool stack_mode)
{
	size_t i;

	print_separator_cell(layout->samples_w);
	print_gap();
	print_separator_cell(layout->insn_w);
	for (i = 0; i < schema->event_count; ++i) {
		print_gap();
		print_separator_cell(layout->event_w[i]);
	}
	print_gap();
	print_separator_cell(stack_mode ? layout->stack_w : layout->top_w);
	putchar('\n');
}

static void print_overview_row(const struct report_entry *entry,
			       const struct table_layout *layout,
			       const struct report_schema *schema)
{
	size_t i;

	print_size_cell(entry->sample_count, layout->samples_w);
	print_gap();
	print_u64_cell(entry->insn_delta_total, layout->insn_w);
	for (i = 0; i < schema->event_count; ++i) {
		print_gap();
		print_u64_cell(entry->event_totals[i], layout->event_w[i]);
	}
	print_gap();
	print_text_cell(entry->top, layout->top_w, PMI_REPORT_TOP_DISPLAY_WIDTH);
	putchar('\n');
}

static void print_stack_row(const struct stack_entry *entry,
			    const struct table_layout *layout,
			    const struct report_schema *schema)
{
	size_t i;

	print_size_cell(entry->sample_count, layout->samples_w);
	print_gap();
	print_u64_cell(entry->insn_delta_total, layout->insn_w);
	for (i = 0; i < schema->event_count; ++i) {
		print_gap();
		print_u64_cell(entry->event_totals[i], layout->event_w[i]);
	}
	print_gap();
	print_text_cell(entry->stack, layout->stack_w,
			PMI_REPORT_STACK_DISPLAY_WIDTH);
	putchar('\n');
}

static int run_samples_report(FILE *fp, struct pmi_symbolizer *symbolizer,
			      const struct pmi_report_options *opts,
			      const struct report_schema *schema)
{
	struct sample_row *rows = NULL;
	size_t count = 0;
	struct table_layout layout;
	size_t i;
	int err;

	err = collect_symbolized_samples(fp, symbolizer, opts, schema, true, &rows,
					 &count);
	if (err)
		return err;

	init_samples_layout(&layout, schema);
	grow_samples_layout(&layout, rows, count, schema);
	print_samples_header(&layout, schema);
	print_samples_separator(&layout, schema);
	for (i = 0; i < count; ++i)
		print_samples_row(&rows[i], &layout, schema);
	free(rows);
	return err;
}

static int run_overview_report(FILE *fp, struct pmi_symbolizer *symbolizer,
			       const struct pmi_report_options *opts,
			       const struct report_schema *schema)
{
	struct table_layout top_layout;
	struct table_layout stack_layout;
	struct report_entry *entries = NULL;
	struct stack_entry *stack_entries = NULL;
	size_t count = 0;
	size_t cap = 0;
	size_t stack_count = 0;
	size_t stack_cap = 0;
	size_t i;
	char line[PMI_MAX_LINE_LEN];
	int err = 0;

	while (fgets(line, sizeof(line), fp)) {
		struct parsed_sample sample;
		char resolved_top[PMI_MAX_SYMBOL_LEN];
		struct report_entry *entry;
		size_t j;

		err = parse_sample_line(line, schema, &sample);
		if (err == 1)
			continue;
		if (err != 0)
			goto out;
		if (!is_tid_selected(opts, sample.tid))
			continue;

		resolve_top_text(symbolizer, sample.pid, sample.top, resolved_top,
				 sizeof(resolved_top));
		entry = find_or_add_report_entry(&entries, &count, &cap, resolved_top);
		if (!entry) {
			err = -ENOMEM;
			goto out;
		}
		entry->sample_count++;
		entry->insn_delta_total += sample.insn_delta;
		for (j = 0; j < schema->event_count; ++j)
			entry->event_totals[j] += sample.event_values[j];

		if (strcmp(sample.stack, "-") != 0) {
			struct stack_entry *stack_entry;
			char folded_stack[PMI_MAX_STACK_TEXT_LEN];

			build_symbolized_stack(symbolizer, sample.pid, resolved_top,
					       sample.stack, folded_stack,
					       sizeof(folded_stack));
			if (folded_stack[0] == '\0')
				continue;
			stack_entry = find_or_add_stack_entry(&stack_entries, &stack_count,
						       &stack_cap, folded_stack);
			if (!stack_entry) {
				err = -ENOMEM;
				goto out;
			}
			stack_entry->sample_count++;
			stack_entry->insn_delta_total += sample.insn_delta;
			for (j = 0; j < schema->event_count; ++j)
				stack_entry->event_totals[j] += sample.event_values[j];
		}
	}

	qsort(entries, count, sizeof(*entries), compare_report_entry);
	qsort(stack_entries, stack_count, sizeof(*stack_entries),
	      compare_stack_entry);

	init_overview_layout(&top_layout, schema);
	grow_overview_layout(&top_layout, entries, count, schema);
	print_overview_header(&top_layout, schema, "top");
	print_overview_separator(&top_layout, schema, false);
	for (i = 0; i < count && i < opts->limit; ++i) {
		print_overview_row(&entries[i], &top_layout, schema);
	}

	if (stack_count > 0) {
		printf("\nfull stacks\n");
		init_overview_layout(&stack_layout, schema);
		grow_stack_layout(&stack_layout, stack_entries, stack_count, schema);
		print_overview_header(&stack_layout, schema, "stack");
		print_overview_separator(&stack_layout, schema, true);
		for (i = 0; i < stack_count && i < opts->limit; ++i) {
			print_stack_row(&stack_entries[i], &stack_layout, schema);
		}
	}

out:
	free(entries);
	free(stack_entries);
	return err;
}

static int write_visual_html(FILE *out, const struct sample_row *rows, size_t count,
			     const struct report_schema *schema,
			     const struct pmi_report_options *opts)
{
	size_t i;
	size_t j;
	int err;

	err = file_puts_checked(
		out,
		"<!doctype html>\n"
		"<html lang=\"zh-CN\">\n"
		"<head>\n"
		"<meta charset=\"utf-8\">\n"
		"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
		"<title>PMI Visual Report</title>\n"
		"<style>\n"
		":root{--bg:#f6f7fb;--panel:#ffffff;--line:#d8deea;--text:#1f2937;--muted:#6b7280;--accent:#0f766e;--hot:#d9485f;--warm:#f59e0b;}\n"
		"*{box-sizing:border-box;}body{margin:0;padding:24px;font:14px/1.5 -apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif;color:var(--text);background:linear-gradient(180deg,#f8fafc 0%,#eef2ff 100%);}h1,h2{margin:0 0 12px;}p{margin:0;}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;}\n"
		".page{max-width:1600px;margin:0 auto;display:grid;gap:18px;}.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:18px;box-shadow:0 10px 30px rgba(15,23,42,0.06);} .summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-top:12px;} .stat{padding:12px 14px;border-radius:12px;background:#f8fafc;border:1px solid #e5e7eb;} .stat .label{font-size:12px;color:var(--muted);} .stat .value{font-size:22px;font-weight:700;margin-top:4px;} .controls{display:flex;flex-wrap:wrap;align-items:center;gap:12px;} select{padding:8px 10px;border:1px solid var(--line);border-radius:10px;background:#fff;color:var(--text);} .hint{color:var(--muted);font-size:12px;} .chart-frame{overflow-x:auto;padding-top:8px;} .chart-title{font-weight:700;margin-bottom:10px;} .small-note{font-size:12px;color:var(--muted);margin-top:8px;} .tooltip{position:fixed;display:none;max-width:320px;padding:10px 12px;border-radius:10px;background:rgba(15,23,42,0.94);color:#fff;font-size:12px;pointer-events:none;z-index:9999;box-shadow:0 8px 20px rgba(15,23,42,0.3);} .legend{display:flex;gap:10px;align-items:center;font-size:12px;color:var(--muted);margin-top:10px;} .swatch{width:14px;height:14px;border-radius:4px;background:linear-gradient(90deg,#fff7ed,#f59e0b,#d9485f);} .trend-grid{display:grid;gap:16px;} .empty{padding:24px;border:1px dashed var(--line);border-radius:12px;color:var(--muted);background:#fafafa;}\n"
		"</style>\n"
		"</head>\n"
		"<body>\n"
		"<div class=\"page\">\n"
		"<section class=\"panel\">\n"
		"<h1>PMI 时序热点可视化</h1>\n"
		"<p class=\"hint\">横轴表示按采样序号分桶后的窗口，不是 wall-clock 时间。</p>\n"
		"<div id=\"summary\" class=\"summary-grid\"></div>\n"
		"</section>\n"
		"<section class=\"panel\">\n"
		"<div class=\"controls\">\n"
		"<label for=\"tid-select\"><strong>TID</strong></label>\n"
		"<select id=\"tid-select\"></select>\n"
		"<span class=\"hint\">CLI 的 <code>-t</code> 过滤会先缩小样本集，这里再做页面内单选筛选。</span>\n"
		"</div>\n"
		"</section>\n"
		"<section class=\"panel\">\n"
		"<div class=\"chart-title\">热点函数 × 窗口</div>\n"
		"<div class=\"chart-frame\" id=\"heatmap-frame\"></div>\n"
		"<div class=\"legend\"><span class=\"swatch\"></span><span>颜色深浅表示该窗口内该函数的 sample 数。</span></div>\n"
		"</section>\n"
		"<section class=\"panel\">\n"
		"<div class=\"chart-title\">趋势副图</div>\n"
		"<div class=\"trend-grid\" id=\"trend-grid\"></div>\n"
		"</section>\n"
		"</div>\n"
		"<div id=\"tooltip\" class=\"tooltip\"></div>\n"
		"<script>\n"
		"const reportData = {\n");
	if (err)
		return err;

	err = file_printf(out, "  windowSamples: %zu,\n", opts->window_samples);
	if (err)
		return err;
	err = file_printf(out, "  topLimit: %zu,\n", opts->limit);
	if (err)
		return err;
	err = file_puts_checked(out, "  eventNames: [");
	if (err)
		return err;
	for (i = 0; i < schema->event_count; ++i) {
		if (i > 0 && fputc(',', out) == EOF)
			return -EIO;
		err = json_write_escaped(out, schema->event_names[i]);
		if (err)
			return err;
	}
	err = file_puts_checked(out, "],\n  samples: [\n");
	if (err)
		return err;
	for (i = 0; i < count; ++i) {
		err = file_printf(out,
				  "    {seq:%" PRIu64 ",pid:%d,tid:%d,insnDelta:%" PRIu64 ",top:",
				  rows[i].seq, (int)rows[i].pid, (int)rows[i].tid,
				  rows[i].insn_delta);
		if (err)
			return err;
		err = json_write_escaped(out, rows[i].top);
		if (err)
			return err;
		err = file_puts_checked(out, ",events:[");
		if (err)
			return err;
		for (j = 0; j < schema->event_count; ++j) {
			if (j > 0 && fputc(',', out) == EOF)
				return -EIO;
			err = file_printf(out, "%" PRIu64, rows[i].event_values[j]);
			if (err)
				return err;
		}
		err = file_puts_checked(out, "]}");
		if (err)
			return err;
		if (i + 1 != count && fputc(',', out) == EOF)
			return -EIO;
		if (fputc('\n', out) == EOF)
			return -EIO;
	}

	err = file_puts_checked(
		out,
		"  ]\n"
		"};\n"
		"const state = { tid: 'all' };\n"
		"const tooltip = document.getElementById('tooltip');\n"
		"function sum(arr){return arr.reduce((a,b)=>a+b,0);}\n"
		"function escapeHtml(value){return String(value).replace(/[&<>\"']/g,(c)=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]));}\n"
		"function uniqueTids(samples){return [...new Set(samples.map((s)=>s.tid))].sort((a,b)=>a-b);}\n"
		"function windowRangeLabel(index){const start=index*reportData.windowSamples+1;const end=start+reportData.windowSamples-1;return `${start}-${end}`;}\n"
		"function metricZero(){return {sampleCount:0,insnDelta:0,events:Array(reportData.eventNames.length).fill(0)};}\n"
		"function metricClone(src){return {sampleCount:src.sampleCount,insnDelta:src.insnDelta,events:src.events.slice()};}\n"
		"function getFilteredSamples(){if(state.tid==='all') return reportData.samples; return reportData.samples.filter((sample)=>String(sample.tid)===state.tid);}\n"
		"function computeView(samples){const windows=[];const topTotals=new Map();let maxWindow=-1;for(const sample of samples){const windowIndex=Math.floor((sample.seq-1)/reportData.windowSamples);const top=(sample.top&&sample.top!=='-')?sample.top:'[unknown]';maxWindow=Math.max(maxWindow,windowIndex);while(windows.length<=windowIndex){windows.push({sampleCount:0,insnDelta:0,events:Array(reportData.eventNames.length).fill(0),topMetrics:new Map()});}const bucket=windows[windowIndex];bucket.sampleCount+=1;bucket.insnDelta+=sample.insnDelta;sample.events.forEach((value,index)=>bucket.events[index]+=value);let metric=bucket.topMetrics.get(top);if(!metric){metric=metricZero();bucket.topMetrics.set(top,metric);}metric.sampleCount+=1;metric.insnDelta+=sample.insnDelta;sample.events.forEach((value,index)=>metric.events[index]+=value);topTotals.set(top,(topTotals.get(top)||0)+1);}const topNames=[...topTotals.entries()].sort((lhs,rhs)=>rhs[1]-lhs[1]||lhs[0].localeCompare(rhs[0])).slice(0,reportData.topLimit).map((entry)=>entry[0]);const matrix=topNames.map((name)=>windows.map((bucket)=>bucket.topMetrics.has(name)?metricClone(bucket.topMetrics.get(name)):metricZero()));return {samples,windows,topNames,matrix,totalSamples:samples.length,totalInsn:windows.reduce((acc,bucket)=>acc+bucket.insnDelta,0)};}\n"
		"function renderSummary(view){const tids=uniqueTids(reportData.samples);const summary=document.getElementById('summary');summary.innerHTML='';const cards=[['样本数',String(view.totalSamples)],['窗口数',String(view.windows.length)],['全局 TopN',String(reportData.topLimit)],['事件列',reportData.eventNames.length?reportData.eventNames.join(', '):'-'],['当前 TID',state.tid==='all'?'All':state.tid],['可选 TID',tids.length?tids.join(', '):'-']];for(const [label,value] of cards){const card=document.createElement('div');card.className='stat';card.innerHTML=`<div class=\"label\">${escapeHtml(label)}</div><div class=\"value\">${escapeHtml(value)}</div>`;summary.appendChild(card);}}\n"
		"function renderTidSelect(){const select=document.getElementById('tid-select');const tids=uniqueTids(reportData.samples);select.innerHTML='';const allOption=document.createElement('option');allOption.value='all';allOption.textContent='All';select.appendChild(allOption);for(const tid of tids){const option=document.createElement('option');option.value=String(tid);option.textContent=String(tid);select.appendChild(option);}select.value=state.tid;select.onchange=()=>{state.tid=select.value;updateView();};}\n"
		"function colorFor(value,maxValue){if(maxValue<=0||value<=0) return '#f8fafc';const ratio=value/maxValue;if(ratio<0.35) return '#fde68a';if(ratio<0.7) return '#f59e0b';return '#d9485f';}\n"
		"function showTooltip(event,html){tooltip.innerHTML=html;tooltip.style.display='block';tooltip.style.left=`${event.clientX+14}px`;tooltip.style.top=`${event.clientY+14}px`;}\n"
		"function hideTooltip(){tooltip.style.display='none';}\n"
		"function renderHeatmap(view){const frame=document.getElementById('heatmap-frame');frame.innerHTML='';if(view.topNames.length===0||view.windows.length===0){frame.innerHTML='<div class=\"empty\">当前筛选条件下没有可视化样本。</div>';return;}const leftPad=260;const topPad=48;const cellWidth=Math.max(14,Math.min(28,Math.floor(980/Math.max(1,view.windows.length))));const cellHeight=24;const svgWidth=leftPad+view.windows.length*cellWidth+24;const svgHeight=topPad+view.topNames.length*cellHeight+24;const maxValue=Math.max(1,...view.matrix.flat().map((metric)=>metric.sampleCount));const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');svg.setAttribute('width',String(svgWidth));svg.setAttribute('height',String(svgHeight));svg.setAttribute('viewBox',`0 0 ${svgWidth} ${svgHeight}`);for(let col=0;col<view.windows.length;col++){const label=document.createElementNS('http://www.w3.org/2000/svg','text');label.setAttribute('x',String(leftPad+col*cellWidth+cellWidth/2));label.setAttribute('y','24');label.setAttribute('text-anchor','middle');label.setAttribute('font-size','11');label.setAttribute('fill','#6b7280');label.textContent=String(col+1);svg.appendChild(label);}for(let row=0;row<view.topNames.length;row++){const name=view.topNames[row];const label=document.createElementNS('http://www.w3.org/2000/svg','text');label.setAttribute('x',String(leftPad-10));label.setAttribute('y',String(topPad+row*cellHeight+16));label.setAttribute('text-anchor','end');label.setAttribute('font-size','12');label.setAttribute('fill','#1f2937');label.textContent=name;svg.appendChild(label);for(let col=0;col<view.windows.length;col++){const metric=view.matrix[row][col];const rect=document.createElementNS('http://www.w3.org/2000/svg','rect');rect.setAttribute('x',String(leftPad+col*cellWidth));rect.setAttribute('y',String(topPad+row*cellHeight));rect.setAttribute('width',String(cellWidth-1));rect.setAttribute('height',String(cellHeight-1));rect.setAttribute('rx','3');rect.setAttribute('fill',colorFor(metric.sampleCount,maxValue));rect.addEventListener('mousemove',(event)=>{const eventRows=reportData.eventNames.map((name,index)=>`${escapeHtml(name)}: ${metric.events[index]}`).join('<br>');showTooltip(event,`<strong>${escapeHtml(name)}</strong><br>窗口: ${windowRangeLabel(col)}<br>sample 数: ${metric.sampleCount}<br>insn_delta: ${metric.insnDelta}${eventRows?`<br>${eventRows}`:''}`);});rect.addEventListener('mouseleave',hideTooltip);svg.appendChild(rect);}}frame.appendChild(svg);const note=document.createElement('div');note.className='small-note';note.textContent='热力图窗口编号从 1 开始，tooltip 中显示该窗口覆盖的采样序号范围。';frame.appendChild(note);}\n"
		"function renderLineChart(parent,title,values,color){const card=document.createElement('div');const heading=document.createElement('div');heading.className='chart-title';heading.textContent=title;card.appendChild(heading);if(values.length===0){const empty=document.createElement('div');empty.className='empty';empty.textContent='没有可展示的数据。';card.appendChild(empty);parent.appendChild(card);return;}const width=Math.max(900,values.length*18);const height=180;const left=48;const top=16;const innerWidth=width-left-18;const innerHeight=height-top-28;const maxValue=Math.max(1,...values);const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');svg.setAttribute('width',String(width));svg.setAttribute('height',String(height));svg.setAttribute('viewBox',`0 0 ${width} ${height}`);const axis=document.createElementNS('http://www.w3.org/2000/svg','line');axis.setAttribute('x1',String(left));axis.setAttribute('y1',String(top+innerHeight));axis.setAttribute('x2',String(left+innerWidth));axis.setAttribute('y2',String(top+innerHeight));axis.setAttribute('stroke','#cbd5e1');axis.setAttribute('stroke-width','1');svg.appendChild(axis);const polyline=document.createElementNS('http://www.w3.org/2000/svg','polyline');const points=values.map((value,index)=>{const x=left+(values.length===1?0:index*(innerWidth/(values.length-1||1)));const y=top+innerHeight-(value/maxValue)*innerHeight;return `${x},${y}`;});polyline.setAttribute('fill','none');polyline.setAttribute('stroke',color);polyline.setAttribute('stroke-width','2.5');polyline.setAttribute('points',points.join(' '));svg.appendChild(polyline);values.forEach((value,index)=>{const x=left+(values.length===1?0:index*(innerWidth/(values.length-1||1)));const y=top+innerHeight-(value/maxValue)*innerHeight;const dot=document.createElementNS('http://www.w3.org/2000/svg','circle');dot.setAttribute('cx',String(x));dot.setAttribute('cy',String(y));dot.setAttribute('r','3');dot.setAttribute('fill',color);dot.addEventListener('mousemove',(event)=>showTooltip(event,`<strong>${escapeHtml(title)}</strong><br>窗口: ${windowRangeLabel(index)}<br>值: ${value}`));dot.addEventListener('mouseleave',hideTooltip);svg.appendChild(dot);});const maxLabel=document.createElementNS('http://www.w3.org/2000/svg','text');maxLabel.setAttribute('x','6');maxLabel.setAttribute('y',String(top+12));maxLabel.setAttribute('font-size','11');maxLabel.setAttribute('fill','#6b7280');maxLabel.textContent=String(maxValue);svg.appendChild(maxLabel);const endLabel=document.createElementNS('http://www.w3.org/2000/svg','text');endLabel.setAttribute('x',String(left+innerWidth));endLabel.setAttribute('y',String(height-6));endLabel.setAttribute('text-anchor','end');endLabel.setAttribute('font-size','11');endLabel.setAttribute('fill','#6b7280');endLabel.textContent=`窗口数: ${values.length}`;svg.appendChild(endLabel);const frame=document.createElement('div');frame.className='chart-frame';frame.appendChild(svg);card.appendChild(frame);parent.appendChild(card);}\n"
		"function renderTrends(view){const grid=document.getElementById('trend-grid');grid.innerHTML='';const sampleSeries=view.windows.map((bucket)=>bucket.sampleCount);const insnSeries=view.windows.map((bucket)=>bucket.insnDelta);renderLineChart(grid,'总 sample 数趋势',sampleSeries,'#0f766e');renderLineChart(grid,'insn_delta 趋势',insnSeries,'#2563eb');const palette=['#b91c1c','#7c3aed','#0f766e','#ea580c','#0891b2','#65a30d','#be185d'];reportData.eventNames.forEach((name,index)=>{renderLineChart(grid,`${name} delta 趋势`,view.windows.map((bucket)=>bucket.events[index]),palette[index%palette.length]);});}\n"
		"function updateView(){const filtered=getFilteredSamples();const view=computeView(filtered);renderSummary(view);renderHeatmap(view);renderTrends(view);}renderTidSelect();updateView();\n"
		"</script>\n"
		"</body>\n"
		"</html>\n");
	return err;
}

static int run_visual_report(FILE *fp, struct pmi_symbolizer *symbolizer,
			     const struct pmi_report_options *opts,
			     const struct report_schema *schema)
{
	struct sample_row *rows = NULL;
	size_t count = 0;
	FILE *out = NULL;
	int err;

	err = collect_symbolized_samples(fp, symbolizer, opts, schema, false, &rows,
					 &count);
	if (err)
		return err;

	out = fopen(opts->output_path, "w");
	if (!out) {
		free(rows);
		return -errno;
	}

	err = write_visual_html(out, rows, count, schema, opts);
	if (fclose(out) != 0 && err == 0)
		err = -EIO;
	free(rows);
	return err;
}

int pmi_report_main(int argc, char **argv)
{
	struct pmi_report_options opts;
	struct report_schema schema;
	struct pmi_symbolizer *symbolizer = NULL;
	FILE *fp;
	char magic[64];
	char header[PMI_MAX_LINE_LEN];
	int err;

	err = parse_report_options(argc, argv, &opts);
	if (err) {
		if (err == 2)
			return 0;
		report_usage(stderr);
		return 1;
	}

	err = pmi_symbolizer_init(&symbolizer);
	if (err) {
		fprintf(stderr, "symbolizer init failed: %s\n", strerror(-err));
		return 1;
	}

	fp = fopen(opts.input_path, "r");
	if (!fp) {
		fprintf(stderr, "open %s failed: %s\n", opts.input_path,
			strerror(errno));
		pmi_symbolizer_destroy(symbolizer);
		return 1;
	}
	if (!fgets(magic, sizeof(magic), fp) ||
	    strcmp(magic, "# pmi raw v3\n") != 0) {
		fprintf(stderr, "%s is not a pmi raw v3 file\n", opts.input_path);
		fclose(fp);
		pmi_symbolizer_destroy(symbolizer);
		return 1;
	}
	if (!fgets(header, sizeof(header), fp) ||
	    parse_header_line(header, &schema) != 0) {
		fprintf(stderr, "%s has an invalid pmi raw v3 header\n",
			opts.input_path);
		fclose(fp);
		pmi_symbolizer_destroy(symbolizer);
		return 1;
	}

	if (opts.mode == PMI_REPORT_SAMPLES)
		err = run_samples_report(fp, symbolizer, &opts, &schema);
	else if (opts.mode == PMI_REPORT_VISUAL)
		err = run_visual_report(fp, symbolizer, &opts, &schema);
	else
		err = run_overview_report(fp, symbolizer, &opts, &schema);

	fclose(fp);
	pmi_symbolizer_destroy(symbolizer);
	if (err) {
		fprintf(stderr, "report failed: %s\n", strerror(-err));
		return 1;
	}
	return 0;
}

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
		"  -t, --tid <tid1,tid2,...>    filter samples by tid list\n"
		"  -h, --help                   show this help\n"
		"\n"
		"examples:\n"
		"  pmi report -i out.pmi\n"
		"  pmi report -i out.pmi -t 1234,5678 -m samples\n"
		"  pmi report -i out.pmi -m visual -o out.html\n");
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
			opts->saw_window_samples = true;
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
	if (opts->mode == PMI_REPORT_VISUAL && opts->saw_window_samples) {
		fprintf(stderr,
			"-w/--window-samples is not supported in visual mode\n");
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
			     const struct report_schema *schema)
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
		".page{max-width:1600px;margin:0 auto;display:grid;gap:18px;}.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:18px;box-shadow:0 10px 30px rgba(15,23,42,0.06);} .summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-top:12px;} .stat{padding:12px 14px;border-radius:12px;background:#f8fafc;border:1px solid #e5e7eb;} .stat .label{font-size:12px;color:var(--muted);} .stat .value{font-size:22px;font-weight:700;margin-top:4px;} .controls{display:flex;flex-wrap:wrap;align-items:center;gap:12px;} select{padding:8px 10px;border:1px solid var(--line);border-radius:10px;background:#fff;color:var(--text);} .hint{color:var(--muted);font-size:12px;} .chart-frame{overflow:auto;padding-top:8px;} .chart-title{font-weight:700;margin-bottom:10px;} .small-note{font-size:12px;color:var(--muted);margin-top:8px;} .tooltip{position:fixed;display:none;max-width:320px;padding:10px 12px;border-radius:10px;background:rgba(15,23,42,0.94);color:#fff;font-size:12px;pointer-events:none;z-index:9999;box-shadow:0 8px 20px rgba(15,23,42,0.3);} .legend{display:flex;gap:10px;align-items:center;font-size:12px;color:var(--muted);margin-top:10px;} .swatch{width:14px;height:14px;border-radius:4px;background:linear-gradient(90deg,#fff7ed,#f59e0b,#d9485f);} .detail-grid{display:grid;gap:16px;} .empty{padding:24px;border:1px dashed var(--line);border-radius:12px;color:var(--muted);background:#fafafa;} canvas{display:block;max-width:none;background:#fff;border:1px solid #e5e7eb;border-radius:12px;} .detail-table{width:100%;border-collapse:collapse;font-size:13px;} .detail-table th,.detail-table td{padding:8px 10px;border-bottom:1px solid #e5e7eb;text-align:right;white-space:nowrap;} .detail-table th:last-child,.detail-table td:last-child{text-align:left;} .detail-table caption{text-align:left;font-weight:700;margin-bottom:8px;} .detail-section{display:grid;gap:10px;} .detail-note{font-size:12px;color:var(--muted);} \n"
		"</style>\n"
		"</head>\n"
		"<body>\n"
		"<div class=\"page\">\n"
		"<section class=\"panel\">\n"
		"<h1>PMI 时序热点可视化</h1>\n"
		"<p class=\"hint\">横轴直接使用原始 sample 序号 seq，不做窗口聚合，也不是 wall-clock 时间。</p>\n"
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
		"<div class=\"chart-title\">阶段热条图</div>\n"
		"<div class=\"chart-frame\"><canvas id=\"phase-heatmap\"></canvas></div>\n"
		"<div class=\"legend\"><span class=\"swatch\"></span><span>横轴是按 seq 等宽切出的阶段，纵轴是全局热点函数，颜色深浅表示该函数在该阶段的 sample 数。</span></div>\n"
		"</section>\n"
		"<section class=\"panel\">\n"
		"<div class=\"chart-title\">阶段热点榜</div>\n"
		"<div id=\"phase-detail\" class=\"detail-grid\"></div>\n"
		"<div class=\"small-note\">点击上方热条图的任意阶段列，查看该阶段的热点函数与 folded stack 汇总。</div>\n"
		"</section>\n"
		"</div>\n"
		"<div id=\"tooltip\" class=\"tooltip\"></div>\n"
		"<script>\n"
		"const reportData = {\n");
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
		err = file_puts_checked(out, ",stack:");
		if (err)
			return err;
		err = json_write_escaped(out, rows[i].stack);
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
		"const PHASE_COUNT_DEFAULT = 60;\n"
		"const HEATMAP_TOP_N = 15;\n"
		"const DETAIL_TOP_N = 20;\n"
		"const DETAIL_STACK_N = 10;\n"
		"const state = { tid: 'all', phaseIndex: -1, currentView: null };\n"
		"const tooltip = document.getElementById('tooltip');\n"
		"function escapeHtml(value){return String(value).replace(/[&<>\"']/g,(c)=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]));}\n"
		"function uniqueTids(samples){return [...new Set(samples.map((s)=>s.tid))].sort((a,b)=>a-b);}\n"
		"function getFilteredSamples(){if(state.tid==='all') return reportData.samples; return reportData.samples.filter((sample)=>String(sample.tid)===state.tid);}\n"
		"function normalizeTop(sample){return sample.top && sample.top !== '-' ? sample.top : '[unknown]';}\n"
		"function setupCanvas(canvas,cssWidth,cssHeight){const dpr=window.devicePixelRatio||1;canvas.width=Math.max(1,Math.floor(cssWidth*dpr));canvas.height=Math.max(1,Math.floor(cssHeight*dpr));canvas.style.width=`${cssWidth}px`;canvas.style.height=`${cssHeight}px`;const ctx=canvas.getContext('2d');ctx.setTransform(dpr,0,0,dpr,0,0);ctx.clearRect(0,0,cssWidth,cssHeight);return ctx;}\n"
		"function metricZero(){return {sampleCount:0,insnDelta:0,eventSums:Array(reportData.eventNames.length).fill(0)};}\n"
		"function bumpMetric(metric,sample){metric.sampleCount+=1;metric.insnDelta+=sample.insnDelta;sample.events.forEach((value,index)=>{metric.eventSums[index]+=value;});}\n"
		"function buildView(samples){const normalized=samples.map((sample)=>({seq:sample.seq,pid:sample.pid,tid:sample.tid,insnDelta:sample.insnDelta,top:normalizeTop(sample),stack:sample.stack&&sample.stack!==''?sample.stack:'-',events:sample.events.slice()})).sort((lhs,rhs)=>lhs.seq-rhs.seq);if(normalized.length===0){return {samples:[],phases:[],topNames:[],phaseCount:0,totalSamples:0,functionCount:0,minSeq:0,maxSeq:0,selectedPhaseIndex:-1,selectedPhase:null};}const topTotals=new Map();const minSeq=normalized[0].seq;const maxSeq=normalized[normalized.length-1].seq;const seqSpan=Math.max(1,maxSeq-minSeq);normalized.forEach((sample)=>{topTotals.set(sample.top,(topTotals.get(sample.top)||0)+1);});const phaseCount=Math.max(1,Math.min(PHASE_COUNT_DEFAULT,normalized.length));const phases=Array.from({length:phaseCount},(_,index)=>{const startSeq=Math.round(minSeq+(index/phaseCount)*seqSpan);const endSeq=index===phaseCount-1?maxSeq:Math.round(minSeq+((index+1)/phaseCount)*seqSpan);return {index,startSeq:index===0?minSeq:startSeq,endSeq:index===phaseCount-1?maxSeq:Math.max(startSeq,endSeq),sampleCount:0,insnDelta:0,eventSums:Array(reportData.eventNames.length).fill(0),topMetrics:new Map(),stackMetrics:new Map()};});normalized.forEach((sample)=>{let phaseIndex=0;if(phaseCount>1){phaseIndex=Math.min(phaseCount-1,Math.floor(((sample.seq-minSeq)/seqSpan)*phaseCount));}const phase=phases[phaseIndex];phase.sampleCount+=1;phase.insnDelta+=sample.insnDelta;sample.events.forEach((value,index)=>{phase.eventSums[index]+=value;});let topMetric=phase.topMetrics.get(sample.top);if(!topMetric){topMetric=metricZero();phase.topMetrics.set(sample.top,topMetric);}bumpMetric(topMetric,sample);if(sample.stack&&sample.stack!=='-'){let stackMetric=phase.stackMetrics.get(sample.stack);if(!stackMetric){stackMetric=metricZero();phase.stackMetrics.set(sample.stack,stackMetric);}bumpMetric(stackMetric,sample);}});const topOrder=[...topTotals.entries()].sort((lhs,rhs)=>rhs[1]-lhs[1]||lhs[0].localeCompare(rhs[0])).map((entry)=>entry[0]);const topNames=topOrder.slice(0,HEATMAP_TOP_N);const maxCellCount=Math.max(1,...phases.flatMap((phase)=>topNames.map((name)=>phase.topMetrics.has(name)?phase.topMetrics.get(name).sampleCount:0)));let selectedPhaseIndex=state.phaseIndex;if(!(selectedPhaseIndex>=0&&selectedPhaseIndex<phaseCount)){selectedPhaseIndex=0;for(let index=1;index<phaseCount;index++){if(phases[index].sampleCount>phases[selectedPhaseIndex].sampleCount) selectedPhaseIndex=index;}}const selectedPhase=phases[selectedPhaseIndex];const detailTopEntries=[...selectedPhase.topMetrics.entries()].map(([name,metric])=>({name,sampleCount:metric.sampleCount,insnDelta:metric.insnDelta,eventSums:metric.eventSums.slice()})).sort((lhs,rhs)=>rhs.sampleCount-lhs.sampleCount||rhs.insnDelta-lhs.insnDelta||lhs.name.localeCompare(rhs.name)).slice(0,DETAIL_TOP_N);const detailStackEntries=[...selectedPhase.stackMetrics.entries()].map(([stack,metric])=>({stack,sampleCount:metric.sampleCount,insnDelta:metric.insnDelta,eventSums:metric.eventSums.slice()})).sort((lhs,rhs)=>rhs.sampleCount-lhs.sampleCount||rhs.insnDelta-lhs.insnDelta||lhs.stack.localeCompare(rhs.stack)).slice(0,DETAIL_STACK_N);return {samples:normalized,phases,topNames,phaseCount,totalSamples:normalized.length,functionCount:topOrder.length,minSeq,maxSeq,selectedPhaseIndex,selectedPhase,detailTopEntries,detailStackEntries,maxCellCount};}\n"
		"function renderSummary(view){const tids=uniqueTids(reportData.samples);const summary=document.getElementById('summary');summary.innerHTML='';const seqRange=view.totalSamples?`${view.minSeq}-${view.maxSeq}`:'-';const phaseRange=view.selectedPhase?`${view.selectedPhase.startSeq}-${view.selectedPhase.endSeq}`:'-';const cards=[['样本数',String(view.totalSamples)],['阶段数',String(view.phaseCount)],['函数数',String(view.functionCount)],['seq 范围',seqRange],['当前 TID',state.tid==='all'?'All':state.tid],['当前阶段',view.selectedPhase?String(view.selectedPhase.index+1):'-'],['阶段区间',phaseRange],['事件列',reportData.eventNames.length?reportData.eventNames.join(', '):'-'],['可选 TID',tids.length?tids.join(', '):'-']];for(const [label,value] of cards){const card=document.createElement('div');card.className='stat';card.innerHTML=`<div class=\"label\">${escapeHtml(label)}</div><div class=\"value\">${escapeHtml(value)}</div>`;summary.appendChild(card);}}\n"
		"function renderTidSelect(){const select=document.getElementById('tid-select');const tids=uniqueTids(reportData.samples);select.innerHTML='';const allOption=document.createElement('option');allOption.value='all';allOption.textContent='All';select.appendChild(allOption);for(const tid of tids){const option=document.createElement('option');option.value=String(tid);option.textContent=String(tid);select.appendChild(option);}select.value=state.tid;select.onchange=()=>{state.tid=select.value;state.phaseIndex=-1;updateView();};}\n"
		"function colorFor(value,maxValue){if(maxValue<=0||value<=0) return '#f8fafc';const ratio=value/maxValue;if(ratio<0.15) return '#fff7ed';if(ratio<0.35) return '#fde68a';if(ratio<0.6) return '#f59e0b';return '#d9485f';}\n"
		"function showTooltip(event,html){tooltip.innerHTML=html;tooltip.style.display='block';tooltip.style.left=`${event.clientX+14}px`;tooltip.style.top=`${event.clientY+14}px`;}\n"
		"function hideTooltip(){tooltip.style.display='none';}\n"
		"function formatEventRows(sample){return reportData.eventNames.map((name,index)=>`${escapeHtml(name)}: ${sample.events[index]}`).join('<br>');}\n"
		"function formatEventTotals(values){return reportData.eventNames.map((name,index)=>`${escapeHtml(name)}: ${values[index]}`).join('<br>');}\n"
		"function renderHeatmap(view){const canvas=document.getElementById('phase-heatmap');const left=250;const top=28;const right=12;const bottom=28;const cellWidth=18;const cellHeight=24;const width=left+Math.max(1,view.phaseCount)*cellWidth+right;const height=top+Math.max(1,view.topNames.length)*cellHeight+bottom;const ctx=setupCanvas(canvas,width,height);ctx.fillStyle='#ffffff';ctx.fillRect(0,0,width,height);ctx.strokeStyle='#cbd5e1';ctx.lineWidth=1;ctx.beginPath();ctx.moveTo(left,top+view.topNames.length*cellHeight+0.5);ctx.lineTo(width-right,top+view.topNames.length*cellHeight+0.5);ctx.stroke();ctx.font='12px sans-serif';ctx.fillStyle='#1f2937';view.topNames.forEach((name,rowIndex)=>{const y=top+rowIndex*cellHeight+cellHeight/2;ctx.fillText(name,12,y+4);ctx.strokeStyle='#eef2f7';ctx.beginPath();ctx.moveTo(left,y);ctx.lineTo(width-right,y);ctx.stroke();});ctx.fillStyle='#6b7280';ctx.font='11px sans-serif';const labelStep=Math.max(1,Math.ceil(view.phaseCount/12));view.phases.forEach((phase,index)=>{if(index%labelStep===0||index===view.phaseCount-1){ctx.save();ctx.translate(left+index*cellWidth+cellWidth/2,18);ctx.rotate(-0.55);ctx.fillText(String(index+1),0,0);ctx.restore();}});view.phases.forEach((phase,phaseIndex)=>{if(phaseIndex===view.selectedPhaseIndex){ctx.fillStyle='rgba(37,99,235,0.14)';ctx.fillRect(left+phaseIndex*cellWidth,top,cellWidth,view.topNames.length*cellHeight);ctx.strokeStyle='#2563eb';ctx.strokeRect(left+phaseIndex*cellWidth+0.5,top+0.5,cellWidth-1,view.topNames.length*cellHeight-1);}view.topNames.forEach((name,rowIndex)=>{const metric=phase.topMetrics.get(name);const value=metric?metric.sampleCount:0;ctx.fillStyle=colorFor(value,view.maxCellCount);ctx.fillRect(left+phaseIndex*cellWidth+1,top+rowIndex*cellHeight+1,cellWidth-2,cellHeight-2);});});ctx.fillStyle='#6b7280';ctx.fillText(`seq ${view.minSeq}`,left,height-8);ctx.textAlign='right';ctx.fillText(`seq ${view.maxSeq}`,width-right,height-8);ctx.textAlign='start';canvas.onmousemove=(event)=>{const rect=canvas.getBoundingClientRect();const x=event.clientX-rect.left;const y=event.clientY-rect.top;const phaseIndex=Math.floor((x-left)/cellWidth);const rowIndex=Math.floor((y-top)/cellHeight);if(phaseIndex<0||phaseIndex>=view.phaseCount||rowIndex<0||rowIndex>=view.topNames.length){hideTooltip();return;}const phase=view.phases[phaseIndex];const name=view.topNames[rowIndex];const metric=phase.topMetrics.get(name)||metricZero();const eventRows=formatEventTotals(metric.eventSums);showTooltip(event,`<strong>${escapeHtml(name)}</strong><br>阶段: ${phaseIndex+1}<br>seq: ${phase.startSeq}-${phase.endSeq}<br>samples: ${metric.sampleCount}<br>insn_delta: ${metric.insnDelta}${eventRows?`<br>${eventRows}`:''}`);};canvas.onmouseleave=hideTooltip;canvas.onclick=(event)=>{const rect=canvas.getBoundingClientRect();const x=event.clientX-rect.left;const phaseIndex=Math.floor((x-left)/cellWidth);if(phaseIndex<0||phaseIndex>=view.phaseCount) return;state.phaseIndex=phaseIndex;updateView();};}\n"
		"function formatCell(value){return Number(value).toLocaleString('zh-CN');}\n"
		"function buildTable(columns,rows,lastKey){const header=columns.map((column)=>`<th>${escapeHtml(column.label)}</th>`).join('');const body=rows.map((row)=>`<tr>${columns.map((column,index)=>{const raw=row[column.key];const text=index===columns.length-1?escapeHtml(String(raw)):formatCell(raw);return `<td>${text}</td>`;}).join('')}</tr>`).join('');return `<table class=\"detail-table\"><thead><tr>${header}</tr></thead><tbody>${body||`<tr><td colspan=\"${columns.length}\">无数据</td></tr>`}</tbody></table>`;}\n"
		"function renderPhaseDetails(view){const container=document.getElementById('phase-detail');container.innerHTML='';if(!view.selectedPhase){container.innerHTML='<div class=\"empty\">当前筛选条件下没有阶段可展示。</div>';return;}const phase=view.selectedPhase;const header=document.createElement('div');header.className='detail-note';header.textContent=`当前阶段 ${phase.index+1} / seq ${phase.startSeq}-${phase.endSeq} / samples ${phase.sampleCount}`;container.appendChild(header);const hotspot=document.createElement('div');hotspot.className='detail-section';const hotspotTitle=document.createElement('div');hotspotTitle.className='chart-title';hotspotTitle.textContent='该阶段热点榜';hotspot.appendChild(hotspotTitle);const hotspotColumns=[{label:'samples',key:'sampleCount'},{label:'insn_delta',key:'insnDelta'}].concat(reportData.eventNames.map((name,index)=>({label:name,key:`event${index}`}))).concat([{label:'top',key:'name'}]);const hotspotRows=view.detailTopEntries.map((entry)=>{const row={sampleCount:entry.sampleCount,insnDelta:entry.insnDelta,name:entry.name};entry.eventSums.forEach((value,index)=>{row[`event${index}`]=value;});return row;});hotspot.innerHTML+=buildTable(hotspotColumns,hotspotRows,'name');container.appendChild(hotspot);if(view.detailStackEntries.length>0){const stackSection=document.createElement('div');stackSection.className='detail-section';const stackTitle=document.createElement('div');stackTitle.className='chart-title';stackTitle.textContent='该阶段 full stacks';stackSection.appendChild(stackTitle);const stackColumns=[{label:'samples',key:'sampleCount'},{label:'insn_delta',key:'insnDelta'}].concat(reportData.eventNames.map((name,index)=>({label:name,key:`event${index}`}))).concat([{label:'stack',key:'stack'}]);const stackRows=view.detailStackEntries.map((entry)=>{const row={sampleCount:entry.sampleCount,insnDelta:entry.insnDelta,stack:entry.stack};entry.eventSums.forEach((value,index)=>{row[`event${index}`]=value;});return row;});stackSection.innerHTML+=buildTable(stackColumns,stackRows,'stack');container.appendChild(stackSection);}}\n"
		"function updateView(){const filtered=getFilteredSamples();const view=buildView(filtered);state.currentView=view;renderSummary(view);renderHeatmap(view);renderPhaseDetails(view);hideTooltip();}\n"
		"function initVisual(){renderTidSelect();updateView();window.addEventListener('resize',()=>{if(state.currentView) renderHeatmap(state.currentView);});}\n"
		"initVisual();\n"
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

	err = collect_symbolized_samples(fp, symbolizer, opts, schema, true, &rows,
					 &count);
	if (err)
		return err;

	out = fopen(opts->output_path, "w");
	if (!out) {
		free(rows);
		return -errno;
	}

	err = write_visual_html(out, rows, count, schema);
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

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pmi/record.h"
#include "pmi/shared.h"
#include "pmi/strutil.h"
#include "pmi/symbolizer.h"

#define PMI_REPORT_MAX_FIELDS (PMI_MAX_EVENTS + 6)

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
		"  -l, --limit <N>              max rows, default: 20\n"
		"  -m, --mode <overview|samples>\n"
		"                               default: overview\n"
		"  -t, --tid <tid1,tid2,...>    filter samples by tid list\n"
		"  -h, --help                   show this help\n"
		"\n"
		"examples:\n"
		"  pmi report -i out.pmi\n"
		"  pmi report -i out.pmi -t 1234,5678 -m samples\n");
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
	char pretty_top[PMI_MAX_SYMBOL_LEN];
	char *token;
	char *saveptr = NULL;

	if (!out || out_cap == 0)
		return -EINVAL;

	out[0] = '\0';
	if (has_symbol_text(top)) {
		pmi_copy_cstr_trunc(pretty_top, sizeof(pretty_top), top);
		prettify_symbol(symbolizer, pretty_top, sizeof(pretty_top));
		pmi_copy_cstr_trunc(out, out_cap, pretty_top);
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

static int parse_report_options(int argc, char **argv, struct pmi_report_options *opts)
{
	static const struct option long_options[] = {
		{ "input", required_argument, NULL, 'i' },
		{ "limit", required_argument, NULL, 'l' },
		{ "mode", required_argument, NULL, 'm' },
		{ "tid", required_argument, NULL, 't' },
		{ "help", no_argument, NULL, 'h' },
		{ 0, 0, 0, 0 },
	};
	int opt;

	memset(opts, 0, sizeof(*opts));
	opts->limit = 20;
	opts->mode = PMI_REPORT_OVERVIEW;
	opterr = 0;
	optind = 1;

	while ((opt = getopt_long(argc, argv, "i:l:m:t:h", long_options, NULL)) != -1) {
		switch (opt) {
		case 'i':
			opts->input_path = optarg;
			break;
		case 'l':
			opts->limit = strtoul(optarg, NULL, 10);
			break;
		case 'm':
			if (strcmp(optarg, "overview") == 0)
				opts->mode = PMI_REPORT_OVERVIEW;
			else if (strcmp(optarg, "samples") == 0)
				opts->mode = PMI_REPORT_SAMPLES;
			else {
				fprintf(stderr, "invalid report mode: %s\n", optarg);
				return -EINVAL;
			}
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

static void print_event_headers(const struct report_schema *schema)
{
	size_t i;

	for (i = 0; i < schema->event_count; ++i)
		printf("\t%s", schema->event_names[i]);
}

static void print_event_values(const uint64_t *values, size_t count)
{
	size_t i;

	for (i = 0; i < count; ++i)
		printf("\t%" PRIu64, values[i]);
}

static int run_samples_report(FILE *fp, struct pmi_symbolizer *symbolizer,
			      const struct pmi_report_options *opts,
			      const struct report_schema *schema)
{
	char line[PMI_MAX_LINE_LEN];

	printf("seq\tpid\ttid\tinsn_delta");
	print_event_headers(schema);
	printf("\ttop\tstack\n");

	while (fgets(line, sizeof(line), fp)) {
		struct parsed_sample sample;
		char symbolized_stack[PMI_MAX_STACK_TEXT_LEN];
		int err;

		err = parse_sample_line(line, schema, &sample);
		if (err == 1)
			continue;
		if (err != 0)
			return err;
		if (!is_tid_selected(opts, sample.tid))
			continue;

		prettify_symbol(symbolizer, sample.top, sizeof(sample.top));
		if (strcmp(sample.stack, "-") == 0) {
			pmi_copy_cstr_trunc(symbolized_stack, sizeof(symbolized_stack),
					    "-");
		} else {
			build_symbolized_stack(symbolizer, sample.pid, sample.top,
					       sample.stack, symbolized_stack,
					       sizeof(symbolized_stack));
		}

		printf("%" PRIu64 "\t%d\t%d\t%" PRIu64, sample.seq, sample.pid,
		       sample.tid, sample.insn_delta);
		print_event_values(sample.event_values, schema->event_count);
		printf("\t%s\t%s\n", sample.top, symbolized_stack);
	}

	return 0;
}

static int run_overview_report(FILE *fp, struct pmi_symbolizer *symbolizer,
			       const struct pmi_report_options *opts,
			       const struct report_schema *schema)
{
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
		struct report_entry *entry;
		size_t j;

		err = parse_sample_line(line, schema, &sample);
		if (err == 1)
			continue;
		if (err != 0)
			goto out;
		if (!is_tid_selected(opts, sample.tid))
			continue;

		prettify_symbol(symbolizer, sample.top, sizeof(sample.top));
		entry = find_or_add_report_entry(&entries, &count, &cap, sample.top);
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

			build_symbolized_stack(symbolizer, sample.pid, sample.top,
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

	printf("samples\tinsn_delta");
	print_event_headers(schema);
	printf("\ttop\n");
	for (i = 0; i < count && i < opts->limit; ++i) {
		printf("%zu\t%" PRIu64, entries[i].sample_count,
		       entries[i].insn_delta_total);
		print_event_values(entries[i].event_totals, schema->event_count);
		printf("\t%s\n", entries[i].top);
	}

	if (stack_count > 0) {
		printf("\nfull stacks\n");
		printf("samples\tinsn_delta");
		print_event_headers(schema);
		printf("\tstack\n");
		for (i = 0; i < stack_count && i < opts->limit; ++i) {
			printf("%zu\t%" PRIu64, stack_entries[i].sample_count,
			       stack_entries[i].insn_delta_total);
			print_event_values(stack_entries[i].event_totals,
					   schema->event_count);
			printf("\t%s\n", stack_entries[i].stack);
		}
	}

out:
	free(entries);
	free(stack_entries);
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

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

struct event_sum {
	char name[PMI_MAX_EVENT_NAME];
	uint64_t total;
};

struct report_entry {
	char top[PMI_MAX_SYMBOL_LEN];
	size_t sample_count;
	struct event_sum events[PMI_MAX_EVENTS];
	size_t event_count;
};

struct stack_entry {
	char stack[PMI_MAX_STACK_TEXT_LEN];
	size_t sample_count;
	struct event_sum events[PMI_MAX_EVENTS];
	size_t event_count;
};

struct parsed_sample {
	pid_t pid;
	char top[PMI_MAX_SYMBOL_LEN];
	char events[PMI_MAX_FOLDED_LEN];
	char stack[PMI_MAX_STACK_TEXT_LEN];
};

static void report_usage(FILE *stream)
{
	fprintf(stream,
		"usage: pmi report -i <file> [options]\n"
		"\n"
		"options:\n"
		"  -i, --input <file>   raw v3 sample file\n"
		"  -l, --limit <N>      max hotspot rows, default: 20\n"
		"  -h, --help           show this help\n"
		"\n"
		"example:\n"
		"  pmi report -i out.pmi -l 20\n");
}

static void normalize_symbol(char *symbol)
{
	char *plus;

	if (!symbol || symbol[0] == '\0' || strncmp(symbol, "0x", 2) == 0)
		return;

	plus = strstr(symbol, "+0x");
	if (plus)
		*plus = '\0';
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

static void add_event_sum(struct event_sum *events, size_t *count,
			  const char *name, uint64_t value)
{
	size_t i;

	for (i = 0; i < *count; ++i) {
		if (strcmp(events[i].name, name) == 0) {
			events[i].total += value;
			return;
		}
	}

	if (*count >= PMI_MAX_EVENTS)
		return;

	pmi_copy_cstr_trunc(events[*count].name, sizeof(events[*count].name), name);
	events[*count].total = value;
	(*count)++;
}

static void parse_event_blob(struct event_sum *events, size_t *count, char *blob)
{
	char *token;
	char *saveptr = NULL;

	if (!blob || strcmp(blob, "-") == 0)
		return;

	for (token = strtok_r(blob, ",", &saveptr); token;
	     token = strtok_r(NULL, ",", &saveptr)) {
		char *eq = strchr(token, '=');
		uint64_t value;

		if (!eq)
			continue;
		*eq = '\0';
		value = strtoull(eq + 1, NULL, 10);
		add_event_sum(events, count, token, value);
	}
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
		normalize_symbol(symbol);
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
	char *token;
	char *saveptr = NULL;
	bool first_frame = true;

	if (!out || out_cap == 0)
		return -EINVAL;

	out[0] = '\0';
	if (has_symbol_text(top))
		pmi_copy_cstr_trunc(out, out_cap, top);
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
		if (first_frame && has_symbol_text(top) && strcmp(symbol, top) == 0) {
			first_frame = false;
			continue;
		}
		if (append_stack_symbol(out, out_cap, symbol) != 0)
			break;
		first_frame = false;
	}

	return 0;
}

static int parse_report_options(int argc, char **argv, struct pmi_report_options *opts)
{
	static const struct option long_options[] = {
		{ "input", required_argument, NULL, 'i' },
		{ "limit", required_argument, NULL, 'l' },
		{ "help", no_argument, NULL, 'h' },
		{ 0, 0, 0, 0 },
	};
	int opt;

	memset(opts, 0, sizeof(*opts));
	opts->limit = 20;
	opterr = 0;
	optind = 1;

	while ((opt = getopt_long(argc, argv, "i:l:h", long_options, NULL)) != -1) {
		switch (opt) {
		case 'i':
			opts->input_path = optarg;
			break;
		case 'l':
			opts->limit = strtoul(optarg, NULL, 10);
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

static int parse_sample_line(char *line, struct parsed_sample *sample)
{
	char *cursor = line;
	char *field;
	char *fields[9] = { 0 };
	size_t field_count = 0;

	if (!line || !sample)
		return -EINVAL;
	if (line[0] == '#')
		return 1;

	while ((field = strsep(&cursor, "\t")) != NULL && field_count < 9) {
		field[strcspn(field, "\r\n")] = '\0';
		fields[field_count++] = trim_field(field);
	}
	if (field_count != 9)
		return 1;
	if (strcmp(fields[0], "type") == 0)
		return 1;
	if (strcmp(fields[0], "S") != 0)
		return 1;

	memset(sample, 0, sizeof(*sample));
	sample->pid = (pid_t)strtol(fields[4], NULL, 10);
	pmi_copy_cstr_trunc(sample->top, sizeof(sample->top), fields[6]);
	pmi_copy_cstr_trunc(sample->events, sizeof(sample->events), fields[7]);
	pmi_copy_cstr_trunc(sample->stack, sizeof(sample->stack), fields[8]);
	normalize_symbol(sample->top);
	return 0;
}

int pmi_report_main(int argc, char **argv)
{
	struct pmi_report_options opts;
	struct pmi_symbolizer *symbolizer = NULL;
	struct report_entry *entries = NULL;
	struct stack_entry *stack_entries = NULL;
	size_t count = 0;
	size_t cap = 0;
	size_t stack_count = 0;
	size_t stack_cap = 0;
	size_t i;
	FILE *fp;
	char line[PMI_MAX_LINE_LEN];
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

	while (fgets(line, sizeof(line), fp)) {
		struct parsed_sample sample;
		struct report_entry *entry;
		char event_copy[PMI_MAX_FOLDED_LEN];

		err = parse_sample_line(line, &sample);
		if (err == 1)
			continue;
		if (err != 0) {
			fclose(fp);
			pmi_symbolizer_destroy(symbolizer);
			free(entries);
			free(stack_entries);
			return 1;
		}

		entry = find_or_add_report_entry(&entries, &count, &cap, sample.top);
		if (!entry) {
			fclose(fp);
			pmi_symbolizer_destroy(symbolizer);
			free(entries);
			free(stack_entries);
			return 1;
		}
		entry->sample_count++;
		pmi_copy_cstr_trunc(event_copy, sizeof(event_copy), sample.events);
		parse_event_blob(entry->events, &entry->event_count, event_copy);

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
				fclose(fp);
				pmi_symbolizer_destroy(symbolizer);
				free(entries);
				free(stack_entries);
				return 1;
			}
			stack_entry->sample_count++;
			pmi_copy_cstr_trunc(event_copy, sizeof(event_copy), sample.events);
			parse_event_blob(stack_entry->events, &stack_entry->event_count,
					 event_copy);
		}
	}
	fclose(fp);
	pmi_symbolizer_destroy(symbolizer);

	qsort(entries, count, sizeof(*entries), compare_report_entry);
	qsort(stack_entries, stack_count, sizeof(*stack_entries),
	      compare_stack_entry);

	printf("%-8s %-40s %s\n", "samples", "top", "events");
	for (i = 0; i < count && i < opts.limit; ++i) {
		size_t j;

		printf("%-8zu %-40s ", entries[i].sample_count, entries[i].top);
		if (entries[i].event_count == 0) {
			printf("-");
		} else {
			for (j = 0; j < entries[i].event_count; ++j) {
				if (j != 0)
					printf(", ");
				printf("%s=%" PRIu64, entries[i].events[j].name,
				       entries[i].events[j].total);
			}
		}
		printf("\n");
	}

	if (stack_count > 0) {
		printf("\nfull stacks\n");
		printf("%-8s %-60s %s\n", "samples", "stack", "events");
		for (i = 0; i < stack_count && i < opts.limit; ++i) {
			size_t j;

			printf("%-8zu %-60s ", stack_entries[i].sample_count,
			       stack_entries[i].stack);
			if (stack_entries[i].event_count == 0) {
				printf("-");
			} else {
				for (j = 0; j < stack_entries[i].event_count; ++j) {
					if (j != 0)
						printf(", ");
					printf("%s=%" PRIu64, stack_entries[i].events[j].name,
					       stack_entries[i].events[j].total);
				}
			}
			printf("\n");
		}
	}

	free(entries);
	free(stack_entries);
	return 0;
}

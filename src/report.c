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
	char symbol[PMI_MAX_SYMBOL_LEN];
	size_t sample_count;
	struct event_sum events[PMI_MAX_EVENTS];
	size_t event_count;
};

static void report_usage(FILE *stream)
{
	fprintf(stream,
		"usage: pmi report -i <file> [options]\n"
		"\n"
		"options:\n"
		"  -i, --input <file>   raw v2 sample file\n"
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

static bool is_hex_fallback(const char *symbol)
{
	return symbol && strncmp(symbol, "0x", 2) == 0;
}

static struct report_entry *find_or_add(struct report_entry **entries, size_t *count,
					size_t *cap, const char *symbol)
{
	size_t i;

	for (i = 0; i < *count; ++i) {
		if (strcmp((*entries)[i].symbol, symbol) == 0)
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
	pmi_copy_cstr_trunc((*entries)[*count].symbol,
			    sizeof((*entries)[*count].symbol), symbol);
	return &(*entries)[(*count)++];
}

static void add_event_sum(struct report_entry *entry, const char *name, uint64_t value)
{
	size_t i;

	for (i = 0; i < entry->event_count; ++i) {
		if (strcmp(entry->events[i].name, name) == 0) {
			entry->events[i].total += value;
			return;
		}
	}

	if (entry->event_count >= PMI_MAX_EVENTS)
		return;

	pmi_copy_cstr_trunc(entry->events[entry->event_count].name,
			    sizeof(entry->events[entry->event_count].name), name);
	entry->events[entry->event_count].total = value;
	entry->event_count++;
}

static void parse_event_blob(struct report_entry *entry, char *blob)
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
		add_event_sum(entry, token, value);
	}
}

static int compare_entry(const void *lhs, const void *rhs)
{
	const struct report_entry *a = lhs;
	const struct report_entry *b = rhs;

	if (a->sample_count < b->sample_count)
		return 1;
	if (a->sample_count > b->sample_count)
		return -1;
	return strcmp(a->symbol, b->symbol);
}

static uint64_t parse_first_stack_ip(char *stack)
{
	char *token;
	char *saveptr = NULL;

	if (!stack || strcmp(stack, "-") == 0)
		return 0;

	for (token = strtok_r(stack, ";", &saveptr); token;
	     token = strtok_r(NULL, ";", &saveptr)) {
		uint64_t ip;

		if (*token == '\0')
			continue;
		ip = strtoull(token, NULL, 0);
		if (ip != 0)
			return ip;
	}

	return 0;
}

static void resolve_leaf_symbol(struct pmi_symbolizer *symbolizer, pid_t pid,
				uint64_t ip, char *symbol, size_t symbol_cap)
{
	char module[PMI_MAX_MODULE_LEN];

	if (!symbolizer || !symbol || ip == 0)
		return;

	if (pmi_symbolizer_symbolize_ip(symbolizer, pid, ip, module, sizeof(module),
					symbol, symbol_cap) == 0)
		normalize_symbol(symbol);
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

int pmi_report_main(int argc, char **argv)
{
	struct pmi_report_options opts;
	struct pmi_symbolizer *symbolizer = NULL;
	struct report_entry *entries = NULL;
	size_t count = 0;
	size_t cap = 0;
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
		char *cursor = line;
		char *field;
		char *fields[10] = { 0 };
		size_t field_count = 0;
		struct report_entry *entry;
		char symbol_key[PMI_MAX_SYMBOL_LEN];
		char stack_copy[PMI_MAX_STACK_TEXT_LEN];
		uint64_t ip = 0;
		pid_t pid = 0;

		if (line[0] == '#')
			continue;

		while ((field = strsep(&cursor, "\t")) != NULL && field_count < 10) {
			field[strcspn(field, "\r\n")] = '\0';
			fields[field_count++] = field;
		}
		if (field_count != 10 || strcmp(fields[0], "S") != 0)
			continue;

		pid = (pid_t)strtol(fields[4], NULL, 10);
		ip = strtoull(fields[6], NULL, 0);
		pmi_copy_cstr_trunc(symbol_key, sizeof(symbol_key), fields[7]);
		normalize_symbol(symbol_key);

		if (is_hex_fallback(symbol_key) && strcmp(fields[9], "-") != 0) {
			uint64_t stack_ip;

			pmi_copy_cstr_trunc(stack_copy, sizeof(stack_copy), fields[9]);
			stack_ip = parse_first_stack_ip(stack_copy);
			if (stack_ip != 0)
				resolve_leaf_symbol(symbolizer, pid, stack_ip, symbol_key,
						    sizeof(symbol_key));
		}
		if (is_hex_fallback(symbol_key) && ip != 0)
			resolve_leaf_symbol(symbolizer, pid, ip, symbol_key,
					    sizeof(symbol_key));

		entry = find_or_add(&entries, &count, &cap, symbol_key);
		if (!entry) {
			fclose(fp);
			pmi_symbolizer_destroy(symbolizer);
			free(entries);
			return 1;
		}
		entry->sample_count++;

		pmi_copy_cstr_trunc(stack_copy, sizeof(stack_copy), fields[8]);
		parse_event_blob(entry, stack_copy);
	}
	fclose(fp);
	pmi_symbolizer_destroy(symbolizer);

	qsort(entries, count, sizeof(*entries), compare_entry);

	printf("%-8s %-40s %s\n", "samples", "symbol", "events");
	for (i = 0; i < count && i < opts.limit; ++i) {
		size_t j;

		printf("%-8zu %-40s ", entries[i].sample_count, entries[i].symbol);
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

	free(entries);
	return 0;
}

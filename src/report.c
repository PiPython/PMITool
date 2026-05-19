#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pmi/record.h"
#include "pmi/shared.h"
#include "pmi/strutil.h"

struct event_sum {
	char name[PMI_MAX_EVENT_NAME];
	uint64_t total;
};

struct report_entry {
	char module[PMI_MAX_MODULE_LEN];
	char symbol[PMI_MAX_SYMBOL_LEN];
	size_t sample_count;
	struct event_sum events[PMI_MAX_EVENTS];
	size_t event_count;
};

static struct report_entry *find_or_add(struct report_entry **entries, size_t *count,
					size_t *cap, const char *module,
					const char *symbol)
{
	size_t i;

	for (i = 0; i < *count; ++i) {
		if (strcmp((*entries)[i].module, module) == 0 &&
		    strcmp((*entries)[i].symbol, symbol) == 0)
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
	pmi_copy_cstr_trunc((*entries)[*count].module,
			    sizeof((*entries)[*count].module), module);
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

	for (token = strtok_r(blob, ",", &saveptr); token;
	     token = strtok_r(NULL, ",", &saveptr)) {
		char *at = strchr(token, '@');
		char *eq = strchr(token, '=');
		char *slash = strchr(token, '/');
		char name[PMI_MAX_EVENT_NAME];
		uint64_t value;

		if (!eq || !slash || slash < eq)
			continue;
		if (at && at < eq)
			*at = '\0';
		pmi_copy_cstr_trunc(name, sizeof(name), token);
		value = strtoull(eq + 1, NULL, 10);
		add_event_sum(entry, name, value);
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

int pmi_report_main(int argc, char **argv)
{
	struct pmi_report_options opts = {
		.limit = 20,
	};
	struct report_entry *entries = NULL;
	size_t count = 0, cap = 0, i;
	FILE *fp;
	char line[PMI_MAX_LINE_LEN];

	for (i = 1; i < (size_t)argc; ++i) {
		if (strcmp(argv[i], "--input") == 0 && i + 1 < (size_t)argc) {
			opts.input_path = argv[++i];
		} else if (strcmp(argv[i], "--limit") == 0 && i + 1 < (size_t)argc) {
			opts.limit = strtoul(argv[++i], NULL, 10);
		} else {
			fprintf(stderr, "unknown report option: %s\n", argv[i]);
			return 1;
		}
	}

	if (!opts.input_path) {
		fprintf(stderr, "--input is required\n");
		return 1;
	}

	fp = fopen(opts.input_path, "r");
	if (!fp) {
		fprintf(stderr, "open %s failed: %s\n", opts.input_path,
			strerror(errno));
		return 1;
	}

	while (fgets(line, sizeof(line), fp)) {
		char *cursor = line;
		char *field;
		size_t field_idx = 0;
		char *module = NULL, *symbol = NULL, *event_blob = NULL;
		struct report_entry *entry;

		if (line[0] == '#')
			continue;

		while ((field = strsep(&cursor, "\t")) != NULL) {
			if (field_idx == 11)
				module = field;
			else if (field_idx == 12)
				symbol = field;
			else if (field_idx == 13)
				event_blob = field;
			field_idx++;
		}

		if (!module || !symbol || !event_blob)
			continue;
		entry = find_or_add(&entries, &count, &cap, module, symbol);
		if (!entry) {
			fclose(fp);
			free(entries);
			return 1;
		}
		entry->sample_count++;
		parse_event_blob(entry, event_blob);
	}
	fclose(fp);

	qsort(entries, count, sizeof(*entries), compare_entry);

	printf("%-8s %-32s %-40s %s\n", "samples", "module", "symbol", "events");
	for (i = 0; i < count && i < opts.limit; ++i) {
		size_t j;

		printf("%-8zu %-32s %-40s ", entries[i].sample_count,
		       entries[i].module, entries[i].symbol);
		for (j = 0; j < entries[i].event_count; ++j) {
			if (j != 0)
				printf(", ");
			printf("%s=%" PRIu64, entries[i].events[j].name,
			       entries[i].events[j].total);
		}
		printf("\n");
	}

	free(entries);
	return 0;
}

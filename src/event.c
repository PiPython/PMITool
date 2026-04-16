#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pmi/event.h"

#define PMI_MAX_FORMAT_RANGES 8

struct pmi_format_field {
	int target;
	struct {
		unsigned int lo;
		unsigned int hi;
	} ranges[PMI_MAX_FORMAT_RANGES];
	size_t nranges;
};

static int copy_cstr(char *dst, size_t cap, const char *src)
{
	size_t len;

	if (!dst || !src || cap == 0)
		return -EINVAL;
	len = strlen(src);
	if (len >= cap)
		return -E2BIG;
	memcpy(dst, src, len + 1);
	return 0;
}

static int read_first_line(const char *path, char *buf, size_t cap)
{
	FILE *fp;

	fp = fopen(path, "r");
	if (!fp)
		return -errno;
	if (!fgets(buf, cap, fp)) {
		fclose(fp);
		return ferror(fp) ? -errno : -ENOENT;
	}
	fclose(fp);
	buf[strcspn(buf, "\r\n")] = '\0';
	return 0;
}

static bool is_blacklisted_pmu(const char *name)
{
	static const char *const prefixes[] = {
		"uncore", "software", "tracepoint", "breakpoint",
		"kprobe", "uprobe", "intel_pt", "cs_etm", "msr", "power",
	};
	size_t i;

	for (i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i) {
		if (strncmp(name, prefixes[i], strlen(prefixes[i])) == 0)
			return true;
	}
	return false;
}

static int read_pmu_type(const char *sysfs_root, const char *pmu, uint32_t *type)
{
	char path[PATH_MAX];
	char line[64];
	char *end;
	unsigned long value;
	int err;

	snprintf(path, sizeof(path), "%s/%s/type", sysfs_root, pmu);
	err = read_first_line(path, line, sizeof(line));
	if (err)
		return err;
	value = strtoul(line, &end, 10);
	if (*end != '\0')
		return -EINVAL;
	*type = (uint32_t)value;
	return 0;
}

static int parse_format_field(const char *spec, struct pmi_format_field *field)
{
	char copy[256];
	char *colon;
	char *saveptr = NULL;
	char *token;

	memset(field, 0, sizeof(*field));
	if (strlen(spec) >= sizeof(copy))
		return -E2BIG;
	strcpy(copy, spec);

	colon = strchr(copy, ':');
	if (!colon)
		return -EINVAL;
	*colon++ = '\0';

	if (strcmp(copy, "config") == 0)
		field->target = 0;
	else if (strcmp(copy, "config1") == 0)
		field->target = 1;
	else if (strcmp(copy, "config2") == 0)
		field->target = 2;
	else
		return -EINVAL;

	for (token = strtok_r(colon, ",", &saveptr); token;
	     token = strtok_r(NULL, ",", &saveptr)) {
		unsigned long lo, hi;
		char *dash;
		char *end = NULL;

		if (field->nranges >= PMI_MAX_FORMAT_RANGES)
			return -E2BIG;
		dash = strchr(token, '-');
		lo = strtoul(token, &end, 10);
		if (end == token)
			return -EINVAL;
		if (dash) {
			hi = strtoul(dash + 1, &end, 10);
		} else {
			hi = lo;
		}
		field->ranges[field->nranges].lo = (unsigned int)lo;
		field->ranges[field->nranges].hi = (unsigned int)hi;
		field->nranges++;
	}

	return 0;
}

static void apply_format_value(struct pmi_event_spec *spec,
			       const struct pmi_format_field *field, uint64_t value)
{
	uint64_t *target;
	size_t i;
	unsigned int src_bit = 0;

	if (field->target == 0)
		target = &spec->config;
	else if (field->target == 1)
		target = &spec->config1;
	else
		target = &spec->config2;

	for (i = 0; i < field->nranges; ++i) {
		unsigned int bit;

		for (bit = field->ranges[i].lo; bit <= field->ranges[i].hi; ++bit) {
			if (value & (1ULL << src_bit))
				*target |= (1ULL << bit);
			src_bit++;
		}
	}
}

static int apply_term(struct pmi_event_spec *spec, const char *sysfs_root,
		      const char *pmu, char *term)
{
	char *eq;
	char path[PATH_MAX];
	char fmt[256];
	struct pmi_format_field field;
	uint64_t value = 1;
	char *end = NULL;
	int err;

	eq = strchr(term, '=');
	if (eq) {
		*eq++ = '\0';
		value = strtoull(eq, &end, 0);
		if (*end != '\0')
			return -EINVAL;
	}

	snprintf(path, sizeof(path), "%s/%s/format/%s", sysfs_root, pmu, term);
	err = read_first_line(path, fmt, sizeof(fmt));
	if (err)
		return err;

	err = parse_format_field(fmt, &field);
	if (err)
		return err;

	apply_format_value(spec, &field, value);
	return 0;
}

static int resolve_event_expr(struct pmi_event_spec *spec, const char *sysfs_root,
			      const char *pmu, const char *name,
			      const char *expr)
{
	char copy[512];
	char *token;
	char *saveptr = NULL;
	int err;

	memset(spec, 0, sizeof(*spec));
	err = copy_cstr(spec->name, sizeof(spec->name), name);
	if (err)
		return err;
	err = copy_cstr(spec->pmu, sizeof(spec->pmu), pmu);
	if (err)
		return err;
	err = read_pmu_type(sysfs_root, pmu, &spec->type);
	if (err)
		return err;

	if (strlen(expr) >= sizeof(copy))
		return -E2BIG;
	strcpy(copy, expr);

	for (token = strtok_r(copy, ",", &saveptr); token;
	     token = strtok_r(NULL, ",", &saveptr)) {
		while (isspace((unsigned char)*token))
			token++;
		err = apply_term(spec, sysfs_root, pmu, token);
		if (err)
			return err;
	}
	return 0;
}

static int resolve_raw(struct pmi_event_spec *spec, const char *sysfs_root,
		       const char *input)
{
	const char *slash0;
	const char *slash1;
	char pmu[PMI_MAX_PMU_NAME];
	char expr[512];
	size_t pmu_len, expr_len;

	slash0 = strchr(input, '/');
	if (!slash0)
		return -EINVAL;
	slash1 = strrchr(input, '/');
	if (!slash1 || slash1 == slash0)
		return -EINVAL;
	pmu_len = (size_t)(slash0 - input);
	expr_len = (size_t)(slash1 - slash0 - 1);
	if (pmu_len == 0 || pmu_len >= sizeof(pmu) || expr_len >= sizeof(expr))
		return -E2BIG;

	memcpy(pmu, input, pmu_len);
	pmu[pmu_len] = '\0';
	memcpy(expr, slash0 + 1, expr_len);
	expr[expr_len] = '\0';

	if (is_blacklisted_pmu(pmu))
		return -EINVAL;

	return resolve_event_expr(spec, sysfs_root, pmu, input, expr);
}

static int resolve_alias(struct pmi_event_spec *spec, const char *sysfs_root,
			 const char *alias)
{
	DIR *dir;
	struct dirent *ent;
	char path[PATH_MAX];
	char expr[512];
	char pmu[PMI_MAX_PMU_NAME] = "";
	int err = -ENOENT;

	dir = opendir(sysfs_root);
	if (!dir)
		return -errno;

	while ((ent = readdir(dir)) != NULL) {
		if (ent->d_name[0] == '.' || is_blacklisted_pmu(ent->d_name))
			continue;
		snprintf(path, sizeof(path), "%s/%s/events/%s", sysfs_root,
			 ent->d_name, alias);
		if (read_first_line(path, expr, sizeof(expr)) == 0) {
			if (pmu[0] != '\0') {
				closedir(dir);
				return -EEXIST;
			}
			err = copy_cstr(pmu, sizeof(pmu), ent->d_name);
			if (err) {
				closedir(dir);
				return err;
			}
			err = 0;
		}
	}
	closedir(dir);
	if (err)
		return err;

	return resolve_event_expr(spec, sysfs_root, pmu, alias, expr);
}

int pmi_event_list_resolve(struct pmi_event_list *list, char *const *inputs,
			   size_t count, const char *sysfs_root)
{
	size_t i;
	int err;

	if (!list)
		return -EINVAL;
	memset(list, 0, sizeof(*list));

	err = copy_cstr(list->sysfs_root, sizeof(list->sysfs_root),
			sysfs_root ? sysfs_root : "/sys/bus/event_source/devices");
	if (err)
		return err;

	if (count > PMI_MAX_EVENTS - 1)
		return -E2BIG;

	for (i = 0; i < count; ++i) {
		if (strchr(inputs[i], '/'))
			err = resolve_raw(&list->items[list->count], list->sysfs_root,
					  inputs[i]);
		else
			err = resolve_alias(&list->items[list->count],
					    list->sysfs_root, inputs[i]);
		if (err)
			return err;
		list->count++;
	}
	return 0;
}

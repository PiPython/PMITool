#ifndef PMI_STRUTIL_H
#define PMI_STRUTIL_H

#include <errno.h>
#include <stddef.h>
#include <string.h>

static inline int pmi_copy_cstr(char *dst, size_t cap, const char *src)
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

static inline void pmi_copy_cstr_trunc(char *dst, size_t cap, const char *src)
{
	size_t len;

	if (!dst || cap == 0)
		return;
	if (!src) {
		dst[0] = '\0';
		return;
	}

	len = strlen(src);
	if (len >= cap)
		len = cap - 1;
	memcpy(dst, src, len);
	dst[len] = '\0';
}

#endif

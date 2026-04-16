#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "pmi/shared.h"
#include "pmi/symbolizer.h"

struct pmi_symbol {
	uint64_t value;
	uint64_t size;
	char *name;
};

struct pmi_module_cache {
	char path[PATH_MAX];
	struct pmi_symbol *symbols;
	size_t count;
};

struct pmi_symbolizer {
	struct pmi_module_cache *modules;
	size_t count;
	size_t cap;
};

static int parse_symbols(struct pmi_module_cache *cache, const void *image, size_t len)
{
	const Elf64_Ehdr *ehdr = image;
	const Elf64_Shdr *shdrs;
	const char *base = image;
	size_t i, total = 0;

	if (len < sizeof(*ehdr) || memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0)
		return -EINVAL;
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64)
		return -ENOTSUP;
	if (len < ehdr->e_shoff + (size_t)ehdr->e_shentsize * ehdr->e_shnum)
		return -EINVAL;

	shdrs = (const Elf64_Shdr *)(base + ehdr->e_shoff);
	for (i = 0; i < ehdr->e_shnum; ++i) {
		if (shdrs[i].sh_type == SHT_SYMTAB || shdrs[i].sh_type == SHT_DYNSYM)
			total += shdrs[i].sh_size / sizeof(Elf64_Sym);
	}
	cache->symbols = calloc(total ? total : 1, sizeof(*cache->symbols));
	if (!cache->symbols)
		return -ENOMEM;

	for (i = 0; i < ehdr->e_shnum; ++i) {
		const Elf64_Shdr *symtab = &shdrs[i];
		const Elf64_Shdr *strtab;
		const Elf64_Sym *syms;
		size_t j, nsyms;

		if (symtab->sh_type != SHT_SYMTAB && symtab->sh_type != SHT_DYNSYM)
			continue;
		if (symtab->sh_link >= ehdr->e_shnum)
			continue;
		if (len < symtab->sh_offset + symtab->sh_size)
			continue;

		strtab = &shdrs[symtab->sh_link];
		if (len < strtab->sh_offset + strtab->sh_size)
			continue;
		syms = (const Elf64_Sym *)(base + symtab->sh_offset);
		nsyms = symtab->sh_size / sizeof(Elf64_Sym);

		for (j = 0; j < nsyms; ++j) {
			const char *name;

			if (syms[j].st_name == 0 || syms[j].st_shndx == SHN_UNDEF)
				continue;
			if (ELF64_ST_TYPE(syms[j].st_info) != STT_FUNC &&
			    ELF64_ST_TYPE(syms[j].st_info) != STT_NOTYPE)
				continue;
			name = base + strtab->sh_offset + syms[j].st_name;
			cache->symbols[cache->count].value = syms[j].st_value;
			cache->symbols[cache->count].size = syms[j].st_size;
			cache->symbols[cache->count].name = strdup(name);
			if (!cache->symbols[cache->count].name)
				return -ENOMEM;
			cache->count++;
		}
	}

	return 0;
}

static struct pmi_module_cache *find_module(struct pmi_symbolizer *symbolizer,
					    const char *path)
{
	size_t i;

	for (i = 0; i < symbolizer->count; ++i) {
		if (strcmp(symbolizer->modules[i].path, path) == 0)
			return &symbolizer->modules[i];
	}
	return NULL;
}

static struct pmi_module_cache *load_module(struct pmi_symbolizer *symbolizer,
					    const char *path)
{
	struct pmi_module_cache *cache;
	struct stat st;
	void *image = MAP_FAILED;
	int fd = -1;
	int err;

	cache = find_module(symbolizer, path);
	if (cache)
		return cache;

	if (symbolizer->count == symbolizer->cap) {
		size_t new_cap = symbolizer->cap ? symbolizer->cap * 2 : 16;
		struct pmi_module_cache *tmp;

		tmp = realloc(symbolizer->modules, new_cap * sizeof(*tmp));
		if (!tmp)
			return NULL;
		symbolizer->modules = tmp;
		symbolizer->cap = new_cap;
	}
	cache = &symbolizer->modules[symbolizer->count];
	memset(cache, 0, sizeof(*cache));
	snprintf(cache->path, sizeof(cache->path), "%s", path);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return NULL;
	if (fstat(fd, &st) != 0)
		goto fail;
	image = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (image == MAP_FAILED)
		goto fail;
	err = parse_symbols(cache, image, st.st_size);
	if (err)
		goto fail;
	munmap(image, st.st_size);
	close(fd);
	symbolizer->count++;
	return cache;

fail:
	if (image != MAP_FAILED)
		munmap(image, st.st_size);
	if (fd >= 0)
		close(fd);
	for (size_t i = 0; i < cache->count; ++i)
		free(cache->symbols[i].name);
	free(cache->symbols);
	memset(cache, 0, sizeof(*cache));
	return NULL;
}

static int resolve_module(pid_t pid, uint64_t ip, char *module, size_t module_cap,
			  uint64_t *relative_ip)
{
	char maps_path[PATH_MAX];
	FILE *fp;
	char line[PATH_MAX * 2];

	snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
	fp = fopen(maps_path, "r");
	if (!fp)
		return -errno;

	while (fgets(line, sizeof(line), fp)) {
		unsigned long start, end, offset, inode;
		char perms[8];
		char dev[32];
		int consumed = 0;
		char *path;

		if (sscanf(line, "%lx-%lx %7s %lx %31s %lu %n", &start, &end, perms,
			   &offset, dev, &inode, &consumed) < 6)
			continue;
		if (ip < start || ip >= end)
			continue;

		path = line + consumed;
		while (*path == ' ')
			path++;
		path[strcspn(path, "\r\n")] = '\0';
		if (*path == '\0')
			snprintf(module, module_cap, "[anon]");
		else
			snprintf(module, module_cap, "%s", path);
		*relative_ip = ip - start + offset;
		fclose(fp);
		return 0;
	}

	fclose(fp);
	return -ENOENT;
}

static int lookup_symbol(struct pmi_module_cache *cache, uint64_t rel_ip,
			 char *symbol, size_t cap)
{
	const struct pmi_symbol *best = NULL;
	size_t i;

	for (i = 0; i < cache->count; ++i) {
		if (cache->symbols[i].value > rel_ip)
			continue;
		if (!best || cache->symbols[i].value > best->value)
			best = &cache->symbols[i];
	}
	if (!best)
		return -ENOENT;

	snprintf(symbol, cap, "%s+0x%" PRIx64, best->name, rel_ip - best->value);
	return 0;
}

int pmi_symbolizer_init(struct pmi_symbolizer **symbolizer)
{
	struct pmi_symbolizer *out;

	if (!symbolizer)
		return -EINVAL;
	out = calloc(1, sizeof(*out));
	if (!out)
		return -ENOMEM;
	*symbolizer = out;
	return 0;
}

void pmi_symbolizer_destroy(struct pmi_symbolizer *symbolizer)
{
	size_t i, j;

	if (!symbolizer)
		return;
	for (i = 0; i < symbolizer->count; ++i) {
		for (j = 0; j < symbolizer->modules[i].count; ++j)
			free(symbolizer->modules[i].symbols[j].name);
		free(symbolizer->modules[i].symbols);
	}
	free(symbolizer->modules);
	free(symbolizer);
}

int pmi_symbolizer_symbolize_ip(struct pmi_symbolizer *symbolizer, pid_t pid,
				uint64_t ip, char *module, size_t module_cap,
				char *symbol, size_t symbol_cap)
{
	uint64_t relative_ip = ip;
	struct pmi_module_cache *cache;
	int err;

	if (!symbolizer || !module || !symbol)
		return -EINVAL;

	err = resolve_module(pid, ip, module, module_cap, &relative_ip);
	if (err) {
		snprintf(module, module_cap, "[unknown]");
		snprintf(symbol, symbol_cap, "0x%" PRIx64, ip);
		return err;
	}

	if (module[0] == '[') {
		snprintf(symbol, symbol_cap, "0x%" PRIx64, ip);
		return 0;
	}

	cache = load_module(symbolizer, module);
	if (!cache || lookup_symbol(cache, relative_ip, symbol, symbol_cap) != 0)
		snprintf(symbol, symbol_cap, "0x%" PRIx64, ip);
	return 0;
}

int pmi_symbolizer_symbolize_stack(struct pmi_symbolizer *symbolizer, pid_t pid,
				   const uint64_t *ips, size_t depth,
				   char *folded, size_t folded_cap)
{
	size_t i;
	size_t len = 0;

	if (!symbolizer || !ips || !folded || folded_cap == 0)
		return -EINVAL;

	folded[0] = '\0';
	for (i = depth; i > 0; --i) {
		char module[PMI_MAX_MODULE_LEN];
		char symbol[PMI_MAX_SYMBOL_LEN];
		int written;

		if (ips[i - 1] == 0)
			continue;
		pmi_symbolizer_symbolize_ip(symbolizer, pid, ips[i - 1], module,
					    sizeof(module), symbol,
					    sizeof(symbol));
		written = snprintf(folded + len, folded_cap - len, "%s%s",
				   len ? ";" : "", symbol);
		if (written < 0 || (size_t)written >= folded_cap - len)
			break;
		len += (size_t)written;
	}
	return 0;
}

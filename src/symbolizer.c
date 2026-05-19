#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
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
#include "pmi/strutil.h"
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
	uint16_t elf_type;
};

struct pmi_demangle_cache {
	char *raw;
	char *pretty;
};

typedef char *(*pmi_cxa_demangle_fn)(const char *mangled_name, char *output_buffer,
				      size_t *length, int *status);

struct pmi_symbolizer {
	struct pmi_module_cache *modules;
	size_t count;
	size_t cap;

	void *demangle_handle;
	pmi_cxa_demangle_fn demangle_fn;
	bool demangle_attempted;
	struct pmi_demangle_cache *demangle_cache;
	size_t demangle_count;
	size_t demangle_cap;
};

static bool looks_like_mangled_cpp_name(const char *raw)
{
	return raw && raw[0] == '_' && raw[1] == 'Z';
}

static void strip_symbol_offset(const char *raw, char *base, size_t base_cap)
{
	char *plus;

	pmi_copy_cstr_trunc(base, base_cap, raw ? raw : "");
	plus = strstr(base, "+0x");
	if (plus)
		*plus = '\0';
}

static int parse_symbols(struct pmi_module_cache *cache, const void *image, size_t len)
{
	const Elf64_Ehdr *ehdr = image;
	const Elf64_Shdr *shdrs;
	const char *base = image;
	size_t i;
	size_t total = 0;

	if (len < sizeof(*ehdr) || memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0)
		return -EINVAL;
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64)
		return -ENOTSUP;
	if (len < ehdr->e_shoff + (size_t)ehdr->e_shentsize * ehdr->e_shnum)
		return -EINVAL;

	cache->elf_type = ehdr->e_type;
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
		size_t j;
		size_t nsyms;

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
			    ELF64_ST_TYPE(syms[j].st_info) != STT_GNU_IFUNC)
				continue;

			name = base + strtab->sh_offset + syms[j].st_name;
			if (name[0] == '\0' || name[0] == '$')
				continue;

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

static void free_module_cache(struct pmi_module_cache *cache)
{
	size_t i;

	if (!cache)
		return;
	for (i = 0; i < cache->count; ++i)
		free(cache->symbols[i].name);
	free(cache->symbols);
	memset(cache, 0, sizeof(*cache));
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
	if (pmi_copy_cstr(cache->path, sizeof(cache->path), path) != 0)
		return NULL;

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
	free_module_cache(cache);
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
		unsigned long start;
		unsigned long end;
		unsigned long offset;
		unsigned long inode;
		char perms[8];
		char dev[32];
		int consumed = 0;
		char *path;

		if (sscanf(line, "%lx-%lx %7s %lx %31s %lu %n",
			   &start, &end, perms, &offset, dev, &inode, &consumed) < 6)
			continue;
		if (ip < start || ip >= end)
			continue;

		path = line + consumed;
		while (*path == ' ')
			path++;
		path[strcspn(path, "\r\n")] = '\0';
		if (*path == '\0')
			pmi_copy_cstr_trunc(module, module_cap, "[anon]");
		else
			pmi_copy_cstr_trunc(module, module_cap, path);
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

static void maybe_init_demangler(struct pmi_symbolizer *symbolizer)
{
	static const char *const libs[] = {
		"libstdc++.so.6",
		"libc++abi.so.1",
		"libc++abi.so",
	};
	size_t i;

	if (!symbolizer || symbolizer->demangle_attempted)
		return;

	symbolizer->demangle_attempted = true;
	for (i = 0; i < sizeof(libs) / sizeof(libs[0]); ++i) {
		void *handle = dlopen(libs[i], RTLD_LAZY | RTLD_LOCAL);

		if (!handle)
			continue;
		symbolizer->demangle_fn =
			(pmi_cxa_demangle_fn)dlsym(handle, "__cxa_demangle");
		if (symbolizer->demangle_fn) {
			symbolizer->demangle_handle = handle;
			return;
		}
		dlclose(handle);
	}
}

static const char *find_pretty_name(struct pmi_symbolizer *symbolizer, const char *raw)
{
	size_t i;

	for (i = 0; i < symbolizer->demangle_count; ++i) {
		if (strcmp(symbolizer->demangle_cache[i].raw, raw) == 0)
			return symbolizer->demangle_cache[i].pretty;
	}

	return NULL;
}

static int cache_pretty_name(struct pmi_symbolizer *symbolizer, const char *raw,
			     const char *pretty)
{
	struct pmi_demangle_cache *entry;

	if (symbolizer->demangle_count == symbolizer->demangle_cap) {
		size_t new_cap = symbolizer->demangle_cap ? symbolizer->demangle_cap * 2 : 32;
		struct pmi_demangle_cache *tmp;

		tmp = realloc(symbolizer->demangle_cache,
			      new_cap * sizeof(*symbolizer->demangle_cache));
		if (!tmp)
			return -ENOMEM;
		symbolizer->demangle_cache = tmp;
		symbolizer->demangle_cap = new_cap;
	}

	entry = &symbolizer->demangle_cache[symbolizer->demangle_count++];
	entry->raw = strdup(raw);
	entry->pretty = strdup(pretty);
	if (!entry->raw || !entry->pretty) {
		free(entry->raw);
		free(entry->pretty);
		entry->raw = NULL;
		entry->pretty = NULL;
		symbolizer->demangle_count--;
		return -ENOMEM;
	}

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
	size_t i;

	if (!symbolizer)
		return;

	for (i = 0; i < symbolizer->count; ++i)
		free_module_cache(&symbolizer->modules[i]);
	for (i = 0; i < symbolizer->demangle_count; ++i) {
		free(symbolizer->demangle_cache[i].raw);
		free(symbolizer->demangle_cache[i].pretty);
	}
	free(symbolizer->modules);
	free(symbolizer->demangle_cache);
	if (symbolizer->demangle_handle)
		dlclose(symbolizer->demangle_handle);
	free(symbolizer);
}

int pmi_symbolizer_symbolize_ip(struct pmi_symbolizer *symbolizer, pid_t pid,
				uint64_t ip, char *module, size_t module_cap,
				char *symbol, size_t symbol_cap)
{
	uint64_t relative_ip = ip;
	struct pmi_module_cache *cache;
	uint64_t lookup_ip;
	int err;

	if (!symbolizer || !module || !symbol)
		return -EINVAL;

	err = resolve_module(pid, ip, module, module_cap, &relative_ip);
	if (err) {
		pmi_copy_cstr_trunc(module, module_cap, "[unknown]");
		snprintf(symbol, symbol_cap, "0x%" PRIx64, ip);
		return err;
	}

	if (module[0] == '[') {
		snprintf(symbol, symbol_cap, "0x%" PRIx64, ip);
		return 0;
	}

	cache = load_module(symbolizer, module);
	lookup_ip = (cache && cache->elf_type == ET_EXEC) ? ip : relative_ip;
	if (!cache || lookup_symbol(cache, lookup_ip, symbol, symbol_cap) != 0)
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

int pmi_symbolizer_pretty_name(struct pmi_symbolizer *symbolizer,
			       const char *raw, char *pretty,
			       size_t pretty_cap)
{
	char base[PMI_MAX_SYMBOL_LEN];
	const char *cached;

	if (!symbolizer || !raw || !pretty || pretty_cap == 0)
		return -EINVAL;

	strip_symbol_offset(raw, base, sizeof(base));
	if (!looks_like_mangled_cpp_name(base)) {
		pmi_copy_cstr_trunc(pretty, pretty_cap, base);
		return 0;
	}

	cached = find_pretty_name(symbolizer, base);
	if (!cached) {
		const char *resolved = base;

		maybe_init_demangler(symbolizer);
		if (symbolizer->demangle_fn) {
			int status = 0;
			char *demangled =
				symbolizer->demangle_fn(base, NULL, NULL, &status);

			if (status == 0 && demangled && demangled[0] != '\0')
				resolved = demangled;
			cache_pretty_name(symbolizer, base, resolved);
			free(demangled);
		} else {
			cache_pretty_name(symbolizer, base, base);
		}
		cached = find_pretty_name(symbolizer, base);
	}

	pmi_copy_cstr_trunc(pretty, pretty_cap, cached ? cached : base);
	return 0;
}

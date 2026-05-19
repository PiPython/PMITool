#ifndef PMI_SYMBOLIZER_H
#define PMI_SYMBOLIZER_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct pmi_symbolizer;

int pmi_symbolizer_init(struct pmi_symbolizer **symbolizer);
void pmi_symbolizer_destroy(struct pmi_symbolizer *symbolizer);
int pmi_symbolizer_symbolize_ip(struct pmi_symbolizer *symbolizer, pid_t pid,
				uint64_t ip, char *module, size_t module_cap,
				char *symbol, size_t symbol_cap);
int pmi_symbolizer_symbolize_stack(struct pmi_symbolizer *symbolizer, pid_t pid,
				   const uint64_t *ips, size_t depth,
				   char *folded, size_t folded_cap);

#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "pmi/symbolizer.h"

#define CHECK(cond)                                                             \
	do {                                                                    \
		if (!(cond)) {                                                   \
			fprintf(stderr, "CHECK failed at %s:%d: %s\n",           \
				__FILE__, __LINE__, #cond);                    \
			exit(1);                                                \
		}                                                               \
	} while (0)

__attribute__((noinline)) static void fixture_symbol_target(void)
{
	__asm__ __volatile__("" ::: "memory");
}

int main(void)
{
	struct pmi_symbolizer *symbolizer;
	char module[256];
	char symbol[256];
	int err;

	err = pmi_symbolizer_init(&symbolizer);
	CHECK(err == 0);
	fixture_symbol_target();
	err = pmi_symbolizer_symbolize_ip(symbolizer, getpid(),
					  (unsigned long long)(uintptr_t)
						  &fixture_symbol_target,
					  module, sizeof(module), symbol,
					  sizeof(symbol));
	CHECK(err == 0);
	CHECK(strstr(symbol, "fixture_symbol_target") != NULL);
	pmi_symbolizer_destroy(symbolizer);
	return 0;
}

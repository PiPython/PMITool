#ifndef PMI_JOINER_H
#define PMI_JOINER_H

#include <stddef.h>
#include <stdint.h>

#include "pmi/perf_session.h"
#include "pmi/shared.h"

struct pmi_joined_sample {
	struct pmi_perf_sample perf;
	struct pmi_bpf_event bpf;
	unsigned int lost_flags;
};

typedef int (*pmi_joined_sample_cb)(const struct pmi_joined_sample *sample,
				    void *ctx);

struct pmi_joiner;

int pmi_joiner_init(struct pmi_joiner **joiner, pmi_joined_sample_cb cb, void *ctx);
void pmi_joiner_destroy(struct pmi_joiner *joiner);
int pmi_joiner_push_perf(struct pmi_joiner *joiner,
			 const struct pmi_perf_sample *sample);
int pmi_joiner_push_bpf(struct pmi_joiner *joiner,
			const struct pmi_bpf_event *event);
int pmi_joiner_flush(struct pmi_joiner *joiner);

#endif

#ifndef PMI_PROCFS_H
#define PMI_PROCFS_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include "pmi/shared.h"

struct pmi_tid_list {
	pid_t tids[1024];
	size_t count;
};

int pmi_procfs_list_tids(pid_t pid, struct pmi_tid_list *list);
int pmi_procfs_read_comm(pid_t tid, char comm[PMI_COMM_LEN]);
bool pmi_procfs_tid_exists(pid_t tid);

#endif

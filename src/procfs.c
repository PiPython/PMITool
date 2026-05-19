#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "pmi/procfs.h"

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

int pmi_procfs_list_tids(pid_t pid, struct pmi_tid_list *list)
{
	char path[PATH_MAX];
	DIR *dir;
	struct dirent *ent;

	if (!list)
		return -EINVAL;

	list->count = 0;
	snprintf(path, sizeof(path), "/proc/%d/task", pid);
	dir = opendir(path);
	if (!dir)
		return -errno;

	while ((ent = readdir(dir)) != NULL) {
		char *end;
		long tid;

		if (ent->d_name[0] == '.')
			continue;
		tid = strtol(ent->d_name, &end, 10);
		if (*end != '\0')
			continue;
		if (list->count >= sizeof(list->tids) / sizeof(list->tids[0])) {
			closedir(dir);
			return -E2BIG;
		}
		list->tids[list->count++] = (pid_t)tid;
	}

	closedir(dir);
	return 0;
}

int pmi_procfs_read_comm(pid_t tid, char comm[PMI_COMM_LEN])
{
	char path[PATH_MAX];
	int err;

	snprintf(path, sizeof(path), "/proc/%d/comm", tid);
	err = read_first_line(path, comm, PMI_COMM_LEN);
	if (err)
		return err;
	return 0;
}

bool pmi_procfs_tid_exists(pid_t tid)
{
	char path[PATH_MAX];
	struct stat st;

	snprintf(path, sizeof(path), "/proc/%d", tid);
	return stat(path, &st) == 0;
}

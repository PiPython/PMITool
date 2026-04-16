#include <stdio.h>
#include <string.h>

#include "pmi/record.h"

static void usage(FILE *stream)
{
	fprintf(stream,
		"usage:\n"
		"  pmi record [options]\n"
		"  pmi report --input <file> [--limit N]\n");
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(stderr);
		return 1;
	}

	if (strcmp(argv[1], "record") == 0)
		return pmi_record_main(argc - 1, argv + 1);
	if (strcmp(argv[1], "report") == 0)
		return pmi_report_main(argc - 1, argv + 1);
	if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
		usage(stdout);
		return 0;
	}

	fprintf(stderr, "unknown subcommand: %s\n", argv[1]);
	usage(stderr);
	return 1;
}

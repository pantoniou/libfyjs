/*
 * fyjs-simple-validate.c - validator tester using the simple interface
 *
 * Copyright (c) 2020 Pantelis Antoniou <pantelis.antoniou@konsulko.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <errno.h>
#include <ctype.h>
#include <getopt.h>

#include <libfyjs.h>

#include "fy-valgrind.h"

static struct option lopts[] = {
	{"version",		no_argument,		0,	'v' },
	{"help",		no_argument,		0,	'h' },
	{0,			0,              	0,	 0  },
};

static void display_usage(FILE *fp, char *progname)
{
	fprintf(fp, "Usage: %s [options] <schema-file> <file-to-validate>\n", progname);
	fprintf(fp, "\nOptions:\n\n");

	fprintf(fp, "\t--version, -v            : Display %s version\n", PACKAGE);
	fprintf(fp, "\t--help, -h               : Display  help message\n");
}

#if 0
static int text_to_validation_type(const char *str)
{
	if (!str)
		return -1;

	if (!strcmp(str, "jsc-draft3") || !strcmp(str, "json-schema-draft3"))
		return FYJSVT_JSON_SCHEMA_DRAFT3;
	if (!strcmp(str, "jsc-draft4") || !strcmp(str, "json-schema-draft4"))
		return FYJSVT_JSON_SCHEMA_DRAFT4;
	if (!strcmp(str, "jsc-draft6") || !strcmp(str, "json-schema-draft6"))
		return FYJSVT_JSON_SCHEMA_DRAFT6;
	if (!strcmp(str, "jsc-draft-2019-09") || !strcmp(str, "json-schema-draft-2019-09"))
		return FYJSVT_JSON_SCHEMA_DRAFT2019_09;
	if (!strcmp(str, "jsc-latest") || !strcmp(str, "json-schema-latest"))
		return FYJSVT_JSON_SCHEMA_LATEST;
	if (!strcmp(str, "openapi-2.0"))
		return FYJSVT_OPENAPI_SCHEMA_2_0;
	if (!strcmp(str, "openapi-3.0"))
		return FYJSVT_OPENAPI_SCHEMA_3_0;
	if (!strcmp(str, "openapi-latest"))
		return FYJSVT_OPENAPI_SCHEMA_LATEST;

	return  -1;
}
#endif

int main(int argc, char *argv[])
{
	int ret = EXIT_FAILURE, opt, lidx, rc;
	char *progname, *log = NULL;
	struct fy_document *fyd_schema, *fyd_file;

	fy_valgrind_check(&argc, &argv);

	/* select the appropriate tool mode */
	progname = argv[0];
	progname = strrchr(argv[0], '/');
	if (!progname)
		progname = argv[0];
	else
		progname++;

	/* strip lt-* prefix */
	if (strlen(progname) > 3 && !memcmp(progname, "lt-", 3))
		progname += 3;

	while ((opt = getopt_long_only(argc, argv, "d:qr:t:hv", lopts, &lidx)) != -1) {
		switch (opt) {
		case 'h' :
		default:
			if (opt != 'h')
				fprintf(stderr, "Unknown option '%c' %d\n", opt, opt);
			display_usage(opt == 'h' ? stdout : stderr, progname);
			return opt == 'h' ? EXIT_SUCCESS : EXIT_FAILURE;
		case 'v':
			printf("%s\n", PACKAGE_VERSION);
			return EXIT_SUCCESS;
		}
	}

	if ((argc - optind) < 2) {
		fprintf(stderr, "Missing arguments\n");
		display_usage(stderr, progname);
		return EXIT_FAILURE;
	}
	fyd_schema = fy_document_build_from_file(NULL, argv[optind]);
	if (!fyd_schema) {
		fprintf(stderr, "unable to load schema \"%s\"\n", argv[optind]);
		goto err_out;
	}

	fyd_file = fy_document_build_from_file(NULL, argv[optind+1]);
	if (!fyd_file) {
		fprintf(stderr, "unable to load file \"%s\"\n", argv[optind+1]);
		goto err_out;
	}

	rc = fyjs_validate_simple_node(
			fy_document_root(fyd_file), FYJSVT_JSON_SCHEMA_LATEST ,
			fy_document_root(fyd_schema), &log);

	if (rc != VALID) {
		printf("Validation failed; error code %d (%s)\n", rc, fyjs_error_text(rc));
		if (log)
			printf("%s", log);
	} else {
		printf("OK\n");
		ret = EXIT_SUCCESS;
	}

err_out:
	if (log)
		free(log);
	fy_document_destroy(fyd_file);
	fy_document_destroy(fyd_schema);

	return ret;
}

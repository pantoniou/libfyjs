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

#define SCHEMA_TYPE_DEFAULT		FYJSVT_JSON_SCHEMA_AUTO_DRAFT4_TO_2019_09

static struct option lopts[] = {
	{"schema-type",		required_argument,	0,	't' },
	{"version",		no_argument,		0,	'v' },
	{"help",		no_argument,		0,	'h' },
	{0,			0,              	0,	 0  },
};

static void display_usage(FILE *fp, char *progname)
{
	fprintf(fp, "Usage: %s [options] <schema-file> <file-to-validate>\n", progname);
	fprintf(fp, "\nOptions:\n\n");

	fprintf(fp, "\t--schema-type, -t        : Type of schema (one of jsc-draft[347], \n"
		    "                             jsc-draft-2019-09, jsc-latest, openapi-2.0, openapi-3.0, \n"
		    "                             openapi-latest) default is %s\n",
						fyjs_validation_type_to_str(SCHEMA_TYPE_DEFAULT));
	fprintf(fp, "\t--version, -v            : Display %s version\n", PACKAGE);
	fprintf(fp, "\t--help, -h               : Display  help message\n");
}

int main(int argc, char *argv[])
{
	int ret = EXIT_FAILURE, opt, lidx, rc;
	char *progname, *log = NULL;
	struct fy_document *fyd_schema, *fyd_file;
	enum fyjs_validation_type schema_type;

	fy_valgrind_check(&argc, &argv);

	schema_type = SCHEMA_TYPE_DEFAULT;

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

	while ((opt = getopt_long_only(argc, argv, "t:hv", lopts, &lidx)) != -1) {
		switch (opt) {
		case 't':
			rc = fyjs_str_to_validation_type(optarg);
			if (rc < 0) {
				fprintf(stderr, "bad schema type: %s\n", optarg);
				return EXIT_FAILURE;
			}
			schema_type = rc;
			if (!fyjs_validation_type_supported(schema_type)) {
				fprintf(stderr, "unsupported schema type: %s\n", optarg);
				return EXIT_FAILURE;
			}
			break;
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
			fy_document_root(fyd_file), schema_type,
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

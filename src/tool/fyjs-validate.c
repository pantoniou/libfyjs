/*
 * fyjs-validate.c - validate file(s) against schema
 *
 * Copyright (c) 2019 Pantelis Antoniou <pantelis.antoniou@konsulko.com>
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

#include "fyjs-tool.h"

static const struct fy_parse_cfg doc_cfg = {
	.flags = ((FYPCF_DEFAULT_DOC & ~FYPCF_COLOR(FYPCF_COLOR_MASK)) | FYPCF_COLOR_AUTO),
};

int do_validate(struct fyjs_validate_ctx *vc, int argc, char *argv[])
{
	struct fy_document *fyd = NULL, *fyd_schema = NULL;
	const char *validate_file;
	int i, rc = -1;
	bool any_failed = true;

	if (!schema) {
		fprintf(stderr, "Schema missing\n");
		goto err_out;
	}

	fyd_schema = fyjs_load_schema_document(vc, schema);
	if (!fyd_schema) {
		fprintf(stderr, "failed to load schema file %s\n", schema);
		goto err_out;
	}

	any_failed = false;
	for (i = 0; i < argc; i++) {
		validate_file = argv[i];

		fyd = fy_document_build_from_file(&doc_cfg, validate_file);
		if (!fyd) {
			if (!quiet)
				printf("FAIL %s - failed to load file\n", validate_file);
			any_failed = true;
			continue;
		}

		if (!quiet && debug_level > 0)
			fprintf(stderr, "Loaded test file \"%s\" OK.\n", validate_file);

		rc = fyjs_validate(vc, fy_document_root(fyd), fy_document_root(fyd_schema));

		if (rc == 0) {
			if (!quiet)
				printf("OK %s\n", validate_file);
		} else {
			any_failed = true;	
			if (!quiet)
				printf("FAIL %s - failed to validate file\n", validate_file);
		}

		fy_document_destroy(fyd);
		fyd = NULL;
	}

	rc = 0;

err_out:
	fy_document_destroy(fyd);

	fyjs_unload_schema_document(fyd_schema);

	return any_failed ? -1 : 0;
}

/*
 * fyjs-testsuite.c - schema tool
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

#define INCBIN_STYLE INCBIN_STYLE_SNAKE
#define INCBIN_PREFIX g_
#include "incbin.h"

static const struct fy_parse_cfg doc_cfg = {
	.flags = ((FYPCF_DEFAULT_DOC & ~FYPCF_COLOR(FYPCF_COLOR_MASK)) | FYPCF_COLOR_AUTO),
};

static const char *scalar_value(struct fy_node *fyn, const char *path)
{
	const char *value;
	fyn = fy_node_mapping_lookup_value_by_simple_key(fyn, path, FY_NT);
	if (!fyn)
		return NULL;

	value = fy_node_get_scalar0(fyn);
	return value;
}

static int count_nr_of_tests(struct fy_document *fyd)
{
	struct fy_node *fyn, *fyn_iter, *fyn_iter2, *fyn_tests;
	void *iter, *iter2;
	int test_nr;

	fyn = fy_document_root(fyd);

	/* count number of tests */
	test_nr = 0;
	iter = NULL;
	while ((fyn_iter = fy_node_sequence_iterate(fyn, &iter)) != NULL) {
		fyn_tests = fy_node_mapping_lookup_value_by_simple_key(fyn_iter, "tests", FY_NT);
		iter2 = NULL;
		while ((fyn_iter2 = fy_node_sequence_iterate(fyn_tests, &iter2)) != NULL)
			test_nr++;
	}

	return test_nr;
}

#define TEST_DRY_RUN		FY_BIT(0)
#define TEST_TAP_MODE		FY_BIT(1)
#define TEST_TAP_PLAN_DISABLE	FY_BIT(2)

/* include the test-schema */
INCBIN(testschema, "test-schema.json");

static int
validate_testcase(struct fyjs_validate_ctx *vc,
		  const char *test_file,
		  struct fy_document *fyd,
		  int this_execute, int this_tap_start,
		  unsigned int flags)
{
	bool dry_run = !!(flags & TEST_DRY_RUN);
	bool tap_mode = !!(flags & TEST_TAP_MODE);
	struct fy_document *fyd_testschema;
	struct fy_node *fyn, *fyn_iter, *fyn_iter2, *fyn_schema, *fyn_tests;
	struct fy_node *fyn_data;
	const char *schema_str, *tests_str, *valid_str;
	const char *result_str;
	bool valid, result;
	void *iter, *iter2;
	int rc, test;
	const char *s;

	fyd_testschema = fy_document_build_from_string(&doc_cfg,
			(const char *)g_testschema_data, g_testschema_size);
	if (!fyd_testschema) {
		fprintf(stderr, "failed to build test schema document");
		return -1;
	}

	s = strrchr(test_file, '/');
	if (s)
		test_file = s + 1;

	/* first, validate that the test case is correct against the
	 * built-in schema */

	rc = fyjs_validate(vc, fy_document_root(fyd), fy_document_root(fyd_testschema));
	if (rc) {
		fprintf(stderr, "Failed to validate test\n");
		goto err_out_rc;
	}

	/* iterate over the schemas */
	iter = NULL;
	test = this_tap_start;
	fyn = fy_document_root(fyd);
	while ((fyn_iter = fy_node_sequence_iterate(fyn, &iter)) != NULL) {
		schema_str = scalar_value(fyn_iter, "description");
		fyn_schema = fy_node_mapping_lookup_value_by_simple_key(fyn_iter, "schema", FY_NT);
		fyn_tests = fy_node_mapping_lookup_value_by_simple_key(fyn_iter, "tests", FY_NT);

		if (!schema_str || !fyn_schema || !fyn_tests)
			continue;

		iter2 = NULL;
		while ((fyn_iter2 = fy_node_sequence_iterate(fyn_tests, &iter2)) != NULL) {
			tests_str = scalar_value(fyn_iter2, "description");
			fyn_data = fy_node_mapping_lookup_value_by_simple_key(fyn_iter2, "data", FY_NT);
			valid_str = scalar_value(fyn_iter2, "valid");

			if (!tests_str || !fyn_data || !valid_str)
				continue;

			if (this_execute > 0 && this_execute != test) {
				test++;
				continue;
			}

			valid = !strcmp(valid_str, "true");

			if (!dry_run) {
				rc = fyjs_validate(vc, fyn_data, fyn_schema);
				if (IS_ERROR(rc))
					fprintf(stderr, "Unexpected error return %d\n", rc);
				result = rc == VALID;
			} else {
				result = valid;
			}

			result_str = result == valid ?
					(!tap_mode ? "PASS" : "ok") :
					(!tap_mode ? "FAIL" : "not ok");
			if (!tap_mode)
				printf("%s: \"%s\", \"%s\"\n", result_str, schema_str, tests_str);
			else
				printf("%s %d - %s: %s, %s\n",
						result_str,
						test,
						test_file,
						schema_str, tests_str);
			test++;
		}
	}
	rc = 0;

err_out_rc:
	fy_document_destroy(fyd_testschema);
	return rc;
}

static int
testsuite_count(struct fyjs_validate_ctx *vc, int argc, char *argv[])
{
	struct fy_document *fyd = NULL;
	const char *validate_file;
	int i, j, count;

	count = 0;
	for (i = 0; i < argc; i++, count += j) {
		validate_file = argv[i];

		fyd = fy_document_build_from_file(&doc_cfg, validate_file);
		if (!fyd) {
			fprintf(stderr, "failed to load test file %s\n", validate_file);
			goto err_out;
		}

		j = count_nr_of_tests(fyd);
		if (j <= 0) {
			fprintf(stderr, "Failed to count number of tests of \"%s\"\n", validate_file);
			goto err_out;
		}

		fy_document_destroy(fyd);
		fyd = NULL;
	}

	return count;

err_out:
	fy_document_destroy(fyd);
	return -1;
}

int do_testsuite(struct fyjs_validate_ctx *vc, int argc, char *argv[])
{
	struct fy_document *fyd = NULL;
	const char *validate_file;
	int i, j, k, count, start, end, rc = -1;

	count = testsuite_count(vc, argc, argv);
	if (count < 0) {
		fprintf(stderr, "failed to count test cases\n");
		return -1;
	}

	if (count_tests) {
		printf("%d\n", count);
		return 0;
	}

	if (tap_mode && !tap_plan_disable) {
		if (execute == 0)
			printf("%d..%d\n", tap_start, tap_start + count - 1);
		else
			printf("%d..%d\n", execute, execute);
	}

	k = tap_start;
	for (i = 0; i < argc; i++, count += j, k += j) {
		validate_file = argv[i];

		fyd = fy_document_build_from_file(&doc_cfg, validate_file);
		if (!fyd) {
			fprintf(stderr, "failed to load test file %s\n", validate_file);
			goto err_out;
		}

		if (!quiet && debug_level > 0)
			fprintf(stderr, "Loaded test file \"%s\" OK.\n", validate_file);

		j = count_nr_of_tests(fyd);
		if (j <= 0) {
			fprintf(stderr, "Failed to count number of tests of \"%s\"\n", validate_file);
			goto err_out;
		}

		start = k;
		end = k + j;

		if (execute <= 0 || (execute >= start && execute < end)) {
			rc = validate_testcase(vc, validate_file, fyd,
					execute, k,
					(dry_run ? TEST_DRY_RUN : 0) |
					(tap_mode ? TEST_TAP_MODE : 0) |
					(tap_plan_disable ? TEST_TAP_PLAN_DISABLE : 0));
			if (rc) {
				fprintf(stderr, "Failed to validate testcase \"%s\" #%d\n", validate_file, execute);
				goto err_out;
			}
			rc = -1;
		}

		fy_document_destroy(fyd);
		fyd = NULL;
	}

	rc = 0;

err_out:
	fy_document_destroy(fyd);
	return rc;
}

/*
 * fyjs-tool.c - schema tool
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
#include "fy-valgrind.h"

#define DEBUG_LEVEL_DEFAULT		0
#define QUIET_DEFAULT			false
#define TAP_MODE_DEFAULT		false
#define COUNT_TESTS_DEFAULT		false
#define TAP_START_DEFAULT		1
#define TAP_PLAN_DISABLE_DEFAULT	false
#define EXECUTE_DEFAULT			0

int debug_level = DEBUG_LEVEL_DEFAULT;
bool quiet = QUIET_DEFAULT;
bool tap_mode = TAP_MODE_DEFAULT;
bool count_tests = COUNT_TESTS_DEFAULT;
int tap_start = TAP_START_DEFAULT;
bool tap_plan_disable = TAP_PLAN_DISABLE_DEFAULT;
int execute = EXECUTE_DEFAULT;
bool dry_run = false;
const char *schema = NULL;

#define OPT_TOOL			1000
#define OPT_TESTSUITE			1001
#define OPT_VALIDATE			1002

#define OPT_TAP_MODE			2001
#define OPT_COUNT_TESTS			2002
#define OPT_TAP_START			2003
#define OPT_TAP_PLAN_DISABLE		2004
#define OPT_EXECUTE			2005
#define OPT_DRY_RUN			2006

#define OPT_WRITE_CACHE			2100
#define OPT_READ_CACHE			2101
#define OPT_CACHE			2102	/* both read/write */

static struct option lopts[] = {
	{"debug-level",		required_argument,	0,	'd' },
	{"quiet",		no_argument,		0,	'q' },
	{"remote",		required_argument,	0,	'r' },
	{"schema",		required_argument,	0,	's' },

	{"testsuite",		no_argument,		0,	OPT_TESTSUITE },
	{"validate",		no_argument,		0,	OPT_VALIDATE },

	{"tap",			no_argument,		0,	OPT_TAP_MODE },
	{"count-tests",		no_argument,		0,	OPT_COUNT_TESTS },
	{"tap-start",		required_argument,	0,	OPT_TAP_START },
	{"tap-plan-disable",	no_argument,		0,	OPT_TAP_PLAN_DISABLE },
	{"execute",		required_argument,	0,	OPT_EXECUTE },
	{"dry-run",		no_argument,		0,	OPT_DRY_RUN },

	{"read-cache",		required_argument,	0,	OPT_READ_CACHE },
	{"write-cache",		required_argument,	0,	OPT_WRITE_CACHE },
	{"cache",		required_argument,	0,	OPT_CACHE },

	{"version",		no_argument,		0,	'v' },
	{"help",		no_argument,		0,	'h' },
	{0,			0,              	0,	 0  },
};

static void display_usage(FILE *fp, char *progname, int tool_mode)
{
	fprintf(fp, "Usage: %s [options] [args]\n", progname);
	fprintf(fp, "\nOptions:\n\n");
	fprintf(fp, "\t--debug-level, -d <lvl>  : Set debug level to <lvl>"
						"(default level %d)\n",
						DEBUG_LEVEL_DEFAULT);
	fprintf(fp, "\t--quiet, -q              : Quiet operation, do not "
						"output messages (default %s)\n",
						QUIET_DEFAULT ? "true" : "false");
	fprintf(fp, "\t--remote, -r             : Add a mapping of a remote to directory <url,dir>\n");
	fprintf(fp, "\t--schema, -s             : Use this validating schema\n");
	fprintf(fp, "\t--read-cache=<file>      : Read cache from file (- means stdin) at start\n");
	fprintf(fp, "\t--write-cache=<file>     : Write the cache to file (- means stdout) at the end\n");
	fprintf(fp, "\t--cache=<file>           : Use single read/Write cache\n");

	if (tool_mode == OPT_TOOL || tool_mode == OPT_TESTSUITE) {
		fprintf(fp, "\t--tap                    : Test output in tap mode "
							"(default %s)\n",
							TAP_MODE_DEFAULT ? "true" : "false");
		fprintf(fp, "\t--count-tests            : Count the total number of tests "
							"(default %s)\n",
							COUNT_TESTS_DEFAULT ? "true" : "false");
		fprintf(fp, "\t--tap-start              : Start the TAP test using given number "
							"(default %d)\n", TAP_START_DEFAULT);
		fprintf(fp, "\t--tap-plan-disable       : Disable the output of a TAP plan "
							"(default %s)\n",
							TAP_PLAN_DISABLE_DEFAULT ? "true" : "false");
		fprintf(fp, "\t--execute                : Execute the given test only, 0 for all"
							"(default %d)\n", EXECUTE_DEFAULT);
		fprintf(fp, "\t--dry-run                : Do a dry run; don't run test\n");
	}

	fprintf(fp, "\t--version, -v            : Display %s version\n", PACKAGE);
	fprintf(fp, "\t--help, -h               : Display  help message\n");
}

/* since we may reuse the same cache file, disable mmap optimization */
static const struct fy_parse_cfg cache_cfg = {
	.flags = ((FYPCF_DEFAULT_DOC & ~FYPCF_COLOR(FYPCF_COLOR_MASK)) |
			FYPCF_COLOR_AUTO) | FYPCF_DISABLE_MMAP_OPT,
};

int main(int argc, char *argv[])
{
	struct fyjs_validate_ctx *vc = NULL;
	int ret = EXIT_FAILURE, rc, opt, lidx;
	char *progname;
	char *s, *tdir;
	unsigned int j;
	struct fyjs_validate_cfg cfg;
	int rcfg_alloc = 0, rcfg_count = 0;
	struct fyjs_validate_remote_cfg rcfg_empty = { NULL, NULL };
	struct fyjs_validate_remote_cfg *rcfg = &rcfg_empty, *rcfg_tmp;
	const char *read_cache = NULL, *write_cache = NULL;
	struct fy_document *fyd_cache = NULL;
	int tool_mode = OPT_TOOL;

	fy_valgrind_check(&argc, &argv);

	memset(&cfg, 0, sizeof(cfg));
	cfg.type = FYJSVT_JSON_SCHEMA_LATEST;
	cfg.verbose = false;
	cfg.remotes = rcfg;

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

	if (!strcmp(progname, "fyjs-validate"))
		tool_mode = OPT_VALIDATE;
	else if (!strcmp(progname, "fyjs-testsuite"))
		tool_mode = OPT_TESTSUITE;
	else
		tool_mode = OPT_TOOL;

	execute = EXECUTE_DEFAULT;

	while ((opt = getopt_long_only(argc, argv, "d:qr:hv", lopts, &lidx)) != -1) {
		switch (opt) {
		case OPT_VALIDATE:
		case OPT_TESTSUITE:
			tool_mode = opt;
			break;

		case 'd':
			debug_level = atoi(optarg);
			break;
		case 'q':
			quiet = true;
			break;
		case 'r':
			s = strrchr(optarg, ',');
			if (!s) {
				fprintf(stderr, "Missing ',' separating url,dir\n");
				goto out;
			}
			*s = '\0';
			tdir = s + 1;
			j = strlen(tdir);
			while (j > 2 && tdir[j-1] == '/')
				tdir[--j] = '\0';
			if (j <= 0) {
				fprintf(stderr, "empty dir\n");
				goto out;
			}

			if (rcfg_count >= rcfg_alloc) {
				j = rcfg_alloc * 2;
				if (!j)
					j = 16;
				rcfg_tmp = alloca(sizeof(*rcfg_tmp) * (j + 1));
				memcpy(rcfg_tmp, rcfg, rcfg_alloc * sizeof(*rcfg));
				rcfg = rcfg_tmp;
				cfg.remotes = rcfg;

				rcfg_alloc = j;
			}
			rcfg[rcfg_count].url = optarg;
			rcfg[rcfg_count].dir = tdir;
			rcfg[rcfg_count + 1].url = NULL;
			rcfg[rcfg_count + 1].dir = NULL;
			rcfg_count++;
			break;
		case 's':
			schema = optarg;
			break;

		case OPT_TAP_MODE:
			tap_mode = true;
			break;
		case OPT_COUNT_TESTS:
			count_tests = true;
			quiet = true;
			debug_level = 0;
			break;
		case OPT_TAP_START:
			tap_start = atoi(optarg);
			break;
		case OPT_TAP_PLAN_DISABLE:
			tap_plan_disable = true;
			break;
		case OPT_EXECUTE:
			execute = atoi(optarg);
			break;
		case OPT_DRY_RUN:
			dry_run = true;
			break;

		case OPT_READ_CACHE:
			read_cache = optarg;
			break;

		case OPT_WRITE_CACHE:
			write_cache = optarg;
			break;

		case OPT_CACHE:
			read_cache = write_cache = optarg;
			break;

		case 'h' :
		default:
			if (opt != 'h')
				fprintf(stderr, "Unknown option '%c' %d\n", opt, opt);
			display_usage(opt == 'h' ? stdout : stderr, progname, tool_mode);
			return opt == 'h' ? EXIT_SUCCESS : EXIT_FAILURE;
		case 'v':
			printf("%s\n", PACKAGE_VERSION);
			return EXIT_SUCCESS;
		}
	}

	cfg.verbose = !quiet && debug_level > 0;

	vc = fyjs_context_create(&cfg);
	if (!vc) {
		fprintf(stderr, "Failed to create validation context\n");
		goto out;
	}

	if (read_cache) {
		fyd_cache = !strcmp(read_cache, "-") ?
				fy_document_build_from_fp(&cache_cfg, stdin) :
				fy_document_build_from_file(&cache_cfg, read_cache);

		if (fyd_cache) {
			rc = fyjs_context_set_cache(vc, fyd_cache);
			fyd_cache = NULL;
			if (rc) {
				fprintf(stderr, "fyjs_context_set_cache() failed\n");
				goto out;
			}
		}
	}

	switch (tool_mode) {
	case OPT_TESTSUITE:
		rc = do_testsuite(vc, argc - optind, argv + optind);
		if (rc) {
			fprintf(stderr, "testsuite failed\n");
			goto out;
		}
		break;
	case OPT_VALIDATE:
		rc = do_validate(vc, argc - optind, argv + optind);
		if (rc) {
			fprintf(stderr, "validation failed\n");
			goto out;
		}
		break;
	case OPT_TOOL:
	default:
		fprintf(stderr, "Invalid tool mode (one of --testsuite|--validate must be provided)\n");
		display_usage(stderr, progname, tool_mode);
		goto out;
	}

	/* get the cache (only if it's modified) */
	fyd_cache = write_cache && fyjs_context_is_cache_modified(vc) ?
			fyjs_context_get_cache(vc) : NULL;

	ret = EXIT_SUCCESS;

out:
	fyjs_context_destroy(vc);

	if (fyd_cache) {
		if (!strcmp(write_cache, "-"))
			rc = fy_emit_document_to_fp(fyd_cache, FYECF_DEFAULT, stdout);
		else
			rc = fy_emit_document_to_file(fyd_cache, FYECF_DEFAULT, write_cache);
		if (rc) {
			fprintf(stderr, "Failed to emit cache\n");
			ret = EXIT_FAILURE;
		}
		fy_document_destroy(fyd_cache);
	}

	return ret;
}

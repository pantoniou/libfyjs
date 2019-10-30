/*
 * fy-tool.h - tool internal header file
 *
 * Copyright (c) 2019 Pantelis Antoniou <pantelis.antoniou@konsulko.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef FYJS_TOOL_H
#define FYJS_TOOL_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <libfyjs.h>

struct fyjs_validate_ctx;

/* in fyjs-testsuite */
int do_testsuite(struct fyjs_validate_ctx *vc, int argc, char *argv[]);

/* in fyjs-validate */
int do_validate(struct fyjs_validate_ctx *vc, int argc, char *argv[]);

/* the globals filled in from the command line options */
extern int debug_level;
extern bool quiet;
extern bool tap_mode;
extern bool count_tests;
extern int tap_start;
extern bool tap_plan_disable;
extern int execute;
extern bool dry_run;
extern const char *schema;

#endif

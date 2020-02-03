/*
 * fy-jsonschema.h - libfyaml JSON schema internal header file
 *
 * Copyright (c) 2019 Pantelis Antoniou <pantelis.antoniou@konsulko.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef FY_JSONSCHEMA_H
#define FY_JSONSCHEMA_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/queue.h>

#include <libfyaml.h>
#include <libfyjs.h>

#include "fy-uri.h"

struct remote {
	TAILQ_ENTRY(remote) entry;
	const char *url;
	const char *dir;
	struct fy_uri urip;
	char *baseurl;
};

TAILQ_HEAD(remote_list, remote);

struct result_node {
	TAILQ_ENTRY(result_node) entry;
	bool nofree;
	char *msg;
	struct fyjs_result r;
};

TAILQ_HEAD(result_list, result_node);

typedef int (*validate_func)(struct fyjs_validate_ctx *vc, struct fy_node *fyn,
			    struct fy_node *fynt, struct fy_node *fynt_v);

struct validate_desc {
	const char *primary;
	const char **secondary;
	validate_func func;
};

struct fyjs_validate_ctx {
	struct fyjs_validate_cfg cfg;
	enum fyjs_validation_type type;
	bool verbose;
	struct fy_diag *diag;

	void *curl_handle;
	bool pcre_utf8;
	struct fy_document *fyd_cache;
	bool cache_modified;

	struct fy_node *fynt_root;
	struct fy_node *fynt_outmost_anchor;

	struct remote_list rl;

	struct result_list results;
	/* out of memory special area */
	struct {
		struct result_node rn[8];
		char buf[512];
		unsigned int rn_next;
		unsigned int rn_buf_next;
	} oom;
	struct result_node out_of_memory_rn;
	char out_of_memory_result_buffer[512];

	const struct validate_desc *vd_props;
	const struct validate_desc *vd_formats;
};

int fyjs_verror(struct fyjs_validate_ctx *vc, int error,
	        struct fy_node *error_node, struct fy_node *error_rule,
	        const char *fmt, va_list ap);

int fyjs_error(struct fyjs_validate_ctx *vc, int error,
	       struct fy_node *error_node, struct fy_node *error_rule,
	       const char *fmt, ...)
	__attribute__((format(printf, 5, 6)));

#endif

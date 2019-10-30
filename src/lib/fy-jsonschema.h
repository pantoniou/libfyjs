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

struct fyjs_validate_ctx {
	struct fyjs_validate_cfg cfg;
	enum fyjs_validation_type type;
	bool verbose;

	void *curl_handle;
	bool pcre_utf8;
	struct fy_document *fyd_cache;
	bool cache_modified;

	struct fy_node *fynt_root;
	struct fy_node *fynt_outmost_anchor;

	struct remote_list rl;

	int error;
	struct fy_node *error_node;
	struct fy_node *error_rule_node;
	struct fy_node *error_specific_rule_node;

	/* those may change due to spec evolution */
	const char *id_str;		/* $id */
	const char *schema_str;		/* $schema */
};

#endif

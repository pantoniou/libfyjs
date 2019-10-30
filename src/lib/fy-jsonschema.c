/*
 * fy-jsonschema.c - libfyaml JSON schema
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
#include <time.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <unistd.h>

#include <pcre.h>

#include <libfyaml.h>

#include <libfyjs.h>

#include "fy-b64.h"
#include "fy-idn.h"

#define INCBIN_STYLE INCBIN_STYLE_SNAKE
#define INCBIN_PREFIX g_
#include "incbin.h"

#include "numerics.h"

#include "fy-uri.h"
#include "fy-curl.h"

#include "fy-jsonschema.h"

static const struct fy_parse_cfg doc_cfg = {
	.flags = ((FYPCF_DEFAULT_DOC & ~FYPCF_COLOR(FYPCF_COLOR_MASK)) | FYPCF_COLOR_AUTO),
};

static const struct fy_parse_cfg json_doc_cfg = {
	.flags = ((FYPCF_DEFAULT_DOC & ~FYPCF_COLOR(FYPCF_COLOR_MASK)) | FYPCF_COLOR_AUTO) | FYPCF_JSON_FORCE,
};

static inline const struct fy_parse_cfg *schema_cfg(const char *schema)
{
	const char *s;

	return ((s = strrchr(schema, '.')) != NULL && !strcmp(s, ".json")) ?
		&json_doc_cfg : &doc_cfg;
}

static inline const char *ctime_chomp(const time_t *utc_time, char *buf)
{
	char *p, *e;

	p = ctime_r(utc_time, buf);
	if (!p || p != buf)
		return NULL;

	e = buf + strlen(buf);
	while (e + 1 > buf && isspace(e[-1]))
		*--e = '\0';

	return buf;
}

const char *fyjs_error_text(int error)
{
	switch (error) {
	case INVALID_TYPE:
	case INVALID_TYPE_WRONG:
		return "invalid type";
	case INVALID_CONST:
		return "invalid const";
	case INVALID_ENUM:
		return "invalid enum";
	case INVALID_MAXIMUM_OVER:
		return "value greater than maximum";
	case INVALID_EXCLUSIVE_MAXIMUM_OVER:
		return "value greater or equal than maximum";
	case INVALID_MINIMUM_UNDER:
		return "value less than minimum";
	case INVALID_EXCLUSIVE_MINIMUM_UNDER:
		return "value less or equal than minimum";
	case INVALID_MULTIPLEOF_NOT_MULTIPLE:
		return "value not a multiple";
	case INVALID_ANYOF_NO_MATCH:
		return "none of the anyof alternatives match";
	case INVALID_PATTERN_NO_MATCH:
		return "regural expression mismatch";
	case INVALID_MINLENGTH_UNDER:
		return "string length under minimum";
	case INVALID_MAXLENGTH_OVER:
		return "string length over maximum";
	case INVALID_BOOLEAN_FALSE:
		return "false schema always evaluates as invalid";
	case INVALID_CONTAINS_NONE:
		return "array contains none of the items";
	case INVALID_CONTAINS_TOO_MANY:
		return "array contains too many items";
	case INVALID_CONTAINS_NOT_ENOUGH:
		return "array does not contain enough items";
	case INVALID_UNIQUE_NOT_UNIQUE:
		return "array contains non-unique items";
	case INVALID_MIN_ITEMS_NOT_ENOUGH:
		return "array items are not enough";
	case INVALID_MAX_ITEMS_TOO_MANY:
		return "array items are too many";
	case INVALID_MIN_PROPERTIES_NOT_ENOUGH:
		return "object does not contain enough properties";
	case INVALID_MAX_PROPERTIES_TOO_MANY:
		return "object contains too many properties";
	case INVALID_DEPENDENCIES_DEP_MISSING:
		return "missing dependency";
	case INVALID_ALLOF_NO_MATCH:
		return "not all of the rules matched";
	case INVALID_REQUIRED_DEP_MISSING:
		return "missing required dependency missing";
	case INVALID_ONEOF_NO_MATCH:
		return "no match found for any of the rules";
	case INVALID_ONEOF_MANY_MATCHES:
		return "too many matches found for the rules";
	case INVALID_NOT_MATCH:
		return "matched when expected not to";
	case INVALID_THEN_NO_MATCH:
		return "'then' did not match";
	case INVALID_ELSE_NO_MATCH:
		return "'else' did not match";
	case INVALID_PROPNAMES_NO_MATCH:
		return "no match for the given property names";
	case INVALID_ADDPROPS_NO_MATCH:
		return "no match for additional properties";
	case INVALID_PATTERNPROPS_NO_MATCH:
		return "no match for the pattern property regular expression";
	case INVALID_CONTENTENC_BAD:
		return "invalid content encoding";
	case INVALID_CONTENTMT_BAD:
		return "invalid content media type";
	case INVALID_FORMAT_DATE:
		return "invalid date";
	case INVALID_FORMAT_TIME:
		return "invalid time";
	case INVALID_FORMAT_DATE_TIME:
		return "invalid date-time";
	case INVALID_FORMAT_REGEX:
		return "invalid regular expression";
	case INVALID_FORMAT_IPV4:
		return "invalid IPv4 address";
	case INVALID_FORMAT_IPV6:
		return "invalid IPv6 address";
	case INVALID_FORMAT_HOSTNAME:
		return "invalid host name";
	case INVALID_FORMAT_IDN_HOSTNAME:
		return "invalid international host name";
	case INVALID_FORMAT_EMAIL:
		return "invalid email";
	case INVALID_FORMAT_IDN_EMAIL:
		return "invalid international email";
	case INVALID_FORMAT_URI:
		return "invalid URI";
	case INVALID_FORMAT_JSON_POINTER:
		return "invalid JSON pointer";
	case INVALID_FORMAT_RELJSON_POINTER:
		return "invalid relative JSON pointer";
	default:
		break;
	}
	return NULL;
}

struct remote *remote_create(const char *url, const char *dir)
{
	struct remote *r = NULL;
	char *baseurl = NULL;
	struct fy_uri *urip;
	int rc;

	if (!url || !dir)
		return NULL;

	r = malloc(sizeof(*r));
	if (!r)
		return NULL;

	memset(r, 0, sizeof(*r));

	rc = fy_parse_uri_ext(url, &r->urip, 0);
	if (rc)
		return NULL;

	urip = &r->urip;

	rc = asprintf(&baseurl, "%.*s%s" "%.*s" "%s%.*s",
		(int)urip->scheme_len, urip->scheme, urip->scheme_len ? "://" : "",
		(int)urip->authority_len, urip->authority,
		urip->path_len > 0 && urip->path[0] != '/' ? "/" : "",
		(int)urip->path_len, urip->path);
	if (rc == -1)
		goto err_out;

	r->url = url;
	r->dir = dir;
	r->baseurl = baseurl;

	return r;

err_out:
	if (baseurl)
		free(baseurl);
	if (r)
		free(r);
	return NULL;
}

void remote_destroy(struct remote *r)
{
	if (!r)
		return;
	if (r->baseurl)
		free(r->baseurl);
	free(r);
}

static int validate_one(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt);

#define get_path(_fyn) \
	({ \
	 	char *_path, *_patha = ""; \
		\
	 	_path = fy_node_get_path((_fyn)); \
	 	if (_path) { \
	 		_patha = alloca(strlen(_path) + 1); \
	 		strcpy(_patha, _path); \
	 		free(_path); \
	 	} \
	 	_patha; \
	})

void fyjs_context_cleanup(struct fyjs_validate_ctx *vc)
{
	struct remote *r;

	if (!vc)
		return;

	fy_document_destroy(vc->fyd_cache);
	vc->fyd_cache = NULL;

	if (vc->curl_handle)
		fy_curl_cleanup(vc->curl_handle);

	while (!TAILQ_EMPTY(&vc->rl)) {
		r = TAILQ_FIRST(&vc->rl);
		TAILQ_REMOVE(&vc->rl, r, entry);
		remote_destroy(r);
	}
}

int fyjs_context_reset_cache(struct fyjs_validate_ctx *vc)
{
	struct fy_node *fyn;

	fy_document_destroy(vc->fyd_cache);
	vc->fyd_cache = fy_document_create(&doc_cfg);
	if (!vc->fyd_cache) {
		fprintf(stderr, "%s: fy_document_create() failed\n", __func__);
		goto err_out;
	}

	fyn = fy_node_create_sequence(vc->fyd_cache);
	if (!fyn) {
		fprintf(stderr, "%s: fy_node_create_sequence() failed\n", __func__);
		goto err_out;
	}
	fy_document_set_root(vc->fyd_cache, fyn);

	vc->cache_modified = false;

	return 0;

err_out:
	fy_document_destroy(vc->fyd_cache);
	vc->fyd_cache = NULL;
	return -1;
}

int fyjs_context_setup(struct fyjs_validate_ctx *vc,
		       const struct fyjs_validate_cfg *cfg)
{
	int rc, config, i;
	struct remote *r;

	if (!vc || !cfg)
		return -1;

	memset(vc, 0, sizeof(*vc));

	vc->cfg = *cfg;
	TAILQ_INIT(&vc->rl);

	vc->type = cfg->type;
	vc->verbose = cfg->verbose;
	for (i = 0; cfg->remotes && cfg->remotes[i].url; i++) {
		r = remote_create(cfg->remotes[i].url, cfg->remotes[i].dir);
		if (!r) {
			fprintf(stderr, "unable to create remote #%d\n", i);
			goto err_out;
		}
		TAILQ_INSERT_TAIL(&vc->rl, r, entry);

		if (vc->verbose)
			fprintf(stderr, "remote mapping %s -> %s\n",
					r->url, r->dir);
	}

	rc = fyjs_context_reset_cache(vc);
	if (rc) {
		fprintf(stderr, "%s: unable to reset cache\n", __func__);
		goto err_out;
	}

	vc->curl_handle = fy_curl_init();
	if (!vc->curl_handle)
		fprintf(stderr, "warning: CURL not available; no external schemas available\n");

	if (vc->curl_handle)
		fy_curl_set_verbose(vc->curl_handle, vc->verbose);

	if (vc->verbose)
		fprintf(stderr, "curl: %s\n", vc->curl_handle ? "enabled" : "disabled");

	rc = pcre_config(PCRE_CONFIG_UTF8, &config);
	vc->pcre_utf8 = !rc && config;

	if (vc->verbose)
		fprintf(stderr, "pcre: UTF8 is %ssupported\n", vc->pcre_utf8 ? "" : "not ");

	vc->id_str = "$id";
	vc->schema_str = "$schema";

	return 0;
err_out:
	fyjs_context_cleanup(vc);
	return -1;
}

struct fyjs_validate_ctx_state {
	struct fy_node *fynt_root;
	int error;
	struct fy_node *error_node;
	struct fy_node *error_rule_node;
	struct fy_node *error_specific_rule_node;
};

void fyjs_context_save(struct fyjs_validate_ctx *vc, struct fyjs_validate_ctx_state *vcs)
{
	vcs->fynt_root = vc->fynt_root;
	vcs->error = vc->error;
	vcs->error_node = vc->error_node;
	vcs->error_rule_node = vc->error_rule_node;
	vcs->error_specific_rule_node = vc->error_specific_rule_node;
}

void fyjs_context_restore(struct fyjs_validate_ctx *vc, const struct fyjs_validate_ctx_state *vcs)
{
	vc->fynt_root = vcs->fynt_root;
	vc->error = vcs->error;
	vc->error_node = vcs->error_node;
	vc->error_rule_node = vcs->error_rule_node;
	vc->error_specific_rule_node = vcs->error_specific_rule_node;
}

void fyjs_context_reset(struct fyjs_validate_ctx *vc)
{
	vc->fynt_root = NULL;
	vc->error = 0;
	vc->error_node = NULL;
	vc->error_rule_node = NULL;
	vc->error_specific_rule_node = NULL;
}

static const char *get_value(struct fy_node *fyn, const char *path)
{
	const char *value;

	fyn = fy_node_mapping_lookup_value_by_simple_key(fyn, path, FY_NT);
	if (!fyn)
		return NULL;

	value = fy_node_get_scalar0(fyn);
	return value;
}

enum fyjs_type {
	fyjs_invalid = -1,
	fyjs_null = 0,
	fyjs_boolean,
	fyjs_object,
	fyjs_array,
	fyjs_number,
	fyjs_string,
	fyjs_integer,
	fyjs_first = fyjs_null,
	fyjs_last = fyjs_integer,
};

static enum fyjs_type validate_type_node(struct fy_node *fyn);

static int fy_node_scalar_compare_json(struct fy_node *fyn1, struct fy_node *fyn2, void *arg)
{
	enum fyjs_type type1, type2;
	bool num1, num2;
	const char *str1, *str2;
	fyjs_numeric n1, n2;
	int res;

	type1 = validate_type_node(fyn1);
	num1 = type1 == fyjs_integer || type1 == fyjs_number;
	type2 = validate_type_node(fyn2);
	num2 = type2 == fyjs_integer || type2 == fyjs_number;

	/* if types are different sort according to types only (and one is not numeric) */
	if (type1 != type2 && (!num1 || !num2))
		return (int)type1 < (int)type2 ? -1 : 1;

	str1 = fy_node_get_scalar0(fyn1);
	str2 = fy_node_get_scalar0(fyn2);

	if (!str1 || !str2) {
		fprintf(stderr, "%s: out of memory\n", __func__);
		return -1;
	}

	/* non numeric types, compare */
	if (type1 == type2 && !num1)
		return strcmp(str1, str2);

	/* numerics */
	assert(num1 && num2);

	fyjs_numeric_init(n1, type1 == fyjs_integer);
	fyjs_numeric_init(n2, type2 == fyjs_integer);
	fyjs_numeric_set_str(n1, str1);
	fyjs_numeric_set_str(n2, str2);

	res = fyjs_numeric_cmp(n1, n2);

	fyjs_numeric_clear(n1);
	fyjs_numeric_clear(n2);

	return res;
}

bool fy_node_compare_json(struct fy_node *fyn1, struct fy_node *fyn2)
{
	return fy_node_compare_user(fyn1, fyn2, NULL, NULL, fy_node_scalar_compare_json, NULL);
}

typedef int (*validate_func)(struct fyjs_validate_ctx *vc, struct fy_node *fyn,
			    struct fy_node *fynt, struct fy_node *fynt_v);

struct validate_desc {
	const char *primary;
	const char **secondary;
	validate_func func;
};

static enum fyjs_type validate_type_text(const char *str)
{
	if (!strcmp(str, "null"))
		return fyjs_null;
	if (!strcmp(str, "boolean"))
		return fyjs_boolean;
	if (!strcmp(str, "object"))
		return fyjs_object;
	if (!strcmp(str, "array"))
		return fyjs_array;
	if (!strcmp(str, "number"))
		return fyjs_number;
	if (!strcmp(str, "string"))
		return fyjs_string;
	if (!strcmp(str, "integer"))
		return fyjs_integer;
	return fyjs_invalid;
}

const char *fyjs_type_str(enum fyjs_type type)
{
	switch (type) {
	case fyjs_null:
		return "null";
	case fyjs_boolean:
		return "boolean";
	case fyjs_object:
		return "object";
	case fyjs_array:
		return "array";
	case fyjs_number:
		return "number";
	case fyjs_string:
		return "string";
	case fyjs_integer:
		return "integer";
	default:
		break;
	}
	return "invalid";
}

static enum fyjs_type str_integer_or_number(const char *str, size_t len)
{
	const char *s, *e;
	int digits;

	s = str;
	e = s + len;

	/* skip sign */
	if (s < e && (*s == '+' || *s == '-'))
		s++;

	/* skip numeric part */
	digits = 0;
	while (s < e && (*s >= '0' && *s <= '9')) {
		s++;
		digits++;
	}

	/* no more, and digits encountered, it's an integer */
	if (s >= e && digits)
		return fyjs_integer;

	/* decimal part? */
	if (s < e && *s == '.') {
		s++;
		while (s < e && (*s >= '0' && *s <= '9'))
			s++;
		/* out of decimal digits? */
		if (s >= e)
			return fyjs_number;
	}
	/* scientific notation */
	if (s < e && (*s == 'e' || *s == 'E')) {
		if (!digits)
			return fyjs_string;
		s++;
		/* skip scientific notation's sign (if it exists) */
		if (s < e && (*s == '+' || *s == '-'))
			s++;

		/* scientific notation without anything following */
		if (s >= e || *s < '0' || *s > '9')
			return fyjs_string;

		/* skip digits */
		while (s < e && (*s >= '0' && *s <= '9'))
			s++;
	}
	/* number if nothing else follows */
	// return s >= e ? fyjs_number : fyjs_invalid;
	return s >= e ? fyjs_number : fyjs_string;
}

static enum fyjs_type validate_type_node(struct fy_node *fyn)
{
	const char *value;

	/* json can't handle NULL values the same way YAML can */
	if (!fyn)
		return fyjs_invalid;

	/* json doesn't have aliases: TODO maybe follow? */
	if (fy_node_is_alias(fyn))
		return fyjs_invalid;

	/* mappings are objects */
	if (fy_node_is_mapping(fyn))
		return fyjs_object;

	/* sequences are arrays */
	if (fy_node_is_sequence(fyn))
		return fyjs_array;

	/* null, true, false */
	if (fy_node_get_style(fyn) == FYNS_PLAIN) {
		value = fy_node_get_scalar0(fyn);
		/* we return invalid on out of memory */
		if (!value)
			return fyjs_invalid;

		if (!strcmp(value, "null"))
			return fyjs_null;
		if (!strcmp(value, "true") || !strcmp(value, "false"))
			return fyjs_boolean;

		return str_integer_or_number(value, strlen(value));
	}

	/* everything else is a string */
	return fyjs_string;
}

static int validate_type(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			 struct fy_node *fynt_v)
{
	struct fy_node *fyn_type, *fyn_iter;
	enum fyjs_type type, vtype;
	unsigned int type_mask = 0, vtype_mask = 0;
	const char *type_str, *value_str;
	fyjs_numeric value;
	void *iter;
	bool is_integer;

	/* get type node */
	fyn_type = fynt_v;

	if (!fy_node_is_scalar(fyn_type) && !fy_node_is_sequence(fyn_type))
		return ERROR_TYPE_NOT_SCALAR_OR_SEQ;

	/* get the type of this node */
	vtype = validate_type_node(fyn);
	if (vtype == fyjs_invalid)
		return INVALID_TYPE;
	vtype_mask = 1U << (int)vtype;

	if (fy_node_is_scalar(fyn_type)) {
		type_str = fy_node_get_scalar0(fyn_type);
		if (!type_str)
			return ERROR_INTERNAL_OUT_OF_MEMORY;

		type = validate_type_text(type_str);
		if (type == fyjs_invalid)
			return ERROR_TYPE_SPEC_INVALID;

		type_mask = 1U << (int)type;
	} else {
		iter = NULL;
		while ((fyn_iter = fy_node_sequence_iterate(fyn_type, &iter)) != NULL) {
			type_str = fy_node_get_scalar0(fyn_iter);
			if (!type_str)
				return ERROR_INTERNAL_OUT_OF_MEMORY;
			type = validate_type_text(type_str);
			if (type == fyjs_invalid)
				return ERROR_TYPE_SPEC_INVALID;
			type_mask |= 1U << (int)type;
		}
	}

	/* OK if directly matching */
	if (vtype_mask & type_mask)
		return VALID;

	/* special case is integer, promote to number */
	if (vtype_mask & (1U << (int)fyjs_integer)) {
		vtype_mask &= ~(1U << (int)fyjs_integer);
		vtype_mask |=  (1U << (int)fyjs_number);
	}

	/* test again after promotion */
	if (vtype_mask & type_mask)
		return VALID;

	/* another special case, number with fractional part is zero */
	if ((vtype_mask & (1U << (int)fyjs_number)) &&
	    (type_mask & (1U << (int)fyjs_integer))) {

		value_str = fy_node_get_scalar0(fyn);
		if (!value_str)
			return ERROR_INTERNAL_OUT_OF_MEMORY;

		fyjs_numeric_init(value, false);
		fyjs_numeric_set_str(value, value_str);
		is_integer = fyjs_numeric_is_integer(value);
		fyjs_numeric_clear(value);

		if (is_integer)
			return VALID;
	}

	return INVALID_TYPE_WRONG;
}

static int validate_const(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			  struct fy_node *fynt_v)
{
	struct fy_node *fynt_const;

	/* get const node */
	fynt_const = fynt_v;

	return fy_node_compare_json(fynt_const, fyn) ? VALID : INVALID_CONST;
}

static int validate_enum(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			 struct fy_node *fynt_v)
{
	struct fy_node *fynt_enum, *fynt_iter;
	void *iter;

	/* get const node */
	fynt_enum = fynt_v;

	if (!fy_node_is_sequence(fynt_enum))
		return ERROR_ENUM_NOT_SEQ;

	iter = NULL;
	while ((fynt_iter = fy_node_sequence_iterate(fynt_enum, &iter)) != NULL) {
		if (fy_node_compare_json(fynt_iter, fyn))
			return VALID;
	}

	return INVALID_ENUM;
}

static int validate_numeric(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			    struct fy_node *fynt_v, const char *keyword)
{
	struct fy_node *fynt_keyword;
	enum fyjs_type type, vtype;
	fyjs_numeric constraint, value;
	bool res;
	const char *constraint_str;
	const char *value_str;
	int ret = ERROR;

	/* get const node */
	fynt_keyword = fynt_v;

	vtype = validate_type_node(fyn);
	if (vtype != fyjs_number && vtype != fyjs_integer)
		return VALID;

	type = validate_type_node(fynt_keyword);
	if (type != fyjs_number && type != fyjs_integer)
		return ERROR_NUMERIC_CONSTRAINT_NAN;

	constraint_str = fy_node_get_scalar0(fynt_keyword);
	value_str = fy_node_get_scalar0(fyn);

	if (!constraint_str || !value_str)
		return ERROR_INTERNAL_OUT_OF_MEMORY;

	fyjs_numeric_init(constraint, type == fyjs_integer);
	fyjs_numeric_set_str(constraint, constraint_str);
	fyjs_numeric_init(value, vtype == fyjs_integer);
	fyjs_numeric_set_str(value, value_str);

	res = false;

	if (!strcmp(keyword, "multipleOf")) {
		/* protect against division by zero */
		if (fyjs_numeric_cmp_0(constraint) <= 0) {
			ret = ERROR_MULTIPLEOF_LEQ_ZERO;
			goto err_out;
		}
		res = fyjs_numeric_rem_is_0(value, constraint);
		if (!res) {
			ret = INVALID_MULTIPLEOF_NOT_MULTIPLE;
			goto err_out;
		}
	} else if (!strcmp(keyword, "maximum")) {
		res = fyjs_numeric_cmp(value, constraint) <= 0;
		if (!res) {
			ret = INVALID_MAXIMUM_OVER;
			goto err_out;
		}
	} else if (!strcmp(keyword, "exclusiveMaximum")) {
		res = fyjs_numeric_cmp(value, constraint) < 0;
		if (!res) {
			ret = INVALID_EXCLUSIVE_MAXIMUM_OVER;
			goto err_out;
		}
	} else if (!strcmp(keyword, "minimum")) {
		res = fyjs_numeric_cmp(value, constraint) >= 0;
		if (!res) {
			ret = INVALID_MINIMUM_UNDER;
			goto err_out;
		}
	} else if (!strcmp(keyword, "exclusiveMinimum")) {
		res = fyjs_numeric_cmp(value, constraint) > 0;
		if (!res) {
			ret = INVALID_EXCLUSIVE_MINIMUM_UNDER;
			goto err_out;
		}
	} else {
		ret = ERROR_NUMERIC_ILLEGAL_KEYWORD;
		goto err_out;
	}

	ret = VALID;

err_out:

	fyjs_numeric_clear(constraint);
	fyjs_numeric_clear(value);

	return ret;
}

static int validate_multipleof(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			       struct fy_node *fynt_v)
{
	return validate_numeric(vc, fyn, fynt, fynt_v, "multipleOf");
}

static int validate_maximum(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			    struct fy_node *fynt_v)
{
	return validate_numeric(vc, fyn, fynt, fynt_v, "maximum");
}

static int validate_exclusive_maximum(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				      struct fy_node *fynt_v)
{
	return validate_numeric(vc, fyn, fynt, fynt_v, "exclusiveMaximum");
}

static int validate_minimum(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			    struct fy_node *fynt_v)
{
	return validate_numeric(vc, fyn, fynt, fynt_v, "minimum");
}

static int validate_exclusive_minimum(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				      struct fy_node *fynt_v)
{
	return validate_numeric(vc, fyn, fynt, fynt_v, "exclusiveMinimum");
}

static int validate_anyof(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			  struct fy_node *fynt_v)
{
	struct fy_node *fynt_anyof, *fynt_iter;
	int ret;
	void *iter;

	fynt_anyof = fynt_v;

	if (!fy_node_is_sequence(fynt_anyof) ||
	    fy_node_sequence_is_empty(fynt_anyof))
		return ERROR_ONEOF_BAD_SEQ;

	iter = NULL;
	while ((fynt_iter = fy_node_sequence_iterate(fynt_anyof, &iter)) != NULL) {
		ret = validate_one(vc, fyn, fynt_iter);
		/* return immediately if valid, or an error */
		if (ret == VALID || IS_ERROR(ret))
			return ret;
	}
	return INVALID_ANYOF_NO_MATCH;
}

static int validate_allof(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			  struct fy_node *fynt_v)
{
	struct fy_node *fynt_allof, *fynt_iter;
	int ret;
	void *iter;

	fynt_allof = fynt_v;

	if (!fy_node_is_sequence(fynt_allof) ||
	    fy_node_sequence_is_empty(fynt_allof))
		return ERROR_ALLOF_BAD_SEQ;


	iter = NULL;
	while ((fynt_iter = fy_node_sequence_iterate(fynt_allof, &iter)) != NULL) {
		ret = validate_one(vc, fyn, fynt_iter);
		/* return immediately if not valid, or an error */
		if (ret != VALID)
			return IS_ERROR(ret) ? ret : INVALID_ALLOF_NO_MATCH;
	}

	return VALID;
}

static int validate_oneof(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			  struct fy_node *fynt_v)
{
	struct fy_node *fynt_anyof, *fynt_iter;
	int ret;
	void *iter;
	bool match_found;

	fynt_anyof = fynt_v;

	if (!fy_node_is_sequence(fynt_anyof) ||
	    fy_node_sequence_is_empty(fynt_anyof))
		return ERROR_ANYOF_BAD_SEQ;

	match_found = false;
	iter = NULL;
	while ((fynt_iter = fy_node_sequence_iterate(fynt_anyof, &iter)) != NULL) {
		ret = validate_one(vc, fyn, fynt_iter);
		/* error, just return immediately */
		if (IS_ERROR(ret))
			return ret;

		/* invalid, OK */
		if (IS_INVALID(ret))
			continue;

		/* match, check if it's the only one */
		if (match_found)
			return INVALID_ONEOF_MANY_MATCHES;
		match_found = true;
	}

	return match_found ? VALID : INVALID_ONEOF_NO_MATCH;
}

static int validate_not(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			struct fy_node *fynt_v)
{
	struct fy_node *fynt_not;
	int ret;

	fynt_not = fynt_v;

	ret = validate_one(vc, fyn, fynt_not);
	/* error, just return immediately */
	if (IS_ERROR(ret))
		return ret;

	/* clear the error if it's an expected invalid code */
	if (IS_INVALID(ret)) {
		vc->error = 0;
		vc->error_node = vc->error_rule_node = vc->error_specific_rule_node = NULL;
		return VALID;
	}

	return INVALID_NOT_MATCH;
}

static int validate_if_then_else(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				 struct fy_node *fynt_v)
{
	struct fy_node *fynt_if, *fynt_then, *fynt_else;
	int ret;
	bool if_match;

	fynt_if = fynt_v;

	ret = validate_one(vc, fyn, fynt_if);
	/* error, just return immediately */
	if (IS_ERROR(ret))
		return ret;
	if_match = ret == VALID;

	if (if_match && (fynt_then = fy_node_mapping_lookup_value_by_simple_key(fynt, "then", FY_NT)) != NULL) {
		ret = validate_one(vc, fyn, fynt_then);
		if (IS_ERROR(ret))
			return ret;
		return ret == VALID ? VALID : INVALID_THEN_NO_MATCH;
	}
	if (!if_match && (fynt_else = fy_node_mapping_lookup_value_by_simple_key(fynt, "else", FY_NT)) != NULL) {
		ret = validate_one(vc, fyn, fynt_else);
		if (IS_ERROR(ret))
			return ret;
		return ret == VALID ? VALID : INVALID_ELSE_NO_MATCH;
	}

	return VALID;
}

static int validate_properties(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			       struct fy_node *fynt_v)
{
	struct fy_node *fynt_props, *fynt_key, *fynt_value, *fyn_inst;
	struct fy_node_pair *fynp;
	enum fyjs_type vtype;
	int ret;
	void *iter;
	const char *key_str;

	fynt_props = fynt_v;

	if (!fy_node_is_mapping(fynt_props))
		return ERROR_PROPERTIES_NOT_MAP;

	/* ignore non-objects */
	vtype = validate_type_node(fyn);
	if (vtype != fyjs_object)
		return VALID;

	iter = NULL;
	while ((fynp = fy_node_mapping_iterate(fynt_props, &iter)) != NULL) {
		fynt_key = fy_node_pair_key(fynp);
		fynt_value = fy_node_pair_value(fynp);

		if (!fynt_key || !fy_node_is_scalar(fynt_key) || fy_node_is_alias(fynt_key))
			return ERROR_PROPERTIES_BAD_KEY;

		if (!fynt_value)
			return ERROR_PROPERTIES_BAD_VALUE;

		key_str = fy_node_get_scalar0(fynt_key);
		if (!key_str)
			return ERROR_INTERNAL_OUT_OF_MEMORY;

		fyn_inst = fy_node_mapping_lookup_value_by_simple_key(fyn, key_str, FY_NT);

		if (!fyn_inst)
			continue;

		ret = validate_one(vc, fyn_inst, fynt_value);
		if (ret != VALID)
			return ret;
	}

	return VALID;
}

static int validate_pattern_properties(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				       struct fy_node *fynt_v)
{
	struct fy_node *fynt_patprops, *fynt_key, *fynt_value, *fyn_key, *fyn_value;
	struct fy_node_pair *fynp, *fynpv;
	enum fyjs_type type, vtype;
	void *viter, *iter;
	const char *pattern_str, *pname_str, *error;
	int erroroffset, rc, ret;
	pcre *re;
	bool match;

	fynt_patprops = fynt_v;

	/* ignore non-objects */
	vtype = validate_type_node(fyn);
	if (vtype != fyjs_object)
		return VALID;

	/* non object pattern props is an error */
	type = validate_type_node(fynt_patprops);
	if (type != fyjs_object)
		return ERROR_PATTERNPROPS_NOT_OBJ;

	iter = NULL;
	while ((fynp = fy_node_mapping_iterate(fynt_patprops, &iter)) != NULL) {
		fynt_key = fy_node_pair_key(fynp);
		fynt_value = fy_node_pair_value(fynp);

		if (!fynt_key || !fy_node_is_scalar(fynt_key) || fy_node_is_alias(fynt_key))
			return ERROR_PATTERNPROPS_BAD_KEY;

		pattern_str = fy_node_get_scalar0(fynt_key);
		if (!pattern_str)
			return ERROR_INTERNAL_OUT_OF_MEMORY;

		re = pcre_compile(pattern_str,
				  PCRE_JAVASCRIPT_COMPAT |
				  (vc->pcre_utf8 ? PCRE_UTF8 : 0) |
				  PCRE_DOLLAR_ENDONLY,
				&error, &erroroffset, NULL);
		if (!re)
			return ERROR_PATTERNPROPS_BAD_PATTERN;

		viter = NULL;
		while ((fynpv = fy_node_mapping_iterate(fyn, &viter)) != NULL) {
			fyn_key = fy_node_pair_key(fynpv);
			fyn_value = fy_node_pair_value(fynpv);

			if (!fyn_key || !fy_node_is_scalar(fyn_key) || fy_node_is_alias(fyn_key)) {
				pcre_free(re);
				return ERROR_PATTERNPROPS_BAD_KEY;
			}

			pname_str = fy_node_get_scalar0(fyn_key);
			if (!pname_str) {
				pcre_free(re);
				return ERROR_INTERNAL_OUT_OF_MEMORY;
			}

			rc = pcre_exec(re, NULL, pname_str, strlen(pname_str), 0, 0, NULL, 0);
			match = !rc;

			if (match) {
				ret = validate_one(vc, fyn_value, fynt_value);
				if (ret != VALID) {
					pcre_free(re);
					return INVALID_PATTERNPROPS_NO_MATCH;
				}
			}

		}
		pcre_free(re);
		re = NULL;
	}

	return VALID;
}

static int validate_property_names(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				   struct fy_node *fynt_v)
{
	struct fy_node *fynt_propnames, *fyn_key;
	struct fy_node_pair *fynp;
	enum fyjs_type vtype;
	int ret;
	void *iter;
	const char *key_str;

	fynt_propnames = fynt_v;

	/* ignore non-objects */
	vtype = validate_type_node(fyn);
	if (vtype != fyjs_object)
		return VALID;

	iter = NULL;
	while ((fynp = fy_node_mapping_iterate(fyn, &iter)) != NULL) {
		fyn_key = fy_node_pair_key(fynp);

		if (!fyn_key || !fy_node_is_scalar(fyn_key) || fy_node_is_alias(fyn_key))
			return ERROR_PROPNAMES_BAD_KEY;

		key_str = fy_node_get_scalar0(fyn_key);
		if (!key_str)
			return ERROR_INTERNAL_OUT_OF_MEMORY;

		ret = validate_one(vc, fyn_key, fynt_propnames);
		if (ret != VALID)
			return IS_ERROR(ret) ? ret : INVALID_PROPNAMES_NO_MATCH;
	}

	return VALID;
}

static int validate_additional_properties(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
					  struct fy_node *fynt_v)
{
	struct fy_node *fynt_addprops, *fynt_props, *fynt_patprops, *fyn_key, *fynt_key2;
	struct fy_node_pair *fynp, *fynp2;
	enum fyjs_type vtype;
	int erroroffset, rc, ret;
	pcre *re;
	void *iter, *iter2;
	const char *key_str, *pattern_str, *error;

	fynt_addprops = fynt_v;

	/* ignore non-objects */
	vtype = validate_type_node(fyn);
	if (vtype != fyjs_object)
		return VALID;

	/* get properties node */
	fynt_props = fy_node_mapping_lookup_value_by_simple_key(fynt, "properties", FY_NT);

	/* we don't do errors here, so ignore */
	if (fynt_props && !fy_node_is_mapping(fynt_props))
		fynt_props = NULL;

	fynt_patprops = fy_node_mapping_lookup_value_by_simple_key(fynt, "patternProperties", FY_NT);
	if (fynt_patprops && !fy_node_is_mapping(fynt_patprops))
		fynt_patprops = NULL;

	/* iterate over the properties */
	iter = NULL;
	while ((fynp = fy_node_mapping_iterate(fyn, &iter)) != NULL) {

		fyn_key = fy_node_pair_key(fynp);

		/* only scalar keys */
		if (!fyn_key || !fy_node_is_scalar(fyn_key) ||
				  fy_node_is_alias(fyn_key))
			continue;

		key_str = fy_node_get_scalar0(fyn_key);
		if (!key_str)
			return ERROR_INTERNAL_OUT_OF_MEMORY;

		/* match with "properties" */
		if (fynt_props && fy_node_mapping_lookup_value_by_simple_key(fynt_props, key_str, FY_NT))
			continue;

		/* match with patternProperties */
		if (fynt_patprops) {
			iter2 = NULL;
			while ((fynp2 = fy_node_mapping_iterate(fynt_patprops, &iter2)) != NULL) {
				fynt_key2 = fy_node_pair_key(fynp2);

				pattern_str = fy_node_get_scalar0(fynt_key2);
				/* we ignore errors */
				if (!pattern_str)
					continue;

				re = pcre_compile(pattern_str,
						  PCRE_JAVASCRIPT_COMPAT |
						  (vc->pcre_utf8 ? PCRE_UTF8 : 0) |
						  PCRE_DOLLAR_ENDONLY,
						&error, &erroroffset, NULL);
				if (!re)
					continue;

				rc = pcre_exec(re, NULL, key_str, strlen(key_str), 0, 0, NULL, 0);
				pcre_free(re);

				if (rc == 0)
					break;
			}

			/* we had a match */
			if (iter2)
				continue;
		}

		/* OK time to match with "additionalProperties" */
		ret = validate_one(vc, fy_node_pair_value(fynp), fynt_addprops);
		if (ret != VALID)
			return IS_ERROR(ret) ? ret : INVALID_ADDPROPS_NO_MATCH;
	}

	return VALID;
}

static int validate_pattern(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			    struct fy_node *fynt_v)
{
	struct fy_node *fynt_pattern;
	enum fyjs_type vtype;
	const char *error, *pattern_str;
	int erroroffset, rc;
	const char *value;
	pcre *re;
	bool match;

	/* get const node */
	fynt_pattern = fynt_v;

	if (!fy_node_is_scalar(fynt_pattern) || fy_node_is_alias(fynt_pattern))
		return ERROR_PATTERN_NOT_SCALAR;

	vtype = validate_type_node(fyn);
	if (vtype != fyjs_string)
		return VALID;

	value = fy_node_get_scalar0(fyn);
	pattern_str = fy_node_get_scalar0(fynt_pattern);
	if (!value || !pattern_str)
		return ERROR_INTERNAL_OUT_OF_MEMORY;

	re = pcre_compile(pattern_str,
			  PCRE_JAVASCRIPT_COMPAT |
			  (vc->pcre_utf8 ? PCRE_UTF8 : 0) |
			  PCRE_DOLLAR_ENDONLY,
			&error, &erroroffset, NULL);
	if (!re)
		return ERROR_PATTERN_IS_BAD;

	rc = pcre_exec(re, NULL, value, strlen(value), 0, 0, NULL, 0);
	match = !rc;
	pcre_free(re);

	return match ? VALID : INVALID_PATTERN_NO_MATCH;
}

static int validate_string_length(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				  struct fy_node *fynt_v, const char *keyword)
{
	struct fy_node *fynt_constraint;
	enum fyjs_type type, vtype;
	const char *constraint_str;
	long constraint_i;
	size_t constraint;
	int ret;

	fynt_constraint = fynt_v;

	vtype = validate_type_node(fyn);
	if (vtype != fyjs_string)
		return VALID;

	type = validate_type_node(fynt_constraint);
	if (type != fyjs_integer)
		return ERROR_STRLEN_CONSTRAINT_NOT_INT;

	constraint_str = fy_node_get_scalar0(fynt_constraint);
	if (!constraint_str)
		return ERROR_INTERNAL_OUT_OF_MEMORY;

	constraint_i = strtol(constraint_str, NULL, 10);
	if (constraint_i < 0)
		return ERROR_STRLEN_CONSTRAINT_NEG;

	constraint = constraint_i;

	if (!strcmp(keyword, "minLength"))
		ret = fy_node_get_scalar_utf8_length(fyn) >= constraint ?
			VALID : INVALID_MINLENGTH_UNDER;
	else if (!strcmp(keyword, "maxLength"))
		ret = fy_node_get_scalar_utf8_length(fyn) <= constraint ?
			VALID : INVALID_MAXLENGTH_OVER;
	else
		ret = ERROR_STRLEN_ILLEGAL_KEYWORD;

	return ret;
}

static int validate_max_length(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			       struct fy_node *fynt_v)
{
	return validate_string_length(vc, fyn, fynt, fynt_v, "maxLength");
}

static int validate_min_length(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			       struct fy_node *fynt_v)
{
	return validate_string_length(vc, fyn, fynt, fynt_v, "minLength");
}

static int validate_items(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			  struct fy_node *fynt_v)
{
	struct fy_node *fynt_items, *fynt_additional_items = NULL;
	struct fy_node *fyn_value, *fynt_item;
	enum fyjs_type vtype;
	int ret;
	void *iter_items, *iter_values;

	fynt_items = fynt_v;

	/* ignore non-arrays */
	vtype = validate_type_node(fyn);
	if (vtype != fyjs_array)
		return VALID;

	if (!fy_node_is_sequence(fynt_items)) {

		/* all items must match single schema */
		iter_values = NULL;
		while ((fyn_value = fy_node_sequence_iterate(fyn, &iter_values)) != NULL) {
			ret = validate_one(vc, fyn_value, fynt_items);
			if (ret != VALID)
				return ret;
		}

		/* additionalItems is not used */

	} else {

		iter_items = NULL;
		iter_values = NULL;
		for (;;) {
			fynt_item = fy_node_sequence_iterate(fynt_items, &iter_items);
			fyn_value = fy_node_sequence_iterate(fyn, &iter_values);
			if (!fynt_item || !fyn_value)
				break;

			ret = validate_one(vc, fyn_value, fynt_item);
			if (ret != VALID)
				return ret;
		}

		/* if additionalItems exist */
		if (fyn_value &&
		    (fynt_additional_items = fy_node_mapping_lookup_value_by_simple_key(fynt, "additionalItems", FY_NT)) != NULL) {

			do {
				ret = validate_one(vc, fyn_value, fynt_additional_items);
				if (ret != VALID)
					return ret;

				fyn_value = fy_node_sequence_iterate(fyn, &iter_values);
			} while (fyn_value);
		}
	}

	return VALID;
}

static int validate_contains(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			     struct fy_node *fynt_v)
{
	struct fy_node *fynt_contains, *fynt_max_contains, *fynt_min_contains;
	struct fy_node *fyn_value;
	enum fyjs_type vtype;
	void *iter_values;
	int ret, nr_contains, min_contains = -1, max_contains = -1;
	const char *min_str, *max_str;

	/* get contains node */
	fynt_contains = fynt_v;

	/* ignore non-arrays */
	vtype = validate_type_node(fyn);
	if (vtype != fyjs_array)
		return VALID;

	fynt_min_contains = fy_node_mapping_lookup_value_by_simple_key(fynt, "minContains", FY_NT);
	if (fynt_min_contains) {
		if (validate_type_node(fynt_min_contains) != fyjs_integer)
			return ERROR_CONTAINS_MIN_NOT_INT;
		min_str = fy_node_get_scalar0(fynt_min_contains);
		if (!min_str)
			return ERROR_INTERNAL_OUT_OF_MEMORY;
		min_contains = (int)strtol(min_str, NULL, 10);
		if (min_contains < 0)
			return ERROR_CONTAINS_MIN_NEG;
	}
	fynt_max_contains = fy_node_mapping_lookup_value_by_simple_key(fynt, "maxContains", FY_NT);
	if (fynt_max_contains) {
		if (validate_type_node(fynt_max_contains) != fyjs_integer)
			return ERROR_CONTAINS_MAX_NOT_INT;
		max_str = fy_node_get_scalar0(fynt_max_contains);
		if (!max_str)
			return ERROR_INTERNAL_OUT_OF_MEMORY;
		max_contains = (int)strtol(max_str, NULL, 10);
		if (max_contains < 0)
			return ERROR_CONTAINS_MAX_NEG;
	}

	iter_values = NULL;
	nr_contains = 0;
	while ((fyn_value = fy_node_sequence_iterate(fyn, &iter_values)) != NULL) {
		ret = validate_one(vc, fyn_value, fynt_contains);
		if (ret == VALID) {
			nr_contains++;
			/* no need to try more if no min/max contains */
			if (min_contains == -1 && max_contains == -1)
				break;
		}
	}

	/* nothing, report */
	if (!nr_contains)
		return INVALID_CONTAINS_NONE;

	/* less than min */
	if (min_contains >= 0 && nr_contains < min_contains)
		return INVALID_CONTAINS_NOT_ENOUGH;

	/* more than max */
	if (max_contains >= 0 && nr_contains > max_contains)
		return INVALID_CONTAINS_TOO_MANY;

	/* all right */
	return VALID;
}

static int validate_unique_items(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				 struct fy_node *fynt_v)
{
	struct fy_node *fynt_unique;
	struct fy_node *fyn_value1, *fyn_value2;
	enum fyjs_type vtype;
	void *iter_values1, *iter_values2;
	const char *boolean_str;

	/* get contains node */
	fynt_unique = fynt_v;

	/* ignore non-arrays */
	vtype = validate_type_node(fyn);
	if (vtype != fyjs_array)
		return VALID;

	if (validate_type_node(fynt_unique) != fyjs_boolean)
		return ERROR_UNIQUE_NOT_BOOL;

	boolean_str = fy_node_get_scalar0(fynt_unique);
	if (!boolean_str)
		return ERROR_INTERNAL_OUT_OF_MEMORY;

	/* if set to false, return valid immediately */
	if (!strcmp(boolean_str, "false"))
		return VALID;

	iter_values1 = NULL;
	while ((fyn_value1 = fy_node_sequence_iterate(fyn, &iter_values1)) != NULL) {

		iter_values2 = NULL;
		while ((fyn_value2 = fy_node_sequence_iterate(fyn, &iter_values2)) != NULL) {

			/* do not check with self */
			if (fyn_value1 == fyn_value2)
				continue;

			if (fy_node_compare_json(fyn_value1, fyn_value2))
				return INVALID_UNIQUE_NOT_UNIQUE;
		}
	}

	return VALID;
}

static int validate_min_max_items(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				  struct fy_node *fynt_v, const char *keyword)
{
	struct fy_node *fynt_minmax;
	enum fyjs_type vtype;
	const char *minmax_str;
	bool min;
	long minmax;
	int count;

	min = !strcmp(keyword, "minItems");

	/* get contains node */
	fynt_minmax = fynt_v;

	/* ignore non-arrays */
	vtype = validate_type_node(fyn);
	if (vtype != fyjs_array)
		return VALID;

	if (validate_type_node(fynt_minmax) != fyjs_integer)
		return min ?  ERROR_MIN_ITEMS_NOT_INT : ERROR_MAX_ITEMS_NOT_INT;

	minmax_str = fy_node_get_scalar0(fynt_minmax);
	if (!minmax_str)
		return ERROR_INTERNAL_OUT_OF_MEMORY;

	minmax = strtol(minmax_str, NULL, 10);
	if (minmax == LONG_MAX && errno == ERANGE) {
		errno = 0;
		return min ? ERROR_MIN_ITEMS_OVERFLOW : ERROR_MAX_ITEMS_OVERFLOW;
	}

	count = fy_node_sequence_item_count(fyn);
	if (min && count < minmax)
		return INVALID_MIN_ITEMS_NOT_ENOUGH;

	if (!min && count > minmax)
		return INVALID_MAX_ITEMS_TOO_MANY;

	return VALID;
}

static int validate_min_items(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			      struct fy_node *fynt_v)
{
	return validate_min_max_items(vc, fyn, fynt, fynt_v, "minItems");
}

static int validate_max_items(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			      struct fy_node *fynt_v)
{
	return validate_min_max_items(vc, fyn, fynt, fynt_v, "maxItems");
}

static int validate_min_max_properties(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				       struct fy_node *fynt_v, const char *keyword)
{
	struct fy_node *fynt_minmax;
	enum fyjs_type vtype;
	const char *minmax_str;
	bool min;
	long minmax;
	int count;

	min = !strcmp(keyword, "minProperties");

	/* get contains node */
	fynt_minmax = fynt_v;

	/* ignore non-objects */
	vtype = validate_type_node(fyn);
	if (vtype != fyjs_object)
		return VALID;

	if (validate_type_node(fynt_minmax) != fyjs_integer)
		return min ?  ERROR_MIN_PROPERTIES_NOT_INT : ERROR_MAX_PROPERTIES_NOT_INT;

	minmax_str = fy_node_get_scalar0(fynt_minmax);
	if (!minmax_str)
		return ERROR_INTERNAL_OUT_OF_MEMORY;

	minmax = strtol(minmax_str, NULL, 10);
	if (minmax == LONG_MAX && errno == ERANGE) {
		errno = 0;
		return min ? ERROR_MIN_PROPERTIES_OVERFLOW : ERROR_MAX_PROPERTIES_OVERFLOW;
	}

	count = fy_node_mapping_item_count(fyn);
	if (min && count < minmax)
		return INVALID_MIN_PROPERTIES_NOT_ENOUGH;

	if (!min && count > minmax)
		return INVALID_MAX_PROPERTIES_TOO_MANY;

	return VALID;
}

static int validate_min_properties(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				   struct fy_node *fynt_v)
{
	return validate_min_max_properties(vc, fyn, fynt, fynt_v, "minProperties");
}

static int validate_max_properties(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				   struct fy_node *fynt_v)
{
	return validate_min_max_properties(vc, fyn, fynt, fynt_v, "maxProperties");
}

static int validate_required(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			     struct fy_node *fynt_v)
{
	struct fy_node *fynt_required;
	enum fyjs_type vtype;
	struct fy_node *fynt_value1, *fynt_value2;
	const char *value1_str;
	void *iter_values1, *iter_values2;
	size_t value1_len;

	fynt_required = fynt_v;

	/* validate it's a sequence */
	if (!fy_node_is_sequence(fynt_required))
		return ERROR_REQUIRED_NOT_ARRAY;

	/* ignore non-objects */
	vtype = validate_type_node(fyn);
	if (vtype != fyjs_object)
		return VALID;

	iter_values1 = NULL;
	while ((fynt_value1 = fy_node_sequence_iterate(fynt_required, &iter_values1)) != NULL) {

		/* check that the value is a string */
		if (validate_type_node(fynt_value1) != fyjs_string)
			return ERROR_REQUIRED_REQ_NOT_STR;

		value1_str = fy_node_get_scalar(fynt_value1, &value1_len);
		if (!value1_str)
			return ERROR_INTERNAL_OUT_OF_MEMORY;

		/* verify that the property is not duplicated */
		iter_values2 = NULL;
		while ((fynt_value2 = fy_node_sequence_iterate(fynt_required, &iter_values2)) != NULL) {

			/* do not check with self */
			if (fynt_value1 == fynt_value2)
				continue;

			/* compare */
			if (fy_node_compare_json(fynt_value1, fynt_value2))
				return ERROR_REQUIRED_REQ_IS_DUP;
		}

		/* required property must exist */
		if (!fy_node_mapping_lookup_value_by_simple_key(fyn, value1_str, value1_len))
			return INVALID_REQUIRED_DEP_MISSING;
	}

	return VALID;
}

enum fyjs_dependent_type {
	fyjsdt_required,
	fyjsdt_schemas,
	fyjsdt_dependencies,
	fyjsdt_max,
};

static int validate_dependent_required_internal(struct fyjs_validate_ctx *vc, struct fy_node *fyn,
		struct fy_node *fynt, struct fy_node *fynt_v, enum fyjs_dependent_type dep_type)
{
	struct fy_node *fynt_dreq, *fynt_key, *fynt_value, *fynt_value1, *fynt_value2, *fynt_skey, *fynt_svalue;
	struct fy_node_pair *fynp, *fynps;
	enum fyjs_type vtype, type_key, type_value;
	void *iter_dreq, *iter_values1, *iter_values2, *iter_dschema;
	const char *key_str, *value1_str, *skey_str;
	bool key_exists;
	int ret;

	assert(dep_type >= fyjsdt_required && dep_type < fyjsdt_max);

	/* get depend* node */
	fynt_dreq = fynt_v;

	/* ignore non-objects */
	vtype = validate_type_node(fyn);
	if (vtype != fyjs_object)
		return VALID;

	if (validate_type_node(fynt_dreq) != fyjs_object)
		return ERROR_DEPENDENCIES_NOT_OBJ;

	iter_dreq = NULL;
	while ((fynp = fy_node_mapping_iterate(fynt_dreq, &iter_dreq)) != NULL) {
		fynt_key = fy_node_pair_key(fynp);
		fynt_value = fy_node_pair_value(fynp);

		type_key = validate_type_node(fynt_key);
		if (type_key != fyjs_string)
			return ERROR_DEPENDENCIES_BAD_KEY;

		key_str = fy_node_get_scalar0(fynt_key);
		if (!key_str)
			return ERROR_INTERNAL_OUT_OF_MEMORY;

		type_value = validate_type_node(fynt_value);

		if (dep_type == fyjsdt_required && type_value != fyjs_array)
			return ERROR_DEPENDENCIES_BAD_VALUE;

		if (dep_type == fyjsdt_schemas && type_value != fyjs_object)
			return ERROR_DEPENDENCIES_BAD_VALUE;

		/* does the key exist? */
		key_exists = fy_node_mapping_lookup_value_by_simple_key(fyn, key_str, FY_NT) != NULL;

		/* if array, check for existence */
		if (type_value == fyjs_array) {
			iter_values1 = NULL;
			while ((fynt_value1 = fy_node_sequence_iterate(fynt_value, &iter_values1)) != NULL) {

				/* check that the value is a string */
				if (validate_type_node(fynt_value1) != fyjs_string)
					return ERROR_DEPENDENCIES_DEP_NOT_STR;

				value1_str = fy_node_get_scalar0(fynt_value1);
				if (!value1_str)
					return ERROR_INTERNAL_OUT_OF_MEMORY;

				/* verify that the property is not duplicated */
				iter_values2 = NULL;
				while ((fynt_value2 = fy_node_sequence_iterate(fynt_value, &iter_values2)) != NULL) {

					/* do not check with self */
					if (fynt_value1 == fynt_value2)
						continue;

					/* compare */
					if (fy_node_compare_json(fynt_value1, fynt_value2))
						return ERROR_DEPENDENCIES_DEP_IS_DUP;
				}

				/* it must exist */
				if (key_exists && !fy_node_mapping_lookup_value_by_simple_key(fyn, value1_str, FY_NT))
					return INVALID_DEPENDENCIES_DEP_MISSING;
			}
		} else if (type_value == fyjs_object || type_value == fyjs_boolean) {

			if (dep_type == fyjsdt_dependencies) {

				/* the key must exist for the dependency to 'take' */
				if (!key_exists)
					continue;

				ret = validate_one(vc, fyn, fynt_value);
				/* return immediately if valid, or an error */
				if (ret != VALID)
					return ret;
			} else if (dep_type == fyjsdt_schemas) {
				iter_dschema = NULL;
				while ((fynps = fy_node_mapping_iterate(fynt_value, &iter_dschema)) != NULL) {
					fynt_skey = fy_node_pair_key(fynps);
					fynt_svalue = fy_node_pair_value(fynps);

					/* the value must be an object */
					if (!fy_node_is_mapping(fynt_svalue))
						return ERROR_DEPENDENCIES_SVAL_NOT_OBJ;

					skey_str = fy_node_get_scalar0(fynt_skey);
					if (!skey_str)
						return ERROR_INTERNAL_OUT_OF_MEMORY;

					/* if the property doesn't exist... */
					if (!fy_node_mapping_lookup_value_by_simple_key(fyn, skey_str, FY_NT))
						continue;

					ret = validate_one(vc, fyn, fynt_value);
					/* return immediately if valid, or an error */
					if (ret != VALID)
						return ret;
				}

			} else
				return ERROR_DEPENDENCIES_BAD_VALUE;

		} else
			return ERROR_DEPENDENCIES_BAD_VALUE;

	}

	return VALID;
}

static int validate_dependent_required(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				       struct fy_node *fynt_v)
{
	return validate_dependent_required_internal(vc, fyn, fynt, fynt_v, fyjsdt_required);
}

static int validate_dependent_schemas(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				      struct fy_node *fynt_v)
{
	return validate_dependent_required_internal(vc, fyn, fynt, fynt_v, fyjsdt_schemas);
}

static int validate_dependencies(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				 struct fy_node *fynt_v)
{
	return validate_dependent_required_internal(vc, fyn, fynt, fynt_v, fyjsdt_dependencies);
}

static inline bool ascii_streq(const char *s1, const char *s2)
{
	char c1, c2;

	for ( ; (c1 = *s1) != '\0' && (c2 = *s2) != '\0'; s1++, s2++) {
		/* if anything is non 7-bit ascii it's false */
		if ((unsigned char)c1 > 0x7f || (unsigned char)c2 > 0x7f)
			return false;
		if (c1 >= 'A' && c1 <= 'Z')
			c1 = (c1 - 'A') + 'a';
		if (c2 >= 'A' && c2 <= 'Z')
			c2 = (c2 - 'A') + 'a';
		if (c1 != c2)
			return false;
	}

	return !*s1 && !*s2;
}

static int validate_content_encoding(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				     struct fy_node *fynt_v)
{
	struct fy_node *fynt_enc;
	enum fyjs_type type, vtype;
	const char *type_str, *value_str;

	fynt_enc = fynt_v;

	type = validate_type_node(fynt_enc);
	if (type != fyjs_string)
		return ERROR_CONTENTENC_NOT_STR;

	/* ignore non-strings */
	vtype = validate_type_node(fyn);
	if (vtype != fyjs_string)
		return VALID;

	type_str = fy_node_get_scalar0(fynt_enc);
	if (!type_str)
		return ERROR_INTERNAL_OUT_OF_MEMORY;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return ERROR_INTERNAL_OUT_OF_MEMORY;

	if (ascii_streq(type_str, "7bit")) {
		/* verify it's 7 bit only */
		return VALID;
	}

	if (ascii_streq(type_str, "8bit")) {
		return VALID;
	}

	if (ascii_streq(type_str, "base64"))
		return fy_b64_valid(value_str) ? VALID : INVALID_CONTENTENC_BAD;

	return ERROR_CONTENTENC_BAD;
}

static int validate_content_media_type(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				       struct fy_node *fynt_v)
{
	struct fy_node *fynt_cmt, *fynt_enc;
	enum fyjs_type type, vtype;
	const char *cmt_str, *type_str, *value_str;
	char *decoded = NULL;
	size_t decoded_len = -1;
	struct fy_document *fyd;
	int ret;

	fynt_cmt = fynt_v;

	type = validate_type_node(fynt_cmt);
	if (type != fyjs_string)
		return ERROR_CONTENTMT_NOT_STR;

	/* ignore non-strings */
	vtype = validate_type_node(fyn);
	if (vtype != fyjs_string)
		return VALID;

	cmt_str = fy_node_get_scalar0(fynt_cmt);
	if (!cmt_str)
		return ERROR_INTERNAL_OUT_OF_MEMORY;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return ERROR_INTERNAL_OUT_OF_MEMORY;

	fynt_enc = fy_node_mapping_lookup_value_by_simple_key(fynt, "contentEncoding", FY_NT);
	if (fynt_enc) {
		type_str = fy_node_get_scalar0(fynt_enc);
		if (!type_str)
			return ERROR_INTERNAL_OUT_OF_MEMORY;

		if (ascii_streq(type_str, "base64")) {
			decoded = fy_b64_decode(value_str, &decoded_len);
			if (!decoded)
				return INVALID_CONTENTENC_BAD;
			value_str = decoded;
		}
	}

	ret = INVALID_CONTENTMT_BAD;
	if (ascii_streq(cmt_str, "application/json")) {
		fyd = fy_document_build_from_string(&json_doc_cfg, value_str, strlen(value_str));
		if (fyd)
			ret = VALID;
		fy_document_destroy(fyd);
	}

	if (decoded)
		free(decoded);

	return ret;
}

/*************************/

static bool valid_hostname(const char *str, size_t len)
{
	const char *s, *e, *ss;
	char c;

	if (len == (size_t)-1)
		len = strlen(str);

	s = str;
	e = s + len;

	/* must be >= 1 and not larger than 254 (if it has a terminating .) */
	if (s >= e || (e - s) > 254)
		return false;

	/* for a non terminating dot, maximum is 253 */
	if ((e - s) > 253 && e[-1] != '.')
		return false;

	/* parse dot separated labels */
	while (s < e) {

		/* mark start of label */
		ss = s;

		/* must start with [a-zA-Z] */
		c = *s;
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')))
			return false;

		for (s++; s < e && (c = *s) != '.'; s++) {

			/* each label must be less than 64 characters long */
			if ((s - ss) >= 64)
				return false;

			/* [a-zA-Z0-9] always valid */
			if ((c >= 'a' && c <= 'z') ||
			    (c >= 'A' && c <= 'Z') ||
			    (c >= '0' && c <= '9'))
				continue;

			/* - only if not last in label */
			if (c == '-' && !((s + 1) >= e || s[1] == '.'))
				continue;

			/* anything else is illegal */
			return false;
		}

		/* skip dot */
		if (s < e && *s == '.')
			s++;
	}

	return true;
}

static bool valid_localpart(const char *str, size_t len)
{
	const char *s, *e;

	if (len == (size_t)-1)
		len = strlen(str);

	/* validate local-part */
	s = str;
	e = s + len;

	/* must have at least 1 character */
	if (s >= e)
		return false;

	while (s < e) {
		if (*s == '"') {
			/* quoted string */
			s++;
			while (s < e && *s != '"') {
				if (*s == '\\') {
					if (s + 1 >= e)
						return false;
					s++;
				}
				s++;
			}
			if (s >= e)
				return false;
			/* skip '"' */
			s++;
			continue;
		}
		/* it must not be one of those */
		if (strchr("()<>[]:;@\\,", *s))
			return false;

		/* must be a printable */
		if (!isprint(*s))
			return false;

		s++;
	}

	return true;
}

static bool valid_uri(const char *str, size_t len)
{
	char *str2;
	struct fy_uri urip;
	int rc;

	if (len != (size_t)-1) {
		str2 = alloca(len + 1);
		memcpy(str2, str, len);
		str2[len] = '\0';
		str = str2;
	}

	rc = fy_parse_uri_ext(str, &urip, 0);
	if (rc)
		return false;

	return true;
}

static bool valid_uri_reference(const char *str, size_t len)
{
	char *str2;
	struct fy_uri urip;
	int rc;

	if (len != (size_t)-1) {
		str2 = alloca(len + 1);
		memcpy(str2, str, len);
		str2[len] = '\0';
		str = str2;
	}

	rc = fy_parse_uri_ext(str, &urip, URI_REF);
	if (rc)
		return false;

	return true;
}

static bool valid_uri_template(const char *str, size_t len)
{
	char *str2;
	struct fy_uri urip;
	int rc;

	if (len != (size_t)-1) {
		str2 = alloca(len + 1);
		memcpy(str2, str, len);
		str2[len] = '\0';
		str = str2;
	}

	rc = fy_parse_uri_ext(str, &urip, URI_TEMPLATE);
	if (rc)
		return false;

	return true;
}

static bool valid_iri(const char *str, size_t len)
{
	char *str2;
	struct fy_uri urip;
	int rc;

	if (len != (size_t)-1) {
		str2 = alloca(len + 1);
		memcpy(str2, str, len);
		str2[len] = '\0';
		str = str2;
	}

	rc = fy_parse_uri_ext(str, &urip, URI_IRI);
	if (rc)
		return false;

	return true;
}

static bool valid_iri_reference(const char *str, size_t len)
{
	char *str2;
	struct fy_uri urip;
	int rc;

	if (len != (size_t)-1) {
		str2 = alloca(len + 1);
		memcpy(str2, str, len);
		str2[len] = '\0';
		str = str2;
	}

	rc = fy_parse_uri_ext(str, &urip, URI_IRI | URI_REF);
	if (rc)
		return false;

	return true;
}

static bool valid_idn_hostname(const char *str, size_t len)
{
	const char *str2;
	char *str3;

	if (len == (size_t)-1)
		str2 = str;
	else {
		str3 = alloca(len + 1);
		memcpy(str3, str, len);
		str3[len] = '\0';
		str2 = str3;
	}

	return fy_idn_is_hostname(str2);
}

bool valid_idn_localpart(const char *str, size_t len)
{
	const char *s, *e;
	int w;

	if (len == (size_t)-1)
		len = strlen(str);

	/* validate local-part */
	s = str;
	e = s + len;

	/* must have at least 1 character */
	if (s >= e)
		return false;

	while (s < e) {
		if (*s == '"') {
			/* quoted string */
			s++;
			while (s < e && *s != '"') {
				if (*s == '\\') {
					w = utf8_width_by_first_octet((uint8_t)*s);
					if (!w || s + w > e)
						return false;
					s += w;
				}
				s++;
			}
			if (s >= e)
				return false;
			/* skip '"' */
			s++;
			continue;
		}
		/* it must not be one of those */
		if (strchr("()<>[]:;@\\,", *s))
			return false;

		/* must be a printable */
		if ((uint8_t)*s < 0x80 && !isprint(*s))
			return false;

		w = utf8_width_by_first_octet((uint8_t)*s);
		if (!w || s + w > e)
			return false;

		s += w;
	}

	return true;
}

static int validate_format_email(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				 struct fy_node *fynt_v)
{
	const char *value_str, *d;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return ERROR_INTERNAL_OUT_OF_MEMORY;

	d = strchr(value_str, '@');
	if (!d)
		return INVALID_FORMAT_EMAIL;

	if (!valid_localpart(value_str, (size_t)(d - value_str)))
		return INVALID_FORMAT_EMAIL;

	if (!valid_hostname(d + 1, (size_t)-1))
		return INVALID_FORMAT_EMAIL;

	return VALID;
}

static int validate_format_idn_email(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				     struct fy_node *fynt_v)
{
	const char *value_str, *d;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return ERROR_INTERNAL_OUT_OF_MEMORY;

	d = strchr(value_str, '@');
	if (!d)
		return INVALID_FORMAT_IDN_EMAIL;

	if (!valid_idn_localpart(value_str, (size_t)(d - value_str)))
		return INVALID_FORMAT_IDN_EMAIL;

	if (!valid_idn_hostname(d + 1, (size_t)-1))
		return INVALID_FORMAT_IDN_EMAIL;

	return VALID;
}

static int validate_format_regex(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				 struct fy_node *fynt_v)
{
	const char *value_str, *error;
	const char *s, *e;
	int erroroffset;
	pcre *re;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return ERROR_INTERNAL_OUT_OF_MEMORY;

	/* compile the pattern for a quick test */
	re = pcre_compile(value_str,
			  PCRE_JAVASCRIPT_COMPAT |
			  (vc->pcre_utf8 ? PCRE_UTF8 : 0) |
			  PCRE_DOLLAR_ENDONLY,
			&error, &erroroffset, NULL);
	if (!re)
		return INVALID_FORMAT_REGEX;

	pcre_free(re);

	/* PCRE is more permissive, so check for valid metacharacters only */
	s = value_str;
	e = s + strlen(value_str);
	for (; s < e; s++) {
		if (*s != '\\')
			continue;

		/* too short */
		if (s + 1 >= e)
			return INVALID_FORMAT_REGEX;

		s++;

		/* must only be one of those */
		if (!strchr("wWdDsSbB0nfrtvxu", *s))
			return INVALID_FORMAT_REGEX;
	}

	return VALID;
}

static int validate_format_ipv4(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				struct fy_node *fynt_v)
{
	struct sockaddr_in sa4;
	const char *value_str;
	int rc;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return ERROR_INTERNAL_OUT_OF_MEMORY;

	rc = inet_pton(AF_INET, value_str, &sa4);
	return rc == 1 ? VALID : INVALID_FORMAT_IPV4;
}

static int validate_format_ipv6(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				struct fy_node *fynt_v)
{
	struct sockaddr_in6 sa6;
	const char *value_str;
	int rc;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return ERROR_INTERNAL_OUT_OF_MEMORY;

	rc = inet_pton(AF_INET6, value_str, &sa6);
	return rc == 1 ? VALID : INVALID_FORMAT_IPV6;
}

static int validate_format_hostname(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				    struct fy_node *fynt_v)
{
	const char *value_str;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return ERROR_INTERNAL_OUT_OF_MEMORY;

	return valid_hostname(value_str, (size_t)-1) ? VALID : INVALID_FORMAT_HOSTNAME;
}

static int validate_format_idn_hostname(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
					struct fy_node *fynt_v)
{
	const char *value_str;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return ERROR_INTERNAL_OUT_OF_MEMORY;

	return valid_idn_hostname(value_str, (size_t)-1) ? VALID : INVALID_FORMAT_IDN_HOSTNAME;
}

static int validate_format_date(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				struct fy_node *fynt_v)
{
	const char *value_str, *p;
	struct tm tm, tm_orig;
	time_t t;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return ERROR_INTERNAL_OUT_OF_MEMORY;

	memset(&tm, 0, sizeof(tm));
	p = strptime(value_str, "%Y-%m-%d", &tm);
	if (!p || *p)	/* everything must be consumed */
		return INVALID_FORMAT_DATE;

	memcpy(&tm_orig, &tm, sizeof(tm));

	t = mktime(&tm);
	if (t == (time_t)-1)
		return INVALID_FORMAT_DATE;

	/* if tm has been normalized it's an error */
	if (tm.tm_year != tm_orig.tm_year ||
	    tm.tm_mon != tm_orig.tm_mon ||
	    tm.tm_mday != tm_orig.tm_mday)
		return INVALID_FORMAT_DATE;

	return VALID;
}

static int validate_format_time(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				struct fy_node *fynt_v)
{
	const char *value_str, *p;
	struct tm tm;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return ERROR_INTERNAL_OUT_OF_MEMORY;

	memset(&tm, 0, sizeof(tm));
	p = strptime(value_str, "%H:%M:%S", &tm);
	if (!p)
		return INVALID_FORMAT_TIME;

	/* no fractional part i.e. 00:00:00 */
	if (!*p)
		return VALID;

	/* fractional part i.e. 00:00:00.1234.. */
	if (*p == '.') {
		p++;
		if (!isdigit(*p))
			return INVALID_FORMAT_TIME;
		while (isdigit(*p))
			p++;
	}

	/* Z */
	if (*p == 'z' || *p == 'Z') {
		p++;
		return *p ? INVALID_FORMAT_TIME : VALID;
	}

	/* or [+-]00:00 */
	if (*p != '+' && *p != '-')
		return INVALID_FORMAT_TIME;
	p++;

	memset(&tm, 0, sizeof(tm));
	p = strptime(p, "%H:%M", &tm);
	if (!p || *p)
		return INVALID_FORMAT_TIME;

	return VALID;
}

static int validate_format_date_time(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				     struct fy_node *fynt_v)
{
	const char *value_str, *p;
	struct tm tm, tm_orig;
	time_t t;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return ERROR_INTERNAL_OUT_OF_MEMORY;

	memset(&tm, 0, sizeof(tm));
	p = strptime(value_str, "%Y-%m-%d", &tm);
	if (!p)
		return INVALID_FORMAT_DATE_TIME;

	if (*p != 't' && *p != 'T')
		return INVALID_FORMAT_DATE_TIME;
	p++;

	p = strptime(p, "%H:%M:%S", &tm);
	if (!p)
		return INVALID_FORMAT_DATE_TIME;

	/* no fractional part i.e. 00:00:00 */
	if (!*p)
		return VALID;

	/* fractional part i.e. 00:00:00.1234.. */
	if (*p == '.') {
		p++;
		if (!isdigit(*p))
			return INVALID_FORMAT_DATE_TIME;
		while (isdigit(*p))
			p++;
	}

	/* Z */
	if (*p == 'z' || *p == 'Z') {
		p++;
		return *p ? INVALID_FORMAT_DATE_TIME : VALID;
	}

	/* or [+-]00:00 */
	if (*p != '+' && *p != '-')
		return INVALID_FORMAT_DATE_TIME;
	p++;

	memset(&tm_orig, 0, sizeof(tm_orig));
	p = strptime(p, "%H:%M", &tm_orig);
	if (!p || *p)
		return INVALID_FORMAT_TIME;

	memcpy(&tm_orig, &tm, sizeof(tm));

	t = mktime(&tm);
	if (t == (time_t)-1)
		return INVALID_FORMAT_DATE_TIME;

	/* if tm has been normalized it's an error */
	if (tm.tm_year != tm_orig.tm_year ||
	    tm.tm_mon != tm_orig.tm_mon ||
	    tm.tm_mday != tm_orig.tm_mday ||
	    tm.tm_hour != tm_orig.tm_hour ||
	    tm.tm_min != tm_orig.tm_min ||
	    tm.tm_sec != tm_orig.tm_sec)
		return INVALID_FORMAT_DATE_TIME;

	return VALID;
}

static int validate_format_json_pointer(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
					struct fy_node *fynt_v)
{
	const char *value_str;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return ERROR_INTERNAL_OUT_OF_MEMORY;

	return is_valid_json_pointer(value_str) ? VALID : INVALID_FORMAT_JSON_POINTER;
}

static int validate_format_relative_json_pointer(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
						 struct fy_node *fynt_v)
{
	const char *value_str;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return ERROR_INTERNAL_OUT_OF_MEMORY;

	return is_valid_reljson_pointer(value_str) ? VALID : INVALID_FORMAT_RELJSON_POINTER;
}

static int validate_format_iri(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			       struct fy_node *fynt_v)
{
	const char *value_str;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return ERROR_INTERNAL_OUT_OF_MEMORY;

	return valid_iri(value_str, (size_t)-1) ? VALID : INVALID_FORMAT_URI;
}

static int validate_format_iri_reference(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
					 struct fy_node *fynt_v)
{
	const char *value_str;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return ERROR_INTERNAL_OUT_OF_MEMORY;

	return valid_iri_reference(value_str, (size_t)-1) ? VALID : INVALID_FORMAT_URI;
}

static int validate_format_uri(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			       struct fy_node *fynt_v)
{
	const char *value_str;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return ERROR_INTERNAL_OUT_OF_MEMORY;

	return valid_uri(value_str, (size_t)-1) ? VALID : INVALID_FORMAT_URI;
}

static int validate_format_uri_reference(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
					 struct fy_node *fynt_v)
{
	const char *value_str;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return ERROR_INTERNAL_OUT_OF_MEMORY;

	return valid_uri_reference(value_str, (size_t)-1) ? VALID : INVALID_FORMAT_URI;
}

static int validate_format_uri_template(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				        struct fy_node *fynt_v)
{
	const char *value_str;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return ERROR_INTERNAL_OUT_OF_MEMORY;

	return valid_uri_template(value_str, (size_t)-1) ? VALID : INVALID_FORMAT_URI;
}

static const struct validate_desc format_validators[] = {
	{ .primary = "email", 			.func = validate_format_email },
	{ .primary = "idn-email", 		.func = validate_format_idn_email },
	{ .primary = "regex", 			.func = validate_format_regex },
	{ .primary = "ipv4", 			.func = validate_format_ipv4 },
	{ .primary = "ipv6", 			.func = validate_format_ipv6 },
	{ .primary = "hostname",		.func = validate_format_hostname },
	{ .primary = "idn-hostname",		.func = validate_format_idn_hostname },
	{ .primary = "date",			.func = validate_format_date },
	{ .primary = "time",			.func = validate_format_time },
	{ .primary = "date-time",		.func = validate_format_date_time },
	{ .primary = "json-pointer",		.func = validate_format_json_pointer },
	{ .primary = "relative-json-pointer",	.func = validate_format_relative_json_pointer },
	{ .primary = "iri",			.func = validate_format_iri },
	{ .primary = "iri-reference",		.func = validate_format_iri_reference },
	{ .primary = "uri",			.func = validate_format_uri },
	{ .primary = "uri-reference",		.func = validate_format_uri_reference },
	{ .primary = "uri-template",		.func = validate_format_uri_template },

	{ .primary = NULL, .func = NULL }
};

static int validate_format(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			   struct fy_node *fynt_v)
{
	struct fy_node *fynt_format;
	enum fyjs_type type, vtype;
	const char *format_str;
	const struct validate_desc *vd = NULL;
	int ret;

	/* get format node */
	fynt_format = fynt_v;

	/* must be string */
	type = validate_type_node(fynt_format);
	if (type != fyjs_string)
		return ERROR_FORMAT_NOT_STRING;

	/* if not a string just valid */
	vtype = validate_type_node(fyn);
	if (vtype != fyjs_string)
		return VALID;

	format_str = fy_node_get_scalar0(fynt_format);
	if (!format_str)
		return ERROR_INTERNAL_OUT_OF_MEMORY;

	ret = VALID;
	for (vd = format_validators; vd->func; vd++) {

		if (strcmp(format_str, vd->primary))
			continue;

		ret = vd->func(vc, fyn, fynt, fynt);
		if (ret != VALID)
			break;
	}

	return ret;
}

static const struct validate_desc validators[] = {
	/* generic checks */
	{ .primary = "type",			.func = validate_type },
	{ .primary = "const",			.func = validate_const },
	{ .primary = "enum",			.func = validate_enum },
	{ .primary = "anyOf",			.func = validate_anyof },
	{ .primary = "allOf",			.func = validate_allof },
	{ .primary = "oneOf",			.func = validate_oneof },
	{ .primary = "not",			.func = validate_not },
	{
		.primary = "if",
		.secondary = (const char *[]) { "then", "else", NULL },
		.func = validate_if_then_else
	},
	/* numerics */
	{ .primary = "multipleOf",		.func = validate_multipleof },
	{ .primary = "maximum",			.func = validate_maximum },
	{ .primary = "exclusiveMaximum",	.func = validate_exclusive_maximum },
	{ .primary = "minimum",			.func = validate_minimum },
	{ .primary = "exclusiveMinimum",	.func = validate_exclusive_minimum },

	/* string */
	{ .primary = "pattern",			.func = validate_pattern },
	{ .primary = "maxLength",		.func = validate_max_length },
	{ .primary = "minLength",		.func = validate_min_length },
	{ .primary = "format",			.func = validate_format },

	/* array */
	{ .primary = "items",			.func = validate_items },
	{
		.primary = "contains",
		.secondary = (const char *[]) { "minContains", "maxContains", NULL },
		.func = validate_contains
	},
	{ .primary = "uniqueItems",		.func = validate_unique_items },
	{ .primary = "minItems",		.func = validate_min_items },
	{ .primary = "maxItems",		.func = validate_max_items },

	/* object checks */
	{ .primary = "properties",		.func = validate_properties },
	{ .primary = "patternProperties",	.func = validate_pattern_properties },
	{ .primary = "propertyNames",		.func = validate_property_names },
	{ .primary = "additionalProperties",	.func = validate_additional_properties },
	{ .primary = "minProperties",		.func = validate_min_properties },
	{ .primary = "maxProperties",		.func = validate_max_properties },
	{ .primary = "required",		.func = validate_required },
	{ .primary = "dependentRequired",	.func = validate_dependent_required },
	{ .primary = "dependentSchemas",	.func = validate_dependent_schemas },
	{ .primary = "dependencies",		.func = validate_dependencies },

	/* content */
	{ .primary = "contentEncoding",		.func = validate_content_encoding },
	{
		.primary = "contentMediaType",
		.secondary = (const char *[]) { "contentEncoding", NULL },
		.func = validate_content_media_type
	},

	{ .primary = NULL, 			.func = NULL }
};

static struct fy_node *
lookup_for_uri_match(struct fyjs_validate_ctx *vc,
		     struct fy_node *fynt_root, struct fy_node *fynt,
		     struct fy_uri *urip, const char *base)
{
	struct fy_node *fynt_defs, *fynt_key, *fynt_value, *fynt_match;
	struct fy_node_pair *fynp;
	const char *id_str, *anchor_str;
	char *this_uri, *s , *e;
	void *iter;
	struct fy_uri urip_id, urip_base;
	int rc, this_uri_len;

	memset(&urip_id, 0, sizeof(urip_id));
	memset(&urip_base, 0, sizeof(urip_base));

	if (vc->verbose)
		fprintf(stderr, "base: %s\n", base);

	id_str = get_value(fynt, vc->id_str);
	if (id_str) {

		if (vc->verbose)
			fprintf(stderr, "%s: %s\n", vc->id_str, id_str);

		rc = fy_parse_uri_ext(id_str, &urip_id, URI_REF);
		if (rc)
			return NULL;
		this_uri_len = strlen(base) + 1 + urip_id.uri_len + 1;
		this_uri = alloca(this_uri_len);
		this_uri[0] = this_uri[this_uri_len] = '\0';
		s = this_uri;
		e = s + this_uri_len;

		if (uri_absolute_path(&urip_id)) {
			s += snprintf(s, e - s, "%.*s%s" "%.*s",
					(int)urip_id.scheme_len, urip_id.scheme, urip_id.scheme_len ? "://" : "",
					(int)urip_id.authority_len, urip_id.authority);

			if (urip_id.path_len)
				s += snprintf(s, e - s, "%.*s",
					(int)urip_id.path_len, urip_id.path);
			else
				s += snprintf(s, e - s, "/");
		} else {
			rc = fy_parse_uri_ext(base, &urip_base, URI_REF);
			if (rc)
				return NULL;

			s += snprintf(s, e - s, "%.*s%s" "%.*s",
					(int)urip_base.scheme_len, urip_base.scheme, urip_base.scheme_len ? "://" : "",
					(int)urip_base.authority_len, urip_base.authority);
			s += snprintf(s, e - s, "%s%.*s",
					urip_id.path_len > 0 && urip_id.path[0] != '/' ? "/" : "",
					(int)urip_id.path_len, urip_id.path);
		}

		base = this_uri;
	}

	rc = fy_parse_uri_ext(base, &urip_base, URI_REF);
	if (rc)
		return NULL;

	if (vc->verbose) {
		dump_uri("lookup-uri", urip);
		dump_uri("lookup-base", &urip_base);
	}

	fynt_match = NULL;

	if (urip->fragment && uri_authority_eq(urip, &urip_base)) {

		/* only a #fragment */
		if (!urip->fragment_len) 	/* empty fragment too URI='#' */
			fynt_match = fynt;
		else if (urip->fragment[0] == '/') 	/* absolute path */
			fynt_match = fy_node_by_path(fynt,
					urip->fragment, urip->fragment_len,
					FYNWF_PTR_JSON | FYNWF_URI_ENCODED);
		else if ((anchor_str = get_value(fynt, "$anchor")) != NULL &&
			 strlen(anchor_str) == (size_t)urip->fragment_len &&
			 !memcmp(anchor_str, urip->fragment, urip->fragment_len))
			fynt_match = fynt;
		else if (uri_fragment_only(&urip_id) && uri_fragment_only(urip) &&
				uri_fragment_eq(&urip_id, urip))
			fynt_match = fynt;	/* draft 7 */

	} else if (!urip->fragment && uri_authority_eq(urip, &urip_base) && uri_path_eq(urip, &urip_base))
		fynt_match = fynt;

	if (fynt_match)
		return fynt_match;

	fynt_defs = fy_node_mapping_lookup_value_by_simple_key(fynt, "$defs", FY_NT);

	if (!fynt_defs)	/* draft 7 */
		fynt_defs = fy_node_mapping_lookup_value_by_simple_key(fynt, "definitions", FY_NT);

	if (!fynt_defs)
		return NULL;

	iter = NULL;
	while ((fynp = fy_node_mapping_iterate(fynt_defs, &iter)) != NULL) {
		fynt_key = fy_node_pair_key(fynp);
		fynt_value = fy_node_pair_value(fynp);

		if (!fynt_key || !fy_node_is_scalar(fynt_key) || fy_node_is_alias(fynt_key))
			continue;

		if (!fynt_value || !fy_node_is_mapping(fynt_value))
			continue;

		fynt_match = lookup_for_uri_match(vc, fynt_root, fynt_value, urip, base);
		if (fynt_match)
			return fynt_match;
	}

	return NULL;
}

struct fy_node *deref_ref(struct fyjs_validate_ctx *vc, struct fy_node *fynt, const char *ref_str,
			  struct fy_node **fynt_root2p)
{
	struct fy_node *fynt_root = vc->fynt_root;
	struct fy_node *fynt_parent, *fynt_match, *fynt_iter, *fynt_root2 = NULL;
	struct fy_node *fynt_content;
	struct fy_uri urip_ref, urip_id;
	const char *id_str;
	char *full_id, *s, *e;
	int rc, i, count, pass, ids_count, full_id_len;
	struct fy_node **fynt_ids;
	struct remote *r, *rfound;
	const char *trest;
	int trest_len;
	char *newurl, *newfile, *out_fynt, *ref_url;
	struct fy_document *fyd;
	bool need_slash;
	size_t len;
	struct fy_node *fyn;
	void *iter;
	bool fail_if_no_cache = false;
	time_t utc_time;
	const char *origin;
	char ctime_buf[32];
	struct stat st;

	memset(&urip_ref, 0, sizeof(urip_ref));
	memset(&urip_id, 0, sizeof(urip_id));

	*fynt_root2p = fynt_root;

	rc = fy_parse_uri_ext(ref_str, &urip_ref, URI_REF);
	if (rc)
		return NULL;

	if (vc->verbose) {
		fprintf(stderr, "\n");
		dump_uri("deref_ref original ref", &urip_ref);

		out_fynt = fy_emit_node_to_string(fynt, FYECF_MODE_FLOW_ONELINE);
		fprintf(stderr, "fynt: %s\n", out_fynt);
		free(out_fynt);
	}

	/* if it's a relative path, need to traverse up to fynt_root */
	if (uri_empty(&urip_ref) || !uri_relative_path(&urip_ref))
		goto skip_rel_ref;

	/* traverse parents until we get to the root or an absolute path */
	count = 0;
	fynt_ids = NULL;
	ids_count = 0;
	full_id_len = urip_ref.uri_len + 1;
	for (pass = 1; pass <= 2; pass++) {
		memset(&urip_id, 0, sizeof(urip_id));
		fynt_parent = fynt;
		i = 0;
		do {
			fynt_parent = fy_node_get_parent(fynt_parent);
			if (!fynt_parent)
				break;

			id_str = get_value(fynt_parent, vc->id_str);
			if (id_str && fy_parse_uri_ext(id_str, &urip_id, URI_REF) == 0) {
				if (pass == 2) {
					fynt_ids[i] = fynt_parent;
					full_id_len += strlen(id_str) + 1;
				}
				i++;
				if (uri_absolute_path(&urip_id))
					break;
			}
			memset(&urip_id, 0, sizeof(urip_id));

		} while (fynt_parent && fynt_parent != fynt_root);

		if (pass == 1) {
			count = i;
			ids_count = count;
			if (!ids_count)
				break;
			fynt_ids = alloca(sizeof(*fynt_ids) * ids_count);
			memset(fynt_ids, 0, sizeof(*fynt_ids) * ids_count);
		}
	}

	full_id = alloca(full_id_len + 1);
	full_id[0] = full_id[full_id_len] = '\0';

	s = full_id;
	e = s + full_id_len;

	i = count - 1;
	if (i >= 0) {
		fynt_parent = fynt_ids[i--];
		id_str = get_value(fynt_parent, vc->id_str);
		if (!id_str)
			return NULL;

		rc = fy_parse_uri_ext(id_str, &urip_id, URI_REF);
		if (rc)
			return NULL;

		s += snprintf(s, e - s, "%.*s%s" "%.*s" "%.*s",
				(int)urip_id.scheme_len, urip_id.scheme, urip_id.scheme_len ? "://" : "",
				(int)urip_id.authority_len, urip_id.authority,
				(int)urip_id.nslug_len, urip_id.nslug);

		// fprintf(stderr, "start: full_id=%s\n", full_id);
		// fprintf(stderr, "start: absolute %s=%s\n", vc->id_str, id_str);

		while (i >= 0) {
			fynt_parent = fynt_ids[i--];
			id_str = get_value(fynt_parent, vc->id_str);
			if (!id_str)
				return NULL;

			rc = fy_parse_uri_ext(id_str, &urip_id, URI_REF);
			if (rc)
				return NULL;

			s += snprintf(s, e - s, "%.*s",
					(int)urip_id.path_len, urip_id.path);

			// fprintf(stderr, "rel: full_id=%s\n", full_id);
			// fprintf(stderr, "rel: $id=%s\n", id_str);
		}
	}

	// dump_uri("original ref", &urip_ref);

	s += snprintf(s, e - s, "%.*s" "%s%.*s%s%.*s",
			(int)urip_ref.path_len, urip_ref.path,
			urip_ref.query ? "&" : "", (int)urip_ref.query_len, urip_ref.query,
			urip_ref.fragment ? "#" : "", (int)urip_ref.fragment_len, urip_ref.fragment);

	// fprintf(stderr, "full_id=%s\n", full_id);
	rc = fy_parse_uri_ext(full_id, &urip_ref, URI_REF);
	if (rc) {
		fprintf(stderr, "%s: bad URL %s\n", __func__, full_id);
		goto err_out;
	}

skip_rel_ref:

	if (vc->verbose)
		dump_uri("ref-full-path", &urip_ref);

	/* try with the root of the active schema */
	fynt_match = lookup_for_uri_match(vc, fynt_root, fynt_root, &urip_ref, "");
	if (fynt_match)
		return fynt_match;

	/* no authority, no remote mapping possible */
	if (!urip_ref.authority) {
		fprintf(stderr, "%s: reference url contains no authority\n", __func__);
		goto err_out;
	}

do_cache:

	fynt_match = NULL;
	fynt_root2 = fy_document_root(vc->fyd_cache);
	iter = NULL;
	while (!fynt_match && (fynt_iter = fy_node_sequence_iterate(fynt_root2, &iter)) != NULL) {
		id_str = get_value(fynt_iter, vc->id_str);
		fynt_content = fy_node_mapping_lookup_value_by_simple_key(fynt_iter, "content", FY_NT);
		if (!id_str || fy_parse_uri_ext(id_str, &urip_id, URI_REF) != 0 || !fynt_content)
			continue;

		if (!(urip_id.path && urip_id.path_len <= urip_ref.path_len &&
			!memcmp(urip_id.path, urip_ref.path, urip_id.path_len)))
			continue;

		trest = urip_ref.path + urip_id.path_len;
		trest_len = urip_ref.path_len - urip_id.path_len;

		len = urip_id.uri_len;
		need_slash = (len > 1 && urip_id.uri[len-1] != '/') &&
			     trest_len > 1 && trest[0] != '/';
		rc = asprintf(&newurl, "%.*s%s%.*s",
				(int)urip_id.uri_len, urip_id.uri,
				need_slash ? "/" : "", trest_len, trest);
		if (rc == -1) {
			fprintf(stderr, "%s: out of memory\n", __func__);
			goto err_out;
		}

		fynt_match = lookup_for_uri_match(vc, fynt_content, fynt_content, &urip_ref, newurl);
		free(newurl);
		newurl = NULL;
		if (fynt_match) {
			*fynt_root2p = fynt_content;
			return fynt_match;
		}
	}

	if (fail_if_no_cache)
		return NULL;

	/* no match still */
	newfile = NULL;
	newurl = NULL;

	rfound = NULL;
	TAILQ_FOREACH(r, &vc->rl, entry) {

		if (!uri_falls_under(&r->urip, &urip_ref))
			continue;

		trest = urip_ref.path + r->urip.path_len;
		trest_len = urip_ref.path_len - r->urip.path_len;

		len = strlen(r->dir);
		need_slash = (len > 1 && r->dir[len-1] != '/') &&
			     trest_len > 1 && trest[0] != '/';
		rc = asprintf(&newfile, "%s%s%.*s", r->dir,
				need_slash ? "/" : "", trest_len, trest);
		if (rc == -1) {
			fprintf(stderr, "%s: out of memory\n", __func__);
			goto err_out;
		}

		len = strlen(r->baseurl);
		need_slash = (len > 1 && r->baseurl[len-1] != '/') &&
			     trest_len > 1 && trest[0] != '/';
		rc = asprintf(&newurl, "%s%s%.*s", r->baseurl,
				need_slash ? "/" : "", trest_len, trest);
		if (rc == -1) {
			fprintf(stderr, "%s: out of memory\n", __func__);
			goto err_out;
		}

		fyd = fy_document_build_from_file(schema_cfg(newfile), newfile);

		/* loaded */
		if (fyd) {
			fynt_root2 = fy_document_root(fyd);

			fynt_match = lookup_for_uri_match(vc, fynt_root2, fynt_root2, &urip_ref, newurl);
			if (fynt_match) {
				rfound = r;
				break;
			}
		}

		free(newfile);
		newfile = NULL;
		free(newurl);
		newurl = NULL;
		fy_document_destroy(fyd);
		fyd = NULL;
	}
	r = rfound;

	/* failed to find locally */
	if (!r) {

		ref_url = alloca(urip_ref.uri_len + 1);
		memcpy(ref_url, urip_ref.uri, urip_ref.uri_len);
		ref_url[urip_ref.uri_len] = '\0';

		fyd = fy_curl_get_document(vc->curl_handle, NULL, ref_url);
		if (!fyd) {
			fprintf(stderr, "%s: failed to get schema at %s\n", __func__,
					ref_url);
			goto err_out;
		}

		utc_time = fy_curl_get_filetime(vc->curl_handle);

		fynt_root2 = fy_document_root(fyd);
		if (vc->verbose)
			fprintf(stderr, "match from online url %s\n", ref_url);

		origin = ref_url;
	} else {
		/* the file must exist */
		rc = stat(newfile, &st);
		if (rc) {
			fprintf(stderr, "%s: failed to stat %s\n", __func__, newfile);
			goto err_out;
		}

		/* get last modification time */
		utc_time = st.st_mtime;

		ref_url = newurl;
		s = realpath(newfile, NULL);
		if (!s) {
			fprintf(stderr, "%s: realpath() failed\n", __func__);
			goto err_out;
		}
		rc = asprintf(&e, "file://%s", s);
		free(s);
		if (rc == -1) {
			fprintf(stderr, "%s: out of memory\n", __func__);
			goto err_out;
		}
		free(newfile);
		newfile = e;
		origin = newfile;
	}

	/* get at least the current time */
	if (utc_time == (time_t)-1)
		utc_time = time(NULL);

	if (vc->verbose && utc_time != (time_t)-1)
		fprintf(stderr, "timestamp: %s\n",
				ctime_chomp(&utc_time, ctime_buf));

	fyn = fy_node_buildf(vc->fyd_cache,
			"{ \"%s\": \"%s\", \"origin\": \"%s\", "
			"\"timestamp\": %llu, "
			"\"timestamp-human\": \"%s\", "
			"\"%s\": { } }",
			vc->id_str, ref_url, origin,
			(unsigned long long)utc_time,
			ctime_chomp(&utc_time, ctime_buf),
			"content");
	if (!fyn) {
		fprintf(stderr, "%s: fy_node_buildf() failed\n", __func__);
		goto err_out;
	}

	fynt_content = fy_node_mapping_lookup_value_by_simple_key(fyn, "content", FY_NT);
	if (!fynt_content) {
		fprintf(stderr, "%s: fy_node_mapping_lookup_value_by_simple_key() content lookup failed\n", __func__);
		goto err_out;
	}

	rc = fy_node_insert(fynt_content, fynt_root2);
	if (rc) {
		fprintf(stderr, "%s: fy_node_insert () failed\n", __func__);
		goto err_out;
	}

	rc = fy_node_sequence_append(fy_document_root(vc->fyd_cache), fyn);
	if (rc) {
		fprintf(stderr, "%s: fy_node_sequence_append() failed\n", __func__);
		goto err_out;
	}
	vc->cache_modified = true;

	fyn = NULL;
	fynt_root2 = NULL;

	free(newfile);
	newfile = NULL;

	free(newurl);
	newurl = NULL;

	/* we can destroy the document now */
	fy_document_destroy(fyd);
	fyd = NULL;

	fail_if_no_cache = true;
	goto do_cache;

err_out:
	if (newfile)
		free(newfile);
	if (newurl)
		free(newurl);
	fy_document_destroy(fyd);
	return NULL;
}

static int validate_one(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt)
{
	int ret;
	const struct validate_desc *vd = NULL;
	char *schema_str;
	const char *ref_str, *recanchor_str;
	const char *boolean_value;
	struct fy_node *fynt_ref, *fynt_deref, *fynt_root2;
	struct fy_node *fynt_root_save, *fynt_v = NULL;
	bool set_outmost_anchor, ref_was_recursive;
	enum fyjs_type type;

	if (vc->verbose) {
		schema_str = fy_emit_node_to_string(fynt, FYECF_MODE_FLOW_ONELINE);

		fprintf(stderr, "Validating    \"%s\" against %s - %s\n",
			get_path(fyn), get_path(fynt), schema_str);

		free(schema_str);
		schema_str = NULL;
	}

	/* true/false are special non-property validator */
	type = validate_type_node(fynt);
	if (type == fyjs_boolean) {
		boolean_value = fy_node_get_scalar0(fynt);
		if (!boolean_value) {
			ret = ERROR_INTERNAL_OUT_OF_MEMORY;
			goto out;
		}

		if (!strcmp(boolean_value, "true"))
			ret = VALID;
		else if (!strcmp(boolean_value, "false"))
			ret = INVALID_BOOLEAN_FALSE;
		else
			ret = ERROR_BOOLEAN_NOT_BOOLEAN;

		goto out;
	}

	set_outmost_anchor = false;
	recanchor_str = get_value(fynt, "$recursiveAnchor");
	if (recanchor_str && !strcmp(recanchor_str, "true")) {
		if (!vc->fynt_outmost_anchor) {
			vc->fynt_outmost_anchor = fynt;
			set_outmost_anchor = true;
		}
	}

	ref_was_recursive = false;
	fynt_ref = fy_node_mapping_lookup_value_by_simple_key(fynt, "$ref", FY_NT);
	if (!fynt_ref) {
		fynt_ref = fy_node_mapping_lookup_value_by_simple_key(fynt, "$recursiveRef", FY_NT);
		if (fynt_ref)
			ref_was_recursive = true;
	}

	if (fynt_ref) {
		if (validate_type_node(fynt_ref) != fyjs_string) {
			ret = ERROR_REF_NOT_STR;
			goto out;
		}
		ref_str = fy_node_get_scalar0(fynt_ref);
		if (!ref_str) {
			ret = ERROR_INTERNAL_OUT_OF_MEMORY;
			goto out;
		}

		fynt_deref = deref_ref(vc, fynt, ref_str, &fynt_root2);

		if (!fynt_deref) {
			ret = ERROR_REF_BAD_PATH;
			goto out;
		}

		if (ref_was_recursive) {
			recanchor_str = get_value(fynt_deref, "$recursiveAnchor");
			if (recanchor_str && !strcmp(recanchor_str, "true") && vc->fynt_outmost_anchor)
				fynt_deref = vc->fynt_outmost_anchor;
		}

		/* new root */
		fynt_root_save = vc->fynt_root;
		vc->fynt_root = fynt_root2;

		ret = validate_one(vc, fyn, fynt_deref);

		/* restore root */
		vc->fynt_root = fynt_root_save;

		/* $ref overrides all others */
	} else {

		ret = VALID;
		fynt_v = NULL;
		for (vd = validators; vd->func; vd++) {

			fynt_v = fy_node_mapping_lookup_value_by_simple_key(fynt, vd->primary, FY_NT);
			if (!fynt_v)
				continue;

			ret = vd->func(vc, fyn, fynt, fynt_v);
			if (ret != VALID)
				break;
			fynt_v = NULL;
		}
	}

	/* clear the anchor if we've set it */
	if (set_outmost_anchor)
		vc->fynt_outmost_anchor = NULL;

out:

	if (vc->verbose) {
		if (ret) {
			fprintf(stderr, "Validation of \"%s\" against \"%s\" failed @%s, error=%d.\n",
					get_path(fyn), get_path(fynt), vd ? vd->primary : "$ref", ret);
		} else {
			fprintf(stderr, "Validates     \"%s\" against \"%s\" OK.\n",
					get_path(fyn), get_path(fynt));
		}

	}

	if (!vc->error) {
		vc->error = ret;
		vc->error_node = fyn;
		vc->error_rule_node = fynt;
		vc->error_specific_rule_node = fynt_v;
	}

	return ret;
}

struct fyjs_validate_ctx *
fyjs_context_create(const struct fyjs_validate_cfg *cfg)
{
	struct fyjs_validate_ctx *vc;
	int rc;

	vc = malloc(sizeof(*vc));
	if (!vc)
		return NULL;

	rc = fyjs_context_setup(vc, cfg);
	if (rc) {
		free(vc);
		return NULL;
	}

	return vc;
}

void fyjs_context_destroy(struct fyjs_validate_ctx *vc)
{
	if (!vc)
		return;

	fyjs_context_cleanup(vc);

	free(vc);
}

int fyjs_context_set_cache(struct fyjs_validate_ctx *vc, struct fy_document *fyd)
{
	if (!vc)
		return -1;

	fy_document_destroy(vc->fyd_cache);
	vc->fyd_cache = fyd;

	return 0;
}

struct fy_document *fyjs_context_get_cache(struct fyjs_validate_ctx *vc)
{
	struct fy_document *fyd_cache;
	int rc;

	if (!vc)
		return NULL;

	/* get the cache document */
	fyd_cache = vc->fyd_cache;
	vc->fyd_cache = NULL;

	rc = fyjs_context_reset_cache(vc);
	if (rc) {
		fprintf(stderr, "%s: failed to reset cache\n", __func__);
		fy_document_destroy(fyd_cache);
		return NULL;
	}

	return fyd_cache;
}

bool fyjs_context_is_cache_modified(struct fyjs_validate_ctx *vc)
{
	if (!vc)
		return false;

	return vc->fyd_cache && vc->cache_modified;
}

static struct fy_node *
get_cache_top_rule(struct fyjs_validate_ctx *vc, struct fy_node *fyn)
{
	char *path, *s;

	/* it must be a node of the cache */
	if (!vc || !fyn || fy_node_document(fyn) != vc->fyd_cache)
		return NULL;

	path = get_path(fyn);
	if (!path)
		return NULL;

	/* find where the content starts */
	s = strstr(path, "/content/");
	if (!s)
		return NULL;

	*s = '\0';

	return fy_node_by_path(fy_document_root(vc->fyd_cache),
			path, s - path, FYNWF_DONT_FOLLOW);
}

static const char *
get_cache_top_rule_scalar(struct fyjs_validate_ctx *vc, struct fy_node *fyn, const char *what)
{
	return get_value(get_cache_top_rule(vc, fyn), what);
}

int fyjs_validate(struct fyjs_validate_ctx *vc,
		  struct fy_node *fyn, struct fy_node *fynt)
{
	const char *path;
	const char *msg;
	struct fyjs_validate_ctx_state vcs;
	int rc;

	fyjs_context_save(vc, &vcs);
	fyjs_context_reset(vc);

	vc->fynt_root = fynt;
	rc = validate_one(vc, fyn, fynt);
	if (!rc)
		goto out;

	/* return innermost error */
	if (vc->error) {
		rc = vc->error;

		msg = fyjs_error_text(vc->error);

		path = get_path(vc->error_node);
		if (!msg) {
			fy_node_report(vc->error_node, FYET_ERROR, "return error code #%d - @%s",
					rc, path);
		} else {
			fy_node_report(vc->error_node, FYET_ERROR, "%s - @%s",
					msg, path);
		}
		fy_node_override_report(vc->error_specific_rule_node, FYET_NOTICE,
				get_cache_top_rule_scalar(vc, vc->error_specific_rule_node, "origin"), 0, 0,
				"failing rule");

		vc->error = 0;
		vc->error_node = vc->error_rule_node = vc->error_specific_rule_node = NULL;
	}
out:
	fyjs_context_restore(vc, &vcs);
	return rc;
}

struct fy_document *
fyjs_load_schema_document(struct fyjs_validate_ctx *vc, const char *schema)
{
	struct fy_document *fyd = NULL;
	struct fy_node *fyn, *fynt_content;
	struct fy_uri urip;
	const struct fy_parse_cfg *cfg;
	int rc;
	time_t utc_time = (time_t)-1;
	struct stat st;
	char *s, *e;
	const char *origin;
	const char *id;
	char ctime_buf[32];

	if (!vc || !schema)
		return NULL;

	cfg = schema_cfg(schema);

	/* if it's a URL get it via CURL */
	rc = fy_parse_uri_ext(schema, &urip, 0);
	if (!rc) {
		fyd = fy_curl_get_document(vc->curl_handle, cfg, schema);
		if (!fyd)
			goto err_out;

		utc_time = fy_curl_get_filetime(vc->curl_handle);
		origin = schema;

	} else {
		/* the file must exist */
		rc = stat(schema, &st);
		if (rc)
			goto err_out;

		fyd = fy_document_build_from_file(cfg, schema);
		if (!fyd)
			goto err_out;

		/* get last modification time */
		utc_time = st.st_mtime;

		s = realpath(schema, NULL);
		if (!s)
			goto err_out;
		rc = asprintf(&e, "file://%s", s);
		free(s);
		if (rc == -1)
			goto err_out;

		s = alloca(strlen(e) + 1);
		strcpy(s, e);
		origin = s;
	}

	id = get_value(fy_document_root(fyd), vc->id_str);
	if (!id)
		id = schema;

	/* get at least the current time */
	if (utc_time == (time_t)-1)
		utc_time = time(NULL);

	if (vc->verbose)
		fprintf(stderr, "timestamp: %s\n",
				ctime_chomp(&utc_time, ctime_buf));

	fyn = fy_node_buildf(vc->fyd_cache,
			"{ \"%s\": \"%s\", \"origin\": \"%s\", "
			"\"timestamp\": %llu, "
			"\"timestamp-human\": \"%s\", "
			"\"%s\": { } }",
			vc->id_str, id, origin,
			(unsigned long long)utc_time,
			ctime_chomp(&utc_time, ctime_buf),
			"content");
	if (!fyn) {
		fprintf(stderr, "%s: fy_node_buildf() failed\n", __func__);
		goto err_out;
	}

	fynt_content = fy_node_mapping_lookup_value_by_simple_key(fyn, "content", FY_NT);
	if (!fynt_content) {
		fprintf(stderr, "%s: fy_node_mapping_lookup_value_by_simple_key() content lookup failed\n", __func__);
		goto err_out;
	}

	rc = fy_node_insert(fynt_content, fy_document_root(fyd));
	if (rc) {
		fprintf(stderr, "%s: fy_node_insert () failed\n", __func__);
		goto err_out;
	}

	rc = fy_node_sequence_append(fy_document_root(vc->fyd_cache), fyn);
	if (rc) {
		fprintf(stderr, "%s: fy_node_sequence_append() failed\n", __func__);
		goto err_out;
	}
	vc->cache_modified = true;

	return fyd;
err_out:
	fy_document_destroy(fyd);
	return NULL;
}

void
fyjs_unload_schema_document(struct fy_document *fyd_schema)
{
	fy_document_destroy(fyd_schema);
}

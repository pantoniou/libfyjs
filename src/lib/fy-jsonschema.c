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

struct fy_parse_cfg *
fyjs_parse_cfg(struct fyjs_validate_ctx *vc, const struct fy_parse_cfg *cfg_template,
       struct fy_parse_cfg *cfg_fill)
{
	*cfg_fill = *cfg_template;
	cfg_fill->diag = vc->diag;
	return cfg_fill;
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
		return "invalid type";
	case INVALID_TYPE_WRONG:
		return "wrong type";
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
	case INVALID_PROPERTY:
		return "invalid property";
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
	case INVALID_REQUIRED_MISSING:
		return "missing required property";
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
		return "no match for the given property name";
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
	case INVALID_FORMAT_IRI:
		return "invalid IRI";
	case INVALID_FORMAT_IRI_REFERENCE:
		return "invalid IRI reference";
	case INVALID_FORMAT_URI:
		return "invalid URI";
	case INVALID_FORMAT_URI_REFERENCE:
		return "invalid URI reference";
	case INVALID_FORMAT_URI_TEMPLATE:
		return "invalid URI template";
	case INVALID_FORMAT_JSON_POINTER:
		return "invalid JSON pointer";
	case INVALID_FORMAT_RELJSON_POINTER:
		return "invalid relative JSON pointer";
	case INVALID_ITEMS_NO_MATCH:
		return "no matching item";
	case INVALID_ADDITIONAL_ITEMS_NO_MATCH:
		return "no matching additional item";
	case ERROR_INTERNAL_UNKNOWN:
		return "unknown";
	case ERROR_INTERNAL_OUT_OF_MEMORY:
		return "out of memory";
	case ERROR_INTERNAL_ARGS:
		return "illegal arguments";
	case ERROR_REF_NOT_STR:
		return "reference not a string";
	case ERROR_REF_BAD_PATH:
		return "reference, bad path";
	case ERROR_REF_BAD_URI_REF:
		return "reference, bad uri reference";
	case ERROR_REF_BAD_ID:
		return "reference, bad id property";
	case ERROR_REF_NOT_FOUND:
		return "reference not found";
	case ERROR_REF_NOT_FOUND_REMOTE:
		return "reference not found remotely";
	case ERROR_REF_NOT_FOUND_FILE:
		return "reference not found file";
	case ERROR_TYPE_NOT_SCALAR_OR_SEQ:
		return "type not a scalar or a sequence";
	case ERROR_TYPE_SPEC_INVALID:
		return "type spec is invalid";
	case ERROR_ENUM_NOT_SEQ:
		return "enum is not an array";
	case ERROR_NUMERIC_CONSTRAINT_NAN:
		return "numeric constraint is not a number";
	case ERROR_MULTIPLEOF_LEQ_ZERO:
		return "multiple of was less or equal to zero";
	case ERROR_ANYOF_BAD_SEQ:
		return "any of is not a non-empty sequence";
	case ERROR_PROPERTIES_NOT_MAP:
		return "properties are not a map";
	case ERROR_PROPERTIES_BAD_KEY:
		return "bad property key (not a scalar)";
	case ERROR_PROPERTIES_BAD_VALUE:
		return "bad property value (NULL)";
	case ERROR_PATTERN_NOT_STRING:
		return "pattern is not a string";
	case ERROR_PATTERN_IS_BAD:
		return "bad pattern regular expression";
	case ERROR_STRLEN_CONSTRAINT_NOT_INT:
		return "string length is not an integer";
	case ERROR_STRLEN_CONSTRAINT_NEG:
		return "string length is negative";
	case ERROR_CONTAINS_MIN_NOT_INT:
		return "minContains is not an integer";
	case ERROR_CONTAINS_MIN_NEG:
		return "minContains is negative";
	case ERROR_CONTAINS_MAX_NOT_INT:
		return "maxContains is not an integer";
	case ERROR_CONTAINS_MAX_NEG:
		return "minContains is negative";
	case ERROR_UNIQUE_NOT_BOOL:
		return "uniqueItems is not a boolean";
	case ERROR_MIN_ITEMS_NOT_INT:
		return "minItems is not an integer";
	case ERROR_MAX_ITEMS_NOT_INT:
		return "maxItems is not an integer";
	case ERROR_MIN_ITEMS_OVERFLOW:
		return "minItems integer overflow";
	case ERROR_MAX_ITEMS_OVERFLOW:
		return "maxItems integer overflow";
	case ERROR_MIN_PROPERTIES_NOT_INT:
		return "minProperties is not an integer";
	case ERROR_MAX_PROPERTIES_NOT_INT:
		return "maxProperties is not an integer";
	case ERROR_MIN_PROPERTIES_OVERFLOW:
		return "minProperties integer overflow";
	case ERROR_MAX_PROPERTIES_OVERFLOW:
		return "maxProperties integer overflow";
	case ERROR_DEPENDENCIES_NOT_OBJ:
		return "dependency not an object";
	case ERROR_DEPENDENCIES_BAD_VALUE:
		return "dependency bad value";
	case ERROR_DEPENDENCIES_DEP_NOT_STR:
		return "dependency not a string";
	case ERROR_ALLOF_BAD_SEQ:
		return "allOf must be a non-empty sequence";
	case ERROR_REQUIRED_NOT_ARRAY:
		return "required is not an array";
	case ERROR_REQUIRED_REQ_NOT_STR:
		return "required item is not a string";
	case ERROR_REQUIRED_REQ_IS_DUP:
		return "required item is duplicated";
	case ERROR_ONEOF_BAD_SEQ:
		return "oneOf must be a non-empty sequence";
	case ERROR_PATTERNPROPS_NOT_OBJ:
		return "patternProperties are not an object";
	case ERROR_PATTERNPROPS_BAD_PATTERN:
		return "bad pattern property regular expression";
	case ERROR_CONTENTENC_NOT_STR:
		return "contentEncoding not a string";
	case ERROR_CONTENTENC_BAD:
		return "bad content encoding";
	case ERROR_CONTENTMT_NOT_STR:
		return "contentMediaType not a string";
	case ERROR_FORMAT_NOT_STRING:
		return "format not a string";
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

void result_destroy(struct result_node *rn)
{
	if (!rn || rn->nofree)
		return;

	if (rn->msg)
		free(rn->msg);

	free(rn);
}

void result_list_clear(struct result_list *rl)
{
	struct result_node *rn;

	if (!rl)
		return;

	while (!TAILQ_EMPTY(rl)) {
		rn = TAILQ_FIRST(rl);
		TAILQ_REMOVE(rl, rn, entry);
		result_destroy(rn);
	}
}

int result_list_append(struct result_list *rl, const struct fyjs_result *res)
{
	struct result_node *rn;

	if (!rl || !res)
		return -1;

	rn = malloc(sizeof(*rn));
	if (!rn)
		return -1;

	/* copy all fields by default */
	rn->r = *res;
	if (res->msg)
		rn->msg = strdup(res->msg);

	TAILQ_INSERT_TAIL(rl, rn, entry);

	return 0;
}

const struct fyjs_result *result_list_last(struct result_list *rl)
{
	struct result_node *rn;

	if (!rl)
		return NULL;

	rn = TAILQ_LAST(rl, result_list);
	if (!rn)
		return NULL;
	return &rn->r;
}

void result_list_remove_after(struct result_list *rl, const struct fyjs_result *r)
{
	struct result_node *rn, *rnn;
	bool found;

	if (!rl)
		return;

	if (r) {
		/* iterate until we find it (safer too) */
		found = false;
		TAILQ_FOREACH(rn, rl, entry) {
			if (&rn->r == r) {
				found = true;
				break;
			}
		}

		if (!found)
			return;

		rn = TAILQ_NEXT(rn, entry);
	} else
		rn = TAILQ_FIRST(rl);

	while (rn != NULL) {
		rnn = TAILQ_NEXT(rn, entry);
		TAILQ_REMOVE(rl, rn, entry);
		result_destroy(rn);
		rn = rnn;
	}
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

struct fyjs_validate_ctx_state {
	struct fy_node *fynt_root;
	struct result_list results;
};

void fyjs_context_save(struct fyjs_validate_ctx *vc, struct fyjs_validate_ctx_state *vcs)
{
	vcs->fynt_root = vc->fynt_root;

	TAILQ_INIT(&vcs->results);
	TAILQ_CONCAT(&vcs->results, &vc->results, entry);

	vc->fynt_root = NULL;
}

void fyjs_context_restore(struct fyjs_validate_ctx *vc, struct fyjs_validate_ctx_state *vcs)
{
	vc->fynt_root = vcs->fynt_root;

	TAILQ_CONCAT(&vc->results, &vcs->results, entry);
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

static const char *get_id(struct fyjs_validate_ctx *vc, struct fy_node *fyn)
{
	const char *id;

	/* try for "$id" followed by "id" */
	id = get_value(fyn, "$id");
	if (id)
		return id;

	id = get_value(fyn, "id");
	if (id)
		return id;

	return NULL;
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
	struct fyjs_validate_ctx *vc = arg;
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
		(void)fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, NULL, NULL,
				 "%s:%d @%s", __FILE__, __LINE__, __func__);
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

bool fy_node_compare_json(struct fyjs_validate_ctx *vc, struct fy_node *fyn1, struct fy_node *fyn2)
{
	return fy_node_compare_user(fyn1, fyn2, NULL, NULL, fy_node_scalar_compare_json, vc);
}

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

int fyjs_verror(struct fyjs_validate_ctx *vc, int error,
		struct fy_node *error_node, struct fy_node *error_rule,
		const char *fmt, va_list ap)
{
	struct result_node *rn = NULL;
	va_list ap_copy;
	char *msg = NULL;
	int rc;

	if (error == VALID || !vc)
		return error;

	/* try to allocate by default */
	rn = malloc(sizeof(*rn));
	if (fmt) {
		va_copy(ap_copy, ap);
		rc = vasprintf(&msg, fmt, ap_copy);
		va_end(ap_copy);
	} else
		rc = 0;

	if (!rn || rc == -1) {
		if (rn)
			free(rn);
		if (msg)
			free(msg);
		rn = NULL;
		msg = NULL;

		/* if out of space, abort */
		if (vc->oom.rn_next >= sizeof(vc->oom.rn)/sizeof(vc->oom.rn))
			abort();

		rn = &vc->oom.rn[vc->oom.rn_next++];

		if (fmt) {
			va_copy(ap_copy, ap);
			rc = vsnprintf(vc->oom.buf + vc->oom.rn_buf_next,
				       sizeof(vc->oom.buf) - vc->oom.rn_buf_next - 1,
				       fmt, ap_copy);
			va_end(ap_copy);
			if (rc == -1)
				abort();

			vc->oom.rn_buf_next += rc + 1;
		}
		/* do not free */
		rn->nofree = true;
	} else
		rn->nofree = false;

	memset(&rn->r, 0, sizeof(rn->r));
	rn->r.error = error;
	rn->r.error_node = error_node;
	rn->r.error_rule = error_rule;

	rn->msg = msg;
	rn->r.msg = msg ? : "";

	TAILQ_INSERT_TAIL(&vc->results, rn, entry);

	return error;
}

int fyjs_error(struct fyjs_validate_ctx *vc, int error,
	       struct fy_node *error_node, struct fy_node *error_rule,
	       const char *fmt, ...)
{
	va_list ap;
	int rc;

	va_start(ap, fmt);
	rc = fyjs_verror(vc, error, error_node, error_rule, fmt, ap);
	va_end(ap);

	return rc;
}

static char *uri_split_str(const struct fy_uri *urip)
{
	int rc;
	char *str;

	rc = asprintf(&str, "%s%.*s%s%.*s%s%.*s%s%.*s%s%.*s%s%.*s%s%.*s%s%.*s%s%.*s%s%.*s",
			urip->scheme ? " scheme=" : "", (int)urip->scheme_len, urip->scheme,
			urip->userinfo ? " userinfo=" : "", (int)urip->userinfo_len, urip->userinfo,
			urip->host ? " host=" : "", (int)urip->host_len, urip->host,
			urip->port ? " port=" : "", (int)urip->port_len, urip->port,
			urip->authority ? " authority=" : "", (int)urip->authority_len, urip->authority,
			urip->path ? " path=" : "", (int)urip->path_len, urip->path,
			urip->nslug ? " nslug=" : "", (int)urip->nslug_len, urip->nslug,
			urip->slug ? " slug=" : "", (int)urip->slug_len, urip->slug,
			urip->query ? " query=" : "", (int)urip->query_len, urip->query,
			urip->fragment ? " fragment=" : "", (int)urip->fragment_len, urip->fragment);
	if (rc == -1)
		return NULL;
	return str;
}

static void
fyjs_dump_uri(struct fyjs_validate_ctx *vc, const char *banner, const struct fy_uri *urip)
{
	char *str;

	str = uri_split_str(urip);
	if (!str) {
		(void)fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, NULL, NULL,
				 "%s:%d @%s", __FILE__, __LINE__, __func__);
		return;
	}

	fy_info(vc->diag, "%s: URI=%.*s%s\n", banner, (int)urip->uri_len, urip->uri, str);

	free(str);
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
		return fyjs_error(vc, ERROR_TYPE_NOT_SCALAR_OR_SEQ, fyn, fynt_v, NULL);

	/* get the type of this node */
	vtype = validate_type_node(fyn);
	if (vtype == fyjs_invalid)
		return fyjs_error(vc, INVALID_TYPE, fyn, fynt_v, NULL);

	vtype_mask = 1U << (int)vtype;

	if (fy_node_is_scalar(fyn_type)) {
		type_str = fy_node_get_scalar0(fyn_type);
		if (!type_str)
			return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY,
					  fyn, fynt_v, "%s:%d @%s",
					  __FILE__, __LINE__, __func__);

		type = validate_type_text(type_str);
		if (type == fyjs_invalid)
			return fyjs_error(vc, ERROR_TYPE_SPEC_INVALID, fyn, fynt_v, NULL);

		type_mask = 1U << (int)type;
	} else {
		iter = NULL;
		while ((fyn_iter = fy_node_sequence_iterate(fyn_type, &iter)) != NULL) {
			type_str = fy_node_get_scalar0(fyn_iter);
			if (!type_str)
				return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY,
						  fyn, fynt_v, "%s:%d @%s",
						  __FILE__, __LINE__, __func__);

			type = validate_type_text(type_str);
			if (type == fyjs_invalid)
				return fyjs_error(vc, ERROR_TYPE_SPEC_INVALID, fyn, fynt_v, NULL);

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
			return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY,
					  fyn, fynt_v,  "%s:%d @%s",
					  __FILE__, __LINE__, __func__);

		fyjs_numeric_init(value, false);
		fyjs_numeric_set_str(value, value_str);
		is_integer = fyjs_numeric_is_integer(value);
		fyjs_numeric_clear(value);

		if (is_integer)
			return VALID;
	}

	return fyjs_error(vc, INVALID_TYPE_WRONG, fyn, fynt_v, "was %s", fyjs_type_str(vtype));
}

static int validate_const(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			  struct fy_node *fynt_v)
{
	struct fy_node *fynt_const;
	bool res;

	/* get const node */
	fynt_const = fynt_v;

	res = fy_node_compare_json(vc, fynt_const, fyn);
	if (!res)
		return fyjs_error(vc, INVALID_CONST, fyn, fynt_v, NULL);
	return VALID;

}

static int validate_enum(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			 struct fy_node *fynt_v)
{
	struct fy_node *fynt_enum, *fynt_iter;
	void *iter;

	/* get const node */
	fynt_enum = fynt_v;

	if (!fy_node_is_sequence(fynt_enum))
		return fyjs_error(vc, ERROR_ENUM_NOT_SEQ, fyn, fynt_v, NULL);

	iter = NULL;
	while ((fynt_iter = fy_node_sequence_iterate(fynt_enum, &iter)) != NULL) {
		if (fy_node_compare_json(vc, fynt_iter, fyn))
			return VALID;
	}

	return fyjs_error(vc, INVALID_ENUM, fyn, fynt_v, NULL);
}

static int validate_numeric(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			    struct fy_node *fynt_v, const char *keyword)
{
	struct fy_node *fynt_keyword, *fynt_exclusive;
	enum fyjs_type type, vtype;
	fyjs_numeric constraint, value;
	bool res;
	const char *constraint_str;
	const char *value_str;
	const char *exclusive_str;
	int ret, cmp;
	bool is_exclusive;

	/* get const node */
	fynt_keyword = fynt_v;

	vtype = validate_type_node(fyn);
	if (vtype != fyjs_number && vtype != fyjs_integer)
		return VALID;

	type = validate_type_node(fynt_keyword);
	if (type != fyjs_number && type != fyjs_integer) {

		/* draft4 exclusiveMinimums and maximums are booleans */
		/* so ignore them */
		if (type == fyjs_boolean &&
			(!strcmp(keyword, "exclusiveMaximum") ||
			 !strcmp(keyword, "exclusiveMinimum")))
			return VALID;

		return fyjs_error(vc, ERROR_NUMERIC_CONSTRAINT_NAN, fyn, fynt_v, NULL);
	}

	constraint_str = fy_node_get_scalar0(fynt_keyword);
	value_str = fy_node_get_scalar0(fyn);

	if (!constraint_str || !value_str)
		return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, fyn, fynt_v,
				  "%s:%d @%s", __FILE__, __LINE__, __func__);

	fyjs_numeric_init(constraint, type == fyjs_integer);
	fyjs_numeric_set_str(constraint, constraint_str);
	fyjs_numeric_init(value, vtype == fyjs_integer);
	fyjs_numeric_set_str(value, value_str);

	res = false;

	if (!strcmp(keyword, "multipleOf")) {
		/* protect against division by zero */
		if (fyjs_numeric_cmp_0(constraint) <= 0) {
			ret = fyjs_error(vc, ERROR_MULTIPLEOF_LEQ_ZERO, fyn, fynt_v, NULL);
			goto err_out;
		}
		res = fyjs_numeric_rem_is_0(value, constraint);
		if (!res) {
			ret = fyjs_error(vc, INVALID_MULTIPLEOF_NOT_MULTIPLE, fyn, fynt_v, NULL);
			goto err_out;
		}
	} else if (!strcmp(keyword, "maximum")) {

		/* draft4 */
		is_exclusive = (fynt_exclusive = fy_node_mapping_lookup_value_by_simple_key(
					fynt, "exclusiveMaximum", FY_NT)) &&
				validate_type_node(fynt_exclusive) == fyjs_boolean &&
				(exclusive_str = fy_node_get_scalar0(fynt_exclusive)) != NULL &&
				!strcmp(exclusive_str, "true");

		cmp = fyjs_numeric_cmp(value, constraint);

		res = is_exclusive ? (cmp < 0) : (cmp <= 0);
		if (!res) {
			ret = fyjs_error(vc, INVALID_MAXIMUM_OVER, fyn, fynt_v, NULL);
			goto err_out;
		}
	} else if (!strcmp(keyword, "exclusiveMaximum")) {

		cmp = fyjs_numeric_cmp(value, constraint);

		res = cmp < 0;
		if (!res) {
			ret = fyjs_error(vc, INVALID_EXCLUSIVE_MAXIMUM_OVER, fyn, fynt_v, NULL);
			goto err_out;
		}
	} else if (!strcmp(keyword, "minimum")) {

		/* draft4 */
		is_exclusive = (fynt_exclusive = fy_node_mapping_lookup_value_by_simple_key(
					fynt, "exclusiveMinimum", FY_NT)) &&
				validate_type_node(fynt_exclusive) == fyjs_boolean &&
				(exclusive_str = fy_node_get_scalar0(fynt_exclusive)) != NULL &&
				!strcmp(exclusive_str, "true");

		cmp = fyjs_numeric_cmp(value, constraint);

		res = is_exclusive ? (cmp > 0) : (cmp >= 0);
		if (!res) {
			ret = fyjs_error(vc, INVALID_MINIMUM_UNDER, fyn, fynt_v, NULL);
			goto err_out;
		}
	} else if (!strcmp(keyword, "exclusiveMinimum")) {

		cmp = fyjs_numeric_cmp(value, constraint);

		res = cmp > 0;
		if (!res) {
			ret = fyjs_error(vc, INVALID_EXCLUSIVE_MINIMUM_UNDER, fyn, fynt_v, NULL);
			goto err_out;
		}
	} else {
		/* this should never happen normally */
		assert(0);
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
	int ret, tmpret;
	void *iter;
	const struct fyjs_result *r;

	fynt_anyof = fynt_v;

	if (!fy_node_is_sequence(fynt_anyof) ||
	     fy_node_sequence_is_empty(fynt_anyof))
		return fyjs_error(vc, ERROR_ANYOF_BAD_SEQ, fyn, fynt_v, NULL);

	r = result_list_last(&vc->results);

	iter = NULL;
	ret = INVALID_ANYOF_NO_MATCH;
	while ((fynt_iter = fy_node_sequence_iterate(fynt_anyof, &iter)) != NULL) {

		tmpret = validate_one(vc, fyn, fynt_iter);

		/* return immediately on error */
		if (IS_ERROR(tmpret))
			return tmpret;

		if (tmpret == VALID) {
			ret = VALID;
			continue;
		}

	}

	if (ret == VALID) {
		/* remove the errors that were generated */
		result_list_remove_after(&vc->results, r);
		return VALID;
	}

	return fyjs_error(vc, ret, fyn, fynt_v, NULL);
}

static int validate_allof(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			  struct fy_node *fynt_v)
{
	struct fy_node *fynt_allof, *fynt_iter;
	int ret, tmpret;
	void *iter;

	fynt_allof = fynt_v;

	if (!fy_node_is_sequence(fynt_allof) ||
	     fy_node_sequence_is_empty(fynt_allof))
		return fyjs_error(vc, ERROR_ALLOF_BAD_SEQ, fyn, fynt_v, NULL);

	iter = NULL;
	ret = VALID;
	while ((fynt_iter = fy_node_sequence_iterate(fynt_allof, &iter)) != NULL) {

		tmpret = validate_one(vc, fyn, fynt_iter);
		if (tmpret == VALID)
			continue;

		if (IS_ERROR(tmpret))
			return tmpret;

		ret = INVALID_ALLOF_NO_MATCH;
	}

	if (ret == VALID)
		return VALID;

	return fyjs_error(vc, ret, fyn, fynt_v, NULL);
}

static int validate_oneof(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			  struct fy_node *fynt_v)
{
	struct fy_node *fynt_anyof, *fynt_iter;
	int ret, tmpret;
	void *iter;
	bool match_found;
	const struct fyjs_result *r;

	fynt_anyof = fynt_v;

	if (!fy_node_is_sequence(fynt_anyof) ||
	     fy_node_sequence_is_empty(fynt_anyof))
		return fyjs_error(vc, ERROR_ONEOF_BAD_SEQ, fyn, fynt_v, NULL);

	r = result_list_last(&vc->results);

	match_found = false;
	iter = NULL;
	ret = INVALID_ONEOF_NO_MATCH;
	while ((fynt_iter = fy_node_sequence_iterate(fynt_anyof, &iter)) != NULL) {

		tmpret = validate_one(vc, fyn, fynt_iter);
		/* error, just return immediately */
		if (IS_ERROR(tmpret))
			return tmpret;

		/* invalid, OK */
		if (IS_INVALID(tmpret))
			continue;

		/* match, check if it's the only one */
		if (match_found)
			ret = INVALID_ONEOF_MANY_MATCHES;
		else
			ret = VALID;
		match_found = true;
	}

	if (ret == VALID) {
		/* remove the errors that were generated */
		result_list_remove_after(&vc->results, r);
		return VALID;
	}

	return fyjs_error(vc, ret, fyn, fynt_v, NULL);
}

static int validate_not(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			struct fy_node *fynt_v)
{
	struct fy_node *fynt_not;
	const struct fyjs_result *r;
	int ret, tmpret;

	fynt_not = fynt_v;

	r = result_list_last(&vc->results);

	tmpret = validate_one(vc, fyn, fynt_not);
	/* error, just return immediately */
	if (IS_ERROR(tmpret))
		return tmpret;

	ret = IS_INVALID(tmpret) ? VALID : INVALID_NOT_MATCH;

	if (ret == VALID) {
		/* remove the errors that were expected */
		result_list_remove_after(&vc->results, r);
		return VALID;
	}

	return fyjs_error(vc, ret, fyn, fynt_v, NULL);
}

static int validate_if_then_else(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				 struct fy_node *fynt_v)
{
	struct fy_node *fynt_if, *fynt_then, *fynt_else;
	int ret, tmpret;
	bool if_match;
	const struct fyjs_result *r;

	fynt_if = fynt_v;

	r = result_list_last(&vc->results);

	tmpret = validate_one(vc, fyn, fynt_if);
	/* error, just return immediately */
	if (IS_ERROR(tmpret))
		return tmpret;
	if_match = tmpret == VALID;

	/* remove all errors that were expected */
	result_list_remove_after(&vc->results, r);

	ret = VALID;
	if (if_match && (fynt_then = fy_node_mapping_lookup_value_by_simple_key(fynt, "then", FY_NT)) != NULL) {
		tmpret = validate_one(vc, fyn, fynt_then);
		if (IS_ERROR(tmpret))
			return tmpret;
		if (tmpret != VALID)
			ret = INVALID_THEN_NO_MATCH;

	} else if (!if_match && (fynt_else = fy_node_mapping_lookup_value_by_simple_key(fynt, "else", FY_NT)) != NULL) {
		tmpret = validate_one(vc, fyn, fynt_else);
		if (IS_ERROR(tmpret))
			return tmpret;

		if (tmpret != VALID)
			ret = INVALID_ELSE_NO_MATCH;
	}

	if (ret == VALID)
		return VALID;

	return fyjs_error(vc, ret, fyn, fynt_v, NULL);
}

static int validate_properties(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			       struct fy_node *fynt_v)
{
	struct fy_node *fynt_props, *fynt_key, *fynt_value, *fyn_inst;
	struct fy_node_pair *fynp;
	enum fyjs_type vtype;
	int ret, tmpret;
	void *iter;
	const char *key_str;

	fynt_props = fynt_v;

	if (!fy_node_is_mapping(fynt_props))
		return fyjs_error(vc, ERROR_PROPERTIES_NOT_MAP, fyn, fynt_v, NULL);

	/* ignore non-objects */
	vtype = validate_type_node(fyn);
	if (vtype != fyjs_object)
		return VALID;

	iter = NULL;
	ret = VALID;
	while ((fynp = fy_node_mapping_iterate(fynt_props, &iter)) != NULL) {
		fynt_key = fy_node_pair_key(fynp);
		fynt_value = fy_node_pair_value(fynp);

		if (!fynt_key)
			return fyjs_error(vc, ERROR_PROPERTIES_BAD_KEY, fyn, fynt_v, NULL);

		if (!fynt_value)
			return fyjs_error(vc, ERROR_PROPERTIES_BAD_VALUE, fyn, fynt_v, NULL);

		if (!fy_node_is_scalar(fynt_key) || fy_node_is_alias(fynt_key))
			return fyjs_error(vc, ERROR_PROPERTIES_BAD_KEY, fyn, fynt_key, NULL);

		key_str = fy_node_get_scalar0(fynt_key);
		if (!key_str)
			return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY,
					  fyn, fynt_v, "%s:%d @%s",
					  __FILE__, __LINE__, __func__);

		fyn_inst = fy_node_mapping_lookup_value_by_simple_key(fyn, key_str, FY_NT);

		if (!fyn_inst)
			continue;

		tmpret = validate_one(vc, fyn_inst, fynt_value);
		if (tmpret == VALID)
			continue;

		if (IS_ERROR(tmpret))
			return tmpret;

		if (ret == VALID)
			ret = INVALID_PROPERTY;

		fyjs_error(vc, INVALID_PROPERTY, fyn_inst, fynt_value, "%s", key_str);
	}

	return ret;

}

static int validate_pattern_properties(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				       struct fy_node *fynt_v)
{
	struct fy_node *fynt_patprops, *fynt_key, *fynt_value, *fyn_key, *fyn_value;
	struct fy_node_pair *fynp, *fynpv;
	enum fyjs_type type, vtype;
	void *viter, *iter;
	const char *pattern_str, *pname_str, *error;
	int erroroffset, rc, ret, tmpret;
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
		return fyjs_error(vc, ERROR_PATTERNPROPS_NOT_OBJ, fyn, fynt_v, NULL);

	iter = NULL;
	ret = VALID;
	while ((fynp = fy_node_mapping_iterate(fynt_patprops, &iter)) != NULL) {
		fynt_key = fy_node_pair_key(fynp);
		fynt_value = fy_node_pair_value(fynp);

		if (!fynt_key)
			return fyjs_error(vc, ERROR_PROPERTIES_BAD_KEY, fyn, fynt_v, NULL);

		if (!fynt_value)
			return fyjs_error(vc, ERROR_PROPERTIES_BAD_VALUE, fyn, fynt_v, NULL);

		if (!fy_node_is_scalar(fynt_key) || fy_node_is_alias(fynt_key))
			return fyjs_error(vc, ERROR_PROPERTIES_BAD_KEY, fyn, fynt_key, NULL);

		pattern_str = fy_node_get_scalar0(fynt_key);
		if (!pattern_str)
			return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY,
					  fyn, fynt_v, "%s:%d @%s",
					  __FILE__, __LINE__, __func__);

		re = pcre_compile(pattern_str,
				  PCRE_JAVASCRIPT_COMPAT |
				  (vc->pcre_utf8 ? PCRE_UTF8 : 0) |
				  PCRE_DOLLAR_ENDONLY,
				&error, &erroroffset, NULL);
		if (!re)
			return fyjs_error(vc, ERROR_PATTERNPROPS_BAD_PATTERN, fyn, fynt_key, NULL);

		viter = NULL;
		while ((fynpv = fy_node_mapping_iterate(fyn, &viter)) != NULL) {
			fyn_key = fy_node_pair_key(fynpv);
			fyn_value = fy_node_pair_value(fynpv);

			/* ignore non scalar keys */
			if (!fyn_key || !fy_node_is_scalar(fyn_key) || fy_node_is_alias(fyn_key))
				continue;

			pname_str = fy_node_get_scalar0(fyn_key);
			if (!pname_str) {
				pcre_free(re);
				return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY,
						  fyn, fynt_v, "%s:%d @%s",
						  __FILE__, __LINE__, __func__);
			}

			rc = pcre_exec(re, NULL, pname_str, strlen(pname_str), 0, 0, NULL, 0);
			match = !rc;

			if (!match)
				continue;

			tmpret = validate_one(vc, fyn_value, fynt_value);
			if (tmpret == VALID)
				continue;

			/* some kind of internal error, return just this */
			if (IS_ERROR(tmpret))
				return tmpret;

			if (ret == VALID)
				ret = INVALID_PATTERNPROPS_NO_MATCH;

			fyjs_error(vc, ret, fyn_value, fynt_value, "%s", pname_str);
		}
		pcre_free(re);
		re = NULL;
	}

	return ret;
}

static int validate_property_names(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				   struct fy_node *fynt_v)
{
	struct fy_node *fynt_propnames, *fyn_key;
	struct fy_node_pair *fynp;
	enum fyjs_type vtype;
	int ret, tmpret;
	void *iter;
	const char *key_str;

	fynt_propnames = fynt_v;

	/* ignore non-objects */
	vtype = validate_type_node(fyn);
	if (vtype != fyjs_object)
		return VALID;

	iter = NULL;
	ret = VALID;
	while ((fynp = fy_node_mapping_iterate(fyn, &iter)) != NULL) {
		fyn_key = fy_node_pair_key(fynp);

		/* ignore non scalars */
		if (!fyn_key || !fy_node_is_scalar(fyn_key) || fy_node_is_alias(fyn_key))
			continue;

		key_str = fy_node_get_scalar0(fyn_key);
		if (!key_str)
			return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY,
					  fyn, fynt_v, "%s:%d @%s",
					  __FILE__, __LINE__, __func__);

		tmpret = validate_one(vc, fyn_key, fynt_propnames);
		if (tmpret == VALID)
			continue;

		/* some kind of internal error, return just this */
		if (IS_ERROR(tmpret))
			return tmpret;

		if (ret == VALID)
			ret = INVALID_PROPNAMES_NO_MATCH;

		fyjs_error(vc, ret, fyn_key, fynt_propnames, "%s", key_str);
	}

	return ret;
}

static int validate_additional_properties(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
					  struct fy_node *fynt_v)
{
	struct fy_node *fynt_addprops, *fynt_props, *fynt_patprops, *fyn_key, *fynt_key2, *fyn_value;
	struct fy_node_pair *fynp, *fynp2;
	enum fyjs_type vtype;
	int erroroffset, rc, ret, tmpret;
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
	ret = VALID;
	while ((fynp = fy_node_mapping_iterate(fyn, &iter)) != NULL) {

		fyn_key = fy_node_pair_key(fynp);
		fyn_value = fy_node_pair_value(fynp);

		/* only scalar keys */
		if (!fyn_key || !fy_node_is_scalar(fyn_key) ||
				  fy_node_is_alias(fyn_key))
			continue;

		if (!fyn_value)
			continue;

		key_str = fy_node_get_scalar0(fyn_key);
		if (!key_str)
			return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY,
					  fyn, fynt_v, "%s:%d @%s",
					  __FILE__, __LINE__, __func__);

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
		tmpret = validate_one(vc, fyn_value, fynt_addprops);
		if (tmpret == VALID)
			continue;

		/* some kind of internal error, return just this */
		if (IS_ERROR(tmpret))
			return tmpret;

		if (ret == VALID)
			ret = INVALID_ADDPROPS_NO_MATCH;

		fyjs_error(vc, ret, fyn_value, fynt_addprops, "%s", key_str);
	}

	return ret;
}

static int validate_pattern(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			    struct fy_node *fynt_v)
{
	struct fy_node *fynt_pattern;
	enum fyjs_type vtype;
	const char *error, *pattern_str;
	int erroroffset, rc, ret;
	const char *value;
	pcre *re;
	bool match;

	/* get const node */
	fynt_pattern = fynt_v;

	if (!fy_node_is_scalar(fynt_pattern) || fy_node_is_alias(fynt_pattern))
		return fyjs_error(vc, ERROR_PATTERN_NOT_STRING, fyn, fynt_v, NULL);

	vtype = validate_type_node(fyn);
	if (vtype != fyjs_string)
		return VALID;

	value = fy_node_get_scalar0(fyn);
	pattern_str = fy_node_get_scalar0(fynt_pattern);
	if (!value || !pattern_str)
		return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY,
				  fyn, fynt_v, "%s:%d @%s",
				  __FILE__, __LINE__, __func__);

	re = pcre_compile(pattern_str,
			  PCRE_JAVASCRIPT_COMPAT |
			  (vc->pcre_utf8 ? PCRE_UTF8 : 0) |
			  PCRE_DOLLAR_ENDONLY,
			&error, &erroroffset, NULL);
	if (!re)
		return fyjs_error(vc, ERROR_PATTERN_IS_BAD, fyn, fynt_v, NULL);

	rc = pcre_exec(re, NULL, value, strlen(value), 0, 0, NULL, 0);
	match = !rc;
	pcre_free(re);

	if (match)
		return VALID;

	ret = INVALID_PATTERN_NO_MATCH;
	return fyjs_error(vc, ret, fyn, fynt_v, "%s", value);
}

static int validate_string_length(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				  struct fy_node *fynt_v, const char *keyword)
{
	struct fy_node *fynt_constraint;
	enum fyjs_type type, vtype;
	const char *constraint_str;
	long constraint_i;
	size_t constraint, len;

	fynt_constraint = fynt_v;

	vtype = validate_type_node(fyn);
	if (vtype != fyjs_string)
		return VALID;

	type = validate_type_node(fynt_constraint);
	if (type != fyjs_integer)
		return fyjs_error(vc, ERROR_STRLEN_CONSTRAINT_NOT_INT, fyn, fynt_v, NULL);

	constraint_str = fy_node_get_scalar0(fynt_constraint);
	if (!constraint_str)
		return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY,
				  fyn, fynt_v, "%s:%d @%s",
				  __FILE__, __LINE__, __func__);

	constraint_i = strtol(constraint_str, NULL, 10);
	if (constraint_i < 0)
		return fyjs_error(vc, ERROR_STRLEN_CONSTRAINT_NEG, fyn, fynt_v, NULL);

	constraint = constraint_i;

	len = fy_node_get_scalar_utf8_length(fyn);

	if (!strcmp(keyword, "minLength")) {
		if (len < constraint)
			return fyjs_error(vc, INVALID_MINLENGTH_UNDER, fyn, fynt_v, NULL);

		return VALID;

	}

	if (!strcmp(keyword, "maxLength")) {

		if (len > constraint)
			return fyjs_error(vc, INVALID_MAXLENGTH_OVER, fyn, fynt_v, NULL);

		return VALID;
	}

	/* should never get to here */
	assert(0);
	return VALID;
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
	int ret, tmpret;
	void *iter_items, *iter_values;

	fynt_items = fynt_v;

	/* ignore non-arrays */
	vtype = validate_type_node(fyn);
	if (vtype != fyjs_array)
		return VALID;

	ret = VALID;

	if (!fy_node_is_sequence(fynt_items)) {

		/* all items must match single schema */
		iter_values = NULL;
		while ((fyn_value = fy_node_sequence_iterate(fyn, &iter_values)) != NULL) {

			tmpret = validate_one(vc, fyn_value, fynt_items);

			if (tmpret == VALID)
				continue;

			if (IS_ERROR(tmpret))
				return tmpret;

			if (ret == VALID)
				ret = INVALID_ITEMS_NO_MATCH;

			fyjs_error(vc, ret, fyn_value, fynt_items, NULL);
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

			tmpret = validate_one(vc, fyn_value, fynt_item);
			if (tmpret == VALID)
				continue;

			if (IS_ERROR(tmpret))
				return tmpret;

			if (ret == VALID)
				ret = INVALID_ITEMS_NO_MATCH;

			fyjs_error(vc, ret, fyn_value, fynt_item, NULL);
		}

		/* if additionalItems exist */
		if (fyn_value &&
		    (fynt_additional_items = fy_node_mapping_lookup_value_by_simple_key(fynt, "additionalItems", FY_NT)) != NULL) {

			do {
				tmpret = validate_one(vc, fyn_value, fynt_additional_items);
				if (tmpret != VALID) {

					if (IS_ERROR(tmpret))
						return tmpret;

					if (ret == VALID)
						ret = INVALID_ADDITIONAL_ITEMS_NO_MATCH;

					fyjs_error(vc, ret, fyn_value, fynt_additional_items, NULL);
				}

				fyn_value = fy_node_sequence_iterate(fyn, &iter_values);
			} while (fyn_value);
		}
	}

	return ret;
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
			return fyjs_error(vc, ERROR_CONTAINS_MIN_NOT_INT, fyn, fynt_min_contains, NULL);

		min_str = fy_node_get_scalar0(fynt_min_contains);
		if (!min_str)
			return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY,
					  fyn, fynt_min_contains, "%s:%d @%s",
					  __FILE__, __LINE__, __func__);

		min_contains = (int)strtol(min_str, NULL, 10);
		if (min_contains < 0)
			return fyjs_error(vc, ERROR_CONTAINS_MIN_NEG, fyn, fynt_min_contains, NULL);
	}

	fynt_max_contains = fy_node_mapping_lookup_value_by_simple_key(fynt, "maxContains", FY_NT);
	if (fynt_max_contains) {
		if (validate_type_node(fynt_max_contains) != fyjs_integer)
			return fyjs_error(vc, ERROR_CONTAINS_MAX_NOT_INT, fyn, fynt_max_contains, NULL);

		max_str = fy_node_get_scalar0(fynt_max_contains);
		if (!max_str)
			return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY,
					  fyn, fynt_max_contains, "%s:%d @%s",
					  __FILE__, __LINE__, __func__);

		max_contains = (int)strtol(max_str, NULL, 10);
		if (max_contains < 0)
			return fyjs_error(vc, ERROR_CONTAINS_MAX_NEG, fyn, fynt_max_contains, NULL);
	}

	/* XXX mark errors */
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
		return fyjs_error(vc, INVALID_CONTAINS_NONE, fyn, fynt_v, NULL);

	/* less than min */
	if (min_contains >= 0 && nr_contains < min_contains)
		return fyjs_error(vc, INVALID_CONTAINS_NOT_ENOUGH, fyn, fynt_v, NULL);

	/* more than max */
	if (max_contains >= 0 && nr_contains > max_contains)
		return fyjs_error(vc, INVALID_CONTAINS_TOO_MANY, fyn, fynt_v, NULL);

	/* XXX rollback all errors */

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
	int ret;

	/* get contains node */
	fynt_unique = fynt_v;

	/* ignore non-arrays */
	vtype = validate_type_node(fyn);
	if (vtype != fyjs_array)
		return VALID;

	if (validate_type_node(fynt_unique) != fyjs_boolean)
		return fyjs_error(vc, ERROR_UNIQUE_NOT_BOOL, fyn, fynt_v, NULL);

	boolean_str = fy_node_get_scalar0(fynt_unique);
	if (!boolean_str)
		return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY,
				  fyn, fynt_v, "%s:%d @%s",
				  __FILE__, __LINE__, __func__);

	/* if set to false, return valid immediately */
	if (!strcmp(boolean_str, "false"))
		return VALID;

	iter_values1 = NULL;
	ret = VALID;
	while ((fyn_value1 = fy_node_sequence_iterate(fyn, &iter_values1)) != NULL) {

		iter_values2 = NULL;
		while ((fyn_value2 = fy_node_sequence_iterate(fyn, &iter_values2)) != NULL) {

			/* do not check with self */
			if (fyn_value1 == fyn_value2)
				continue;

			if (fy_node_compare_json(vc, fyn_value1, fyn_value2)) {
				if (ret == VALID)
					ret = INVALID_UNIQUE_NOT_UNIQUE;

				fyjs_error(vc, ret, fyn_value1, fynt_unique, NULL);
			}
		}
	}

	return ret;
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
		return fyjs_error(vc,
				  min ? ERROR_MIN_ITEMS_NOT_INT : ERROR_MAX_ITEMS_NOT_INT,
				  fyn, fynt_v, NULL);

	minmax_str = fy_node_get_scalar0(fynt_minmax);
	if (!minmax_str)
		return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, fyn, fynt_v,
				  "%s:%d @%s", __FILE__, __LINE__, __func__);

	minmax = strtol(minmax_str, NULL, 10);
	if (minmax == LONG_MAX && errno == ERANGE) {
		errno = 0;
		return fyjs_error(vc,
				  min ? ERROR_MIN_ITEMS_OVERFLOW : ERROR_MAX_ITEMS_OVERFLOW,
				  fyn, fynt_v,
				  NULL);
	}

	count = fy_node_sequence_item_count(fyn);
	if (min && count < minmax)
		return fyjs_error(vc, INVALID_MIN_ITEMS_NOT_ENOUGH, fyn, fynt_v, "(%d)", count);

	if (!min && count > minmax)
		return fyjs_error(vc, INVALID_MAX_ITEMS_TOO_MANY, fyn, fynt_v, "(%d)", count);

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
		return fyjs_error(vc,
				  min ? ERROR_MIN_PROPERTIES_NOT_INT : ERROR_MAX_PROPERTIES_NOT_INT,
				  fyn, fynt_v, NULL);

	minmax_str = fy_node_get_scalar0(fynt_minmax);
	if (!minmax_str)
		return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, fyn, fynt_v,
				  "%s:%d @%s", __FILE__, __LINE__, __func__);

	minmax = strtol(minmax_str, NULL, 10);
	if (minmax == LONG_MAX && errno == ERANGE) {
		errno = 0;
		return fyjs_error(vc,
				  min ? ERROR_MIN_PROPERTIES_OVERFLOW : ERROR_MAX_PROPERTIES_OVERFLOW,
				  fyn, fynt_v, NULL);
	}

	count = fy_node_mapping_item_count(fyn);
	if (min && count < minmax)
		return fyjs_error(vc, INVALID_MIN_PROPERTIES_NOT_ENOUGH, fyn, fynt_v, "(%d)", count);

	if (!min && count > minmax)
		return fyjs_error(vc, INVALID_MAX_PROPERTIES_TOO_MANY, fyn, fynt_v, "(%d)", count);

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
	int ret;

	fynt_required = fynt_v;

	/* validate it's a sequence */
	if (!fy_node_is_sequence(fynt_required))
		return fyjs_error(vc, ERROR_REQUIRED_NOT_ARRAY, fyn, fynt_v, NULL);

	/* ignore non-objects */
	vtype = validate_type_node(fyn);
	if (vtype != fyjs_object)
		return VALID;

	iter_values1 = NULL;
	ret = VALID;
	while ((fynt_value1 = fy_node_sequence_iterate(fynt_required, &iter_values1)) != NULL) {

		/* check that the value is a string */
		if (validate_type_node(fynt_value1) != fyjs_string)
			return fyjs_error(vc, ERROR_REQUIRED_REQ_NOT_STR, fyn, fynt_value1, NULL);

		value1_str = fy_node_get_scalar(fynt_value1, &value1_len);
		if (!value1_str)
			return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY,
					  fyn, fynt_value1, "%s:%d @%s",
					  __FILE__, __LINE__, __func__);

		/* verify that the property is not duplicated */
		iter_values2 = NULL;
		while ((fynt_value2 = fy_node_sequence_iterate(fynt_required, &iter_values2)) != NULL) {

			/* do not check with self */
			if (fynt_value1 == fynt_value2)
				continue;

			/* compare */
			if (fy_node_compare_json(vc, fynt_value1, fynt_value2))
				return fyjs_error(vc, ERROR_REQUIRED_REQ_IS_DUP, fyn, fynt_value1, NULL);
		}

		/* required property must exist */
		if (fy_node_mapping_lookup_value_by_simple_key(fyn, value1_str, value1_len))
			continue;

		if (ret == VALID)
			ret = INVALID_REQUIRED_MISSING;

		fyjs_error(vc, ret, fyn, fynt_value1, "\"%.*s\"", (int)value1_len, value1_str);
	}

	return ret;
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
	int tmpret, ret;

	assert(dep_type == fyjsdt_required || dep_type == fyjsdt_schemas || dep_type == fyjsdt_dependencies);

	/* get depend* node */
	fynt_dreq = fynt_v;

	/* ignore non-objects */
	vtype = validate_type_node(fyn);
	if (vtype != fyjs_object)
		return VALID;

	if (validate_type_node(fynt_dreq) != fyjs_object)
		return fyjs_error(vc, ERROR_DEPENDENCIES_NOT_OBJ, fyn, fynt_v, NULL);

	iter_dreq = NULL;
	ret = VALID;
	while ((fynp = fy_node_mapping_iterate(fynt_dreq, &iter_dreq)) != NULL) {
		fynt_key = fy_node_pair_key(fynp);
		fynt_value = fy_node_pair_value(fynp);

		type_key = validate_type_node(fynt_key);
		if (type_key != fyjs_string)
			return fyjs_error(vc, ERROR_DEPENDENCIES_NOT_OBJ, fyn, fynt_v, NULL);

		key_str = fy_node_get_scalar0(fynt_key);
		if (!key_str)
			return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY,
					  fyn, fynt_v, "%s:%d @%s",
					  __FILE__, __LINE__, __func__);

		type_value = validate_type_node(fynt_value);

		if ((dep_type == fyjsdt_required && type_value != fyjs_array) ||
		    (dep_type == fyjsdt_schemas && type_value != fyjs_object))
			return fyjs_error(vc, ERROR_DEPENDENCIES_BAD_VALUE, fyn, fynt_v, NULL);

		/* does the key exist? */
		key_exists = fy_node_mapping_lookup_value_by_simple_key(fyn, key_str, FY_NT) != NULL;

		/* if array, check for existence */
		if (type_value == fyjs_array) {
			iter_values1 = NULL;
			while ((fynt_value1 = fy_node_sequence_iterate(fynt_value, &iter_values1)) != NULL) {

				/* check that the value is a string */
				if (validate_type_node(fynt_value1) != fyjs_string)
					return fyjs_error(vc, ERROR_DEPENDENCIES_DEP_NOT_STR, fyn, fynt_value1, NULL);

				value1_str = fy_node_get_scalar0(fynt_value1);
				if (!value1_str)
					return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY,
							  fyn, fynt_v, "%s:%d @%s",
							  __FILE__, __LINE__, __func__);

				/* verify that the property is not duplicated */
				iter_values2 = NULL;
				while ((fynt_value2 = fy_node_sequence_iterate(fynt_value, &iter_values2)) != NULL) {

					/* do not check with self */
					if (fynt_value1 == fynt_value2)
						continue;

					/* compare */
					if (fy_node_compare_json(vc, fynt_value1, fynt_value2))
						return fyjs_error(vc, ERROR_DEPENDENCIES_DEP_NOT_STR, fyn, fynt_value1, NULL);
				}

				/* it must exist */
				if (key_exists && !fy_node_mapping_lookup_value_by_simple_key(fyn, value1_str, FY_NT)) {

					tmpret = INVALID_DEPENDENCIES_DEP_MISSING;
					if (ret == VALID)
						ret = tmpret;

					fyjs_error(vc, ret, fyn, fynt_value1, "\"%s\"", value1_str);
				}
			}
		} else if (type_value == fyjs_object || type_value == fyjs_boolean) {

			if (dep_type == fyjsdt_dependencies) {

				/* the key must exist for the dependency to 'take' */
				if (!key_exists)
					continue;

				tmpret = validate_one(vc, fyn, fynt_value);

				if (tmpret == VALID)
					continue;

				if (IS_ERROR(tmpret))
					return tmpret;

				if (ret == VALID)
					ret = INVALID_DEPENDENCIES_DEP_MISSING;

				fyjs_error(vc, INVALID_DEPENDENCIES_DEP_MISSING, fyn, fynt_value, NULL);

			} else if (dep_type == fyjsdt_schemas) {
				iter_dschema = NULL;
				while ((fynps = fy_node_mapping_iterate(fynt_value, &iter_dschema)) != NULL) {
					fynt_skey = fy_node_pair_key(fynps);
					fynt_svalue = fy_node_pair_value(fynps);

					/* the value must be an object */
					if (!fy_node_is_mapping(fynt_svalue))
						return fyjs_error(vc, ERROR_DEPENDENCIES_NOT_OBJ, fyn, fynt_v, NULL);

					skey_str = fy_node_get_scalar0(fynt_skey);
					if (!skey_str)
						return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY,
								  fyn, fynt_v, "%s:%d @%s",
								  __FILE__, __LINE__, __func__);

					/* if the property doesn't exist... */
					if (!fy_node_mapping_lookup_value_by_simple_key(fyn, skey_str, FY_NT))
						continue;

					tmpret = validate_one(vc, fyn, fynt_value);

					if (tmpret == VALID)
						continue;

					if (IS_ERROR(tmpret))
						return tmpret;

					if (ret == VALID)
						ret = INVALID_DEPENDENCIES_DEP_MISSING;

					fyjs_error(vc, INVALID_DEPENDENCIES_DEP_MISSING, fyn, fynt_value, NULL);
				}

			} else {
				/* should never get here */
				assert(0);
			}
		} else
			return fyjs_error(vc, ERROR_DEPENDENCIES_BAD_VALUE, fyn, fynt_key, NULL);
	}

	return ret;
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
		return fyjs_error(vc, ERROR_CONTENTENC_NOT_STR, fyn, fynt_v, NULL);

	/* ignore non-strings */
	vtype = validate_type_node(fyn);
	if (vtype != fyjs_string)
		return VALID;

	type_str = fy_node_get_scalar0(fynt_enc);
	value_str = fy_node_get_scalar0(fyn);

	if (!type_str || !value_str)
		return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, fyn, fynt_v,
				  "%s:%d @%s", __FILE__, __LINE__, __func__);

	if (ascii_streq(type_str, "7bit"))
		return VALID; /* TODO verify it's 7 bit only */

	if (ascii_streq(type_str, "8bit"))
		return VALID;

	if (ascii_streq(type_str, "base64")) {
		if (fy_b64_valid(value_str))
			return VALID;

		return fyjs_error(vc, INVALID_CONTENTENC_BAD, fyn, fynt_v, NULL);
	}

	return fyjs_error(vc, ERROR_CONTENTENC_BAD, fyn, fynt_v, NULL);
}

static void json_no_diag_output_fn(struct fy_diag *diag, void *user,
				  const char *buf, size_t len)
{
	/* nothing */
}

static int validate_content_media_type(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				       struct fy_node *fynt_v)
{
	struct fy_parse_cfg json_doc_mt_cfg;
	struct fy_diag_cfg dcfg;
	struct fy_diag *diag;
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
		return fyjs_error(vc, ERROR_CONTENTMT_NOT_STR, fyn, fynt_v, NULL);

	/* ignore non-strings */
	vtype = validate_type_node(fyn);
	if (vtype != fyjs_string)
		return VALID;

	cmt_str = fy_node_get_scalar0(fynt_cmt);
	value_str = fy_node_get_scalar0(fyn);
	if (!cmt_str || !value_str)
		return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, fyn, fynt_v,
				  "%s:%d @%s", __FILE__, __LINE__, __func__);

	fynt_enc = fy_node_mapping_lookup_value_by_simple_key(fynt, "contentEncoding", FY_NT);
	if (fynt_enc) {
		type_str = fy_node_get_scalar0(fynt_enc);
		if (!type_str)
			return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY,
					  fyn, fynt_v, "%s:%d @%s",
					  __FILE__, __LINE__, __func__);

		if (ascii_streq(type_str, "base64")) {
			decoded = fy_b64_decode(value_str, &decoded_len);
			if (!decoded)
				return fyjs_error(vc, INVALID_CONTENTENC_BAD, fyn, fynt_v,
						  "(unable to decode)");
			value_str = decoded;
		}
	}

	if (ascii_streq(cmt_str, "application/json")) {

		fy_diag_cfg_default(&dcfg);
		dcfg.output_fn = json_no_diag_output_fn;
		dcfg.fp = NULL;
		diag = fy_diag_create(&dcfg);
		if (!diag)
			return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY,
					  fyn, fynt_v, "%s:%d @%s",
					  __FILE__, __LINE__, __func__);

		memset(&json_doc_mt_cfg, 0, sizeof(json_doc_mt_cfg));
		json_doc_mt_cfg.flags = ((FYPCF_DEFAULT_DOC & ~FYPCF_COLOR(FYPCF_COLOR_MASK)) | FYPCF_COLOR_AUTO) | FYPCF_JSON_FORCE,
		json_doc_mt_cfg.diag = diag;

		fyd = fy_document_build_from_string(
				&json_doc_mt_cfg,
				value_str, strlen(value_str));
		ret = fyd ? VALID : INVALID_CONTENTMT_BAD;
		fy_document_destroy(fyd);

		fy_diag_destroy(diag);
		diag = NULL;
	} else
		ret = INVALID_CONTENTMT_BAD;

	if (decoded)
		free(decoded);

	if (ret == VALID)
		return VALID;

	return fyjs_error(vc, ret, fyn, fynt_v, NULL);
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
		return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, fyn, fynt_v,
				  "%s:%d @%s", __FILE__, __LINE__, __func__);

	d = strchr(value_str, '@');
	if (!d)
		return fyjs_error(vc, INVALID_FORMAT_EMAIL, fyn, fynt_v, "(missing @)");

	if (!valid_localpart(value_str, (size_t)(d - value_str)))
		return fyjs_error(vc, INVALID_FORMAT_EMAIL, fyn, fynt_v, "(invalid local-part)");

	if (!valid_hostname(d + 1, (size_t)-1))
		return fyjs_error(vc, INVALID_FORMAT_EMAIL, fyn, fynt_v, "(invalid hostname)");

	return VALID;
}

static int validate_format_idn_email(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				     struct fy_node *fynt_v)
{
	const char *value_str, *d;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, fyn, fynt_v,
				  "%s:%d @%s", __FILE__, __LINE__, __func__);

	d = strchr(value_str, '@');
	if (!d)
		return fyjs_error(vc, INVALID_FORMAT_IDN_EMAIL, fyn, fynt_v, "(missing @)");

	if (!valid_idn_localpart(value_str, (size_t)(d - value_str)))
		return fyjs_error(vc, INVALID_FORMAT_IDN_EMAIL, fyn, fynt_v, "(invalid local-part)");

	if (!valid_idn_hostname(d + 1, (size_t)-1))
		return fyjs_error(vc, INVALID_FORMAT_IDN_EMAIL, fyn, fynt_v, "(invalid hostname)");

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
		return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, fyn, fynt_v,
				  "%s:%d @%s", __FILE__, __LINE__, __func__);

	/* compile the pattern for a quick test */
	re = pcre_compile(value_str,
			  PCRE_JAVASCRIPT_COMPAT |
			  (vc->pcre_utf8 ? PCRE_UTF8 : 0) |
			  PCRE_DOLLAR_ENDONLY,
			&error, &erroroffset, NULL);
	if (!re)
		return fyjs_error(vc, INVALID_FORMAT_REGEX, fyn, fynt_v, NULL);

	pcre_free(re);

	/* PCRE is more permissive, so check for valid metacharacters only */
	s = value_str;
	e = s + strlen(value_str);
	for (; s < e; s++) {
		if (*s != '\\')
			continue;

		/* too short */
		if (s + 1 >= e)
			return fyjs_error(vc, INVALID_FORMAT_REGEX, fyn, fynt_v, "(too short)");

		s++;

		/* must only be one of those */
		if (!strchr("wWdDsSbB0nfrtvxu", *s))
			return fyjs_error(vc, INVALID_FORMAT_REGEX, fyn, fynt_v, "(invalid operator %c)", *s);
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
		return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, fyn, fynt_v,
				  "%s:%d @%s", __FILE__, __LINE__, __func__);

	rc = inet_pton(AF_INET, value_str, &sa4);
	if (rc == 1)
		return VALID;

	return fyjs_error(vc, INVALID_FORMAT_IPV4, fyn, fynt_v, NULL);
}

static int validate_format_ipv6(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				struct fy_node *fynt_v)
{
	struct sockaddr_in6 sa6;
	const char *value_str;
	int rc;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, fyn, fynt_v,
				  "%s:%d @%s", __FILE__, __LINE__, __func__);

	rc = inet_pton(AF_INET6, value_str, &sa6);
	if (rc == 1)
		return VALID;

	return fyjs_error(vc, INVALID_FORMAT_IPV6, fyn, fynt_v, NULL);
}

static int validate_format_hostname(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				    struct fy_node *fynt_v)
{
	const char *value_str;
	bool valid;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, fyn, fynt_v,
				  "%s:%d @%s", __FILE__, __LINE__, __func__);

	valid = valid_hostname(value_str, (size_t)-1);
	if (valid)
		return VALID;

	return fyjs_error(vc, INVALID_FORMAT_HOSTNAME, fyn, fynt_v, NULL);
}

static int validate_format_idn_hostname(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
					struct fy_node *fynt_v)
{
	const char *value_str;
	bool valid;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, fyn, fynt_v,
				  "%s:%d @%s", __FILE__, __LINE__, __func__);

	valid = valid_idn_hostname(value_str, (size_t)-1);

	if (valid)
		return VALID;

	return fyjs_error(vc, INVALID_FORMAT_IDN_HOSTNAME, fyn, fynt_v, NULL);
}

static int validate_format_date(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				struct fy_node *fynt_v)
{
	const char *value_str, *p;
	struct tm tm, tm_orig;
	time_t t;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, fyn, fynt_v,
				  "%s:%d @%s", __FILE__, __LINE__, __func__);

	memset(&tm, 0, sizeof(tm));
	p = strptime(value_str, "%Y-%m-%d", &tm);
	if (!p || *p)	/* everything must be consumed */
		return fyjs_error(vc, INVALID_FORMAT_DATE, fyn, fynt_v, "(bad format)");

	memcpy(&tm_orig, &tm, sizeof(tm));

	t = mktime(&tm);
	if (t == (time_t)-1)
		return fyjs_error(vc, INVALID_FORMAT_DATE, fyn, fynt_v, "(invalid time)");

	/* if tm has been normalized it's an error */
	if (tm.tm_year != tm_orig.tm_year ||
	    tm.tm_mon != tm_orig.tm_mon ||
	    tm.tm_mday != tm_orig.tm_mday)
		return fyjs_error(vc, INVALID_FORMAT_DATE, fyn, fynt_v, "(invalid time)");

	return VALID;
}

static int validate_format_time(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				struct fy_node *fynt_v)
{
	const char *value_str, *p;
	struct tm tm;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, fyn, fynt_v,
				  "%s:%d @%s", __FILE__, __LINE__, __func__);

	memset(&tm, 0, sizeof(tm));
	p = strptime(value_str, "%H:%M:%S", &tm);
	if (!p)
		return fyjs_error(vc, INVALID_FORMAT_TIME, fyn, fynt_v, "(bad format)");

	/* no fractional part i.e. 00:00:00 */
	if (!*p)
		return VALID;

	/* fractional part i.e. 00:00:00.1234.. */
	if (*p == '.') {
		p++;
		if (!isdigit(*p))
			return fyjs_error(vc, INVALID_FORMAT_TIME, fyn, fynt_v, "(bad format)");
		while (isdigit(*p))
			p++;
	}

	/* Z */
	if (*p == 'z' || *p == 'Z') {
		p++;
		if (!*p)
			return VALID;

		return fyjs_error(vc, INVALID_FORMAT_TIME, fyn, fynt_v, "(bad format)");
	}

	/* or [+-]00:00 */
	if (*p != '+' && *p != '-')
		return fyjs_error(vc, INVALID_FORMAT_TIME, fyn, fynt_v, "(bad format)");
	p++;

	memset(&tm, 0, sizeof(tm));
	p = strptime(p, "%H:%M", &tm);
	if (!p || *p)
		return fyjs_error(vc, INVALID_FORMAT_TIME, fyn, fynt_v, "(bad format)");

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
		return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, fyn, fynt_v,
				  "%s:%d @%s", __FILE__, __LINE__, __func__);

	memset(&tm, 0, sizeof(tm));
	p = strptime(value_str, "%Y-%m-%d", &tm);
	if (!p)
		return fyjs_error(vc, INVALID_FORMAT_DATE_TIME, fyn, fynt_v, "(bad format)");

	if (*p != 't' && *p != 'T')
		return fyjs_error(vc, INVALID_FORMAT_DATE_TIME, fyn, fynt_v, "(bad format)");
	p++;

	p = strptime(p, "%H:%M:%S", &tm);
	if (!p)
		return fyjs_error(vc, INVALID_FORMAT_DATE_TIME, fyn, fynt_v, "(bad format)");

	/* no fractional part i.e. 00:00:00 */
	if (!*p)
		return VALID;

	/* fractional part i.e. 00:00:00.1234.. */
	if (*p == '.') {
		p++;
		if (!isdigit(*p))
			return fyjs_error(vc, INVALID_FORMAT_DATE_TIME, fyn, fynt_v, "(bad format)");
		while (isdigit(*p))
			p++;
	}

	/* Z */
	if (*p == 'z' || *p == 'Z') {
		p++;
		if (!*p)
			return VALID;

		return fyjs_error(vc, INVALID_FORMAT_DATE_TIME, fyn, fynt_v, "(bad format)");
	}

	/* or [+-]00:00 */
	if (*p != '+' && *p != '-')
		return fyjs_error(vc, INVALID_FORMAT_DATE_TIME, fyn, fynt_v, "(bad format)");
	p++;

	memset(&tm_orig, 0, sizeof(tm_orig));
	p = strptime(p, "%H:%M", &tm_orig);
	if (!p || *p)
		return fyjs_error(vc, INVALID_FORMAT_DATE_TIME, fyn, fynt_v, "(bad format)");

	memcpy(&tm_orig, &tm, sizeof(tm));

	t = mktime(&tm);
	if (t == (time_t)-1)
		return fyjs_error(vc, INVALID_FORMAT_DATE_TIME, fyn, fynt_v, "(bad format)");

	/* if tm has been normalized it's an error */
	if (tm.tm_year != tm_orig.tm_year ||
	    tm.tm_mon != tm_orig.tm_mon ||
	    tm.tm_mday != tm_orig.tm_mday ||
	    tm.tm_hour != tm_orig.tm_hour ||
	    tm.tm_min != tm_orig.tm_min ||
	    tm.tm_sec != tm_orig.tm_sec)
		return fyjs_error(vc, INVALID_FORMAT_DATE_TIME, fyn, fynt_v, "(bad format)");

	return VALID;
}

static int validate_format_json_pointer(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
					struct fy_node *fynt_v)
{
	const char *value_str;
	bool valid;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, fyn, fynt_v,
				  "%s:%d @%s", __FILE__, __LINE__, __func__);

	valid = is_valid_json_pointer(value_str);
	if (valid)
		return VALID;

	return fyjs_error(vc, INVALID_FORMAT_JSON_POINTER, fyn, fynt_v, NULL);
}

static int validate_format_relative_json_pointer(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
						 struct fy_node *fynt_v)
{
	const char *value_str;
	bool valid;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, fyn, fynt_v,
				  "%s:%d @%s", __FILE__, __LINE__, __func__);

	valid = is_valid_reljson_pointer(value_str);

	if (valid)
		return VALID;

	return fyjs_error(vc, INVALID_FORMAT_RELJSON_POINTER, fyn, fynt_v, NULL);
}

static int validate_format_iri(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			       struct fy_node *fynt_v)
{
	const char *value_str;
	bool valid;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, fyn, fynt_v,
				  "%s:%d @%s", __FILE__, __LINE__, __func__);

	valid = valid_iri(value_str, (size_t)-1);
	if (valid)
		return VALID;

	return fyjs_error(vc, INVALID_FORMAT_IRI, fyn, fynt_v, NULL);
}

static int validate_format_iri_reference(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
					 struct fy_node *fynt_v)
{
	const char *value_str;
	bool valid;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, fyn, fynt_v,
				  "%s:%d @%s", __FILE__, __LINE__, __func__);

	valid = valid_iri_reference(value_str, (size_t)-1);
	if (valid)
		return VALID;

	return fyjs_error(vc, INVALID_FORMAT_IRI_REFERENCE, fyn, fynt_v, NULL);
}

static int validate_format_uri(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
			       struct fy_node *fynt_v)
{
	const char *value_str;
	bool valid;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, fyn, fynt_v,
				  "%s:%d @%s", __FILE__, __LINE__, __func__);

	valid = valid_uri(value_str, (size_t)-1);

	if (valid)
		return VALID;

	return fyjs_error(vc, INVALID_FORMAT_URI, fyn, fynt_v, NULL);
}

static int validate_format_uri_reference(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
					 struct fy_node *fynt_v)
{
	const char *value_str;
	bool valid;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, fyn, fynt_v,
				  "%s:%d @%s", __FILE__, __LINE__, __func__);

	valid = valid_uri_reference(value_str, (size_t)-1);
	if (valid)
		return VALID;

	return fyjs_error(vc, INVALID_FORMAT_URI_REFERENCE, fyn, fynt_v, NULL);
}

static int validate_format_uri_template(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt,
				        struct fy_node *fynt_v)
{
	const char *value_str;
	bool valid;

	value_str = fy_node_get_scalar0(fyn);
	if (!value_str)
		return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, fyn, fynt_v,
				  "%s:%d @%s", __FILE__, __LINE__, __func__);

	valid = valid_uri_template(value_str, (size_t)-1);
	if (valid)
		return VALID;

	return fyjs_error(vc, INVALID_FORMAT_URI_TEMPLATE, fyn, fynt_v, NULL);
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

	/* get format node */
	fynt_format = fynt_v;

	/* must be string */
	type = validate_type_node(fynt_format);
	if (type != fyjs_string)
		return fyjs_error(vc, ERROR_FORMAT_NOT_STRING, fyn, fynt_v, NULL);

	/* if not a string just valid */
	vtype = validate_type_node(fyn);
	if (vtype != fyjs_string)
		return VALID;

	format_str = fy_node_get_scalar0(fynt_format);
	if (!format_str)
		return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, fyn, fynt_v,
				  "%s:%d @%s", __FILE__, __LINE__, __func__);

	for (vd = vc->vd_formats; vd->func; vd++) {

		if (strcmp(format_str, vd->primary))
			continue;

		return vd->func(vc, fyn, fynt, fynt);
	}

	/* unknown format? valid */
	return VALID;
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
		fy_info(vc->diag, "base: %s\n", base);

	id_str = get_id(vc, fynt);
	if (id_str) {

		if (vc->verbose)
			fy_info(vc->diag, "%s: %s\n", vc->id_str, id_str);

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
		fyjs_dump_uri(vc, "lookup-uri", urip);
		fyjs_dump_uri(vc, "lookup-base", &urip_base);
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
		else if (urip_id.fragment && urip->fragment && uri_fragment_eq(&urip_id, urip))
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

int deref_ref(struct fyjs_validate_ctx *vc,
              struct fy_node *fyn, struct fy_node *fynt,
	      struct fy_node *fynt_ref,
	      struct fy_node **fynt_root2p, struct fy_node **fynt_matchp)
{
	struct fy_parse_cfg pcfg;
	struct fy_node *fynt_root = vc->fynt_root;
	struct fy_node *fynt_parent, *fynt_match, *fynt_iter, *fynt_root2 = NULL;
	struct fy_node *fynt_content;
	struct fy_uri urip_ref, urip_id;
	const char *id_str;
	char *full_id, *s, *e;
	int rc, i, count, pass, ids_count, full_id_len, ret;
	struct fy_node **fynt_ids;
	struct remote *r, *rfound;
	const char *trest;
	int trest_len;
	char *newurl = NULL, *newfile = NULL, *out_fynt, *ref_url;
	struct fy_document *fyd = NULL;
	bool need_slash;
	size_t len;
	struct fy_node *fynn;
	void *iter;
	bool fail_if_no_cache = false;
	time_t utc_time;
	const char *origin, *ref_str;
	char ctime_buf[32];
	struct stat st;

	*fynt_root2p = NULL;
	*fynt_matchp = NULL;

	/* default */
	ret = ERROR_REF_BAD_PATH;

	if (validate_type_node(fynt_ref) != fyjs_string)
		return fyjs_error(vc, ERROR_REF_NOT_STR, fyn, fynt_ref, NULL);

	ref_str = fy_node_get_scalar0(fynt_ref);
	if (!ref_str)
		return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY,
					fyn, fynt_ref, "%s:%d @%s",
					__FILE__, __LINE__, __func__);

	memset(&urip_ref, 0, sizeof(urip_ref));
	memset(&urip_id, 0, sizeof(urip_id));

	*fynt_root2p = fynt_root;

	rc = fy_parse_uri_ext(ref_str, &urip_ref, URI_REF);
	if (rc)
		return fyjs_error(vc, ERROR_REF_BAD_URI_REF,
					fyn, fynt_ref, NULL);

	if (vc->verbose) {
		fyjs_dump_uri(vc, "deref_ref original ref", &urip_ref);

		out_fynt = fy_emit_node_to_string(fynt, FYECF_MODE_FLOW_ONELINE);
		fy_info(vc->diag, "fynt: %s\n", out_fynt);
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

			id_str = get_id(vc, fynt_parent);
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
		id_str = get_id(vc, fynt_parent);
		if (!id_str) {
			ret = fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY,
					fyn, fynt_parent, "%s:%d @%s",
					__FILE__, __LINE__, __func__);
			goto err_out;
		}

		rc = fy_parse_uri_ext(id_str, &urip_id, URI_REF);
		if (rc) {
			ret = fyjs_error(vc, ERROR_REF_BAD_ID,
					fyn, fynt_parent, NULL);
			goto err_out;
		}

		s += snprintf(s, e - s, "%.*s%s" "%.*s" "%.*s",
				(int)urip_id.scheme_len, urip_id.scheme, urip_id.scheme_len ? "://" : "",
				(int)urip_id.authority_len, urip_id.authority,
				(int)urip_id.nslug_len, urip_id.nslug);

		// fy_debug(vc->diag, "start: full_id=%s\n", full_id);
		// fy_debug(vc->diag, "start: absolute %s=%s\n", vc->id_str, id_str);

		while (i >= 0) {
			fynt_parent = fynt_ids[i--];
			id_str = get_id(vc, fynt_parent);
			if (!id_str)
				return fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY,
						fyn, fynt_parent, "%s:%d @%s",
						__FILE__, __LINE__, __func__);

			rc = fy_parse_uri_ext(id_str, &urip_id, URI_REF);
			if (rc)
				return fyjs_error(vc, ERROR_REF_BAD_ID,
					fyn, fynt_parent, NULL);

			s += snprintf(s, e - s, "%.*s",
					(int)urip_id.path_len, urip_id.path);

			// fy_debug(vc->diag, "rel: full_id=%s\n", full_id);
			// fy_debug(vc->diag, "rel: $id=%s\n", id_str);
		}
	}

	// fyjs_dump_uri(vc, "original ref", &urip_ref);

	s += snprintf(s, e - s, "%.*s" "%s%.*s%s%.*s",
			(int)urip_ref.path_len, urip_ref.path,
			urip_ref.query ? "&" : "", (int)urip_ref.query_len, urip_ref.query,
			urip_ref.fragment ? "#" : "", (int)urip_ref.fragment_len, urip_ref.fragment);

	rc = fy_parse_uri_ext(full_id, &urip_ref, URI_REF);
	if (rc) {
		ret = fyjs_error(vc, ERROR_REF_BAD_URI_REF,
					fyn, fynt_ref,
					"bad URL was \"%s\"",
					full_id);

		goto err_out;
	}

skip_rel_ref:

	if (vc->verbose)
		fyjs_dump_uri(vc, "ref-full-path", &urip_ref);

	/* try with the root of the active schema */
	fynt_match = lookup_for_uri_match(vc, fynt_root, fynt_root, &urip_ref, "");
	if (fynt_match) {
		*fynt_matchp = fynt_match;
		return VALID;
	}

	/* no authority, no remote mapping possible */
	if (!urip_ref.authority) {
		ret = fyjs_error(vc, ERROR_REF_BAD_URI_REF,
					fyn, fynt_ref,
					"reference URL without authority \"%s\"",
					full_id);
		goto err_out;
	}

do_cache:

	fynt_match = NULL;
	fynt_root2 = fy_document_root(vc->fyd_cache);
	iter = NULL;
	while (!fynt_match && (fynt_iter = fy_node_sequence_iterate(fynt_root2, &iter)) != NULL) {
		id_str = get_id(vc, fynt_iter);
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
			ret = fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, NULL, NULL,
					"%s:%d @%s", __FILE__, __LINE__, __func__);
			goto err_out;
		}

		fynt_match = lookup_for_uri_match(vc, fynt_content, fynt_content, &urip_ref, newurl);
		free(newurl);
		newurl = NULL;
		if (fynt_match) {
			*fynt_root2p = fynt_content;
			*fynt_matchp = fynt_match;
			return VALID;
		}
	}

	if (fail_if_no_cache) {
		ret = fyjs_error(vc, ERROR_REF_NOT_FOUND, fyn, fynt_ref, NULL);
		goto err_out;
	}

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
			ret = fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, NULL, NULL,
					"%s:%d @%s", __FILE__, __LINE__, __func__);
			goto err_out;
		}

		len = strlen(r->baseurl);
		need_slash = (len > 1 && r->baseurl[len-1] != '/') &&
			     trest_len > 1 && trest[0] != '/';
		rc = asprintf(&newurl, "%s%s%.*s", r->baseurl,
				need_slash ? "/" : "", trest_len, trest);
		if (rc == -1) {
			ret = fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, NULL, NULL,
					"%s:%d @%s", __FILE__, __LINE__, __func__);
			goto err_out;
		}

		fyd = fy_document_build_from_file(
				fyjs_parse_cfg(vc, schema_cfg(newfile), &pcfg),
				newfile);

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
			ret = fyjs_error(vc, ERROR_REF_NOT_FOUND_REMOTE, fyn, fynt_ref, 
					"reference URL \"%s\"", ref_url);
			goto err_out;
		}

		utc_time = fy_curl_get_filetime(vc->curl_handle);

		fynt_root2 = fy_document_root(fyd);
		if (vc->verbose)
			fy_info(vc->diag, "match from online url %s\n", ref_url);

		origin = ref_url;
	} else {
		/* the file must exist */
		rc = stat(newfile, &st);
		if (rc) {
			ret = fyjs_error(vc, ERROR_REF_NOT_FOUND_FILE, fyn, fynt_ref, 
					"stat(): file \"%s\"", newfile);
			goto err_out;
		}

		/* get last modification time */
		utc_time = st.st_mtime;

		ref_url = newurl;
		s = realpath(newfile, NULL);
		if (!s) {
			ret = fyjs_error(vc, ERROR_REF_NOT_FOUND_FILE, fyn, fynt_ref, 
					"realpath(): file \"%s\"", newfile);
			goto err_out;
		}
		rc = asprintf(&e, "file://%s", s);
		free(s);
		if (rc == -1) {
			ret = fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, NULL, NULL,
					"%s:%d @%s", __FILE__, __LINE__, __func__);
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
		fy_info(vc->diag, "timestamp: %s\n",
				ctime_chomp(&utc_time, ctime_buf));

	fynn = fy_node_buildf(vc->fyd_cache,
			"{ \"%s\": \"%s\", \"origin\": \"%s\", "
			"\"timestamp\": %llu, "
			"\"timestamp-human\": \"%s\", "
			"\"%s\": { } }",
			vc->id_str, ref_url, origin,
			(unsigned long long)utc_time,
			ctime_chomp(&utc_time, ctime_buf),
			"content");
	if (!fynn) {
		ret = fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, NULL, NULL,
				 "%s:%d @%s", __FILE__, __LINE__, __func__);
		goto err_out;
	}

	fynt_content = fy_node_mapping_lookup_value_by_simple_key(fynn, "content", FY_NT);
	if (!fynt_content) {
		ret = fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, NULL, NULL,
				 "%s:%d @%s", __FILE__, __LINE__, __func__);
		goto err_out;
	}

	rc = fy_node_insert(fynt_content, fynt_root2);
	if (rc) {
		ret = fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, NULL, NULL,
				 "%s:%d @%s", __FILE__, __LINE__, __func__);
		goto err_out;
	}

	rc = fy_node_sequence_append(fy_document_root(vc->fyd_cache), fynn);
	if (rc) {
		ret = fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, NULL, NULL,
				 "%s:%d @%s", __FILE__, __LINE__, __func__);
		goto err_out;
	}
	vc->cache_modified = true;

	fynn = NULL;
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

	*fynt_root2p = NULL;
	*fynt_matchp = NULL;
	return ret;
}

static int validate_one(struct fyjs_validate_ctx *vc, struct fy_node *fyn, struct fy_node *fynt)
{
	int ret, tmpret;
	const struct validate_desc *vd = NULL;
	char *schema_str;
	const char *recanchor_str;
	const char *boolean_value;
	struct fy_node *fynt_ref, *fynt_deref, *fynt_root2;
	struct fy_node *fynt_root_save, *fynt_v = NULL;
	bool set_outmost_anchor, ref_was_recursive;
	enum fyjs_type type;

	if (vc->verbose) {
		schema_str = fy_emit_node_to_string(fynt, FYECF_MODE_FLOW_ONELINE);

		fy_info(vc->diag, "Validating    \"%s\" against %s - %s\n",
			get_path(fyn), get_path(fynt), schema_str);

		free(schema_str);
		schema_str = NULL;
	}

	/* true/false are special non-property validator */
	type = validate_type_node(fynt);
	if (type == fyjs_boolean) {
		boolean_value = fy_node_get_scalar0(fynt);
		if (!boolean_value) {
			ret = fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY,
					 fyn, fynt, "%s:%d @%s",
					 __FILE__, __LINE__, __func__);
			goto out;
		}

		if (!strcmp(boolean_value, "true"))
			ret = VALID;
		else
			ret = fyjs_error(vc, INVALID_BOOLEAN_FALSE, fyn, fynt_v, NULL);
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
		ret = deref_ref(vc, fyn, fynt, fynt_ref, &fynt_root2, &fynt_deref);
		if (!fynt_deref)
			goto out;

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
		for (vd = vc->vd_props; vd->func; vd++) {

			fynt_v = fy_node_mapping_lookup_value_by_simple_key(fynt, vd->primary, FY_NT);
			if (!fynt_v)
				continue;

			tmpret = vd->func(vc, fyn, fynt, fynt_v);
			if (tmpret == VALID) {
				fynt_v = NULL;
				continue;
			}

			if (ret == VALID || IS_ERROR(tmpret))
				ret = tmpret;

			if (IS_ERROR(tmpret))
				break;
		}
	}

	/* clear the anchor if we've set it */
	if (set_outmost_anchor)
		vc->fynt_outmost_anchor = NULL;

	return ret;

out:
	if (vc->verbose) {
		if (ret != VALID) {
			fy_info(vc->diag, "Validation of \"%s\" against \"%s\" failed @%s, error=%d.\n",
					get_path(fyn), get_path(fynt), vd ? vd->primary : "$ref", ret);
		} else {
			fy_info(vc->diag, "Validates     \"%s\" against \"%s\" OK.\n",
					get_path(fyn), get_path(fynt));
		}
	}

	return ret;
}

void fyjs_context_cleanup(struct fyjs_validate_ctx *vc)
{
	struct remote *r;

	if (!vc)
		return;

	result_list_clear(&vc->results);

	fy_document_destroy(vc->fyd_cache);
	vc->fyd_cache = NULL;

	if (vc->curl_handle)
		fy_curl_cleanup(vc->curl_handle);

	while (!TAILQ_EMPTY(&vc->rl)) {
		r = TAILQ_FIRST(&vc->rl);
		TAILQ_REMOVE(&vc->rl, r, entry);
		remote_destroy(r);
	}

	fy_diag_unref(vc->diag);
}

int fyjs_context_reset_cache(struct fyjs_validate_ctx *vc)
{
	struct fy_node *fyn;
	struct fy_parse_cfg pcfg;

	fy_document_destroy(vc->fyd_cache);
	vc->fyd_cache = fy_document_create(
			fyjs_parse_cfg(vc, &doc_cfg, &pcfg));
	if (!vc->fyd_cache) {
		(void)fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, NULL, NULL,
				 "%s:%d @%s", __FILE__, __LINE__, __func__);
		goto err_out;
	}

	fyn = fy_node_create_sequence(vc->fyd_cache);
	if (!fyn) {
		(void)fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, NULL, NULL,
				 "%s:%d @%s", __FILE__, __LINE__, __func__);
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
	struct fy_diag_cfg dcfg;
	struct fy_diag *diag;

	if (!vc || !cfg)
		return -1;

	memset(vc, 0, sizeof(*vc));

	vc->cfg = *cfg;

	diag = cfg->diag;
	if (!diag) {
		fy_diag_cfg_default(&dcfg);
		diag = fy_diag_create(&dcfg);
		if (!diag)
			return -1;
	} else
		fy_diag_ref(diag);

	vc->diag = diag;

	TAILQ_INIT(&vc->rl);

	TAILQ_INIT(&vc->results);

	vc->type = cfg->type;
	vc->verbose = cfg->verbose;
	for (i = 0; cfg->remotes && cfg->remotes[i].url; i++) {
		r = remote_create(cfg->remotes[i].url, cfg->remotes[i].dir);
		if (!r) {
			fy_error(vc->diag, "unable to create remote #%d\n", i);
			goto err_out;
		}
		TAILQ_INSERT_TAIL(&vc->rl, r, entry);

		if (vc->verbose)
			fy_info(vc->diag, "remote mapping %s -> %s\n",
					r->url, r->dir);
	}

	rc = fyjs_context_reset_cache(vc);
	if (rc) {
		fy_error(vc->diag, "%s: unable to reset cache\n", __func__);
		goto err_out;
	}

	vc->curl_handle = fy_curl_init();
	if (!vc->curl_handle)
		fy_warning(vc->diag, "warning: CURL not available; no external schemas available\n");

	if (vc->curl_handle)
		fy_curl_set_verbose(vc->curl_handle, vc->verbose);

	if (vc->verbose)
		fy_info(vc->diag, "curl: %s\n", vc->curl_handle ? "enabled" : "disabled");

	rc = pcre_config(PCRE_CONFIG_UTF8, &config);
	vc->pcre_utf8 = !rc && config;

	if (vc->verbose)
		fy_info(vc->diag, "pcre: UTF8 is %ssupported\n", vc->pcre_utf8 ? "" : "not ");

	vc->id_str = "$id";
	vc->schema_str = "$schema";

	vc->vd_props = validators;
	vc->vd_formats = format_validators;

	return 0;
err_out:
	fyjs_context_cleanup(vc);
	return -1;
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

int fyjs_validate(struct fyjs_validate_ctx *vc,
		  struct fy_node *fyn, struct fy_node *fynt)
{
	struct fyjs_validate_ctx_state vcs;
	int rc;

	fyjs_context_save(vc, &vcs);

	vc->fynt_root = fynt;
	rc = validate_one(vc, fyn, fynt);
	fyjs_context_restore(vc, &vcs);
	return rc;
}

const struct fyjs_result *
fyjs_results_iterate(struct fyjs_validate_ctx *vc, void **iterp)
{
	struct result_node *rn;

	if (!vc || !iterp)
		return NULL;

	rn = *iterp ?
		TAILQ_NEXT((struct result_node *)*iterp, entry) :
		TAILQ_FIRST(&vc->results);
	if (!rn)
		return NULL;
	*iterp = rn;
	return &rn->r;
}

void fyjs_results_report(struct fyjs_validate_ctx *vc)
{
	void *iter;
	const struct fyjs_result *r;
	int error;
	const char *errtxt;
	const char *cache_top_rule;
	const char *sep, *msg;

	iter = NULL;
	while ((r = fyjs_results_iterate(vc, &iter)) != NULL) {

		error = r->error;
		errtxt = fyjs_error_text(error);
		if (r->msg && r->msg[0]) {
			sep = " ";
			msg = r->msg;
		} else {
			sep = "";
			msg = "";
		}

		cache_top_rule = get_cache_top_rule_scalar(vc, r->error_rule, "origin");

		if (IS_INVALID(error)) {

			if (r->error_node)
				fy_diag_node_report(vc->diag, r->error_node, FYET_ERROR,
						    "%s%s%s", errtxt, sep, msg);

			if (r->error_rule) {
				if (cache_top_rule)
					fy_diag_node_override_report(vc->diag, r->error_rule,
							FYET_NOTICE, cache_top_rule, 0, 0,
							"failing rule");
				else
					fy_diag_node_report(vc->diag, r->error_rule,
							FYET_NOTICE, "failing rule");
			}

		} else if (IS_ERROR(error)) {

			if (r->error_rule) {
				if (cache_top_rule)
					fy_diag_node_override_report(vc->diag, r->error_rule,
							FYET_ERROR, cache_top_rule, 0, 0,
							"schema error: %s%s%s", errtxt, sep, msg);
				else
					fy_diag_node_report(vc->diag, r->error_rule, FYET_ERROR,
							"schema error: %s%s%s", errtxt, sep, msg);
			} else if (r->error_node) {
				fy_diag_node_report(vc->diag, r->error_node,
						FYET_ERROR, "%s%s%s", errtxt, sep, msg);
			}
		}
	}
}

void fyjs_results_clear(struct fyjs_validate_ctx *vc)
{
	if (!vc)
		return;

	result_list_clear(&vc->results);
}

struct fy_document *
fyjs_load_schema_document(struct fyjs_validate_ctx *vc, const char *schema)
{
	struct fy_document *fyd = NULL;
	struct fy_node *fyn, *fynt_content;
	struct fy_uri urip;
	const struct fy_parse_cfg *cfg;
	struct fy_parse_cfg pcfg;
	int rc;
	time_t utc_time = (time_t)-1;
	struct stat st;
	char *s, *e;
	const char *origin;
	const char *id;
	char ctime_buf[32];

	if (!vc || !schema)
		return NULL;

	cfg = fyjs_parse_cfg(vc, schema_cfg(schema), &pcfg);

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
		free(e);
	}

	id = get_id(vc, fy_document_root(fyd));
	if (!id)
		id = schema;

	/* get at least the current time */
	if (utc_time == (time_t)-1)
		utc_time = time(NULL);

	if (vc->verbose)
		fy_info(vc->diag, "timestamp: %s\n",
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
		(void)fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, NULL, NULL,
				 "%s:%d @%s", __FILE__, __LINE__, __func__);
		goto err_out;
	}

	fynt_content = fy_node_mapping_lookup_value_by_simple_key(fyn, "content", FY_NT);
	if (!fynt_content) {
		fy_error(vc->diag, "%s: fy_node_mapping_lookup_value_by_simple_key() content lookup failed\n", __func__);
		goto err_out;
	}

	rc = fy_node_insert(fynt_content, fy_document_root(fyd));
	if (rc) {
		(void)fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, NULL, NULL,
				 "%s:%d @%s", __FILE__, __LINE__, __func__);
		goto err_out;
	}

	rc = fy_node_sequence_append(fy_document_root(vc->fyd_cache), fyn);
	if (rc) {
		(void)fyjs_error(vc, ERROR_INTERNAL_OUT_OF_MEMORY, NULL, NULL,
				 "%s:%d @%s", __FILE__, __LINE__, __func__);
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

struct validate_simple_diag_ctx {
	char *buf;
	size_t alloc;
	size_t next;
};

static void
validate_simple_ctx_append(struct validate_simple_diag_ctx *ctx,
			   const char *buf, size_t len)
{
	size_t n;
	char *nbuf;

	if (!ctx)
		return;

	/* does not fit, grow */
	if (ctx->next + len > ctx->alloc) {
		/* start with at least one */
		n = ctx->alloc ? : 1;
		while (n < ctx->next + len)
			n <<= 1;
		/* works with ctx->buf == NULL */
		nbuf = realloc(ctx->buf, n);
		if (!nbuf)
			return;
		ctx->buf = nbuf;
		ctx->alloc = n;
	}

	/* fits, append */
	memcpy(ctx->buf + ctx->next, buf, len);
	ctx->next += len;
}

static void
validate_simple_diag_output_fn(struct fy_diag *diag, void *user,
			       const char *buf, size_t len)
{
	struct validate_simple_diag_ctx *ctx = user;

	if (!ctx)	/* nothing output if no context */
		return;

	validate_simple_ctx_append(ctx, buf, len);
}

static int
fyjs_validate_simple_internal(struct fy_node *fyn,
			      enum fyjs_validation_type vt,
			      struct fy_node *fyn_schema,
			      const char *schema,
			      char **logp)
{
	struct fy_diag *diag = NULL;
	struct fy_diag_cfg dcfg;
	struct fyjs_validate_cfg cfg;
	struct fyjs_validate_ctx *vc = NULL;
	struct validate_simple_diag_ctx ctx;
	struct fy_document *fyd_schema = NULL;
	int ret = ERROR_INTERNAL_OUT_OF_MEMORY;
	char *nbuf;

	/* at least one must be non NULL, but not both */
	if ((!fyn_schema && !schema) || (fyn_schema && schema))
		goto err_out;

	memset(&ctx, 0, sizeof(ctx));

	memset(&dcfg, 0, sizeof(dcfg));
	dcfg.output_fn = validate_simple_diag_output_fn;
	dcfg.fp = NULL;
	dcfg.user = logp ? &ctx : NULL;

	diag = fy_diag_create(&dcfg);
	if (!diag)
		goto err_out;

	memset(&cfg, 0, sizeof(cfg));
	cfg.type = vt;
	cfg.diag = diag;

	vc = fyjs_context_create(&cfg);
	if (!vc)
		goto err_out;

	if (!fyn_schema) {
		fyd_schema = fyjs_load_schema_document(vc, schema);
		if (!fyd_schema)
			goto err_out;
		fyn_schema = fy_document_root(fyd_schema);
	}

	ret = fyjs_validate(vc, fyn, fyn_schema);

	if (ret != VALID)
		fyjs_results_report(vc);

	/* at least one character; terminate */
	if (ctx.buf && ctx.next) {
		validate_simple_ctx_append(&ctx, "\0", 1);
		/* be paranoid and terminate anyway */
		ctx.buf[ctx.next] = '\0';
		/* trim */
		nbuf = realloc(ctx.buf, ctx.next);
		if (nbuf)
			ctx.buf = nbuf;
	}

err_out:
	fyjs_unload_schema_document(fyd_schema);
	fyjs_context_destroy(vc);
	fy_diag_destroy(diag);

	if (ctx.buf && logp)
		*logp = ctx.buf;

	return ret;
}

int fyjs_validate_simple_node(struct fy_node *fyn,
			      enum fyjs_validation_type vt,
			      struct fy_node *fyn_schema,
			      char **logp)
{
	return fyjs_validate_simple_internal(fyn, vt, fyn_schema, NULL, logp);
}

int fyjs_validate_simple_str(struct fy_node *fyn,
			     enum fyjs_validation_type vt,
			     const char *schema,
			     char **logp)
{
	return fyjs_validate_simple_internal(fyn, vt, NULL, schema, logp);
}

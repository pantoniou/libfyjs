/*
 * libfyjs.h - Main header file of the public interface of schema validator
 *
 * Copyright (c) 2019 Pantelis Antoniou <pantelis.antoniou@konsulko.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef LIBFYJS_H
#define LIBFYJS_H

#include <stdbool.h>

#include <libfyaml.h>

#ifdef __cplusplus
extern "C" {
#endif

/* reuse libfyaml's definition */
#define FYJS_EXPORT FY_EXPORT

/* fwd declarations */
struct fyjs_validate_ctx;

/* note: only DRAFT2019_09 is working right now */
enum fyjs_validation_type {
	FYJSVT_JSON_SCHEMA_DRAFT3,
	FYJSVT_JSON_SCHEMA_DRAFT4,
	FYJSVT_JSON_SCHEMA_DRAFT6,
	FYJSVT_JSON_SCHEMA_DRAFT7,
	FYJSVT_JSON_SCHEMA_DRAFT2019_09,
	FYJSVT_JSON_SCHEMA_LATEST = FYJSVT_JSON_SCHEMA_DRAFT2019_09,
	FYJSVT_OPENAPI_SCHEMA_2_0,
	FYJSVT_OPENAPI_SCHEMA_3_0,
	FYJSVT_OPENAPI_SCHEMA_LATEST = FYJSVT_OPENAPI_SCHEMA_3_0,
};

struct fyjs_validate_remote_cfg {
	const char *url;
	const char *dir;
};

struct fyjs_validate_cfg {
	enum fyjs_validation_type type;
	const struct fyjs_validate_remote_cfg *remotes;
	struct fy_diag *diag;
	bool verbose : 1;
};

struct fyjs_validate_ctx *
fyjs_context_create(const struct fyjs_validate_cfg *cfg)
	FYJS_EXPORT;

void
fyjs_context_destroy(struct fyjs_validate_ctx *vc)
	FYJS_EXPORT;

int
fyjs_reset_cache(struct fyjs_validate_ctx *vc)
	FYJS_EXPORT;

int
fyjs_context_set_cache(struct fyjs_validate_ctx *vc, struct fy_document *fyd)
	FYJS_EXPORT;

struct fy_document *
fyjs_context_get_cache(struct fyjs_validate_ctx *vc)
	FYJS_EXPORT;

bool
fyjs_context_is_cache_modified(struct fyjs_validate_ctx *vc)
	FYJS_EXPORT;

int
fyjs_validate(struct fyjs_validate_ctx *vc,
	      struct fy_node *fyn, struct fy_node *fynt)
	FYJS_EXPORT;

struct fyjs_result {
	int error;
	struct fy_node *error_node;
	struct fy_node *error_rule;
	const char *msg;
};

const struct fyjs_result *
fyjs_results_iterate(struct fyjs_validate_ctx *vc, void **iterp)
	FYJS_EXPORT;

void fyjs_results_report(struct fyjs_validate_ctx *vc)
	FYJS_EXPORT;

void fyjs_results_clear(struct fyjs_validate_ctx *vc);

struct fy_document *
fyjs_load_schema(struct fyjs_validate_ctx *vc, const char *schema)
	FYJS_EXPORT;

struct fy_document *
fyjs_load_schema_document(struct fyjs_validate_ctx *vc, const char *schema)
	FYJS_EXPORT;

void
fyjs_unload_schema_document(struct fy_document *fyd_schema)
	FYJS_EXPORT;

struct fy_parse_cfg *
fyjs_parse_cfg(struct fyjs_validate_ctx *vc,
	       const struct fy_parse_cfg *cfg_template,
	       struct fy_parse_cfg *cfg_fill)
	FYJS_EXPORT;

int
fyjs_validate_simple_node(struct fy_node *fyn, enum fyjs_validation_type vt,
			  struct fy_node *fyn_schema, char **logp)
	FYJS_EXPORT;

int
fyjs_validate_simple_str(struct fy_node *fyn, enum fyjs_validation_type vt,
			 const char *schema, char **logp)
	FYJS_EXPORT;

/* returned when all is fine */
#define VALID					0

/* type invalids */
#define INVALID_TYPE				100
#define INVALID_TYPE_WRONG			101
/* const invalids */
#define INVALID_CONST				200
/* enum invalids */
#define INVALID_ENUM				300
/* numeric invalids */
#define INVALID_MAXIMUM_OVER			400
#define INVALID_EXCLUSIVE_MAXIMUM_OVER		401
#define INVALID_MINIMUM_UNDER			402
#define INVALID_EXCLUSIVE_MINIMUM_UNDER		403
#define INVALID_MULTIPLEOF_NOT_MULTIPLE		404
/* anyof invalids */
#define INVALID_ANYOF_NO_MATCH			500
/* properties invalids */
#define INVALID_PROPERTY			600
/* pattern invalids */
#define INVALID_PATTERN_NO_MATCH		700
/* string length invalids */
#define INVALID_MINLENGTH_UNDER			800
#define INVALID_MAXLENGTH_OVER			801
/* boolean invalids */
#define INVALID_BOOLEAN_FALSE			900
/* items invalids */
#define INVALID_ITEMS_NO_MATCH			1000
#define INVALID_ADDITIONAL_ITEMS_NO_MATCH	1001
/* contains invalids */
#define INVALID_CONTAINS_NONE			1100
#define INVALID_CONTAINS_TOO_MANY		1101
#define INVALID_CONTAINS_NOT_ENOUGH		1102
/* unique_items invalids */
#define INVALID_UNIQUE_NOT_UNIQUE		1200
/* minmax items invalids */
#define INVALID_MIN_ITEMS_NOT_ENOUGH		1300
#define INVALID_MAX_ITEMS_TOO_MANY		1301
/* minmax properties invalids */
#define INVALID_MIN_PROPERTIES_NOT_ENOUGH	1400
#define INVALID_MAX_PROPERTIES_TOO_MANY		1401
/* dependencies invalids */
#define INVALID_DEPENDENCIES_DEP_MISSING	1500
/* allof invalids */
#define INVALID_ALLOF_NO_MATCH			1600
/* required invalids */
#define INVALID_REQUIRED_MISSING		1700
/* oneof invalids */
#define INVALID_ONEOF_NO_MATCH			1800
#define INVALID_ONEOF_MANY_MATCHES		1801
/* not invalids */
#define INVALID_NOT_MATCH			1900
/* if/then/else invalids */
#define INVALID_THEN_NO_MATCH			2000
#define INVALID_ELSE_NO_MATCH			2001
/* property_names invalids */
#define INVALID_PROPNAMES_NO_MATCH		2100
/* additional_properties invalids */
#define INVALID_ADDPROPS_NO_MATCH		2200
/* pattern_properties invalids */
#define INVALID_PATTERNPROPS_NO_MATCH		2300
/* content_encoding invalids */
#define INVALID_CONTENTENC_BAD			2400
/* content_media_type invalids */
#define INVALID_CONTENTMT_BAD			2500
/* format invalids */
#define INVALID_FORMAT_DATE			2600
#define INVALID_FORMAT_TIME			2601
#define INVALID_FORMAT_DATE_TIME		2602
#define INVALID_FORMAT_REGEX			2603
#define INVALID_FORMAT_IPV4			2604
#define INVALID_FORMAT_IPV6			2605
#define INVALID_FORMAT_HOSTNAME			2606
#define INVALID_FORMAT_IDN_HOSTNAME		2607
#define INVALID_FORMAT_EMAIL			2608
#define INVALID_FORMAT_IDN_EMAIL		2609
#define INVALID_FORMAT_IRI			2610
#define INVALID_FORMAT_IRI_REFERENCE		2611
#define INVALID_FORMAT_URI			2612
#define INVALID_FORMAT_URI_REFERENCE		2613
#define INVALID_FORMAT_URI_TEMPLATE		2614
#define INVALID_FORMAT_JSON_POINTER		2615
#define INVALID_FORMAT_RELJSON_POINTER		2616

/* generic error returns */
#define ERROR_INTERNAL_UNKNOWN			-1
#define ERROR_INTERNAL_OUT_OF_MEMORY		-2
#define ERROR_INTERNAL_ARGS			-3

/* ref walks */
#define ERROR_REF_NOT_STR			-50
#define ERROR_REF_BAD_PATH			-51
#define ERROR_REF_BAD_URI_REF			-52
#define ERROR_REF_BAD_ID			-53
#define ERROR_REF_NOT_FOUND			-54
#define ERROR_REF_NOT_FOUND_REMOTE		-55
#define ERROR_REF_NOT_FOUND_FILE		-56

/* type errors */
#define ERROR_TYPE_NOT_SCALAR_OR_SEQ		-100
#define ERROR_TYPE_SPEC_INVALID			-101
/* enum errors */
#define ERROR_ENUM_NOT_SEQ			-300
/* numerics errors */
#define ERROR_NUMERIC_CONSTRAINT_NAN		-400
#define ERROR_MULTIPLEOF_LEQ_ZERO		-401
/* anyof errors */
#define ERROR_ANYOF_BAD_SEQ			-500
/* properties errors */
#define ERROR_PROPERTIES_NOT_MAP		-600
#define ERROR_PROPERTIES_BAD_KEY		-601
#define ERROR_PROPERTIES_BAD_VALUE		-602
/* pattern errors */
#define ERROR_PATTERN_NOT_STRING		-700
#define ERROR_PATTERN_IS_BAD			-701
/* string length errors */
#define ERROR_STRLEN_CONSTRAINT_NOT_INT		-800
#define ERROR_STRLEN_CONSTRAINT_NEG		-801
/* boolean errors */
/* items errors */
/* contains errors */
#define ERROR_CONTAINS_MIN_NOT_INT		-1100
#define ERROR_CONTAINS_MIN_NEG			-1101
#define ERROR_CONTAINS_MAX_NOT_INT		-1102
#define ERROR_CONTAINS_MAX_NEG			-1103
/* unique_items errors */
#define ERROR_UNIQUE_NOT_BOOL			-1200
/* minmax items errors */
#define ERROR_MIN_ITEMS_NOT_INT			-1300
#define ERROR_MAX_ITEMS_NOT_INT			-1301
#define ERROR_MIN_ITEMS_OVERFLOW		-1302
#define ERROR_MAX_ITEMS_OVERFLOW		-1303
/* minmax properties errors */
#define ERROR_MIN_PROPERTIES_NOT_INT		-1400
#define ERROR_MAX_PROPERTIES_NOT_INT		-1401
#define ERROR_MIN_PROPERTIES_OVERFLOW		-1402
#define ERROR_MAX_PROPERTIES_OVERFLOW		-1403
/* dependencies errors */
#define ERROR_DEPENDENCIES_NOT_OBJ		-1500
#define ERROR_DEPENDENCIES_BAD_VALUE		-1501
#define ERROR_DEPENDENCIES_DEP_NOT_STR		-1502
/* allof errors */
#define ERROR_ALLOF_BAD_SEQ			-1600
/* required errors */
#define ERROR_REQUIRED_NOT_ARRAY		-1700
#define ERROR_REQUIRED_REQ_NOT_STR		-1701
#define ERROR_REQUIRED_REQ_IS_DUP		-1702
/* oneof errors */
#define ERROR_ONEOF_BAD_SEQ			-1800
/* not errors */
/* if/then/else errors */
/* property_names errors */
/* pattern properties error */
#define ERROR_PATTERNPROPS_NOT_OBJ		-2300
#define ERROR_PATTERNPROPS_BAD_PATTERN		-2301
/* content_encoding errors */
#define ERROR_CONTENTENC_NOT_STR		-2400
#define ERROR_CONTENTENC_BAD			-2401
/* content_media_type errors */
#define ERROR_CONTENTMT_NOT_STR			-2500
/* format errors */
#define ERROR_FORMAT_NOT_STRING			-2600

#define IS_VALID(x)	((x) == VALID)
#define IS_INVALID(x)	((x) > 0)
#define IS_ERROR(x)	((x) < 0)

#define IS_ERROR_INTERNAL(x) \
		({ \
		 	int _x = (x); \
			_x < 0 && _x > -100; \
		})

const char *
fyjs_error_text(int error)
	FYJS_EXPORT;

#ifdef __cplusplus
}
#endif

#endif

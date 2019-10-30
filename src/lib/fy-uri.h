/*
 * fy-uri.h - header file for URI parsing
 *
 * Copyright (c) 2019 Pantelis Antoniou <pantelis.antoniou@konsulko.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef FY_URI_H
#define FY_URI_H

#include <stdbool.h>
#include <stdint.h>

struct fy_uri {
	const char *uri;
	size_t uri_len;

	const char *scheme;
	size_t scheme_len;

	const char *authority;
	size_t authority_len;

	const char *userinfo;
	size_t userinfo_len;

	const char *host;
	size_t host_len;

	const char *port;
	size_t port_len;

	const char *path;
	size_t path_len;

	const char *slug;
	size_t slug_len;

	const char *nslug;
	size_t nslug_len;

	const char *query;
	size_t query_len;

	const char *fragment;
	size_t fragment_len;
};

#define URI_TEMPLATE	(1U << 0)
#define URI_IRI		(1U << 1)
#define URI_REF		(1U << 2)

int fy_parse_uri_ext(const char *uri, struct fy_uri *urip, unsigned int flags);
int fy_parse_uri(const char *uri, struct fy_uri *urip);
bool uri_empty(const struct fy_uri *urip);
bool uri_fragment_only(const struct fy_uri *urip);
bool uri_absolute_path(const struct fy_uri *urip);
bool uri_relative_path(const struct fy_uri *urip);

bool uri_scheme_is(const struct fy_uri *urip, const char *what);

bool uri_scheme_eq(const struct fy_uri *uripa, const struct fy_uri *uripb);
bool uri_authority_eq(const struct fy_uri *uripa, const struct fy_uri *uripb);
bool uri_fragment_eq(const struct fy_uri *uripa, const struct fy_uri *uripb);
bool uri_path_eq(const struct fy_uri *uripa, const struct fy_uri *uripb);
bool uri_falls_under(const struct fy_uri *uripa, const struct fy_uri *uripb);

void dump_uri(const char *banner, const struct fy_uri *urip);

static inline size_t
utf8_width_by_first_octet(uint8_t c)
{
        return (c & 0x80) == 0x00 ? 1 :
               (c & 0xe0) == 0xc0 ? 2 :
               (c & 0xf0) == 0xe0 ? 3 :
               (c & 0xf8) == 0xf0 ? 4 : 0;
}

int utf8_get(const char *ptr, size_t left, size_t *widthp);

bool is_valid_json_pointer(const char *str);
bool is_valid_reljson_pointer(const char *str);

#endif


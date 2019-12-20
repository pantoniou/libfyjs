/*
 * fy-uri.c - URI/URL handling methods
 *
 * Copyright (c) 2019 Pantelis Antoniou <pantelis.antoniou@konsulko.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdbool.h>
#include <string.h>
#include <alloca.h>
#include <stdio.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "fy-uri.h"

int utf8_get(const char *ptr, size_t left, size_t *widthp)
{
	const uint8_t *p = (const uint8_t *)ptr;
	size_t i, width;
	int value;

	if (left < 1)
		return -1;

	/* this is the slow path */
	width = utf8_width_by_first_octet(p[0]);
	if (!width)
		return -1;
	if (width > left)
		return -1;

	if (width == 1) {
		*widthp = width;
		return p[0];
	}

	/* initial value */
	value = *p++ & (0x7f >> width);
	for (i = 1; i < width; i++) {
		if ((*p & 0xc0) != 0x80)
			return -1;
		value = (value << 6) | (*p++ & 0x3f);
	}

	/* check for validity */
	if ((width == 4 && value < 0x10000) ||
	    (width == 3 && value <   0x800) ||
	    (width == 2 && value <    0x80) ||
	    (value >= 0xd800 && value <= 0xdfff) || value >= 0x110000)
		return -1;

	*widthp = width;

	return value;
}

/*
 * 000A0-0D7FF / 0F900-0FDCF / 0FDF0-0FFEF
 * 10000-1FFFD / 20000-2FFFD / 30000-3FFFD
 * 40000-4FFFD / 50000-5FFFD / 60000-6FFFD
 * 70000-7FFFD / 80000-8FFFD / 90000-9FFFD
 * A0000-AFFFD / B0000-BFFFD / C0000-CFFFD
 * D0000-DFFFD / E1000-EFFFD
 */
static int is_ucschar(const char *str, size_t len, unsigned int flags)
{
	size_t w;
	int c;

	c = utf8_get(str, len, &w);
	if (c < 0)
		return -1;

	if ((c >= 0x000A0 && c <= 0x0D7FF) ||
	    (c >= 0x0F900 && c <= 0x0FDCF) ||
	    (c >= 0x0FDF0 && c <= 0x0FFEF) ||
	    (c >= 0x10000 && c <= 0x1FFFD) ||
	    (c >= 0x20000 && c <= 0x2FFFD) ||
	    (c >= 0x30000 && c <= 0x3FFFD) ||
	    (c >= 0x40000 && c <= 0x4FFFD) ||
	    (c >= 0x50000 && c <= 0x5FFFD) ||
	    (c >= 0x60000 && c <= 0x6FFFD) ||
	    (c >= 0x70000 && c <= 0x7FFFD) ||
	    (c >= 0x80000 && c <= 0x8FFFD) ||
	    (c >= 0x90000 && c <= 0x9FFFD) ||
	    (c >= 0xA0000 && c <= 0xAFFFD) ||
	    (c >= 0xB0000 && c <= 0xBFFFD) ||
	    (c >= 0xC0000 && c <= 0xCFFFD) ||
	    (c >= 0xD0000 && c <= 0xDFFFD) ||
	    (c >= 0xE1000 && c <= 0xEFFFD))
		return w;

	return 0;
}

static int is_unreserved(const char *str, size_t len, unsigned int flags)
{

	if (!len)
		return 0;

	if ((*str >= 'a' && *str <= 'z') ||
	    (*str >= 'A' && *str <= 'Z') ||
	    (*str >= '0' && *str <= '9') ||
	    strchr("-._~", *str) != NULL)
		return 1;

	if (!(flags & URI_IRI))
		return 0;

	return is_ucschar(str, len, flags);
}

static int is_sub_delim(const char *str, size_t len, unsigned int flags)
{
	return (len > 0 &&
		strchr("!$&'()*+,;=", *str) != NULL) ? 1 : 0;
}

static int is_digit(const char *str, size_t len, unsigned int flags)
{
	return len > 0 && isdigit(*str) ? 1 : 0;
}

static int is_alpha(const char *str, size_t len, unsigned int flags)
{
	if (!len)
		return 0;

	if ((*str >= 'a' && *str <= 'z') ||
	    (*str >= 'A' && *str <= 'Z'))
		return 1;

	if (!(flags & URI_IRI))
		return 0;

	return 0;
}

static int is_pct_encoded(const char *str, size_t len, unsigned int flags)
{
	if (!len)
		return 0;

	if (*str != '%')
		return 0;

	str++;
	len--;
	if (len < 2 || !isxdigit(str[0]) || !isxdigit(str[1]))
		return -1;
	return 3;
}

static int is_reg_name(const char *str, size_t len, unsigned int flags)
{
	int rc;

	if ((rc =  is_unreserved(str, len, flags)) ||
	    (rc =   is_sub_delim(str, len, flags)) ||
	    (rc = is_pct_encoded(str, len, flags)))
		return rc;

	return 0;
}

static int is_oneof(const char *str, size_t len, unsigned int flags, const char *what)
{
	return len > 0 && strchr(what, *str) ? 1 : 0;
}

static bool valid_uri_scheme(const char *str, size_t len, unsigned int flags)
{
	const char *s, *e;
	int rc;

	/* a reference can get by without a scheme */
	if (!str || !len)
		return (flags & (URI_REF | URI_TEMPLATE)) ? true : false;

	s = str;
	e = s + len;

	/* starts with alpha */
	rc = is_alpha(s, e - s, flags);
	if (rc <= 0)
		return false;
	s += rc;

	while (s < e) {

		if ((rc = is_alpha(s, e - s, flags)) ||
		    (rc = is_digit(s, e - s, flags)) ||
		    (rc = is_oneof(s, e - s, flags, "+-.")))
			;

		/* bad */
		if (rc <= 0)
			return false;
		s += rc;
	}

	return true;
}

static bool valid_uri_userinfo(const char *str, size_t len, unsigned int flags)
{
	const char *s, *e;
	int rc;

	if (!str || !len)
		return true;

	s = str;
	e = s + len;

	while (s < e) {

		if ((rc =  is_unreserved(s, e - s, flags)) ||
		    (rc = is_pct_encoded(s, e - s, flags)) ||
		    (rc =   is_sub_delim(s, e - s, flags)) ||
		    (rc =       is_oneof(s, e - s, flags, ":")))
			;

		/* bad */
		if (rc <= 0)
			return false;
		s += rc;
	}

	return true;
}

static bool valid_uri_host(const char *str, size_t len, unsigned int flags)
{
	char *host;
	const char *s, *e;
	struct in6_addr ipv6_addr;
	int rc;

	if (!str || !len)
		return true;

	s = str;
	e = s + len;

	if (s >= e)
		return false;

	/* must be either IPv6 address or IPvFuture */
	if (*s == '[') {
		/* check if last is ] too */
		if (s + 1 >= e || e[-1] != ']')
			return false;
		s++;
		e--;
		if (s >= e)
			return false;
		/* future vX... */
		if (*s == 'v') {
			if (s + 2 >= e || !isxdigit(s[1]) || s[2] != '.')
				return false;
			/* whatever, return true */
			return true;
		}

		host = alloca((e - s) + 1);
		memcpy(host, s, (e - s));
		host[e - s] = '\0';

		rc = inet_pton(AF_INET6, host, &ipv6_addr);
		if (rc != 1)
			return false;
		return true;
	}

	while (s < e) {

		rc = is_reg_name(s, e - s, flags);
		if (rc <= 0)
			return false;
		s += rc;
	}

	/* either ipv4 address or host, either is valid */
	return true;
}

static bool valid_uri_port(const char *str, size_t len, unsigned int flags)
{
	const char *s, *e;
	int rc;

	if (!str || !len)
		return true;

	s = str;
	e = s + len;

	/* too short */
	if (s >= e)
		return false;

	while (s < e) {
		rc = is_digit(s, e - s, flags);
		if (rc <= 0)
			return false;
		s += rc;
	}

	return true;
}

static bool valid_uri_path(const char *str, size_t len, unsigned int flags)
{
	if (!str || !len)
		return true;

	return true;
}

static bool valid_uri_query(const char *str, size_t len, unsigned int flags)
{
	if (!str || !len)
		return true;

	return true;
}

static bool valid_uri_fragment(const char *str, size_t len, unsigned int flags)
{
	if (!str || !len)
		return true;

	return true;
}

int fy_parse_uri_ext(const char *uri, struct fy_uri *urip, unsigned int flags)
{
	const char *s, *e, *t, *p, *ss;
	bool is_template = !!(flags & URI_TEMPLATE);
	int rc;

	if (!urip || !uri)
		return -1;

	memset(urip, 0, sizeof(*urip));

	s = uri;
	e = uri + strlen(uri);

	/* check for invalid characters (and templates) */
	while (s < e) {
		/* bare } is always an error */
		if (strchr("<>\" \t|\\^`}", *s))
			return -1;

		if (*s == '{') {
			if (!is_template)
				return -1;

			s++;
			while (s < e && *s != '}')
				s++;
			if (s >= e)
				return -1;
		}
		s++;
	}

	s = uri;

	urip->uri = s;
	urip->uri_len = e - s;

	/* valid (but empty */
	if (s >= e)
		goto out;

	/* detect a scheme; if not it's a relative */
	ss = s;
	/* starts with alpha */
	rc = is_alpha(ss, e - ss, flags);
	if (rc <= 0)
		goto skip_authority;

	for (ss += rc; ss < e; ss += rc) {

		if ((rc = is_alpha(ss, e - ss, flags)) ||
		    (rc = is_digit(ss, e - ss, flags)) ||
		    (rc = is_oneof(ss, e - ss, flags, "+-.")))
			;

		if (rc <= 0)
			break;
	}
	if (ss >= e || *ss != ':')
		goto skip_authority;

	urip->scheme = s;
	while (s < e && *s != ':')
		s++;
	if (s >= e)
		goto err_out;

	urip->scheme_len = s - urip->scheme;

	/* skip ':' */
	s++;

	/* // */
	if ((e - s) >= 2 && s[0] == '/' && s[1] == '/') {
		s += 2;

		urip->authority = s;

		t = strchr(s, '@');
		if (t) {
			urip->userinfo = s;
			urip->userinfo_len = t - s;
			s = t + 1;
		}
		t = s + strcspn(s, ":/[");

		if (t < e && *t == '[') {
			t = s + strcspn(s, "]");
			if (t >= e)
				goto err_out;
			urip->host = s;
			urip->host_len = t + 1 - s;
			s = t + 1;
			t = s + strcspn(s, ":/");
		} else if (t > s) {
			urip->host = s;
			urip->host_len = t - s;
		}

		if (t < e && *t == ':') {
			s = t + 1;
			t = s + strcspn(s, "/");
			urip->port = s;
			urip->port_len = t - s;
		}
		s = t;

		urip->authority_len = s - urip->authority;
	}

skip_authority:
	t = s + strcspn(s, "?#");

	if (t > s) {
		urip->path = s;
		urip->path_len = t - s;

		p = memrchr(urip->path, '/', urip->path_len);
		if (p) {
			urip->nslug = urip->path;
			urip->nslug_len = p + 1 - urip->path;
			if (p + 1 < t) {
				urip->slug = p + 1;
				urip->slug_len = t - (p + 1);
			}
		} else {
			urip->slug = urip->path;
			urip->slug_len = urip->path_len;
		}
	}

	if (t < e && *t == '?') {
		s = t + 1;
		t = s + strcspn(s, "#");
		urip->query = s;
		urip->query_len = t - s;
	}
	if (t < e && *t == '#') {
		s = t + 1;
		urip->fragment = s;
		urip->fragment_len = e - s;
	}

out:

	if (!valid_uri_scheme(urip->scheme, urip->scheme_len, flags) ||
	    !valid_uri_userinfo(urip->userinfo, urip->userinfo_len, flags) ||
	    !valid_uri_host(urip->host, urip->host_len, flags) ||
	    !valid_uri_port(urip->port, urip->port_len, flags) ||
	    !valid_uri_path(urip->path, urip->path_len, flags) ||
	    !valid_uri_query(urip->query, urip->query_len, flags) ||
	    !valid_uri_fragment(urip->fragment, urip->fragment_len, flags))
		goto err_bad_uri;

	return 0;

err_out:
	memset(urip, 0, sizeof(*urip));
	return -1;

err_bad_uri:
	/* fprintf(stderr, "REF: parse URI=%.*s%s%.*s%s%.*s%s%.*s%s%.*s%s%.*s%s%.*s%s%.*s%s%.*s\n",
			urip->uri_len, urip->uri,
			urip->scheme ? " scheme=" : "", urip->scheme_len, urip->scheme,
			urip->userinfo ? " userinfo=" : "", urip->userinfo_len, urip->userinfo,
			urip->host ? " host=" : "", urip->host_len, urip->host,
			urip->port ? " port=" : "", urip->port_len, urip->port,
			urip->authority ? " authority=" : "", urip->authority_len, urip->authority,
			urip->path ? " path=" : "", urip->path_len, urip->path,
			urip->query ? " query=" : "", urip->query_len, urip->query,
			urip->fragment ? " fragment=" : "", urip->fragment_len, urip->fragment); */
	goto err_out;
}

int fy_parse_uri(const char *uri, struct fy_uri *urip)
{
	return fy_parse_uri_ext(uri, urip, 0);
}

bool uri_empty(const struct fy_uri *urip)
{
	if (!urip)
		return true;

	return !urip->scheme && !urip->authority && !urip->path && !urip->query &&
	       !urip->fragment;
}

bool uri_fragment_only(const struct fy_uri *urip)
{
	return !urip->scheme && !urip->authority && !urip->path && !urip->query &&
	       urip->fragment;
}

bool uri_absolute_path(const struct fy_uri *urip)
{
	if (!urip)
		return false;

	return urip->path && ((urip->path_len && urip->path[0] == '/') ||
			       urip->path_len == 0);
}

bool uri_relative_path(const struct fy_uri *urip)
{
	return !uri_absolute_path(urip);
}

bool uri_scheme_is(const struct fy_uri *urip, const char *what)
{
	return urip->scheme && strlen(what) == urip->scheme_len &&
		!memcmp(what, urip->scheme, urip->scheme_len);
}

bool uri_scheme_eq(const struct fy_uri *uripa, const struct fy_uri *uripb)
{
	return (!uripa->scheme && !uripb->scheme) ||
		(uripa->scheme_len == uripb->scheme_len && !memcmp(uripa->scheme, uripb->scheme, uripa->scheme_len));
}

bool uri_authority_eq(const struct fy_uri *uripa, const struct fy_uri *uripb)
{
	return (!uripa->authority && !uripb->authority) ||
		(uripa->authority_len == uripb->authority_len && !memcmp(uripa->authority, uripb->authority, uripa->authority_len));
}

bool uri_fragment_eq(const struct fy_uri *uripa, const struct fy_uri *uripb)
{
	return (!uripa->fragment && !uripb->fragment) ||
		(uripa->fragment_len == uripb->fragment_len && !memcmp(uripa->fragment, uripb->fragment, uripa->fragment_len));
}

bool uri_path_eq(const struct fy_uri *uripa, const struct fy_uri *uripb)
{
	return (!uripa->path && !uripb->path) ||
		(uripa->path_len == uripb->path_len && !memcmp(uripa->path, uripb->path, uripa->path_len));
}

bool uri_falls_under(const struct fy_uri *uripa, const struct fy_uri *uripb)
{
	if (!uri_scheme_eq(uripa, uripb) || !uri_authority_eq(uripa, uripb))
		return false;

	/* if the base has no path, then by default it matches */
	if (!uripa->path || !uripa->path_len)
		return true;

	/* the a nslug must exist and be smaller than b */
	if (!uripa->nslug || !uripb->nslug ||
		uripa->nslug_len > uripb->nslug_len)
		return false;

	return !memcmp(uripa->nslug, uripb->nslug, uripa->nslug_len);
}

/*
json-pointer    = *( "/" reference-token )
reference-token = *( unescaped / escaped )
unescaped       = %x00-2E / %x30-7D / %x7F-10FFFF
		; %x2F ('/') and %x7E ('~') are excluded from 'unescaped'
escaped         = "~" ( "0" / "1" )
		; representing '~' and '/', respectively
*/

static int is_unescaped(const char *str, size_t len, unsigned int flags)
{
	size_t w;
	int c;

	c = utf8_get(str, len, &w);
	if (c < 0)
		return -1;

	if ((c >= 0x000000 && c <= 0x00002E) ||
	    (c >= 0x000030 && c <= 0x00007D) ||
	    (c >= 0x00007F && c <= 0x10FFFF))
		return w;
	return 0;
}

static int is_escaped(const char *str, size_t len, unsigned int flags)
{
	if (len < 2 || *str != '~' || (str[1] != '0' && str[1] != '1'))
		return 0;
	return 2;
}

static int is_reference_token(const char *str, size_t len, unsigned int flags)
{
	int rc;

	if ((rc = is_unescaped(str, len, flags)) ||
	    (rc =   is_escaped(str, len, flags)))
		;

	return rc;
}

static int is_json_pointer(const char *str, size_t len, unsigned int flags)
{
	const char *s, *e;
	int rc;

	s = str;
	e = s + len;

	while (s < e) {

		if (*s != '/')
			break;
		s++;
		while ((rc = is_reference_token(s, e - s, flags)) > 0)
			s += rc;
	}

	return s - str;
}

bool is_valid_json_pointer(const char *str)
{
	size_t len;
	int rc;

	len = strlen(str);
	rc = is_json_pointer(str, len, 0);
	return rc == (int)len;
}

bool is_valid_reljson_pointer(const char *str)
{
	const char *s;
	size_t len;
	int rc;

	s = str;
	if (*s == '0')
		s++;
	else {
		while (isdigit(*s))
			s++;
	}
	if (s <= str)
		return false;

	len = strlen(s);

	/* only part that remains is # */
	if (len == 1 && *s == '#')
		return true;

	rc = is_json_pointer(s, len, 0);
	return rc == (int)len;
}

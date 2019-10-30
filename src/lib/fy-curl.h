/*
 * fy-curl.c - minimal curl wrapper
 *
 * Copyright (c) 2019 Pantelis Antoniou <pantelis.antoniou@konsulko.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef FY_CURL_H
#define FY_CURL_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>

#include <libfyaml.h>

#if defined(HAVE_LIBCURL) && HAVE_LIBCURL
#include <curl/curl.h>
#endif

#if defined(HAVE_LIBCURL) && HAVE_LIBCURL

void *fy_curl_init(void);
void fy_curl_cleanup(void *handle);
char *fy_curl_get_file(void *handle, const char *url, size_t *lenp);
void fy_curl_set_verbose(void *handle, bool verbose);
struct fy_document *
fy_curl_get_document(void *handle, const struct fy_parse_cfg *cfg, const char *url);
time_t fy_curl_get_filetime(void *handle);

#else

static inline void *fy_curl_init(void)
{
	/* return non-NULL */
	return (void *)(intptr_t)-1;
}

static inline void fy_curl_cleanup(void *handle)
{
	/* nothing */
}

static inline char *fy_curl_get_file(void *handle, const char *url, size_t *lenp)
{
	return NULL;
}

static inline void fy_curl_set_verbose(void *handle, bool verbose)
{
	/* nothing */
}

static inline struct fy_document *
fy_curl_get_document(void *handle, const struct fy_parse_cfg *cfg, const char *url)
{
	return NULL;
}

static inline time_t fy_curl_get_filetime(void *handle)
{
	return (time_t)-1;
}

#endif

#endif


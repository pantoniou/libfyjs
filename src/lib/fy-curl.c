/*
 * fy-curl.c - FY curl wrapper
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
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#include <libfyaml.h>

#include "fy-curl.h"

static int curl_init_count = 0;

void *fy_curl_init(void)
{
	bool was_first = false;
	CURL *curl_handle;

	if (curl_init_count++ == 0) {
		curl_global_init(CURL_GLOBAL_ALL);
		was_first = true;
	}

	/* init the curl session */
	curl_handle = curl_easy_init();
	if (curl_handle)
		return curl_handle;

	if (was_first)
		curl_global_cleanup();

	return NULL;
}

void fy_curl_cleanup(void *handle)
{
	CURL *curl_handle = handle;

	if (!handle)
		return;

	/* cleanup curl stuff */
	curl_easy_cleanup(curl_handle);

	if (--curl_init_count <= 0)
		curl_global_cleanup();
}

struct curl_write_data_ctx {
	char *buffer;
	size_t alloc;
	size_t count;
};

static size_t curl_write_data(void *ptr, size_t size, size_t nmemb, void *ctx)
{
	struct curl_write_data_ctx *c = ctx;
	size_t nbytes = size * nmemb;
	char *tbuf;
	size_t new_alloc;

	if (!c->buffer) {
		c->buffer = malloc(4096);
		if (!c->buffer)
			return -1;
		c->alloc = 4096;
		c->count = 0;
	}

	new_alloc = c->alloc;
	while (c->count + nbytes > new_alloc)
		new_alloc *= 2;

	if (new_alloc > c->alloc) {
		tbuf = realloc(c->buffer, new_alloc);
		if (!tbuf)
			return -1;
		c->buffer = tbuf;
		c->alloc = new_alloc;
	}

	memcpy(c->buffer + c->count, ptr, nbytes);
	c->count += nbytes;

	return nbytes;
}

char *fy_curl_get_file(void *handle, const char *url, size_t *lenp)
{
	CURL *curl_handle = handle;
	struct curl_write_data_ctx c;
	char *tbuf;

	if (!curl_handle)
		return NULL;

	memset(&c, 0, sizeof(c));

	/* set URL to get here */
	curl_easy_setopt(curl_handle, CURLOPT_URL, url);

	/* disable progress meter, set to 0L to enable and disable debug output */
	curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);

	/* send all data to this function  */
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, curl_write_data);

	/* set the buffer */
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &c);

	/* follow redirections */
	curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);

	/* request remote file modification time */
	curl_easy_setopt(curl_handle, CURLOPT_FILETIME, 1L);

	/* get it! */
	curl_easy_perform(curl_handle);

	if (!c.buffer)
		return NULL;

	tbuf = realloc(c.buffer, c.count + 1);
	if (!tbuf)
		return NULL;
	tbuf[c.count] = '\0';
	*lenp = c.count;

	return tbuf;
}

void fy_curl_set_verbose(void *handle, bool verbose)
{
	CURL *curl_handle = handle;

	if (!curl_handle)
		return;

	/* Switch on full protocol/debug output while testing */
	curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, verbose ? 1L : 0L);
}

struct fy_document *
fy_curl_get_document(void *handle, const struct fy_parse_cfg *cfg, const char *url)
{
	CURL *curl_handle = handle;
	struct fy_document *fyd;
	char *str;
	size_t len;

	if (!curl_handle)
		return NULL;

	str = fy_curl_get_file(curl_handle, url, &len);
	if (!str)
		return NULL;
	fyd = fy_document_build_from_malloc_string(cfg, str, len);
	if (!fyd)
		free(str);
	return fyd;
}

time_t fy_curl_get_filetime(void *handle)
{
	CURL *curl_handle = handle;
	long time;
	CURLcode cc;

	if (!curl_handle)
		return (time_t)-1;
	
	cc = curl_easy_getinfo(curl_handle, CURLINFO_FILETIME, &time);
	if (cc != CURLE_OK || time <= 0)
		return (time_t)-1;

	return (time_t)time;
}

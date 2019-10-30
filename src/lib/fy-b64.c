/*
 * fy-b64.c - base64 decoding wrapper
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

#include "fy-b64.h"

#if defined(HAVE_LIBB64) && HAVE_LIBB64
#include <b64/cdecode.h>
#endif

bool fy_b64_valid(const char *str)
{
	const char *s;

	for (s = str; *s && *s != '='; s++) {
		if (*s == '\n' || *s == '\r')
			continue;
		if (!fy_b64_char(*s))
			return false;
	}
	/* padding at the end */
	while (*s == '=' || *s == '\n' || *s == '\r')
		s++;

	/* and trailing new lines */
	while (*s == '\n' || *s == '\r')
		s++;

	return *s ? false : true;
}

#if defined(HAVE_LIBB64) && HAVE_LIBB64

void *fy_b64_decode(const char *str, size_t *sizep)
{
	base64_decodestate ds;
	size_t len, cnt;
	char *out = NULL, *out2;

	*sizep = 0;

	if (!fy_b64_valid(str))
		goto err_out;

	len = strlen(str);

	out = malloc(len + 1);

	base64_init_decodestate(&ds);
	cnt = base64_decode_block(str, len, out, &ds);
	if (cnt < 0)
		goto err_out;

	/* trim */
	out2 = realloc(out, cnt + 1);
	if (!out2)
		goto err_out;
	out2[cnt] = '\0';

	*sizep = cnt;
	return out2;
err_out:
	if (out)
		free(out);
	return NULL;
}

#else

void *fy_b64_decode(const char *str)
{
	return NULL;
}

#endif

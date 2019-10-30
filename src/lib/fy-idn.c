/*
 * fy-idn.c - IDN handling methods
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

#include "fy-idn.h"

#if defined(HAVE_LIBIDN) && HAVE_LIBIDN
#include <stringprep.h>
#include <idna.h>
#include <tld.h>
#endif

#if defined(HAVE_LIBIDN) && HAVE_LIBIDN

bool fy_idn_is_hostname(const char *str)
{
	int rc, i;
	char *p;
	uint32_t *r;
	size_t errpos;

	rc = idna_to_ascii_8z(str, &p, 0);
	if (rc != IDNA_SUCCESS)
		return false;
	rc = idna_to_unicode_8z4z(p, &r, 0);
	free(p);
	if (rc != IDNA_SUCCESS)
		return false;

	/* check for exceptions that 4z does not check */
	for (i = 0; r[i]; i++) {
		if (!fy_idn_valid_unicode(r[i])) {
			free(r);
			return false;
		}
	}

	rc = tld_check_4z(r, &errpos, NULL);
	free(r);
	return rc == TLD_SUCCESS;
}

#else

bool fy_idn_is_hostname(const char *str)
{
	return false;
}

#endif

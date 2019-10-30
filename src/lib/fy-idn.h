/*
 * fy-idn.h - IDN methods
 *
 * Copyright (c) 2019 Pantelis Antoniou <pantelis.antoniou@konsulko.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef FY_IDN64_H
#define FY_IDN64_H

#include <stdbool.h>
#include <stdint.h>

static inline bool fy_idn_unicode_is_control(uint32_t v)
{
	return (v >= 0 && v <= 0x1f) || (v >= 0x80 && v <= 0x9f);
}

static inline bool fy_idn_unicode_is_space(uint32_t v)
{
	return v == 0x20 || v == 0xa0 ||
	       (v >= 0x2000 && v <= 0x200a) ||
	       v == 0x202f || v == 0x205f || v == 0x3000;
}

static inline bool fy_idn_is_special_exception(uint32_t v)
{
	return v == 0x0640 || v == 0x07FA || v == 0x302E ||
	       v == 0x302F || v == 0x3031 || v == 0x3035 || v == 0x303B;
}

static inline bool fy_idn_valid_unicode(uint32_t v)
{
	/* TODO more ? */
	return !(fy_idn_unicode_is_control(v) ||
		 fy_idn_unicode_is_space(v) ||
		 fy_idn_is_special_exception(v));
}

bool fy_idn_is_hostname(const char *str);

#endif


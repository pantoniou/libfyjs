/*
 * fy-b64.h - header file for base 64 decoding
 *
 * Copyright (c) 2019 Pantelis Antoniou <pantelis.antoniou@konsulko.com>
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef FY_B64_H
#define FY_B64_H

#include <stdbool.h>
#include <stdint.h>

static inline bool fy_b64_char(const char c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
	       (c >= '0' && c <= '9') || c == '+' || c == '/';
}

bool fy_b64_valid(const char *str);
void *fy_b64_decode(const char *str, size_t *sizep);

#endif


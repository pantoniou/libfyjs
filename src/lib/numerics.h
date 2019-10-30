#ifndef NUMERICS_H
#define NUMERICS_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <math.h>

#if defined(HAVE_GMP) && HAVE_GMP
#include <gmp.h>
#endif

/* #define DISABLE_MP */

#if (defined(HAVE_GMP) && HAVE_GMP) && !defined(DISABLE_MP)

typedef mpz_t fyjs_i;
typedef mpf_t fyjs_n;

#define fyjs_i_init(_x)	mpz_init((_x))
#define fyjs_i_clear(_x) mpz_clear((_x))
#define fyjs_i_set_str(_x, _str) mpz_set_str((_x), (_str), 10)
#define fyjs_i_cmp(_x1, _x2) mpz_cmp((_x1), (_x2))
#define fyjs_i_cmp_0(_x) mpz_cmp_si((_x), 0)
#define fyjs_i_rem_is_0(_x, _y) \
	({ \
		bool _res; \
		mpz_t _r; \
		mpz_init(_r); \
		mpz_mod(_r, (_x), (_y)); \
		_res = mpz_cmp_si(_r, 0) == 0; \
		mpz_clear(_r); \
		_res; \
	})

#define fyjs_n_init(_x)	mpf_init((_x))
#define fyjs_n_clear(_x) mpf_clear((_x))
#define fyjs_n_set_str(_x, _str) mpf_set_str((_x), (_str), 10)
#define fyjs_n_cmp(_x1, _x2) mpf_cmp((_x1), (_x2))
#define fyjs_n_cmp_0(_x) mpf_cmp_si((_x), 0)
#define fyjs_n_rem_is_0(_x, _y) \
	({ \
		bool _res; \
		mpf_t _r; \
		mpf_init(_r); \
		mpf_div(_r, (_x), (_y)); \
		_res = mpf_integer_p(_r) != 0; \
		mpf_clear(_r); \
		_res; \
	})

#define fyjs_n_set_i(_n, _i) mpf_set_z((_n), (_i))

#define fyjs_n_is_i(_n) (!!mpf_integer_p((_n)))

#else

typedef long fyjs_i;
typedef double fyjs_n;

#define fyjs_i_init(_x)	do { (_x) = 0; } while(0)
#define fyjs_i_clear(_x) do { } while(0)
#define fyjs_i_set_str(_x, _str) do { (_x) = strtol((_str), NULL, 10); } while(0)
#define fyjs_i_cmp(_x1, _x2) \
	({ \
		fyjs_i __x1 = (_x1); \
		fyjs_i __x2 = (_x2); \
		__x1 < __x2 ? -1 : __x1 > __x2 ? 1 : 0; \
	 })
#define fyjs_i_cmp_0(_x) fyjs_i_cmp((_x), 0)
#define fyjs_i_rem_is_0(_x, _y) (((_x) % (_y)) == 0)

#define fyjs_n_init(_x)	do { (_x) = 0.0; } while(0)
#define fyjs_n_clear(_x) do { } while(0)
#define fyjs_n_set_str(_x, _str) do { (_x) = strtod((_str), NULL); } while(0)
#define fyjs_n_cmp(_x1, _x2) \
	({ \
		fyjs_n __x1 = (_x1); \
		fyjs_n __x2 = (_x2); \
		__x1 < __x2 ? -1 : __x1 > __x2 ? 1 : 0; \
	 })
#define fyjs_n_cmp_0(_x) fyjs_n_cmp((_x), 0.0)
#define fyjs_n_rem_is_0(_x, _y) (fmod((_x), (_y)) == 0.0)

#define fyjs_n_set_i(_n, _i) ((_n) = (fyjs_n)(_i))

#define fyjs_n_is_i(_n) \
	({ \
		fyjs_n __n = (_n); \
		ceil(__n) == __n; \
	})

#endif

typedef struct {
	bool integer;
	union {
		fyjs_i i;
		fyjs_n n;
	};
} fyjs_numeric;

#define fyjs_numeric_init(_number, _integer) \
	do { \
		fyjs_numeric *__number = &(_number); \
		__number->integer = !!(_integer); \
		if (__number->integer) \
			fyjs_i_init(__number->i); \
		else \
			fyjs_n_init(__number->n); \
	} while(0)

#define fyjs_numeric_clear(_number) \
	do { \
		fyjs_numeric *__number = &(_number); \
		if (__number->integer) \
			fyjs_i_clear(__number->i); \
		else \
			fyjs_n_clear(__number->n); \
	} while(0)

#define fyjs_numeric_set_str(_number, _str) \
	do { \
		fyjs_numeric *__number = &(_number); \
		const char *__str = (_str); \
		if (__number->integer) \
			fyjs_i_set_str(__number->i, __str); \
		else \
			fyjs_n_set_str(__number->n, __str); \
	} while(0)

#define fyjs_numeric_cmp(_number1, _number2) \
	({ \
		fyjs_numeric *__number1 = &(_number1); \
		fyjs_numeric *__number2 = &(_number2); \
		int __res; \
		\
		if (__number1->integer && __number2->integer) \
			__res = fyjs_i_cmp(__number1->i, __number2->i); \
		else if (!__number1->integer && !__number2->integer) \
			__res = fyjs_n_cmp(__number1->n, __number2->n); \
		else { \
			fyjs_n __nn; \
			fyjs_n_init(__nn); \
			if (__number1->integer) { \
				fyjs_n_set_i(__nn, __number1->i); \
				__res = fyjs_n_cmp(__nn, __number2->n); \
			} else { \
				fyjs_n_set_i(__nn, __number2->i); \
				__res = fyjs_n_cmp(__number1->n, __nn); \
			} \
			fyjs_n_clear(__nn); \
		} \
		__res; \
	})

#define fyjs_numeric_cmp_0(_number) \
	({ \
		fyjs_numeric *__number = &(_number); \
		__number->integer ? fyjs_i_cmp_0(__number->i) : fyjs_n_cmp_0(__number->n); \
	})

#define fyjs_numeric_rem_is_0(_number1, _number2) \
	({ \
		fyjs_numeric *__number1 = &(_number1); \
		fyjs_numeric *__number2 = &(_number2); \
		bool __res; \
		\
		if (__number1->integer && __number2->integer) \
			__res = fyjs_i_rem_is_0(__number1->i, __number2->i); \
		else if (!__number1->integer && !__number2->integer) \
			__res = fyjs_n_rem_is_0(__number1->n, __number2->n); \
		else { \
			fyjs_n __nn; \
			fyjs_n_init(__nn); \
			if (__number1->integer) { \
				fyjs_n_set_i(__nn, __number1->i); \
				__res = fyjs_n_rem_is_0(__nn, __number2->n); \
			} else { \
				fyjs_n_set_i(__nn, __number2->i); \
				__res = fyjs_n_rem_is_0(__number1->n, __nn); \
			} \
			fyjs_n_clear(__nn); \
		} \
		__res; \
	})

#define fyjs_numeric_is_integer(_number) \
	({ \
		fyjs_numeric *__number = &(_number); \
		__number->integer || fyjs_n_is_i(__number->n); \
	 })

#endif

AC_PREREQ(2.61)

AC_INIT([libfyjs],
        m4_esyscmd([build-aux/git-version-gen .tarball-version]),
	[pantelis.antoniou@konsulko.com])

AC_CONFIG_SRCDIR([src/lib/fy-jsonschema.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign 1.8.5 -Wall subdir-objects ])
AM_EXTRA_RECURSIVE_TARGETS([fastcheck])

m4_define(fyjs_major, `echo $VERSION | cut -d. -f1 | cut -d- -f1`)
m4_define(fyjs_minor, `echo $VERSION | cut -d. -f2 | cut -d- -f1`)
m4_define(fyjs_patch, `echo $VERSION | cut -d. -f3- | cut -d- -f1`)
m4_define(fyjs_extra, `echo $VERSION | cut -d- -f2-`)

AC_SUBST(MAJOR, fyjs_major)
AC_SUBST(MINOR, fyjs_minor)
AC_SUBST(PATCH, fyjs_patch)
AC_SUBST(EXTRA, fyjs_extra)

m4_define(fyjs_date, `git show -s --format=%ci`)
AC_SUBST(DATE, fyjs_date)

AC_SUBST(DEBVERSION, "$MAJOR.$MINOR")

dnl AX_* requires 2.64
m4_version_prereq(2.64, [AX_CHECK_ENABLE_DEBUG()], [true])

AC_PROG_MKDIR_P
AC_PROG_CC
AC_PROG_CC_C99
AM_PROG_CC_C_O

AC_PROG_GCC_TRADITIONAL
AC_USE_SYSTEM_EXTENSIONS
m4_ifdef([AM_PROG_AR], [AM_PROG_AR],
	 [AC_MSG_WARN([Old automake version without AM_PROG_AR, library versioning will not be available])])

AC_PROG_CXX
AC_PROG_AWK
AC_PROG_LN_S

AX_PTHREAD

AC_PATH_PROG([M4], [m4 gm4], [no])
if test "x$M4" = xno ; then
   AC_MSG_ERROR([m4 missing])
fi

AC_SUBST(ACLOCAL_AMFLAGS, "-I m4")

# pkg-config
export PKG_CONFIG_PATH="${PKG_CONFIG_PATH}:$prefix/lib/pkgconfig"
AC_MSG_NOTICE([$prefix])
PKG_PROG_PKG_CONFIG

AC_LTDL_ENABLE_INSTALL
AC_LIBLTDL_INSTALLABLE
AC_LIBTOOL_DLOPEN
AC_LIBTOOL_WIN32_DLL
AC_PROG_LIBTOOL
AC_SUBST(LTDLINCL)
AC_SUBST(LIBLTDL)
AC_CONFIG_SUBDIRS(libltdl)

AC_HEADER_STDC
AC_C_CONST
AC_C_BIGENDIAN
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_CHECK_TYPES(ssize_t, , [AC_DEFINE([ssize_t], [signed long],
    [Define ssize_t if it is not done by the standard libs.])])
AC_TYPE_OFF_T
AC_TYPE_SIGNAL
AC_TYPE_UID_T
AC_CHECK_DECLS(environ)

dnl for old autoconf version AX_APPEND_COMPILE_FLAGS does not work
m4_version_prereq(2.64,
	 [AX_APPEND_COMPILE_FLAGS([-Wall -Wsign-compare], [CFLAGS], [-pedantic -Werror])],
         [CFLAGS="$CFLAGS -Wall -Wsign-compare"])

dnl -O2 is universal no need for AX_APPEND_COMPILE_FLAGS
if test "x$ax_enable_debug" != "xyes" ; then
	# CAUTION; gcc >=7 generates thunks that expect -z execstack
	CFLAGS="$CFLAGS -O2"
	m4_version_prereq(2.64,
		[AX_APPEND_COMPILE_FLAGS([-zexecstack], [CFLAGS], [])],
		[CFLAGS="$CFLAGS -zexecstack"])
fi

# include -lm in the link
AC_SEARCH_LIBS([fmod], [m], [], [AC_MSG_ERROR([unable to find the fmod() function])])

# the minimum supported release is 0.4
PKG_CHECK_MODULES(LIBFYAML, [ libfyaml >= 0.4 ], HAVE_LIBFYAML=1, HAVE_LIBFYAML=0)
if test "x$HAVE_LIBFYAML" != "x1" ; then
	AC_MSG_ERROR([failed to find libfyaml])
fi

AC_SUBST(HAVE_LIBFYAML)
AC_SUBST(LIBFYAML_CFLAGS)
AC_SUBST(LIBFYAML_LIBS)
AC_DEFINE_UNQUOTED([HAVE_LIBFYAML], [$HAVE_LIBFYAML], [Define to 1 if you have libfyaml available])
AM_CONDITIONAL([HAVE_LIBFYAML], [ test x$HAVE_LIBFYAML = x1 ])

PKG_CHECK_MODULES(LIBPCRE, [ libpcre ], HAVE_LIBPCRE=1, HAVE_LIBPCRE=0)
if test "x$HAVE_LIBPCRE" != "x1" ; then
	AC_MSG_ERROR([failed to find libpcre])
fi

AC_SUBST(HAVE_LIBPCRE)
AC_SUBST(LIBPCRE_CFLAGS)
AC_SUBST(LIBPCRE_LIBS)
AC_DEFINE_UNQUOTED([HAVE_LIBPCRE], [$HAVE_LIBPCRE], [Define to 1 if you have libpcre available])
AM_CONDITIONAL([HAVE_LIBPCRE], [ test x$HAVE_LIBPCRE = x1 ])

PKG_CHECK_MODULES(LIBCURL, [ libcurl ], HAVE_LIBCURL=1, HAVE_LIBCURL=0)
if test "x$HAVE_LIBCURL" != "x1" ; then
	AC_MSG_WARN([failed to find libcurl, will be unable to retreive online schemas])
fi

AC_SUBST(HAVE_LIBCURL)
AC_SUBST(LIBCURL_CFLAGS)
AC_SUBST(LIBCURL_LIBS)
AC_DEFINE_UNQUOTED([HAVE_LIBCURL], [$HAVE_LIBCURL], [Define to 1 if you have libfyaml available])
AM_CONDITIONAL([HAVE_LIBCURL], [ test x$HAVE_LIBCURL = x1 ])

# bignum support
AC_CHECK_HEADERS([gmp.h], [HAVE_GMP_H=1], [HAVE_GMP_H=0])
save_LIBS="$LIBS"
AC_SEARCH_LIBS([__gmpz_init], [gmp], [HAVE_LIBGMP=1], [HAVE_LIBGMP=0])
LIBS="$save_LIBS"

LIBGMP_CFLAGS=""
LIBGMP_LIBS=""
if test "x${HAVE_GMP_H}x${HAVE_LIBGMP}" == "x1x1"; then
	HAVE_GMP=1
	LIBGMP_LIBS="-lgmp"
else
	HAVE_GMP=0
fi
AC_SUBST(LIBGMP_CFLAGS)
AC_SUBST(LIBGMP_LIBS)
AC_DEFINE_UNQUOTED([HAVE_GMP], [$HAVE_GMP], [Define to 1 if you have gnu mp available])
AM_CONDITIONAL([HAVE_GMP], [ test x$HAVE_GMP = x1 ])

# libidn support (for IDN stuff)
PKG_CHECK_MODULES(LIBIDN, [ libidn ], HAVE_LIBIDN=1, HAVE_LIBIDN=0)
AC_SUBST(HAVE_LIBIDN)
AC_SUBST(LIBIDN_CFLAGS)
AC_SUBST(LIBIDN_LDFLAGS)
AC_SUBST(LIBIDN_LIBS)
AC_DEFINE_UNQUOTED([HAVE_LIBIDN], [$HAVE_LIBIDN], [Define to 1 if you have libidn available])
AM_CONDITIONAL([HAVE_LIBIDN], [ test x$HAVE_LIBIDN = x1 ])

# libb64
AC_CHECK_HEADERS([b64/cencode.h b64/cdecode.h], [HAVE_LIBB64_H=1], [HAVE_LIBB64_H=0])
save_LIBS="$LIBS"
AC_SEARCH_LIBS([base64_init_encodestate], [b64], [HAVE_LIBB64=1], [HAVE_LIBB64=0])
LIBS="$save_LIBS"

LIBB64_CFLAGS=""
LIBB64_LIBS=""
if test "x${HAVE_LIBB64_H}x${HAVE_LIBB64}" == "x1x1"; then
	HAVE_LIBB64=1
	LIBB64_LIBS="-lb64"
else
	HAVE_LIBB64=0
fi
AC_SUBST(LIBB64_CFLAGS)
AC_SUBST(LIBB64_LIBS)
AC_DEFINE_UNQUOTED([HAVE_LIBB64], [$HAVE_LIBB64], [Define to 1 if you have libb64 available])
AM_CONDITIONAL([HAVE_LIBB64], [ test x$HAVE_LIBB64 = x1 ])

PKG_CHECK_MODULES(CHECK, [ check ], HAVE_CHECK=1, HAVE_CHECK=0)

AC_SUBST(HAVE_CHECK)
AC_SUBST(CHECK_CFLAGS)
AC_SUBST(CHECK_LDFLAGS)
AC_SUBST(CHECK_LIBS)
AC_DEFINE_UNQUOTED([HAVE_CHECK], [$HAVE_CHECK], [Define to 1 if you have check available])
AM_CONDITIONAL([HAVE_CHECK], [ test x$HAVE_CHECK = x1 ])

HAVE_COMPATIBLE_CHECK=0
if test "x$HAVE_CHECK" == "x1" ; then
	save_LIBS="$LIBS"
	save_CFLAGS="$CFLAGS"
	LIBS="$LIBS $CHECK_LIBS"
	CFLAGS="$CFLAGS $CHECK_CFLAGS"

	# check if libcheck has srunner_set_tap (jessie has outdated libcheck)
	AC_CHECK_FUNC([srunner_set_tap],
		      HAVE_COMPATIBLE_CHECK=1,
		      HAVE_COMPATIBLE_CHECK=0)

	LIBS="$save_LIBS"
	CFLAGS="$save_CFLAGS"
fi

AC_SUBST(HAVE_COMPATIBLE_CHECK)
AC_DEFINE_UNQUOTED([HAVE_COMPATIBLE_CHECK], [$HAVE_COMPATIBLE_CHECK], [Define to 1 if you have a compatible version of check available])
AM_CONDITIONAL([HAVE_COMPATIBLE_CHECK], [ test x$HAVE_COMPATIBLE_CHECK = x1 ])

dnl enable internet available when checking
AC_ARG_ENABLE([network],
	      AS_HELP_STRING([--disable-network],
			     [Disable tests requiring network access]))

if test "x$enable_network" != "xno" ; then 
	HAVE_NETWORK=1
else
	HAVE_NETWORK=0
fi	
AC_SUBST(HAVE_NETWORK)
AM_CONDITIONAL([HAVE_NETWORK],
	       [ test x$HAVE_NETWORK = x1 ])

# check for sphinx
AC_PATH_PROG([SPHINX], [sphinx-build])
if test "x$SPHINX" != "x" ; then
	HAVE_SPHINX=1
else
	HAVE_SPHINX=0
fi
AC_DEFINE_UNQUOTED([HAVE_SPHINX], [$HAVE_SPHINX], [Define to 1 if you have sphinx available])
AM_CONDITIONAL([HAVE_SPHINX], [ test x$HAVE_SPHINX = x1 ])

# check for git
AC_PATH_PROG([GIT], [git])
if test "x$GIT" != "x" ; then
	HAVE_GIT=1
else
	HAVE_GIT=0
fi
AC_DEFINE_UNQUOTED([HAVE_GIT], [$HAVE_GIT], [Define to 1 if you have git available])
AM_CONDITIONAL([HAVE_GIT], [ test x$HAVE_GIT = x1 ])

AC_ARG_VAR(TESTSUITEURL, [Testsuite git repo URL (default: https://github.com/json-schema-org/JSON-Schema-Test-Suite.git)])
if test "x$TESTSUITEURL" == "x" ; then
	TESTSUITEURL="https://github.com/json-schema-org/JSON-Schema-Test-Suite.git"
fi

AC_ARG_VAR(SPECURL, [Scheme spec git repo URL (default: https://github.com/json-schema-org/json-schema-spec.git)])
if test "x$SPECURL" == "x" ; then
	SPECURL="https://github.com/json-schema-org/json-schema-spec.git"
fi

# check for docker
AC_PATH_PROG([DOCKER], [docker])
if test "x$DOCKER"  != "x" ; then
	HAVE_DOCKER=1
else
	HAVE_DOCKER=0
fi
AM_CONDITIONAL([HAVE_DOCKER], [ test x$HAVE_DOCKER = x1 ])

AC_SUBST(LIBFYJS_CFLAGS, "$LIBFYAML_CFLAGS $LIBPCRE_CFLAGS $LIBCURL_CFLAGS $LIBGMP_CFLAGS $LIBIDN_CFLAGS $LIBB64_CFLAGS")
AC_SUBST(LIBFYJS_LIBS, "$LIBFYAML_LIBS $LIBPCRE_LIBS $LIBCURL_LIBS $LIBGMP_LIBS $LIBIDN_LIBS $LIBB64_LIBS")

# Shave by default
SHAVE_INIT([build-aux], [enable])

AC_CONFIG_FILES([
        build-aux/shave
        build-aux/shave-libtool
	Makefile
	src/Makefile
	test/Makefile
	libfyjs.pc
])

AC_REQUIRE_AUX_FILE([tap-driver.sh])

AC_OUTPUT

echo "
 ---{ $PACKAGE_NAME $VERSION }---

    VERSION:               ${VERSION}
    prefix:                ${prefix}
    C compiler:            ${CC}
    CFLAGS:                ${CFLAGS}
    Linker:                ${LD}
    LDFLAGS:               ${LDFLAGS}
    LIBS:                  ${LIBS}
    LIBFYAML_CFLAGS:       $LIBFYAML_CFLAGS
    LIBFYAML_LIBS:         $LIBFYAML_LIBS
    LIBPCRE_CFLAGS:        $LIBPCRE_CFLAGS
    LIBPCRE_LIBS:          $LIBPCRE_LIBS
    LIBCURL_CFLAGS:        $LIBCURL_CFLAGS
    LIBCURL_LIBS:          $LIBCURL_LIBS
    LIBGMP_CFLAGS:         $LIBGMP_CFLAGS
    LIBGMP_LIBS:           $LIBGMP_LIBS
    LIBIDN_CFLAGS:         $LIBIDN_CFLAGS
    LIBIDN_LIBS:           $LIBIDN_LIBS
    LIBB64_CFLAGS:         $LIBB64_CFLAGS
    LIBB64_LIBS:           $LIBB64_LIBS
    HAVE_CHECK:            ${HAVE_CHECK}
    HAVE_COMPATIBLE_CHECK: ${HAVE_COMPATIBLE_CHECK}
    HAVE_NETWORK:          ${HAVE_NETWORK}
    SPHINX:                $SPHINX
    GIT:                   $GIT
    DOCKER:                $DOCKER
    TESTSUITEURL:          $TESTSUITEURL
    SPECURL:               $SPECURL

"

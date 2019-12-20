AM_CPPFLAGS = \
        -I$(top_srcdir)/src \
        -I$(top_srcdir)/include
AM_CFLAGS =

lib_LTLIBRARIES = libfyjs-@MAJOR@.@MINOR@.la
libfyjs_@MAJOR@_@MINOR@_la_SOURCES = \
	lib/fy-jsonschema.c lib/fy-jsonschema.h \
	lib/numerics.h \
	lib/fy-uri.c lib/fy-uri.h \
	lib/fy-curl.c lib/fy-curl.h \
	lib/fy-b64.c lib/fy-b64.h \
	lib/fy-idn.c lib/fy-idn.h

libfyjs_@MAJOR@_@MINOR@_la_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/incbin \
	-I$(top_srcdir)/src/schemas
libfyjs_@MAJOR@_@MINOR@_la_CFLAGS = \
	$(AM_CFLAGS) \
	@LIBFYJS_CFLAGS@
libfyjs_@MAJOR@_@MINOR@_la_LDFLAGS = \
	$(AM_LDFLAGS) $(AM_LIBLDFLAGS) $(VERSIONING_LDFLAGS) \
	-version-info 0:0:0 \
	@LIBFYJS_LIBS@

bin_PROGRAMS = 
noinst_PROGRAMS =

bin_PROGRAMS += fyjs-tool

fyjs_tool_SOURCES = \
	tool/fyjs-tool.c tool/fyjs-tool.h \
	valgrind/fy-valgrind.h \
	tool/fyjs-testsuite.c \
	tool/fyjs-validate.c

fyjs_tool_CPPFLAGS = $(AM_CPPFLAGS) \
		     -I$(top_srcdir)/src/valgrind \
		     -I$(top_srcdir)/src/incbin \
		     -I$(top_srcdir)/src/schemas
fyjs_tool_LDADD = $(AM_LDADDR) libfyjs-@MAJOR@.@MINOR@.la
fyjs_tool_CFLAGS = $(AM_CFLAGS) $(LIBFYAML_CFLAGS)
fyjs_tool_LDFLAGS = $(AM_LDFLAGS) $(LIBFYAML_LIBS)

noinst_PROGRAMS += fyjs-simple-validate

fyjs_simple_validate_SOURCES = \
	simple-validate/simple-validate.c \
	valgrind/fy-valgrind.h

fyjs_simple_validate_CPPFLAGS = $(AM_CPPFLAGS) \
		     -I$(top_srcdir)/src/valgrind
fyjs_simple_validate_LDADD = $(AM_LDADDR) libfyjs-@MAJOR@.@MINOR@.la
fyjs_simple_validate_CFLAGS = $(AM_CFLAGS) $(LIBFYAML_CFLAGS)
fyjs_simple_validate_LDFLAGS = $(AM_LDFLAGS) $(LIBFYAML_LIBS)

include_HEADERS = \
	$(top_srcdir)/include/libfyjs.h

install-exec-hook:
	(cd "$(DESTDIR)$(bindir)" && $(LN_S) -f fyjs-tool fyjs-testsuite)
	(cd "$(DESTDIR)$(bindir)" && $(LN_S) -f fyjs-tool fyjs-validate)

uninstall-hook:
	(cd "$(DESTDIR)$(bindir)" && rm -f fyjs-validate fyjs-testsuite)

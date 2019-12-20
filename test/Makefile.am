# test-suite (run with 'make check')

AM_CPPFLAGS = \
        -I$(top_srcdir)/include
AM_CFLAGS =

AM_TESTS_ENVIRONMENT= \
	TOP_SRCDIR="${top_srcdir}" \
	TOP_BUILDDIR="${top_builddir}" \
	SRCDIR="${srcdir}" \
	BUILDDIR="${builddir}"

TESTS_ENVIRONMENT= \
	TOP_SRCDIR="${top_srcdir}" \
	TOP_BUILDDIR="${top_builddir}" \
	SRCDIR="${srcdir}" \
	BUILDDIR="${builddir}"

# TEST_EXTENSIONS = .test

TEST_LOG_COMPILE = $(SHELL)
TEST_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) $(top_srcdir)/build-aux/tap-driver.sh

TESTS =

if HAVE_NETWORK
if HAVE_GIT

# latest (draft2019-09)
TESTS += testsuite.test testsuite-optional.test testsuite-optional-format.test

# draft7
TESTS += testsuite-draft7.test testsuite-draft7-optional.test testsuite-draft7-optional-format.test

# draft6
TESTS += testsuite-draft6.test testsuite-draft6-optional.test

testsuite.test testsuite-optional.test testsuite-optional-format.test: test-suite-data spec

test-suite-data:
	@GIT@ clone "@TESTSUITEURL@" -- $@

spec:
	@GIT@ clone "@SPECURL@" -- $@

check-local: test-suite-data spec

distclean-local:
	@rm -rf test-suite-data

fastcheck-local: test-suite-data spec
	@echo fastcheck-local
	$(top_builddir)/src/fyjs-tool --testsuite -q \
		-r "http://localhost:1234/,test-suite-data/remotes/" \
		test-suite-data/tests/latest/*.json \
		test-suite-data/tests/latest/optional/*.json \
		test-suite-data/tests/latest/optional/format/*.json

endif
endif

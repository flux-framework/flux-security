AM_CFLAGS = \
	$(WARNING_CFLAGS) \
	-Wno-sign-compare -Wno-unused-parameter \
	$(CODE_COVERAGE_CFLAGS)

AM_LDFLAGS = \
	$(CODE_COVERAGE_LIBS)

AM_CPPFLAGS = \
	-I$(top_srcdir)

noinst_LTLIBRARIES = \
	libutil.la

libutil_la_SOURCES = \
	base64.c \
	base64.h

TESTS = test_base64.t

test_ldadd = \
	$(top_builddir)/src/libutil/libutil.la \
	$(top_builddir)/src/libtap/libtap.la

test_cppflags = \
	$(AM_CPPFLAGS)

check_PROGRAMS = $(TESTS)

TEST_EXTENSIONS = .t
T_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) \
	$(top_srcdir)/config/tap-driver.sh

test_base64_t_SOURCES = test/base64_test.c
test_base64_t_CPPFLAGS = $(test_cppflags)
test_base64_t_LDADD = $(test_ldadd)

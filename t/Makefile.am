AM_CFLAGS = \
	$(WARNING_CFLAGS) \
	-Wno-unused-parameter \
	$(CODE_COVERAGE_CFLAGS)

AM_LDFLAGS = \
	$(CODE_COVERAGE_LIBS)

AM_CPPFLAGS =

TEST_EXTENSIONS = .t
T_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) \
	$(top_srcdir)/config/tap-driver.sh

TESTSCRIPTS = \
	t0000-sharness.t \
	t0100-sudo-unit-tests.t \
	t0101-cf-path-security.t \
	t1000-imp-basic.t \
	t1001-imp-casign.t \
	t1002-sign-munge.t \
	t1003-sign-curve.t \
	t2000-imp-exec.t \
	t2002-imp-run.t \
	t2003-imp-exec-pam.t

TESTS = \
	$(TESTSCRIPTS)

check_SCRIPTS = \
	$(TESTSCRIPTS)

check_PROGRAMS = \
	src/keygen \
	src/certutil \
	src/ca \
	src/cf \
	src/sign \
	src/verify \
	src/xsign_munge \
	src/xsign_curve \
	src/uidlookup \
	src/sanitizers-enabled

check_LTLIBRARIES = \
	src/getpwuid.la

test_cppflags = \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	$(AM_CPPFLAGS) \
	$(MUNGE_CFLAGS)

test_ldadd = \
	$(top_builddir)/src/lib/libsecurity.la \
	$(top_builddir)/src/libca/libca.la \
	$(top_builddir)/src/libutil/libutil.la \
	$(top_builddir)/src/libtomlc99/libtomlc99.la \
	$(top_builddir)/src/imp/testconfig.o \
	$(MUNGE_LIBS)

# N.B. -rpath is required to build a noinst shared library
src_getpwuid_la_SOURCES = src/getpwuid.c
src_getpwuid_la_LDFLAGS = \
        -avoid-version -export-symbols-regex 'getpwuid' \
        --disable-static -shared -export-dynamic -module \
	-rpath $(abs_builddir)

src_keygen_SOURCES = src/keygen.c
src_keygen_CPPFLAGS = $(test_cppflags)
src_keygen_LDADD = $(test_ldadd)

src_certutil_SOURCES = src/certutil.c
src_certutil_CPPFLAGS = $(test_cppflags)
src_certutil_LDADD = $(test_ldadd)

src_ca_SOURCES = src/ca.c
src_ca_CPPFLAGS = $(test_cppflags)
src_ca_LDADD = $(test_ldadd)

src_cf_SOURCES = src/cf.c
src_cf_CPPFLAGS = $(test_cppflags)
src_cf_LDADD = $(test_ldadd)

src_sign_SOURCES = src/sign.c
src_sign_CPPFLAGS = $(test_cppflags)
src_sign_LDADD = $(test_ldadd)

src_verify_SOURCES = src/verify.c
src_verify_CPPFLAGS = $(test_cppflags)
src_verify_LDADD = $(test_ldadd)

src_xsign_munge_SOURCES = src/xsign_munge.c
src_xsign_munge_CPPFLAGS = $(test_cppflags)
src_xsign_munge_LDADD = $(test_ldadd)

src_xsign_curve_SOURCES = src/xsign_curve.c
src_xsign_curve_CPPFLAGS = $(test_cppflags)
src_xsign_curve_LDADD = $(test_ldadd)

src_uidlookup_SOURCES = src/uidlookup.c
src_uidlookup_CPPFLAGS = $(test_cppflags)
src_uidlookup_LDADD = $(test_ldadd)

EXTRA_DIST= \
	sharness.sh \
	sharness.d \
	$(check_SCRIPTS)

clean-local:
	rm -fr trash-directory.* test-results .prove

AM_CFLAGS = \
	$(WARNING_CFLAGS) \
	-Wno-sign-compare -Wno-unused-parameter -Wno-parentheses \
	$(CODE_COVERAGE_CFLAGS)

AM_LDFLAGS = \
	$(CODE_COVERAGE_LIBS) \
	$(JANSSON_LIBS) $(SODIUM_LIBS) $(LIBUUID_LIBS)

AM_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	$(JANSSON_CFLAGS) $(SODIUM_CFLAGS) $(LIBUUID_CFLAGS)

noinst_LTLIBRARIES = \
	libutil.la

libutil_la_SOURCES = \
	hash.c \
	hash.h \
	tomltk.c \
	tomltk.h \
	cf.c \
	cf.h \
	kv.c \
	kv.h \
	timestamp.c \
	timestamp.h \
	sha256.c \
	sha256.h \
	macros.h \
	aux.c \
	aux.h \
	strlcpy.c \
	strlcpy.h \
	path.c \
	path.h \
	argsplit.c \
	argsplit.h

TESTS = \
	test_hash.t \
	test_tomltk.t \
	test_cf.t \
	test_kv.t \
	test_sha256.t \
	test_aux.t \
	test_path.t \
	test_argsplit.t

test_ldadd = \
	$(top_builddir)/src/libutil/libutil.la \
	$(top_builddir)/src/libtomlc99/libtomlc99.la \
	$(top_builddir)/src/libtap/libtap.la \
	$(JANSSON_LIBS) $(SODIUM_LIBS) $(LIBUUID_LIBS)

test_cppflags = \
	$(AM_CPPFLAGS)

check_PROGRAMS = \
	$(TESTS)

TEST_EXTENSIONS = .t
T_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) \
	$(top_srcdir)/config/tap-driver.sh

test_hash_t_SOURCES = test/hash.c
test_hash_t_CPPFLAGS = $(test_cppflags)
test_hash_t_LDADD = $(test_ldadd)

test_tomltk_t_SOURCES = test/tomltk.c
test_tomltk_t_CPPFLAGS = $(test_cppflags)
test_tomltk_t_LDADD = $(test_ldadd)

test_cf_t_SOURCES = test/cf.c
test_cf_t_CPPFLAGS = $(test_cppflags)
test_cf_t_LDADD = $(test_ldadd)

test_kv_t_SOURCES = test/kv.c
test_kv_t_LDADD = $(test_ldadd)
test_kv_t_CPPFLAGS = $(test_cppflags)

test_sha256_t_SOURCES = test/sha256.c
test_sha256_t_LDADD = $(test_ldadd)
test_sha256_t_CPPFLAGS = $(test_cppflags)

test_aux_t_SOURCES = test/aux.c
test_aux_t_LDADD = $(test_ldadd)
test_aux_t_CPPFLAGS = $(test_cppflags)

test_path_t_SOURCES = test/path.c
test_path_t_LDADD = $(test_ldadd)
test_path_t_CPPFLAGS = $(test_cppflags)

test_argsplit_t_SOURCES = test/argsplit.c
test_argsplit_t_LDADD = $(test_ldadd)
test_argsplit_t_CPPFLAGS = $(test_cppflags)

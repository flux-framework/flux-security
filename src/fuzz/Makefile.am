if ENABLE_FUZZING

AM_CFLAGS = \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	$(WARNING_CFLAGS) \
	$(JANSSON_CFLAGS) \
	$(SODIUM_CFLAGS) \
	$(LIBUUID_CFLAGS) \
	$(MUNGE_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS)

AM_LDFLAGS = \
	$(CODE_COVERAGE_LIBS) \
	$(JANSSON_LIBS) \
	$(SODIUM_LIBS) \
	$(LIBUUID_LIBS) \
	$(MUNGE_LIBS) \
	-no-install

AM_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	$(JANSSON_CFLAGS) \
	$(SODIUM_CFLAGS) \
	$(LIBUUID_CFLAGS) \
	$(MUNGE_CFLAGS)

noinst_PROGRAMS = \
	fuzz_sign_unwrap \
	fuzz_kv \
	fuzz_sign_unwrap_noverify \
	fuzz_cf

# Primary harness: sign_unwrap with verification
fuzz_sign_unwrap_SOURCES = fuzz_sign_unwrap.c
fuzz_sign_unwrap_LDADD = \
	$(top_builddir)/src/lib/libflux-security.la \
	$(top_builddir)/src/libutil/libutil.la \
	$(top_builddir)/src/libtomlc99/libtomlc99.la

# Fast harness: sign_unwrap without verification (NOVERIFY flag)
fuzz_sign_unwrap_noverify_SOURCES = fuzz_sign_unwrap_noverify.c
fuzz_sign_unwrap_noverify_LDADD = \
	$(top_builddir)/src/lib/libflux-security.la \
	$(top_builddir)/src/libutil/libutil.la \
	$(top_builddir)/src/libtomlc99/libtomlc99.la

# KV parser harness
fuzz_kv_SOURCES = fuzz_kv.c
fuzz_kv_LDADD = \
	$(top_builddir)/src/libutil/libutil.la

# Configuration (cf) interface harness
fuzz_cf_SOURCES = fuzz_cf.c
fuzz_cf_LDADD = \
	$(top_builddir)/src/libutil/libutil.la \
	$(top_builddir)/src/libtomlc99/libtomlc99.la

endif

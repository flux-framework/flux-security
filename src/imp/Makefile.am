AM_CFLAGS = \
	$(WARNING_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS)

AM_LDFLAGS = \
	$(CODE_COVERAGE_LIBS)

AM_CPPFLAGS = \
	$(CODE_COVERAGE_CPPFLAGS) \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	-I$(top_srcdir)/src
#
#  Create two versions of flux-imp, one that will be used for testing
#   flux-imp, and one that will be installed inst/flux-imp.
#  The only difference is that the test version allows configuration
#   pattern to be overridden for in-tree testing purposes.
#
fluxlibexec_PROGRAMS = \
	inst/flux-imp
noinst_PROGRAMS = \
	flux-imp

flux_imp_LDADD = \
	$(top_builddir)/src/lib/libflux-security.la \
	$(top_builddir)/src/libca/libca.la \
	$(top_builddir)/src/libutil/libutil.la \
	$(top_builddir)/src/libtomlc99/libtomlc99.la \
	$(PAM_LIBS)

#
#  Build the test-only version of flux-imp with -static, which seems
#   to cause libtool to avoid creating a wrapper script (libtool's
#   wrapper script is not compatible with setuid flux-imp tests). However,
#   this embeds the builddir path to libflux-security into the DT_RUNPATH
#   of the resulting executable, so DO NOT use this for the installed
#   copy of the IMP (inst/flux-imp):
#
flux_imp_LDFLAGS = \
	-static

IMP_SOURCES = \
	imp.c \
	imp_state.h \
	imp_log.h \
	imp_log.c \
	privsep.c \
	privsep.h \
	impcmd-list.c \
	impcmd.c \
	impcmd.h \
	sudosim.c \
	sudosim.h \
	version.c \
	whoami.c \
	casign.c \
	passwd.c \
	passwd.h \
	pidinfo.c \
	pidinfo.h \
	kill.c \
	run.c \
	exec/user.h \
	exec/user.c \
	exec/exec.c \
	exec/safe_popen.h \
	exec/safe_popen.c

if HAVE_PAM
IMP_SOURCES += \
	exec/pam.h \
	exec/pam.c
endif

flux_imp_SOURCES = \
	testconfig.c \
	$(IMP_SOURCES)

nodist_flux_imp_SOURCES = \
	testconfig.h

inst_flux_imp_SOURCES = \
	$(IMP_SOURCES)

nodist_inst_flux_imp_SOURCES = \
	config.c

inst_flux_imp_LDADD = \
	$(flux_imp_LDADD)

BUILT_SOURCES = \
	config.c \
	testconfig.h

#  Installed flux-imp configuration pattern is locked down to
#   the system path for security reasons.
config.c:
	@(echo "#include \"src/libutil/cf.h\""; \
	  echo "#include <stdlib.h>"; \
	  echo ; \
	  echo "const char *imp_get_security_config_pattern (void)"; \
	  echo "{"; \
	  echo "    /* Always use built-in config path */"; \
	  echo "    return NULL;"; \
	  echo "}"; \
	  echo ; \
	  echo "const char *imp_get_config_pattern (void)"; \
	  echo "{"; \
	  echo "    return \"$(fluximpcfdir)/*.toml\";"; \
	  echo "}"; \
	  echo ; \
	  echo "int imp_conf_init (__attribute__((unused)) cf_t *cf,"; \
	  echo "        __attribute__((unused)) struct cf_error *error)"; \
	  echo "{"; \
	  echo "    return 0;"; \
	  echo "}"; \
	  echo ; \
	  echo "int imp_get_security_flags (void) { return 0; }"; \
	)> config.c

#  Test version of flux-imp gets builddir config pattern by default,
#   and allows override via FLUX_IMP_CONFIG_PATTERN (see testconfig.c).
testconfig.h: $(top_builddir)/config/config.h
	@(confdir=`cd $(srcdir) && pwd`/imp.conf.d; \
	  echo "const char *imp_config_pattern = \"$$confdir/*.toml\";" \
	 )> testconfig.h

MOSTLYCLEANFILES = \
	testconfig.h \
	config.c

EXTRA_DIST = \
	imp.conf.d

TESTS = \
	test_imp_log.t \
	test_privsep.t \
	test_impcmd.t \
	test_passwd.t \
	test_pidinfo.t

check_PROGRAMS = \
	$(TESTS)

test_ldadd = \
	$(top_builddir)/src/libutil/libutil.la \
	$(top_builddir)/src/libtap/libtap.la

TEST_EXTENSIONS = .t
T_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) \
	$(top_srcdir)/config/tap-driver.sh

test_imp_log_t_SOURCES =  \
	test/imp_log.c \
	imp_log.c \
	imp_log.h

test_imp_log_t_LDADD = $(test_ldadd)

test_privsep_t_SOURCES = \
	test/privsep.c \
	privsep.c \
	privsep.h \
	sudosim.h \
	sudosim.c \
	imp_log.h \
	imp_log.c

test_privsep_t_LDADD = $(test_ldadd)

test_impcmd_t_SOURCES =  \
	test/impcmd.c \
	impcmd.c \
	impcmd.h

test_impcmd_t_LDADD = $(test_ldadd)

test_passwd_t_SOURCES =  \
	test/passwd.c \
	passwd.c \
	passwd.h

test_passwd_t_LDADD = $(test_ldadd)

test_pidinfo_t_SOURCES = \
	test/pidinfo.c \
	pidinfo.c \
	pidinfo.h \
	imp_log.c \
	imp_log.h
test_pidinfo_t_LDADD = $(test_ldadd)

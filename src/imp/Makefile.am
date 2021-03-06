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
	$(top_builddir)/src/libtomlc99/libtomlc99.la

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
	kill.c \
	exec/user.h \
	exec/user.c \
	exec/exec.c

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
	@(echo "#include <stdlib.h>"; \
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
	test_passwd.t

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

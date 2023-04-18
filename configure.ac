#
# Prologue
#

# XXX: replace hard-coded version with git-describe 
AC_INIT([flux-security],
         m4_esyscmd([git describe --always | awk '/.*/ {sub(/^v/, ""); printf "%s",$1; exit}']))

AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([config])
AC_CONFIG_SRCDIR([NEWS.md])
AC_CANONICAL_SYSTEM

#
#  Automake support:
#
AM_INIT_AUTOMAKE([subdir-objects tar-pax foreign])
AM_SILENT_RULES([yes])
AM_CONFIG_HEADER([config/config.h])
AM_MAINTAINER_MODE([enable])

AC_DEFINE([_GNU_SOURCE], 1,
          [Define _GNU_SOURCE so that we get all necessary prototypes])

#
# Generate project versions from PACKAGE_VERSION (set from git describe above)
#
AX_SPLIT_VERSION
AX_POINT_VERSION=$(echo $AX_POINT_VERSION | $SED 's/-.*$//')
AC_SUBST([AX_MAJOR_VERSION])
AC_SUBST([AX_MINOR_VERSION])
AC_SUBST([AX_POINT_VERSION])

#
# Library version
# https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
LIBFLUX_SECURITY_CURRENT=1
LIBFLUX_SECURITY_REVISION=0
LIBFLUX_SECURITY_AGE=0
AC_SUBST(
  [LIBFLUX_SECURITY_VERSION_INFO],
  [$LIBFLUX_SECURITY_CURRENT:$LIBFLUX_SECURITY_REVISION:$LIBFLUX_SECURITY_AGE]
)

#
#  Initialize pkg-config for PKG_CHECK_MODULES to avoid conditional issues
#
PKG_PROG_PKG_CONFIG

#
#  If --enable-sanitizers add selected -fsanitize flags to build
#
AC_MSG_CHECKING([whether to enable sanitizers])
AC_ARG_ENABLE([sanitizers],
              AS_HELP_STRING([--enable-sanitizers], [add {L,A,UB}San to build]),
[
AC_MSG_RESULT($withval)
CFLAGS="$CFLAGS -fsanitize=address -fsanitize=undefined -fsanitize-recover=all"
CFLAGS="$CFLAGS -g -fno-omit-frame-pointer"
LDFLAGS="$LDFLAGS -fsanitize=address -fsanitize=undefined"
AC_DEFINE([SANITIZERS_ENABLED], 1,
          [Define to 1 if flux-security was compiled with --enable-sanitizers])
],
[AC_MSG_RESULT(no)])
AM_CONDITIONAL([SANITIZERS_ENABLED], [test "x$enable_sanitizers" != "xno" ])

#
#  Checks for programs
#
AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_PROG_AWK
AC_ARG_ENABLE([docs],
              AS_HELP_STRING([--disable-docs], [disable building docs]))
AS_IF([test "x$enable_docs" != "xno"], [
	PYTHON_VERSION=3
	AM_PATH_PYTHON([3])
	AM_CHECK_PYMOD(sphinx,
	               [StrictVersion(sphinx.__version__) >= StrictVersion ('1.6.7')],
	               [sphinx=true],
	               [sphinx=false; AC_MSG_WARN([could not find sphinx to generate docs, version 1.6.7+ required])]
                       )
	AM_CHECK_PYMOD(docutils,
                       [StrictVersion(docutils.__version__) >= StrictVersion ('0.11.0')],
                       [docutils=true],
                       [docutils=false; AC_MSG_WARN([could not find docutils to generate docs, version 0.11.0+ required])]
                       )
])
#  If --enable-docs=yes, but no doc generator found,
#   then error immediately:
#
AS_IF([test "x$enable_docs" = "xyes" -a "x$sphinx" = "xfalse"],[
  AC_MSG_ERROR([--enable-docs used but no document generator found!])
])
AS_IF([test "x$enable_docs" = "xyes" -a "x$docutils" = "xfalse"],[
  AC_MSG_ERROR([--enable-docs used but docutils not found!])
])
AM_CONDITIONAL([ENABLE_DOCS], [test "x$sphinx" = "xtrue" -a "x$docutils" = "xtrue"])
AC_CHECK_PROG(ASPELL,[aspell],[aspell])

#
#  If Clang or GNU CC, add warning/hardening flags:
#
AX_COMPILER_VENDOR
AS_CASE($ax_cv_c_compiler_vendor,
  [clang | gnu], [
    WARNING_CFLAGS="-Wall -Werror -Wno-strict-aliasing -Wextra"
    AC_SUBST([WARNING_CFLAGS])
  ]
)

#
#  Libotool support
#
LT_INIT

#
#  Checks for header files
#
AC_HEADER_STDC
AC_CHECK_HEADERS( \
  [linux/magic.h] \
)

#
#  Checks for functions
#
AC_CHECK_FUNC([pipe2], [], AC_MSG_FAILURE([Required function pipe2 missing]))

#
#  Checks for packages
#
PKG_CHECK_MODULES([SODIUM], [libsodium >= 1.0.14], [], [])
PKG_CHECK_MODULES([JANSSON], [jansson >= 2.10], [], [])
PKG_CHECK_MODULES([LIBUUID], [uuid], [], [])
PKG_CHECK_MODULES([MUNGE], [munge], [], [])

#
#  Enable PAM Support?
#
X_AC_PAM

#
#  Other checks
#
AX_CODE_COVERAGE
AS_IF([test x$enable_code_coverage = xyes], [
    AC_DEFINE([CODE_COVERAGE_ENABLED], [1], [code coverage support])])

AC_PKGCONFIG

#
# Project directories
#
AS_VAR_SET(fluxlibdir, $libdir/flux)
AC_SUBST(fluxlibdir)

AS_VAR_SET(fluxlibexecdir, $libexecdir/flux)
AC_SUBST(fluxlibexecdir)

AS_VAR_SET(fluxsecuritycfdir, $sysconfdir/flux/security/conf.d)
AC_SUBST(fluxsecuritycfdir)

AS_VAR_SET(fluxsecurityincludedir, $includedir/flux/security)
AC_SUBST(fluxsecurityincludedir)

AS_VAR_SET(fluximpcfdir, $sysconfdir/flux/imp/conf.d)
AC_SUBST(fluximpcfdir)

#
#  Epilogue
#
AC_CONFIG_FILES( \
  Makefile \
  t/Makefile \
  src/Makefile \
  src/lib/Makefile \
  src/lib/flux-security.pc \
  src/lib/version.h \
  src/libtap/Makefile \
  src/libtomlc99/Makefile \
  src/libutil/Makefile \
  src/libca/Makefile \
  src/imp/Makefile \
  doc/Makefile \
  doc/test/Makefile \
  etc/Makefile \
)

AC_OUTPUT

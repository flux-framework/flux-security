#
# Prologue
#

# XXX: replace hard-coded version with git-describe 
AC_INIT([flux-security],
         m4_esyscmd([git describe --always | awk '/.*/ {sub(/^v/, ""); printf "%s",$1; exit}']))

AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([config])
AC_CONFIG_SRCDIR([NEWS])
AC_CANONICAL_SYSTEM

#
#  Automake support:
#
AM_INIT_AUTOMAKE([subdir-objects tar-pax])
AM_SILENT_RULES([yes])
AM_CONFIG_HEADER([config/config.h])
AM_MAINTAINER_MODE

AC_DEFINE([_GNU_SOURCE], 1,
          [Define _GNU_SOURCE so that we get all necessary prototypes])

#
#  Initialize pkg-config for PKG_CHECK_MODULES to avoid conditional issues
#
PKG_PROG_PKG_CONFIG

#
#  Checks for programs
#
AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_PROG_AWK
AC_ARG_ENABLE([docs],
              AS_HELP_STRING([--disable-docs], [disable building docs]))
AS_IF([test "x$enable_docs" != "xno"], [
  AC_CHECK_PROG(A2X,[a2x],[a2x])
])
AM_CONDITIONAL([ENABLE_DOCS], [test "$A2X" = "a2x" ])
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


#
#  Other checks
#
AX_CODE_COVERAGE


#
#  Epilogue
#
AC_CONFIG_FILES( \
  Makefile \
  src/Makefile \
  src/lib/Makefile \
  src/libtap/Makefile \
  src/libtomlc99/Makefile \
  src/libutil/Makefile \
  src/imp/Makefile \
)

AC_OUTPUT

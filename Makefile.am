if SANITIZERS_ENABLED
ASAN_OPTIONS  ?= verify_asan_link_order=0:check_initialization_order=1:detect_stack_use_after_return=1:detect_invalid_pointer_pairs=1:strict_string_checks=1
UBSAN_OPTIONS ?= print_stacktrace=1
export ASAN_OPTIONS
export UBSAN_OPTIONS
endif
SUBDIRS = src doc etc t
ACLOCAL_AMFLAGS = -I config
EXTRA_DIST = \
	config/tap-driver.sh \
	NOTICE.LLNS \
	README.md \
	NEWS.md

# coverage
CODE_COVERAGE_IGNORE_PATTERN = \
        "*/t/*" \
	"*_test.c" \
	"*/test/*.c" \
	"*/libtap/*" \
	"/usr/include/*"
CODE_COVERAGE_LCOV_OPTIONS =
@CODE_COVERAGE_RULES@

deb: debian scripts/debbuild.sh
	@$(top_srcdir)/scripts/debbuild.sh $(abs_top_srcdir)

clean-local:
	@rm -rf debbuild

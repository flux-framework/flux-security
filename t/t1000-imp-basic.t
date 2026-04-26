#!/bin/sh
#

test_description='IMP basic functionality test

Ensure IMP runs and runs under sudo when SUDO is available.
Also test basic subcommands like "version".
'

# Append --logfile option if FLUX_TESTS_LOGFILE is set in environment:
test -n "$FLUX_TESTS_LOGFILE" && set -- "$@" --logfile
. `dirname $0`/sharness.sh

flux_imp=${SHARNESS_BUILD_DIRECTORY}/src/imp/flux-imp

echo "# Using ${flux_imp}"

test_expect_success 'flux-imp is built and is executable' '
	test -x $flux_imp
'
test_expect_success 'flux-imp returns error when run with no args' '
	test_must_fail $flux_imp 
'
test_expect_success 'flux-imp version works' '
	$flux_imp version | grep "flux-imp v"
'
test_expect_success 'FLUX_IMP_CONFIG_PATTERN works for test flux-imp' '
	( export FLUX_IMP_CONFIG_PATTERN=/noexist &&
        test_must_fail  $flux_imp version 2>config-reset.error ) &&
	grep "No config file" config-reset.error
'
test_expect_success 'Bad IMP config generates error' '
	echo "bad =" > bad.toml &&
	( export FLUX_IMP_CONFIG_PATTERN=bad.toml &&
	  test_must_fail $flux_imp version 2>bad-config.error ) &&
	grep "loading config: bad.toml: 1: syntax error" bad-config.error
'
test_expect_success SUDO 'flux-imp version works under sudo' '
	$SUDO $flux_imp version | grep "flux-imp v"
'
test_expect_success SUDO 'flux-imp fails under sudo if allow-sudo != true' '
	echo "allow-sudo = false" > nosudo.toml &&
	test_expect_code 1 \
	  $SUDO FLUX_IMP_CONFIG_PATTERN=nosudo.toml $flux_imp version
'
test_expect_success SUDO 'flux-imp generates error if SUDO_USER is invalid' '
	test_expect_code 1 $SUDO SUDO_USER=invalid $flux_imp version
'
test_expect_success 'flux-imp whoami works' '
	$flux_imp whoami | sort -k2,2 > output.whoami &&
	test_debug cat output.whoami &&
	cat <<-EOF > expected.whoami &&
	flux-imp: unprivileged: uid=$(id -ru) euid=$(id -u) gid=$(id -rg) egid=$(id -g)
EOF
	test_cmp expected.whoami output.whoami
'
test_expect_success SUDO 'flux-imp whoami works under sudo' '
	$SUDO $flux_imp whoami | sort -k2,2 > output.whoami.sudo &&
	test_debug cat output.whoami.sudo &&
	cat <<-EOF > expected.whoami.sudo &&
	flux-imp: privileged: uid=$(id -ru) euid=0 gid=$(id -rg) egid=0
	flux-imp: unprivileged: uid=$(id -ru) euid=$(id -u) gid=$(id -rg) egid=$(id -g)
EOF
	test_cmp expected.whoami.sudo output.whoami.sudo
'
test_expect_success SUDO 'attempt to create setuid copy of flux-imp for testing' '
	sudo cp $flux_imp . &&
	sudo chmod 4755 ./flux-imp
'

#  In case tests are running on filesystem with nosuid, check that permissions
#   of flux-imp are actually setuid, and if so set SUID_ENABLED prereq
#
test -n "$(find ./flux-imp -perm 4755)" && test_set_prereq SUID_ENABLED


test_expect_success SUID_ENABLED 'setuid copy of flux-imp works' '
        ASAN_OPTIONS=$ASAN_OPTIONS:detect_leaks=0 \
	 ./flux-imp whoami | sort -k2,2 > output.whoami.setuid &&
	test_debug cat output.whoami.setuid &&
	cat <<-EOF >expected.whoami.setuid &&
	flux-imp: privileged: uid=$(id -ru) euid=0 gid=$(id -rg) egid=$(id -g)
	flux-imp: unprivileged: uid=$(id -ru) euid=$(id -u) gid=$(id -rg) egid=$(id -g)
	EOF
	test_cmp expected.whoami.setuid output.whoami.setuid
'
test_expect_success SUID_ENABLED 'flux-imp setuid ignores SUDO_USER' '
        ASAN_OPTIONS=$ASAN_OPTIONS:detect_leaks=0 \
	 SUDO_USER=nobody ./flux-imp whoami | sort -k2,2 > output.whoami.no &&
	test_debug cat output.whoami.no &&
	cat <<-EOF >expected.whoami.no &&
	flux-imp: privileged: uid=$(id -ru) euid=0 gid=$(id -rg) egid=$(id -g)
	flux-imp: unprivileged: uid=$(id -ru) euid=$(id -u) gid=$(id -rg) egid=$(id -g)
	EOF
	test_cmp expected.whoami.no output.whoami.no
'
test_expect_success 'log-level = debug is accepted' '
	printf "log-level = \"debug\"\n" > loglevel-debug.toml &&
	( export FLUX_IMP_CONFIG_PATTERN=loglevel-debug.toml &&
	  $flux_imp version )
'
test_expect_success 'unknown log-level generates a warning' '
	printf "log-level = \"verbose\"\n" > loglevel-bad.toml &&
	( export FLUX_IMP_CONFIG_PATTERN=loglevel-bad.toml &&
	  $flux_imp version 2>loglevel-bad.err ) &&
	grep "unknown log-level" loglevel-bad.err
'
test_done

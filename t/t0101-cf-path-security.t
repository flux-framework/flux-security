#!/bin/sh
#

test_description='config file path security checks'

# Append --logfile option if FLUX_TESTS_LOGFILE is set in environment:
test -n "$FLUX_TESTS_LOGFILE" && set -- "$@" --logfile
. `dirname $0`/sharness.sh

if ! test_have_prereq SUDO; then
   skip_all='skipping all cf security tests, sudo support not found'
   test_done
fi

cf=${SHARNESS_BUILD_DIRECTORY}/t/src/cf
sudo="sudo --preserve-env=FLUX_IMP_CONFIG_PATTERN"

test_expect_success 'create temporary test directory in TMPDIR' '
	CF_TESTDIR=$(mktemp -d -p ${TMPDIR:-/tmp}  \
	             t0101-cf-security.XXXXXXXXXX) &&
	FLUX_IMP_CONFIG_PATTERN="${CF_TESTDIR}/*.toml" &&
	export CF_TESTDIR FLUX_IMP_CONFIG_PATTERN &&
	cleanup "sudo rm $CF_TESTDIR/test.toml; sudo rmdir $CF_TESTDIR"
'
test_expect_success 'create valid test config' '
	cat <<-EOF >${CF_TESTDIR}/test.toml
	[tab]
	id = 1
	ok = "success"
	value = "foo"
	EOF
'
test_expect_success 'cf test program works' '
	$cf tab.id &&
	test $($cf tab.id) = 1
'
test_expect_success 'cf refuses to read config with insecure file ownership' '
	name=bad-owner &&
	test_must_fail $sudo $cf tab.ok 2>cf-${name}.err &&
	test_debug "cat cf-${name}.err" &&
	grep "${CF_TESTDIR}.*: insecure file ownership" cf-${name}.err
'
test_expect_success 'change ownership of test file' '
	sudo chown root.root $CF_TESTDIR/*.toml
'
test_expect_success 'cf refuses to read config with insecure dir ownership' '
	name=bad-dir-owner &&
	test_must_fail $sudo $cf tab.ok 2>cf-${name}.err &&
	test_debug "cat cf-${name}.err" &&
	grep "${CF_TESTDIR}.*: Invalid ownership on parent" cf-${name}.err
'
test_expect_success 'change ownership of test dir' '
	sudo chown root.root $CF_TESTDIR
'
test_expect_success 'cf now succeeds reading config' '
	$sudo $cf tab.ok
'
test_expect_success 'cf reads config with current group write permissions' '
	name=group-write &&
	group=$(sudo id -n -g) &&
	sudo chgrp $group $CF_TESTDIR/test.toml &&
	sudo chmod 660 $CF_TESTDIR/test.toml &&
	$sudo $cf tab.ok
'
test_expect_success 'cf refuses to read config w/ world write perms' '
	name=world-write &&
	sudo chmod 606 $CF_TESTDIR/test.toml &&
	test_must_fail $sudo $cf tab.ok 2>cf-${name}.err &&
	test_debug "cat cf-${name}.err" &&
	grep "${CF_TESTDIR}.*: bad file permissions" cf-${name}.err
'
test_expect_success 'cf refuses to read config w/ other group write perms' '
	name=other-group-write &&
	sudo chgrp $(id -n -g) $CF_TESTDIR/test.toml &&
	sudo chmod 660 $CF_TESTDIR/test.toml &&
	test_must_fail $sudo $cf tab.ok 2>cf-${name}.err &&
	test_debug "cat cf-${name}.err" &&
	grep "${CF_TESTDIR}.*: bad file permissions" cf-${name}.err
'
test_expect_success 'reset file and directory permissions' '
	sudo chgrp root $CF_TESTDIR/test.toml &&
	sudo chmod 600 $CF_TESTDIR/test.toml &&
	$sudo $cf tab.ok
'
test_expect_success 'cf refuses to read config w/ group writable directory' '
	name=world-writeable-dir &&
	sudo chgrp $(id -n -g) $CF_TESTDIR &&
	sudo chmod 770 $CF_TESTDIR &&
	test_must_fail $sudo $cf tab.ok 2>cf-${name}.err &&
	test_debug "cat cf-${name}.err" &&
	grep "${CF_TESTDIR}.*: parent directory is group-writeable" \
	     cf-${name}.err
'
test_expect_success 'cf refuses to read config w/ world writable directory' '
	name=world-writeable-dir &&
	sudo chmod 707 $CF_TESTDIR &&
	test_must_fail $sudo $cf tab.ok 2>cf-${name}.err &&
	test_debug "cat cf-${name}.err" &&
	grep "${CF_TESTDIR}.*: parent directory is world-writeable" \
	     cf-${name}.err
'
test_expect_success 'cf allows group writable directory and sticky bit' '
	sudo chgrp $(id -n -g) $CF_TESTDIR &&
	sudo chmod 1770 $CF_TESTDIR &&
	$sudo $cf tab.ok
'
test_expect_success 'cf allows world writable directory and sticky bit' '
	name=world-writeable-sticky &&
	sudo chmod 1707 $CF_TESTDIR &&
	$sudo $cf tab.ok
'
test_done

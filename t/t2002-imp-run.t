#!/bin/sh
#

test_description='IMP run basic functionality test

Basic flux-imp run functionality and corner case handing tests
'

# Append --logfile option if FLUX_TESTS_LOGFILE is set in environment:
test -n "$FLUX_TESTS_LOGFILE" && set -- "$@" --logfile
. `dirname $0`/sharness.sh

test "$chain_lint" = "t" || test_set_prereq NO_CHAIN_LINT

flux_imp=${SHARNESS_BUILD_DIRECTORY}/src/imp/flux-imp
sign=${SHARNESS_BUILD_DIRECTORY}/t/src/sign

USER=$(id -un)

echo "# Using ${flux_imp}"

test_expect_success 'flux-imp run returns error when run with no args' '
	test_must_fail $flux_imp run
'
test_expect_success 'flux-imp run returns error when run with invalid cmd' '
	test_must_fail $flux_imp run foo
'
test_expect_success 'create configs for flux-imp exec and signer' '
	TESTDIR=$(mktemp -d -p ${TMPDIR:-/tmp}  \
                  t2002-imp-run-testdir.XXXXXXXXXX) &&
	cat <<-EOF >$TESTDIR/test.toml
	allow-sudo = true
	[sign]
	max-ttl = 30
	default-type = "none"
	allowed-types = [ "none" ]
	[run.test]
	allowed-users = [ "$(whoami)" ]
	allowed-environment = [ "TEST_*", "EXACT_MATCH" ]
	path = "$TESTDIR/test.sh"
	[run.nopath]
	allowed-users = [ "$(whoami)" ]
	[run.noexec]
	allowed-users = [ "$(whoami)" ]
	path = "$TESTDIR/noexec.sh"
	[run.badpath]
	allowed-users = [ "$(whoami)" ]
	path = "test.sh"
	[run.notallowed]
	allowed-users = [ ]
	path = "$TESTDIR/test.sh"
	[run.allowednotset]
	path = "$TESTDIR/test.sh"
	[run.sleep]
	allowed-users = [ "$(whoami)" ]
	allowed-environment = [ "TEST_*", "EXACT_MATCH" ]
	path = "$TESTDIR/sleep.sh"
	EOF
'
test_expect_success 'create test shell scripts' '
	cat <<-EOF >$TESTDIR/test.sh &&
	#!/bin/sh
	echo uid=\$(id -u)
	echo ruid=\$(id -r -u)
	echo gid=\$(id -g)
	echo rgid=\$(id -r -g)
	env
	EOF
	chmod +x $TESTDIR/test.sh &&
	cat <<-EOF >$TESTDIR/sleep.sh &&
	#!/bin/sh
	echo \$PPID >$TESTDIR/sleep.pid
	sleep 30
	EOF
	cat $TESTDIR/sleep.sh &&
	chmod +x $TESTDIR/sleep.sh &&
	touch $TESTDIR/noexec.sh &&
	chmod 600 $TESTDIR/noexec.sh
'
test_expect_success SUDO 'set appropriate permissions for sudo based tests' '
	$SUDO chown root.root $TESTDIR $TESTDIR/* &&
	$SUDO chmod 755 $TESTDIR $TESTDIR/test.sh &&
	$SUDO chmod 755 $TESTDIR $TESTDIR/sleep.sh &&
	$SUDO chmod 644 $TESTDIR/test.toml
'

cat <<EOF >failure-tests.txt
nopath:run path not set:path is missing or invalid
noexec:path not executable:Permission denied
badpath:path is missing or invalid
notallowed:user not allowed:permission denied
allowednotset:allowed-users not set:permission denied
nocommand:no such command:no configuration found
EOF
export FLUX_IMP_CONFIG_PATTERN=${TESTDIR}/test.toml
while read line; do
    name=$(echo $line | awk -F: '{print $1}')
    desc=$(echo $line | awk -F: '{print $2}')
    err=$(echo $line  | awk -F: '{print $3}')
    test_expect_success "flux-imp run must fail: $desc" '
	test_must_fail $flux_imp run $name 2> $name.err &&
	test_debug "cat $name.err" &&
	grep "$err" $name.err
    '
done <failure-tests.txt

#  Now run same set of tests under sudo if available:
while read line; do
    name=$(echo $line | awk -F: '{print $1}')
    desc=$(echo $line | awk -F: '{print $2}')
    err=$(echo $line  | awk -F: '{print $3}')
    test_expect_success SUDO "flux-imp run must fail: $desc" '
	test_must_fail $SUDO FLUX_IMP_CONFIG_PATTERN=$TESTDIR/test.toml \
	    $flux_imp run $name 2> $name-sudo.err &&
	test_debug "cat $name.err" &&
	grep "$err" $name-sudo.err
    '
done <failure-tests.txt

test_expect_success 'flux-imp run bails out with no configuration' '
	(
	export FLUX_IMP_CONFIG_PATTERN= &&
	test_must_fail $flux_imp run test
	)
'
test_expect_success SUDO 'flux-imp run: works under sudo' '
	export SUDO="$SUDO --preserve-env=FLUX_IMP_CONFIG_PATTERN" &&
	$SUDO --preserve-env=FLUX_IMP_CONFIG_PATTERN \
	    $flux_imp run test >sudo-run.out 2>&1 &&
	test_debug "cat sudo-run.out" &&
	grep ^FLUX_OWNER_USERID=$(id -u) sudo-run.out &&
	grep ^uid=0 sudo-run.out &&
	grep ^gid=0 sudo-run.out &&
	grep ^ruid=0 sudo-run.out &&
	grep ^rgid=0 sudo-run.out &&
	grep ^USER=root sudo-run.out
'
test_expect_success 'flux-imp run sets FLUX_OWNER_USERID' '
	$flux_imp run test >run-test.out 2>&1 &&
	test_debug "cat run-test.out" &&
	grep ^FLUX_OWNER_USERID=$(id -u) run-test.out
'
test_expect_success 'flux-imp run filters environment' '
	TEST_VAR=foo \
	TEST_VAR_BAR=xxx \
	EXACT_MATCH=yes \
	EXACT_MATCH_BAD=xxx \
	FOO=bar \
	    $flux_imp run test >run-test-env.out &&
	grep ^TEST_VAR=foo run-test-env.out &&
	grep ^TEST_VAR_BAR run-test-env.out &&
	grep ^EXACT_MATCH=yes run-test-env.out &&
	test_expect_code 1 grep ^FOO=bar run-test-env.out &&
	test_expect_code 1 grep ^EXACT_MATCH_BAD run-test-env.out
'
test_expect_success 'flux-imp run allows FLUX_JOB_ID and FLUX_JOB_USERID' '
	FLUX_JOB_ID=1234 \
	FLUX_JOB_USERID=$(id -u) \
	    $flux_imp run test >run-test-uid-jobid.out &&
	grep ^FLUX_JOB_ID=1234 run-test-uid-jobid.out &&
	grep ^FLUX_JOB_USERID=$(id -u) run-test-uid-jobid.out
'
test_expect_success SUDO 'flux-imp run filters environment under sudo' '
	$SUDO -E TEST_VAR=foo -E FOO=bar \
	    $flux_imp run test >sudo-run-test-env.out &&
	grep ^TEST_VAR=foo sudo-run-test-env.out &&
	test_expect_code 1 grep ^FOO=bar sudo-run-test-env.out
'
test_expect_success SUDO 'flux-imp run allows FLUX_JOB_ID and FLUX_JOB_USERID' '
	$SUDO -E FLUX_JOB_ID=1234 -E FLUX_JOB_USERID=$(id -u) \
	    $flux_imp run test >sudo-run-test-uid-jobid.out &&
	grep ^FLUX_JOB_ID=1234 sudo-run-test-uid-jobid.out &&
	grep ^FLUX_JOB_USERID=$(id -u) sudo-run-test-uid-jobid.out
'

wait_for_file() {
        count=0 &&
        while ! test -f $1; do
            sleep 0.1
            count=$((count+1))
            test $count -gt 20 && break
        done
	test -f $1
}
test_expect_success SUDO,NO_CHAIN_LINT 'flux-imp run: setuid IMP lingers' '
	$SUDO $flux_imp run sleep &
	imp_pid=$! &&
	wait_for_file $TESTDIR/sleep.pid &&
	test_when_finished "$SUDO rm -f $TESTDIR/sleep.pid" &&
	pid=$(cat $TESTDIR/sleep.pid) &&
	test $(ps --no-header -o comm -p ${pid}) = "flux-imp" &&
	kill -TERM $pid &&
	test_expect_code 143 wait $imp_pid
'
test_expect_success SUDO,NO_CHAIN_LINT 'flux-imp run: setuid IMP can successfully forward SIGINT' '
	$SUDO $flux_imp run sleep &
	imp_pid=$! &&
	wait_for_file $TESTDIR/sleep.pid &&
	test_when_finished "$SUDO rm -f $TESTDIR/sleep.pid" &&
	pid=$(cat $TESTDIR/sleep.pid) &&
	kill -INT $pid &&
	test_expect_code 130 wait $imp_pid
'
test_expect_success SUDO 'flux-imp run will not run file with bad ownership' '
	$SUDO chown $USER $TESTDIR/test.sh &&
	test_must_fail $SUDO $flux_imp run test &&
	$SUDO chown root $TESTDIR/test.sh
'
test_expect_success SUDO 'flux-imp run will not run file with bad perms' '
	$SUDO chmod 775 $TESTDIR/test.sh &&
	test_must_fail $SUDO $flux_imp run test &&
	$SUDO chmod 755 $TESTDIR/test.sh
'
test_expect_success SUDO 'flux-imp run checks ownership of parent dir' '
	$SUDO chown $USER $TESTDIR &&
	test_must_fail $SUDO $flux_imp run test &&
	$SUDO chown root $TESTDIR
'
test_expect_success SUDO 'flux-imp run checks permission of parent dir' '
	$SUDO chmod 777 $TESTDIR &&
	test_must_fail $SUDO $flux_imp run test &&
	$SUDO chmod 755 $TESTDIR
'
test_expect_success SUDO 'cleanup test directory (sudo)' '
	$SUDO rm $TESTDIR/* && $SUDO rmdir $TESTDIR
'
test_expect_success 'cleanup test directory' '
	if test -d $TESTDIR; then rm -rf $TESTDIR; fi
'
test_done

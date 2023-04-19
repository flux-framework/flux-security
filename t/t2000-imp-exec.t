#!/bin/sh
#

test_description='IMP exec basic functionality test

Basic flux-imp exec functionality and corner case handing tests
'

# Append --logfile option if FLUX_TESTS_LOGFILE is set in environment:
test -n "$FLUX_TESTS_LOGFILE" && set -- "$@" --logfile
. `dirname $0`/sharness.sh

flux_imp=${SHARNESS_BUILD_DIRECTORY}/src/imp/flux-imp
sign=${SHARNESS_BUILD_DIRECTORY}/t/src/sign

echo "# Using ${flux_imp}"

fake_imp_input() {
	printf '{"J":"%s"}' $(echo $1 | $sign)
}

test_expect_success 'create config allowing current user to exec imp' '
	cat <<-EOF >imp-test.toml
	allow-sudo = true
	[exec]
	allowed-users = [ "$(whoami)" ]
	EOF
'
export FLUX_IMP_CONFIG_PATTERN=imp-test.toml
test_expect_success 'flux-imp exec returns error when run with no args' '
	test_must_fail $flux_imp exec
'
test_expect_success 'flux-imp exec returns error when run with only 1 arg' '
	test_must_fail $flux_imp exec foo
'
test_expect_success 'flux-imp exec returns error with no input' '
	test_must_fail $flux_imp exec shell arg < /dev/null
'
test_expect_success 'flux-imp exec returns error with bad input ' '
	echo foo | test_must_fail $flux_imp exec shell arg
'
test_expect_success 'flux-imp exec returns error with bad JSON input ' '
	echo "{}" | test_must_fail $flux_imp exec shell arg
'
test_expect_success 'flux-imp exec returns error with invalid JSON input ' '
	echo "{" | test_must_fail $flux_imp exec shell arg
'
unset FLUX_IMP_CONFIG_PATTERN

test_expect_success 'create configs for flux-imp exec and signer' '
	cat <<-EOF >no-unpriv-exec.toml &&
	allow-sudo = true
	[sign]
	max-ttl = 30
	default-type = "none"
	allowed-types = [ "none" ]
	[exec]
	allowed-users = [ "$(whoami)" ]
	allowed-shells = [ "id", "echo" ]
	EOF
	cat <<-EOF >sign-none.toml &&
	allow-sudo = true
	[sign]
	max-ttl = 30
	default-type = "none"
	allowed-types = [ "none" ]
	[exec]
	allowed-users = [ "$(whoami)" ]
	allowed-shells = [ "id", "echo", "$(pwd)/sleeper.sh" ]
	allow-unprivileged-exec = true
	EOF
	cat <<-EOF >sign-none-allowed-munge.toml &&
	allow-sudo = true
	[sign]
	max-ttl = 30
	default-type = "none"
	allowed-types = [ "munge" ]
	[exec]
	allowed-users = [ "$(whoami)" ]
	allowed-shells = [ "id", "echo" ]
	allow-unprivileged-exec = true
	EOF
	cp sign-none.toml pam-test.toml &&
	cat <<-EOF >>pam-test.toml
	pam-support = true
	EOF
'
test_expect_success 'flux-imp exec fails in unprivileged mode by default' '
	( export FLUX_IMP_CONFIG_PATTERN=no-unpriv-exec.toml  &&
	  fake_imp_input foo | \
		test_must_fail $flux_imp exec echo good >noexec.out 2>&1
	) &&
	grep "IMP not installed setuid" noexec.out
'
test_expect_success 'flux-imp exec works in unprivileged mode if configured' '
	( export FLUX_IMP_CONFIG_PATTERN=sign-none.toml  &&
	  fake_imp_input foo | $flux_imp exec echo good >works.out
	) &&
	cat >works.expected <<-EOF &&
	good
	EOF
	test_cmp works.expected works.out
'
test_expect_success 'flux-imp exec fails when signature type not allowed' '
	( export FLUX_IMP_CONFIG_PATTERN=./sign-none-allowed-munge.toml  &&
	  fake_imp_input foo | \
	    test_must_fail $flux_imp exec echo good >badmech.log 2>&1
	) &&
	test_debug "cat badmech.log" &&
	grep "signature validation failed" badmech.log
'
test_expect_success 'flux-imp bails out with no configuration' '
	( export FLUX_IMP_CONFIG_PATTERN=/nosuchthing &&
	  fake_imp_input foo | \
	    test_must_fail $flux_imp exec echo good >badconf.log 2>&1
	) &&
	grep -i "Failed to load configuration" badconf.log
'
test_expect_success 'flux-imp exec fails with invalid stdin input' '
	( export FLUX_IMP_CONFIG_PATTERN=sign-none.toml &&
	  echo foo | \
	    test_must_fail $flux_imp exec echo good >badjson.log 2>&1
	) &&
	grep -i "invalid json input" badjson.log
'
test_expect_success 'flux-imp exec: shell must be in allowed users' '
	sed "s/allowed-users =//" sign-none.toml > sign-none-nousers.toml &&
	( export FLUX_IMP_CONFIG_PATTERN=sign-none-nousers.toml &&
	  fake_imp_input foo | \
	    test_must_fail $flux_imp exec echo good >nousers.log 2>&1
	) &&
	grep -i "not in allowed-users list" nousers.log
'
test_expect_success SUDO 'flux-imp exec: user must be in allowed-shells' '
	( export FLUX_IMP_CONFIG_PATTERN=sign-none.toml &&
	  fake_imp_input foo | \
	    test_must_fail $SUDO FLUX_IMP_CONFIG_PATTERN=sign-none.toml \
	      $flux_imp exec printf good >badshell.log 2>&1
	) &&
	grep -i "not in allowed-shells" badshell.log
'
test_expect_success SUDO 'flux-imp exec works under sudo' '
	( export FLUX_IMP_CONFIG_PATTERN=sign-none.toml  &&
          fake_imp_input foo | \
	    $SUDO FLUX_IMP_CONFIG_PATTERN=sign-none.toml \
	      $flux_imp exec id -u >id-sudo.out
        ) &&
	test_debug "echo expecting uid=$(id -u), got $(cat id-sudo.out)" &&
	id -u > id-sudo.expected &&
        test_cmp id-sudo.expected id-sudo.out
'
test_expect_success SUDO 'flux-imp exec passes more than one argument to shell' '
	( export FLUX_IMP_CONFIG_PATTERN=sign-none.toml  &&
          fake_imp_input foo | \
	    $SUDO FLUX_IMP_CONFIG_PATTERN=sign-none.toml \
	      $flux_imp exec id --zero --user >id-sudo2.out
        ) &&
	test_debug "echo expecting uid=$(id -u), got $(cat -v id-sudo2.out)" &&
	id --zero --user > id-sudo2.expected &&
        test_cmp id-sudo2.expected id-sudo2.out
'
test "$chain_lint" = "t" || test_set_prereq NO_CHAIN_LINT
test_expect_success SUDO,NO_CHAIN_LINT 'flux-imp exec: setuid IMP lingers' '
	cat <<-EOF >sleeper.sh &&
	#!/bin/sh
	printf "\$PPID\n" >$(pwd)/sleeper.pid
	exec /bin/sleep "\$@"
	EOF
	chmod +x sleeper.sh &&
	( export FLUX_IMP_CONFIG_PATTERN=sign-none.toml  && \
          exec <&- 1>&- 2>&- && \
          fake_imp_input foo | \
	    $SUDO FLUX_IMP_CONFIG_PATTERN=sign-none.toml \
	      $flux_imp exec $(pwd)/sleeper.sh 15 >linger.out 2>&1 & \
	) &&
	count=0 &&
	while ! test -f sleeper.pid; do
	    sleep 0.1
	    count=$((count+1))
	    test $count -gt 20 && break
	    test_debug "echo retrying count=${count}"
	done &&
        test_debug "cat sleeper.pid"
	test -f sleeper.pid &&
	pid=$(cat sleeper.pid) &&
	test_debug "pstree -lup $pid" &&
	test $(ps --no-header -o comm -p ${pid}) = "flux-imp" &&
	kill -TERM $pid &&
	wait
'
$flux_imp version | grep -q pam || test_set_prereq NO_PAM
test_expect_success NO_PAM,SUDO 'flux-imp exec: fails if not built with PAM but pam-support=true' '
	( export FLUX_IMP_CONFIG_PATTERN=pam-test.toml &&
	  fake_imp_input foo | \
		test_must_fail $SUDO FLUX_IMP_CONFIG_PATTERN=pam-test.toml \
			$flux_imp exec echo ok > pam-err.out 2>&1
	) &&
	test_debug "cat pam-err.out" &&
	grep "IMP was built without --enable-pam" pam-err.out
'
test_done

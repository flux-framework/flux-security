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
# Some shells do not support passing environment variable in the same
# line as the invocation. Therefore add a sign-none.toml version of
# the fake_imp_input() helper function: (sign-none.toml is defined later)
fake_input_sign_none() {
	printf '{"J":"%s"}' \
	 $(echo foo | env FLUX_IMP_CONFIG_PATTERN=sign-none.toml $sign)
}
wait_for_file() {
	count=0 &&
	while ! test -f $1; do
	    sleep 0.1
	    count=$((count+1))
	    test $count -gt 20 && break
	    test_debug "echo retrying count=${count}"
	done
}
imp_exec_sign_none() {
	fake_input_sign_none | \
	  $SUDO FLUX_IMP_CONFIG_PATTERN=sign-none.toml \
	    $flux_imp exec $@
}

cat <<EOF >helper.sh
#!/bin/sh
printf '{"J":"%s"}' \$(echo \$1 | $sign)
test -z "\$IMP_HELPER_FAIL"
EOF
chmod +x helper.sh

cat <<EOF >sleeper.sh
#!/bin/sh
printf "\$PPID\n" >$(pwd)/sleeper.pid
exec /bin/sleep "\$@"
EOF
chmod +x sleeper.sh

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

#  Now run the expected failure tests above with a helper of /usr/bin/cat:
export FLUX_IMP_EXEC_HELPER=cat
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
unset FLUX_IMP_EXEC_HELPER

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
test_expect_success 'flux-imp exec works in unprivileged mode with helper' '
	( export FLUX_IMP_CONFIG_PATTERN=sign-none.toml  &&
	  export FLUX_IMP_EXEC_HELPER=$(pwd)/helper.sh &&
	  $flux_imp exec echo good-again >works-helper.out
	) &&
	cat >works-helper.expected <<-EOF &&
	good-again
	EOF
	test_cmp works-helper.expected works-helper.out
'
test_expect_success 'flux-imp exec returns error with invalid helper' '
	( export FLUX_IMP_CONFIG_PATTERN=sign-none.toml &&
	  export FLUX_IMP_EXEC_HELPER="foo bar" &&
	  fake_imp_input foo | \
		test_must_fail $flux_imp exec echo good >badhelper.out 2>&1
	) &&
	test_debug "cat badhelper.out" &&
	grep "imp: popen:" badhelper.out
'
test_expect_success 'flux-imp returns error with empty helper' '
	( export FLUX_IMP_CONFIG_PATTERN=sign-none.toml &&
	  export FLUX_IMP_EXEC_HELPER="" &&
	  fake_imp_input foo | \
		test_must_fail $flux_imp exec echo OK >emptyhelper.out 2>&1
	) &&
	test_debug "cat emptyhelper.out" &&
	grep "FLUX_IMP_EXEC_HELPER is empty" emptyhelper.out
'
test_expect_success 'flux-imp exec fails when helper exits with nonzero status' '
	( export FLUX_IMP_CONFIG_PATTERN=sign-none.toml  &&
	  export FLUX_IMP_EXEC_HELPER=$(pwd)/helper.sh &&
	  export IMP_HELPER_FAIL=1 &&
	  test_must_fail $flux_imp exec echo foo >badhelper.log 2>&1
	) &&
	test_debug "cat badhelper.log" &&
	grep "helper.*failed" badhelper.log
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
	test_must_fail imp_exec_sign_none printf good >badshell.log 2>&1 &&
	test_debug "cat badshell.log" &&
	grep -i "not in allowed-shells" badshell.log
'
test_expect_success SUDO 'flux-imp exec works under sudo' '
	imp_exec_sign_none id -u >id-sudo.out &&
	test_debug "echo expecting uid=$(id -u), got $(cat id-sudo.out)" &&
	id -u > id-sudo.expected &&
        test_cmp id-sudo.expected id-sudo.out
'
test_expect_success SUDO 'flux-imp exec passes more than one argument to shell' '
	imp_exec_sign_none id --zero --user >id-sudo2.out &&
	test_debug "echo expecting uid=$(id -u), got $(cat -v id-sudo2.out)" &&
	id --zero --user > id-sudo2.expected &&
        test_cmp id-sudo2.expected id-sudo2.out
'
test "$chain_lint" = "t" || test_set_prereq NO_CHAIN_LINT
test_expect_success SUDO,NO_CHAIN_LINT 'flux-imp exec: setuid IMP lingers' '
	imp_exec_sign_none $(pwd)/sleeper.sh 15 >linger.out 2>&1 &
	imp_pid=$! &&
	test_when_finished "rm -f sleeper.pid" &&
	wait_for_file sleeper.pid &&
        test_debug "cat sleeper.pid"
	test -f sleeper.pid &&
	pid=$(cat sleeper.pid) &&
	test $(ps --no-header -o comm -p ${pid}) = "flux-imp" &&
	kill -TERM $pid &&
	test_expect_code 143 wait $imp_pid
'
test_expect_success SUDO,NO_CHAIN_LINT 'flux-imp exec: SIGUSR1 sends SIGKILL' '
	imp_exec_sign_none $(pwd)/sleeper.sh 15 >sigkill.out 2>&1 &
	imp_pid=$! &&
	test_when_finished "rm -f sleeper.pid" &&
	wait_for_file sleeper.pid &&
	test -f sleeper.pid &&
	pid=$(cat sleeper.pid) &&
	kill -USR1 $pid &&
	test_expect_code 137 wait $imp_pid
'
# Notes about cgroup kill testing below:
# - systemd-run is used as a convenient way to execute the IMP inside a
#   cgroup named with imp-shell prefix defined in RFC 15.
# - systemd-run is run with --collect so that a failure shouldn't leave
#   a stale transient unit on the system
# - systemd-run is run under sudo instead of `systemd-run sudo flux-imp`
#   because the IMP will send SIGKILL to all processes except itself in the
#   cgroup.procs file. If run directly under sudo, then sudo is a parent of
#   the IMP in the cgroup and gets SIGKILLed.
#
command -v systemd-run >/dev/null 2>&1  \
  && test_have_prereq SUDO \
  && $SUDO systemd-run --collect /bin/true >/dev/null 2>&1 \
  && test_set_prereq SYSTEMD_RUN

test_expect_success SUDO,NO_CHAIN_LINT,SYSTEMD_RUN \
	'flux-imp exec: SIGURS1 sends SIGKILL using cgroup kill' '
	FLUX_IMP_CONFIG_PATTERN=$(pwd)/sign-none.toml \
	  fake_imp_input foo | \
		$SUDO systemd-run --collect --scope \
			--unit=imp-shell-$$ \
			-E FLUX_IMP_CONFIG_PATTERN=sign-none.toml \
				$flux_imp exec $(pwd)/sleeper.sh 5 &
	pid=$! &&
	test_when_finished "rm -f sleeper.pid" &&
	wait_for_file sleeper.pid &&
	kill -USR1 $(cat sleeper.pid) &&
	test_expect_code 137 wait $pid
'

CGROUP_PATH="$(awk '/^cgroup2/ {print $2}' /proc/self/mounts)/imp-shell.$$"
test_have_prereq SUDO &&
 $SUDO mkdir $CGROUP_PATH &&
 test_set_prereq CGROUPFS &&
 cleanup "$SUDO rmdir $CGROUP_PATH"

cat <<'EOF' >run-in-cgroup.sh
#!/bin/sh
path=$1
shift
test -d $path || mkdir -p $path
echo "moving pid $$ to $path" >&2
echo $$ >${path}/cgroup.procs
echo "running $@ as $(id -u)" >&2
exec "$@"
EOF
chmod +x run-in-cgroup.sh

#  Rewrite sleeper script so it results in a hierarchy of processes
cat <<EOF>sleeper.sh
#!/bin/sh
printf "\$PPID\n" >$(pwd)/sleeper.pid
(/bin/sleep "\$@")
EOF
chmod +x sleeper.sh

test_expect_success SUDO,CGROUPFS,NO_CHAIN_LINT \
	'flux-imp exec: SIGUSR1 sends SIGKILL via cgroup kill' '
	fake_input_sign_none | \
		$SUDO FLUX_IMP_CONFIG_PATTERN=sign-none.toml \
			./run-in-cgroup.sh "$CGROUP_PATH" \
				$flux_imp exec $(pwd)/sleeper.sh 15 &
	imp_pid=$! &&
	test_when_finished "rm -f sleeper.pid" &&
	wait_for_file sleeper.pid &&
	kill -USR1 $(cat sleeper.pid) &&
	test_expect_code 137 wait $imp_pid &&
	test_must_be_empty ${CGROUP_PATH}/cgroup.procs
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

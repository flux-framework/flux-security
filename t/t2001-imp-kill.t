#!/bin/sh
#

test_description='IMP kill basic functionality test

Basic flux-imp kill failure handling
'

# Append --logfile option if FLUX_TESTS_LOGFILE is set in environment:
test -n "$FLUX_TESTS_LOGFILE" && set -- "$@" --logfile
. `dirname $0`/sharness.sh

flux_imp=${SHARNESS_BUILD_DIRECTORY}/src/imp/flux-imp

sign=${SHARNESS_BUILD_DIRECTORY}/t/src/sign

fake_imp_input() {
        printf '{"J":"%s"}' $(echo $1 | $sign)
}

echo "# Using ${flux_imp}"

test_expect_success 'flux-imp kill: returns error when run with no args' '
	test_must_fail $flux_imp kill
'
test_expect_success 'flux-imp kill: returns error when run with 1 arg' '
	test_must_fail $flux_imp kill 15
'
test_expect_success 'flux-imp kill: returns error with pid=0' '
	test_must_fail $flux_imp kill 15 0
'
test_expect_success 'flux-imp kill: returns error with invalid signal' '
	test_must_fail $flux_imp kill -15 0
'
test_expect_success 'flux-imp kill: checks exec.allowed-users' '
	name=wronguser &&
	cat <<-EOF >${name}.toml &&
	[exec]
	allowed-users = []
	EOF
	( export FLUX_IMP_CONFIG_PATTERN=${name}.toml &&
	  test_must_fail $flux_imp kill 15 1234 >${name}.log 2>&1
	) &&
	test_debug "cat ${name}.log" &&
	grep "kill command not allowed" ${name}.log && unset name
'
test_expect_success SUDO 'flux-imp kill: sudo: user must be in allowed-users' '
	name=wrongusersudo &&
	cat <<-EOF >${name}.toml &&
	allow-sudo = true
	[exec]
	allowed-users = []
	EOF
	test_must_fail $SUDO FLUX_IMP_CONFIG_PATTERN=${name}.toml \
	      $flux_imp kill 15 1234 >${name}.log 2>&1 &&
	test_debug "cat ${name}.log" &&
	grep -i "kill command not allowed" ${name}.log && unset name
'

test "$chain_lint" = "t" || test_set_prereq NO_CHAIN_LINT


test "$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" = "cgroup2fs" \
  -o "$(stat -fc %T /sys/fs/cgroup/unified 2>/dev/null)" = "cgroup2fs" \
  -o "$(stat -fc %T /sys/fs/cgroup/systemd 2>/dev/null)" = "cgroup2fs" \
  -o "$(stat -fc %T /sys/fs/cgroup/systemd 2>/dev/null)" = "cgroupfs" \
     && test_set_prereq SYSTEMD_CGROUP

test_expect_success NO_CHAIN_LINT,SYSTEMD_CGROUP 'flux-imp kill: works in unpriv mode' '
	name=unpriv &&
	cat <<-EOF >${name}.toml
	allow-sudo = true
	[exec]
	allowed-users = [ "$(whoami)" ]
	EOF
	sleep 300 & pid=$! &&
	FLUX_IMP_CONFIG_PATTERN=${name}.toml \
	    $flux_imp kill 15 $pid >${name}.log 2>&1 &&
	test_debug "cat ${name}.log" &&
	test_expect_code 143 wait $pid
'
test_expect_success NO_CHAIN_LINT,SYSTEMD_CGROUP,SUDO 'flux-imp kill: works with sudo' '
	name=sudo &&
	cat <<-EOF >${name}.toml
	allow-sudo = true
	[exec]
	allowed-users = [ "$(whoami)" ]
	EOF
	sleep 300 & pid=$! &&
	$SUDO FLUX_IMP_CONFIG_PATTERN=${name}.toml \
	    $flux_imp kill 15 $pid >${name}.log 2>&1 &&
	test_expect_code 143 wait $pid
'
test_expect_success SYSTEMD_CGROUP 'flux-imp kill: fails for nonexistent pid' '
	name=pid-noexist &&
	cat <<-EOF >${name}.toml &&
	allow-sudo = true
	[exec]
	allowed-users = [ "$(whoami)" ]
	EOF
	for pid in `seq 10000 12000`; do
            kill -s 0 ${pid} >/dev/null 2>&1 || break
        done &&
	( export FLUX_IMP_CONFIG_PATTERN=${name}.toml &&
	    test_must_fail $flux_imp kill 15 $pid >${name}.log 2>&1
	) &&
	test_debug "cat ${name}.log" &&
	grep "No such file or directory"  ${name}.log
'
test_expect_success SUDO,SYSTEMD_CGROUP 'flux-imp kill: fails for nonexistent pid under sudo' '
	name=noexist-pid-sudo &&
	cat <<-EOF >${name}.toml &&
	allow-sudo = true
	[exec]
	allowed-users = [ "$(whoami)" ]
	EOF
	for pid in `seq 10000 12000`; do
            kill -s 0 ${pid} >/dev/null 2>&1 || break
        done &&
	test_must_fail $SUDO FLUX_IMP_CONFIG_PATTERN=${name}.toml \
	    $flux_imp kill 15 $pid >${name}.log 2>&1 &&
	test_debug "cat ${name}.log" &&
	grep "No such file or directory"  ${name}.log
'
test_expect_success 'create config for flux-imp exec and signer' '
	cat <<-EOF >sign-none.toml
	allow-sudo = true
	[sign]
	max-ttl = 30
	default-type = "none"
	allowed-types = [ "none" ]
	[exec]
	allowed-users = [ "$(whoami)" ]
	allowed-shells = [ "$(pwd)/sleeper.sh" ]
	allow-unprivileged-exec = true
	EOF
'

#  Need a setuid IMP for the following kill tests to work. This is required
#   because on most systemd systems, sudo may migrate children to a root-owned
#   cgroup, and `flux-imp kill` uses the ownership of the containing cgroup
#   to determine authorization to signal a process
test_expect_success SUDO 'attempt to create setuid copy of flux-imp for testing' '
        sudo cp $flux_imp . &&
        sudo chmod 4755 ./flux-imp
'

#  In case tests are running on filesystem with nosuid, check that permissions
#   of flux-imp are actually setuid, and if so set SUID_ENABLED prereq
#
test -n "$(find ./flux-imp -perm 4755)" && test_set_prereq SUID_ENABLED

#  In order for the following kill tests to work, the owner of the current
#   cgroup must be the current user running the test.
#
test "$(FLUX_IMP_CONFIG_PATTERN=sign-none.toml ./flux-imp kill 0 $$ \
	| sed 's/.*cg_owner=//')" = "$(id -u)" && test_set_prereq USER_CGROUP

waitfile()
{
	count=0
	while ! grep "$2" $1 >/dev/null 2>&1; do
	    sleep 0.2
	    count=$(($count + 1))
	    test $count -gt 20 && break
	done
	grep "$2" $1 >/dev/null
}

test_expect_success NO_CHAIN_LINT,SUID_ENABLED,USER_CGROUP \
'flux-imp kill signals children of another flux-imp' '
	cat <<-EOF >sleeper.sh &&
	#!/bin/sh
	echo "\$@"
	printf "\$PPID\n" >$(pwd)/sleeper.pid
	/bin/sleep "\$@" &
	pid=\$! &&
	trap "echo got SIGTERM; kill \$pid" SIGTERM
	wait
	echo sleep exited with \$? >&2
	EOF
	chmod +x sleeper.sh &&
	export FLUX_IMP_CONFIG_PATTERN=sign-none.toml &&
	fake_imp_input foo | \
	  ./flux-imp exec $(pwd)/sleeper.sh 30 >sleeper.out 2>&1 &
	pid=$! &&
	waitfile sleeper.pid ".*" &&
        test_debug "echo calling flux-imp kill $(cat sleeper.pid)" &&
	FLUX_IMP_CONFIG_PATTERN=$(pwd)/unpriv.toml \
            ./flux-imp kill 15 $(cat sleeper.pid) &&
	wait $pid &&
        test_debug "echo waiting for output file" &&
	grep "got SIGTERM" sleeper.out
'

test_done

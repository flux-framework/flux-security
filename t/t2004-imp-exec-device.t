#!/bin/sh
#

test_description='IMP exec device containment tests

Tests for DevicePolicy/DeviceAllow parsing and BPF device containment.
Unprivileged tests check JSON parsing and policy resolution.
Privileged tests check that BPF programs are loaded and attached.
'

# Append --logfile option if FLUX_TESTS_LOGFILE is set in environment:
test -n "$FLUX_TESTS_LOGFILE" && set -- "$@" --logfile
. `dirname $0`/sharness.sh

flux_imp=${SHARNESS_BUILD_DIRECTORY}/src/imp/flux-imp
sign=${SHARNESS_BUILD_DIRECTORY}/t/src/sign
bpf_cgroup_probe=${SHARNESS_BUILD_DIRECTORY}/t/src/bpf_cgroup_probe

echo "# Using ${flux_imp}"

CGROUP_MOUNT=$(awk '$3 == "cgroup2" {print $2}' /proc/self/mounts)
test -n "$CGROUP_MOUNT" || bail_out "Failed to get cgroup2 mount dir!"
CURRENT_CGROUP_PATH=$(cat /proc/self/cgroup | sed -n s/^0:://p)
CGROUP_PATH="${CGROUP_MOUNT}${CURRENT_CGROUP_PATH}/imp-shell.$$"
echo "# using CGROUP_PATH=$CGROUP_PATH"

# Produce IMP exec JSON with no options (baseline, no containment).
fake_J() {
	echo foo | env FLUX_IMP_CONFIG_PATTERN=sign-none.toml $sign
}

no_device_input() {
	printf '{"J":"%s"}' $(fake_J)
}

# Produce IMP exec JSON
# Usage: device_input DevicePolicy DeviceAllow
device_input() {
	printf '{"J":"%s","options":{"DevicePolicy":"%s","DeviceAllow":%s}}' \
		$(fake_J) "$1" "${2:-[]}"
}

cat <<'EOF' >run-in-cgroup.sh
#!/bin/sh
path=$1
shift
test -d $path || mkdir -p $path &&
echo $$ >${path}/cgroup.procs &&
exec "$@"
EOF
chmod +x run-in-cgroup.sh

cat <<EOF >sign-none.toml
allow-sudo = true
[sign]
max-ttl = 30
default-type = "none"
allowed-types = [ "none" ]
[exec]
allowed-users = [ "$(whoami)" ]
allowed-shells = [ "echo", "cat", "true" ]
allow-unprivileged-exec = true
EOF
export FLUX_IMP_CONFIG_PATTERN=sign-none.toml

if test_have_prereq SUDO; then
	if $SUDO mkdir $CGROUP_PATH; then
		test_set_prereq CGROUPFS
		cleanup "$SUDO rmdir $CGROUP_PATH"
	fi
 	if $SUDO ./run-in-cgroup.sh $CGROUP_PATH cat /proc/self/cgroup; then
		test_set_prereq CGROUP_WRITABLE
	fi
	if test_have_prereq CGROUPFS,CGROUP_WRITABLE; then
		if $SUDO $bpf_cgroup_probe; then
			test_set_prereq BPF_CGROUP
		fi
	fi
fi


# ---- Unprivileged tests: policy parsing only, no BPF applied ----

test_expect_success 'absent options key: exec succeeds with no containment' '
	no_device_input | $flux_imp exec echo ok >absent.out &&
	grep -q ok absent.out
'
test_expect_success 'invalid DevicePolicy: exec fails with diagnostic' '
	device_input bogus |
		test_must_fail $flux_imp exec echo ok >bad-device.out 2>&1 &&
	test_debug "cat bad-device.out" &&
	grep "device containment policy" bad-device.out
'
test_expect_success 'auto policy with empty DeviceAllow: exec succeeds' '
	device_input auto |
		$flux_imp exec echo ok >auto-empty.out &&
	grep -q ok auto-empty.out
'
test_expect_success 'strict policy with /dev/null: exec succeeds' '
	device_input strict "[[\"/dev/null\",\"rw\"]]" |
		$flux_imp exec echo ok >strict-null.out &&
	grep -q ok strict-null.out
'
test_expect_success 'closed policy with empty DeviceAllow: exec succeeds' '
	device_input closed |
		$flux_imp exec echo ok >closed-empty.out &&
	grep -q ok closed-empty.out
'
test_expect_success 'block- class specifier: exec succeeds' '
	device_input strict "[[\"block-loop\",\"rw\"]]" |
		$flux_imp exec echo ok >block-loop.out &&
	grep -q ok block-loop.out
'
test_expect_success 'unknown specifier: exec succeeds (entry skipped, no containment failure)' '
	device_input strict "[[\"unknownspec\",\"rw\"]]" |
		$flux_imp exec echo ok >unknown-spec.out &&
	grep -q ok unknown-spec.out
'

# ---- Privileged tests: BPF program loaded and attached to cgroup ----

test_expect_success BPF_CGROUP \
	'closed policy: BPF program loads and job runs successfully' '
	device_input closed |
		$SUDO FLUX_IMP_CONFIG_PATTERN=sign-none.toml \
			./run-in-cgroup.sh "$CGROUP_PATH" \
			$flux_imp exec echo ok >closed-bpf.out &&
	grep -q ok closed-bpf.out
'
test_expect_success BPF_CGROUP \
	'strict policy with /dev/null: BPF program loads and job runs successfully' '
	device_input strict "[[\"/dev/null\",\"rwm\"]]" |
		$SUDO FLUX_IMP_CONFIG_PATTERN=sign-none.toml \
			./run-in-cgroup.sh "$CGROUP_PATH" \
			$flux_imp exec echo ok >strict-bpf.out &&
	grep -q ok strict-bpf.out
'
test_expect_success BPF_CGROUP \
	'strict policy with empty DeviceAllow denies access to /dev/null' '
	device_input strict "[]" |
		test_must_fail $SUDO FLUX_IMP_CONFIG_PATTERN=sign-none.toml \
			./run-in-cgroup.sh "$CGROUP_PATH" \
			$flux_imp exec cat /dev/null >deny-null.out 2>&1 &&
	test_debug "cat deny-null.out" &&
	grep -q "Operation not permitted" deny-null.out
'
test_expect_success BPF_CGROUP \
	'strict policy allowing /dev/null permits access' '
	device_input strict "[[\"/dev/null\",\"rw\"]]" |
		$SUDO FLUX_IMP_CONFIG_PATTERN=sign-none.toml \
			./run-in-cgroup.sh "$CGROUP_PATH" \
			$flux_imp exec cat /dev/null
'

test_done

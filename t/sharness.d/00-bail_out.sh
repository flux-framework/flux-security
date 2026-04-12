# Immediately bail out of the test script with the reason given in [$1].
# See <https://testanything.org/tap-specification.html>.
#
# Taken from MUNGE:
# https://github.com/dun/munge/blob/master/tests/sharness.d/00-bail_out.sh

bail_out()
{
    local cmd="Bail out!" msg="$1"

    say_color >&5 error "${cmd} ${msg}"
    EXIT_OK=t
    exit 1
}


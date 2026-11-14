/************************************************************\
 * Copyright 2026 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#include <errno.h>
#include <sys/types.h>

#include "pidset.h"

#include "src/libtap/tap.h"

static void test_invalid (void)
{
    ok (pidset_contains (NULL, 1) == false,
        "pidset_contains (NULL) returns false");
    errno = 0;
    ok (pidset_add (NULL, 1) < 0 && errno == EINVAL,
        "pidset_add (NULL) fails with EINVAL");
    ok (pidset_count (NULL) == 0,
        "pidset_count (NULL) returns 0");
    lives_ok ({pidset_destroy (NULL);},
              "pidset_destroy (NULL) doesn't crash");
}

static void test_empty (void)
{
    struct pidset *set;

    if (!(set = pidset_create ()))
        BAIL_OUT ("pidset_create failed");
    ok (pidset_count (set) == 0,
        "new pidset is empty");
    ok (pidset_contains (set, 1) == false,
        "pidset_contains returns false on empty set");
    pidset_destroy (set);
}

static void test_basic (void)
{
    struct pidset *set;

    if (!(set = pidset_create ()))
        BAIL_OUT ("pidset_create failed");
    ok (pidset_add (set, 42) == 0,
        "pidset_add 42 works");
    ok (pidset_contains (set, 42),
        "pidset_contains 42");
    ok (!pidset_contains (set, 43),
        "pidset does not contain 43");
    ok (pidset_count (set) == 1,
        "pidset_count is 1");
    ok (pidset_add (set, 42) == 0 && pidset_count (set) == 1,
        "adding duplicate pid has no effect");
    pidset_destroy (set);
}

/*  Add enough pids to grow the set several times past its initial size,
 *  and ensure all pids are retained across each resize.
 */
static void test_grow (void)
{
    struct pidset *set;
    const int n = 200;
    int errors = 0;

    if (!(set = pidset_create ()))
        BAIL_OUT ("pidset_create failed");

    for (pid_t pid = 1; pid <= n; pid++) {
        if (pidset_add (set, pid) < 0) {
            diag ("pidset_add %d failed", (int) pid);
            errors++;
        }
        /* Check all pids after each add to catch a bad resize */
        for (pid_t i = 1; i <= pid; i++) {
            if (!pidset_contains (set, i)) {
                diag ("pid %d missing after adding %d", (int) i, (int) pid);
                errors++;
                break;
            }
        }
        if (errors)
            break;
    }
    ok (errors == 0,
        "added %d pids, all retained across resizes", n);
    ok (pidset_count (set) == n,
        "pidset_count is %d", n);
    ok (!pidset_contains (set, 0) && !pidset_contains (set, n + 1),
        "pidset does not contain pids that were not added");

    errors = 0;
    for (pid_t pid = 1; pid <= n; pid++)
        if (pidset_add (set, pid) < 0)
            errors++;
    ok (errors == 0 && pidset_count (set) == n,
        "re-adding all pids has no effect");

    pidset_destroy (set);
}

int main (void)
{
    plan (NO_PLAN);

    test_invalid ();
    test_empty ();
    test_basic ();
    test_grow ();

    done_testing ();
}

/* vi: ts=4 sw=4 expandtab
 */

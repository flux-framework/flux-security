/************************************************************\
 * Copyright 2023 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <errno.h>

#include "imp_log.h"
#include "exec/safe_popen.h"
#include "src/libtap/tap.h"

static void test_safe_popen_invalid (void)
{
    ok (safe_popen (NULL) == NULL && errno == EINVAL,
        "safe_popen (NULL) fails with EINVAL");
    ok (safe_popen ("") == NULL && errno == EINVAL,
        "safe_popen (\"\") fails with EINVAL");
    ok (safe_popen_wait (NULL, NULL) < 0 && errno == EINVAL,
        "safe_popen_wait (NULL, NULL) returns EINVAL");
    ok (safe_popen_fp (NULL) == NULL && errno == EINVAL,
        "safe_popen_fp (NULL) fails with EINVAL");
    lives_ok ({safe_popen_destroy (NULL);},
            "safe_popen_destroy (NULL) doesn't crash program");
}

static void test_safe_popen_basic (void)
{
    size_t n;
    FILE *fp;
    char buf[64];
    int status;
    struct safe_popen *sp;

    sp = safe_popen ("printf %s hello");
    if (sp == NULL)
        BAIL_OUT ("safe_popen failed");
    pass ("safe_popen success");

    if (!(fp = safe_popen_fp (sp)))
        BAIL_OUT ("safe_popen_get_fp failed");
    pass ("safe_popen_get_fp success");

    memset (buf, 0, sizeof (buf));
    n = fread (buf, 1, sizeof (buf), fp);
    ok (n == 5,
        "fread() from fp got %zu bytes (expected 5)", n);
    is (buf, "hello",
        "buffer == \"hello\"");
    ok (safe_popen_wait (sp, &status) == 0,
        "safe_popen_wait() returned 0");
    ok (status == 0,
        "status == 0");
    ok (safe_popen_wait (sp, &status) < 0,
        "safe_popen_wait() fails when called again");
    ok (WIFEXITED (status) && WEXITSTATUS (status) == 0,
        "safe_popen_wait() reports exit code of 0");
    safe_popen_destroy (sp);
}

static void test_safe_popen_failure (void)
{
    int status;

    /*  Call printf(1) with no arguments, which should fail */
    struct safe_popen *sp = safe_popen ("printf");
    if (sp == NULL)
        BAIL_OUT ("safe_popen(printf) failed");
    pass ("safe_popen (\"printf\") success");
    ok (safe_popen_wait (sp, &status) == 0,
        "safe_popen_wait() == 0");
    ok (WIFEXITED (status) && WEXITSTATUS (status) > 0,
        "safe_popen_wait() reports exit code of %d", WEXITSTATUS (status));
    safe_popen_destroy (sp);

    if (!(sp = safe_popen ("nosuchcommand")))
        BAIL_OUT ("safe_popen(nosuchcommand) failed");
    pass ("safe_popen (\"nosuchcommand\") success");
    ok (safe_popen_wait (sp, &status) == 0,
        "safe_popen_wait() == 0");
    ok (WIFEXITED (status) && WEXITSTATUS (status) == 127,
        "safe_popen_wait() reports exit code of %d", WEXITSTATUS (status));
    safe_popen_destroy (sp);
}

static int log_diag (int level, const char *str,
                     void *arg __attribute__ ((unused)))
{
    diag ("safe_popen: %s: %s\n", imp_log_strlevel (level), str);
    return (0);
}

int main (void)
{
    /*  safe_popen uses imp log for errors so initialize here
     */
    imp_openlog ();
    imp_log_add ("diag", IMP_LOG_DEBUG, log_diag, NULL);

    plan (NO_PLAN);

    test_safe_popen_invalid ();
    test_safe_popen_basic ();
    test_safe_popen_failure ();

    imp_closelog ();
    done_testing ();
}

/*
 * vi: ts=4 sw=4 expandtab
 */

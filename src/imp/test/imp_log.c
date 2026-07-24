/************************************************************\
 * Copyright 2017 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "imp_log.h"

#include "src/libtap/tap.h"


/* Test log destination buffer */
static char testbuf [8192];

/*
 *  Testing log implementation: write log messages to a single buffer
 *   sot that tests can ensure the message made it intact
 */
static int test_logf (int level, const char *msg,
                      void *arg __attribute__ ((unused)))
{
    const char *prefix = imp_log_strlevel (level);
    if (prefix)
        snprintf (testbuf, sizeof (testbuf), "%s: %s", prefix, msg);
    else
        strcpy (testbuf, msg);
    return (0);
}

/*  Zero out test log destination "testbuf"
 */
void reset_logbuf ()
{
    memset (testbuf, 0, sizeof (testbuf));
}

/*  Generate a string of length len for testing
 */
char * long_string (char *buf, int len)
{
    memset (buf, '-', len - 1);
    buf [len-1] = '\0';
    return buf;
}

int main (void)
{
    int rc;

    plan (NO_PLAN);
    imp_openlog ();

    reset_logbuf ();
    rc = imp_log_add ("test", IMP_LOG_DEBUG, test_logf, NULL);
    ok (rc == 0, "imp_log_add: works");

    rc = imp_log_add ("test", IMP_LOG_DEBUG, test_logf, NULL);
    ok (rc < 0 && errno == EEXIST,
        "imp_log_add: duplicate returns errno = EEXIST");

    imp_say ("Hello.");
    is (testbuf, "Notice: Hello.", "imp_say: works");

    imp_warn ("Bad Thing.");
    is (testbuf, "Warning: Bad Thing.", "imp_warn: works");

    reset_logbuf ();
    imp_debug ("Interesting Thing.");
    is (testbuf, "", "imp_debug: by default no debug output");

    ok (imp_log_set_level (NULL, 9999) < 0 && errno == EINVAL,
        "imp_log_set_level: returns EINVAL for invalid level");
    ok (imp_log_set_level (NULL, IMP_LOG_DEBUG) == 0,
        "imp_log_set_level: enable debug messages globally");

    reset_logbuf ();
    imp_debug ("Interesting Thing.");
    is (testbuf, "Debug: Interesting Thing.",
        "imp_debug: works");

    ok (imp_log_set_level ("test", IMP_LOG_INFO) >= 0,
        "imp_log_set_level: decrease level for test logger");

    reset_logbuf ();
    imp_debug ("debug message");
    is (testbuf, "", "test log ignores messages above its set level");

    /*  Test log output truncation */
    char buf [8192];
    reset_logbuf ();
    imp_say ("%s", long_string (buf, 4200));
    rc = strlen (testbuf);
    ok (rc > 0, "very long log message gets written (len = %d)", rc);
    ok (testbuf[rc - 1] == '+', "very long log message is truncated");

    /*  Control characters embedded in a message are neutralized so an
     *   attacker-influenced argument cannot forge log lines or inject
     *   terminal escape sequences (see log_sanitize()).
     */
    reset_logbuf ();
    imp_say ("mechanism=%s unknown", "munge\ndevice: allow /dev/mem");
    is (testbuf, "Notice: mechanism=munge?device: allow /dev/mem unknown",
        "embedded newline is replaced with '?'");

    reset_logbuf ();
    imp_say ("boot\033[2Jsequence");
    is (testbuf, "Notice: boot?[2Jsequence",
        "embedded ESC is replaced with '?'");

    reset_logbuf ();
    imp_say ("trailing newline\n");
    is (testbuf, "Notice: trailing newline",
        "trailing newline is stripped");

    reset_logbuf ();
    imp_say ("tab\tseparated");
    is (testbuf, "Notice: tab\tseparated",
        "tab is preserved");

    /*  Remove logging provider */
    rc = imp_log_remove ("test");
    ok (rc == 0, "imp_log_remove: works");
    rc = imp_log_remove ("test");
    ok (rc <= 0 && errno == ENOENT, "imp_log_remove: fails on missing entry");

    reset_logbuf ();
    imp_say ("Test");
    is (testbuf, "", "test log no longer processes messages after removal");

    /*  Test imp_die */
    dies_ok ({ imp_die (1, "fatal error"); }, "imp_die: works");

    imp_closelog ();
    done_testing ();
}

/*
 * vi: ts=4 sw=4 expandtab
 */

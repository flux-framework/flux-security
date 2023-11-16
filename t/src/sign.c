/************************************************************\
 * Copyright 2017 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

/* sign.c - sign stdin
 *
 * Usage: sign <input >output
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#include "src/lib/context.h"
#include "src/lib/sign.h"

const char *prog = "sign";

static void die (const char *fmt, ...)
{
    va_list ap;
    char buf[256];

    va_start (ap, fmt);
    (void)vsnprintf (buf, sizeof (buf), fmt, ap);
    va_end (ap);
    fprintf (stderr, "%s: %s\n", prog, buf);
    exit (1);
}

static int read_all (void *buf, int bufsz)
{
    int n;
    int count = 0;
    do {
        if ((n = read (STDIN_FILENO, (char *)buf + count, bufsz - count)) < 0)
            die ("read stdin: %s", strerror (errno));
        count += n;
    } while (n > 0 && count < bufsz);
    if (n > 0)
        die ("input buffer exceeded");
    return count;
}

int main (int argc, char **argv)
{
    flux_security_t *ctx;
    char buf[1024];
    int buflen;
    const char *msg;

    if (argc != 1)
        die ("Usage: sign <input >output");

    if (!(ctx = flux_security_create (0)))
        die ("flux_security_create");
    if (flux_security_configure (ctx, getenv ("FLUX_IMP_CONFIG_PATTERN")) < 0)
        die ("flux_security_configure: %s", flux_security_last_error (ctx));

    buflen = read_all (buf, sizeof (buf));

    if (!(msg = flux_sign_wrap (ctx, buf, buflen, NULL, 0)))
        die ("flux_sign_wrap: %s", flux_security_last_error (ctx));

    printf ("%s\n", msg);

    flux_security_destroy (ctx);

    return 0;
}

/* vi: ts=4 sw=4 expandtab
 */

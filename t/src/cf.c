/************************************************************\
 * Copyright 2017 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

/* cf.c - read imp config
 *
 * Usage: keygen path
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "src/libutil/cf.h"

extern const char *imp_get_config_pattern (void);

const char *prog = "cf";

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

void lookup (const cf_t *cf, char *key)
{
    char *nextkey = strchr (key, '.');
    const cf_t *val;

    if (nextkey) {
        *nextkey++ = '\0';
        if (!(val = cf_get_in (cf, key)))
            die ("%s: not found", key);
        if (cf_typeof (val) != CF_TABLE)
            die ("%s: not a table object", key);
        lookup (val, nextkey);
    }
    else {
        if (!(val = cf_get_in (cf, key)))
            die ("%s: not found", key);

        switch (cf_typeof (val)) {
            case CF_INT64:
                printf ("%lld\n", (long long)cf_int64 (val));
                break;
            case CF_DOUBLE:
                printf ("%lf\n", cf_double (val));
                break;
            case CF_BOOL:
                printf ("%s\n", cf_bool (val) ? "true" : "false");
                break;
            case CF_STRING:
                printf ("%s\n", cf_string (val));
                break;
            case CF_TIMESTAMP:
                printf ("%d\n", (int)cf_timestamp (val));
                break;
            case CF_TABLE:
                printf ("[table]\n");
                break;
            case CF_ARRAY:
                printf ("[array]\n");
                break;
            case CF_UNKNOWN:
                die ("unknown type");
                break;
        }
    }
}

int main (int argc, char **argv)
{
    const char *pattern = imp_get_config_pattern ();
    cf_t *cf;
    struct cf_error e;

    if (argc != 2) {
        fprintf (stderr, "Usage: cf key\n");
        exit (1);
    }

    if (!(cf = cf_create ()))
        die ("cf_create: %s", strerror (errno));
    assert (pattern != NULL);
    if (cf_update_glob (cf, pattern, &e) < 0)
        die ("%s::%d: %s", e.filename, e.lineno, e.errbuf);

    lookup (cf, argv[1]);

    cf_destroy (cf);

    return 0;
}

/* vi: ts=4 sw=4 expandtab
 */

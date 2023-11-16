/************************************************************\
 * Copyright 2017 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

/* getpwuid.c - LD_PRELOAD version of getpwuid() that uses TEST_PASSWD_FILE
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <pwd.h>
#include <errno.h>

struct passwd *getpwuid (uid_t uid)
{
    const char *filename;
    struct passwd *pwp = NULL;

    if ((filename = getenv ("TEST_PASSWD_FILE"))) {
        FILE *f;
        if ((f = fopen (filename, "r"))) {
            while ((pwp = fgetpwent (f))) {
                if (pwp->pw_uid == uid)
                    break;
            }
            (void)fclose (f);
        }
    }
    else
        pwp = getpwuid (uid);

    if (pwp == NULL)
        errno = ENOENT;
    return pwp;
}

/* vi: ts=4 sw=4 expandtab
 */

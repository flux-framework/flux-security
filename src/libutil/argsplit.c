/************************************************************\
 * Copyright 2023 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "argsplit.h"

void args_free (char **args)
{
    if (args) {
        int i = 0;
        while (args[i])
            free (args[i++]);
        free (args);
    }
}

char **argsplit (const char *args)
{
    int count = 0;
    char *s;
    char *sp = NULL;
    char *str;
    char *copy;
    char **argv;
    int i = 0;

    if (!args || strlen (args) == 0) {
        errno = 0;
        return NULL;
    }
    if (!(copy = strdup (args)))
        return NULL;

    /*  Non-destructively count number of tokens
     */
    s = copy;
    while ((s = strpbrk (s, " \t"))) {
        count++;
        while (*s == ' ' || *s == '\t')
            s++;
    }

    /*  Allocate return vector: count+1 tokens plus NULL terminator
     */
    int argv_size = count + 2;
    if (!(argv = calloc (argv_size, sizeof (char *))))
        goto error;
    assert (argv_size > 0);

    /*  Split into tokens
     */
    i = 0;
    str = copy;
    while ((s = strtok_r (str, " \t", &sp))) {
        str = NULL;
        /* Defense-in-depth: verify we don't exceed allocated size. This
         * protects against integer overflow in count, future logic bugs, and
         * buffer overflows in security-critical setuid code. Should never
         * trigger with correct counting logic.
         */
        if (i >= argv_size - 1) {
            errno = EINVAL;
            goto error;
        }
        if (!(argv[i] = strdup (s)))
            goto error;
        i++;
    }
    free (copy);
    return argv;
error:
    free (copy);
    args_free (argv);
    return NULL;
}


/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */

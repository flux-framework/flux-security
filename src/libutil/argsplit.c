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

    /*  Allocate return vector
     */
    if (!(argv = calloc (count+2, sizeof (char *))))
        goto error;

    /*  Split into takens
     */
    i = 0;
    str = copy;
    while ((s = strtok_r (str, " \t", &sp))) {
        if (!(argv[i] = strdup (s)))
            goto error;
        i++;
        str = NULL;
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

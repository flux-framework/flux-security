/************************************************************\
 * Copyright 2026 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#if HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdlib.h>
#include <limits.h>
#include <errno.h>

#include "pidset.h"

#define PIDSET_INITIAL_SIZE 16

struct pidset {
    pid_t *pids;
    int count;
    int size;
};

struct pidset *pidset_create (void)
{
    return calloc (1, sizeof (struct pidset));
}

void pidset_destroy (struct pidset *set)
{
    if (set) {
        int saved_errno = errno;
        free (set->pids);
        free (set);
        errno = saved_errno;
    }
}

bool pidset_contains (const struct pidset *set, pid_t pid)
{
    if (!set)
        return false;
    for (int i = 0; i < set->count; i++)
        if (set->pids[i] == pid)
            return true;
    return false;
}

int pidset_add (struct pidset *set, pid_t pid)
{
    if (!set) {
        errno = EINVAL;
        return -1;
    }
    if (pidset_contains (set, pid))
        return 0;
    if (set->count == set->size) {
        int size;
        pid_t *pids;

        if (set->size > INT_MAX / 2) {
            errno = ENOMEM;
            return -1;
        }
        size = set->size ? set->size * 2 : PIDSET_INITIAL_SIZE;
        if (!(pids = realloc (set->pids, size * sizeof (pid_t))))
            return -1;
        set->pids = pids;
        set->size = size;
    }
    set->pids[set->count++] = pid;
    return 0;
}

int pidset_count (const struct pidset *set)
{
    return set ? set->count : 0;
}

/* vi: ts=4 sw=4 expandtab
 */

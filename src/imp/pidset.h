/************************************************************\
 * Copyright 2026 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#ifndef HAVE_IMP_PIDSET_H
#define HAVE_IMP_PIDSET_H 1

#include <stdbool.h>
#include <sys/types.h>

/*  Simple set of pids. The number of pids is expected to be small,
 *  so a linear search is used for lookup.
 */
struct pidset;

struct pidset *pidset_create (void);
void pidset_destroy (struct pidset *set);

/*  Return true if pid is in set.
 */
bool pidset_contains (const struct pidset *set, pid_t pid);

/*  Add pid to set. Returns 0 on success, or -1 with errno set on failure.
 *  Adding a pid that is already in the set is not an error, and has no
 *  effect.
 */
int pidset_add (struct pidset *set, pid_t pid);

/*  Return the number of pids in set.
 */
int pidset_count (const struct pidset *set);

#endif /* !HAVE_IMP_PIDSET_H */

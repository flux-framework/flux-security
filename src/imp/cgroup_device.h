/************************************************************\
 * Copyright 2026 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#ifndef HAVE_IMP_CGROUP_DEVICE_H
#define HAVE_IMP_CGROUP_DEVICE_H 1

#include "cgroup.h"
#include "exec/device.h"

/* Attach a BPF device policy program to the job cgroup.
 * Does nothing and returns 0 if da is NULL.
 * Returns 0 on success, -1 on error with errno set.
 */
int cgroup_device_apply (struct cgroup_info *cgroup,
                         struct device_allow *da);

#endif /* !HAVE_IMP_CGROUP_DEVICE_H */

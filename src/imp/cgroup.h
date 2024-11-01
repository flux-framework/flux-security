/************************************************************\
 * Copyright 2024 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#ifndef HAVE_IMP_CGROUP_H
#define HAVE_IMP_CGROUP_H 1

struct cgroup_info {
    char mount_dir[PATH_MAX + 1];
    char path[PATH_MAX + 1];
    bool unified;
    bool use_cgroup_kill;
};

struct cgroup_info *cgroup_info_create (void);

void cgroup_info_destroy (struct cgroup_info *cgroup);

/*  Send signal to all pids (excluding the current pid) in the
 *  current cgroup.
 */
int cgroup_kill (struct cgroup_info *cgroup, int sig);

/*  Wait for all processes in cgroup (except this one) to exit.
 */
int cgroup_wait_for_empty (struct cgroup_info *cgroup);

#endif /* !HAVE_IMP_CGROUP_H */

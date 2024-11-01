/************************************************************\
 * Copyright 2017 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#ifndef HAVE_IMP_STATE_H
#define HAVE_IMP_STATE_H 1

#include "src/libutil/cf.h"
#include "privsep.h"
#include "cgroup.h"

struct imp_state {
    int        argc;
    char     **argv;        /* cmdline arguments from main() */
    cf_t      *conf;        /* IMP configuration */
    privsep_t *ps;          /* Privilege separation handle */
    struct cgroup_info *cgroup;
};

#endif /* !HAVE_IMP_STATE_H */

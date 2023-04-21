/************************************************************\
 * Copyright 2020 Lawrence Livermore National Security, LLC
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

#include <unistd.h> /* setresuid(2), setresgid(2) */
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#include "imp_log.h"

/*
 *  Switch process to new UID/GID with supplementary group initialization
 *   etc.
 */
void imp_switch_user (uid_t uid)
{
    gid_t gid = -1;
    const char *user = NULL;

    struct passwd *pwd = getpwuid (uid);
    if (!pwd)
        imp_die (1, "lookup userid=%ld failed: %s",
                     (long) uid,
                     strerror (errno));

    user = pwd->pw_name;
    gid = pwd->pw_gid;

    /*  Initialize groups from /etc/group */
    if (initgroups (user, gid) < 0)
        imp_die (1, "initgroups");

    /*  Set saved, effective, and real gids/uids */
    if (setresgid (gid, gid, gid) < 0)
        imp_die (1, "setresgid");
    if (setresuid (uid, uid, uid) < 0)
        imp_die (1, "setresuid");

    /*  Verify privilege cannot be restored */
    if (setreuid (-1, 0) == 0)
        imp_die (1, "irreversible switch to uid %ld failed",
                 (long) uid);
}

/*
 * vi: ts=4 sw=4 expandtab
 */

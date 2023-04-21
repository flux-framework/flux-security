/************************************************************\
 * Copyright 2020 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

/* flux-imp kill - signal tasks on behalf of requestor when authorized
 *
 * PURPOSE:
 *
 *  Allow a non-privileged Flux instance to signal processes in
 *  jobs running as different users.
 *
 * OPERATION:
 *
 *  The IMP kill command currently works under the assumption that the
 *  multiuser instance is running under systemd with Delegate=yes. This
 *  setting directs systemd to delegate ownership of the flux.service
 *  cgroup to the user under which Flux is runnng, e.g. "flux".
 *
 *  Since all Flux jobs will be executed within this cgroup or a child,
 *  flux-imp kill may authorize signal delivery to any task where
 *  the task's cgroup is owned by the requesting user.
 *
 *  These assumptions hold even if Flux is using a systemd user instance
 *  to launch multi-user jobs, since the systemd instance spawning jobs
 *  will also be running under a delegated cgroup.
 *
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <ctype.h>

#include <pwd.h>
#include <signal.h>

#include "src/libutil/kv.h"
#include "src/libutil/strlcpy.h"

#include "imp_log.h"
#include "imp_state.h"
#include "impcmd.h"
#include "privsep.h"
#include "pidinfo.h"

/*  Return true if the user executing the IMP is allowed to run
 *   'flux-imp kill'. This is the same set of users allowed to run
 *   'flux-imp exec', so look in exec.allowed-users.
 */
static bool imp_kill_allowed (const cf_t *conf)
{
    struct passwd * pwd = getpwuid (getuid ());
    const cf_t *exec = cf_get_in (conf, "exec");

    if (pwd && exec)
        return cf_array_contains (cf_get_in (exec, "allowed-users"),
                                  pwd->pw_name);
    return false;
}

static void check_and_kill_process (struct imp_state *imp, pid_t pid, int sig)
{
    uid_t user = getuid ();
    struct pid_info *p = NULL;

    if (!imp_kill_allowed (imp->conf))
        imp_die (1, "kill command not allowed");

    if (!(p = pid_info_create ((pid_t) pid)))
        imp_die (1, "kill: failed to initialize pid info: %s",
                    strerror (errno));
    if (sig == 0) {
        printf ("pid=%ju owner=%ju cg_path=%s cg_owner=%ju",
                 (uintmax_t) pid,
                 (uintmax_t) p->pid_owner,
                 p->cg_path,
                 (uintmax_t) p->cg_owner);
        pid_info_destroy (p);
        return;
    }

    /* Check if pid is in pids cgroup owned by IMP user */
    if (p->cg_owner != user
        && p->pid_owner != user)
        imp_die (1,
            "kill: refusing request from uid=%ju to kill pid %jd (owner=%ju)",
            (uintmax_t) user,
            (intmax_t) pid,
            (uintmax_t) p->cg_owner);

    /*  If pid is owned by root and is a flux-imp process, then deliver
     *   signal to child process instead (presumably a job shell)
     */
    if (p->pid_owner == 0
        && strcmp (p->command, "flux-imp") == 0) {
        int count = pid_kill_children (pid, sig);
        if (count < 0)
            imp_die (1,
                     "kill: failed to signal flux-imp children: %s",
                     strerror (errno));
        else if (count == 0)
            imp_die (1, "kill: killed 0 flux-imp children");
    }
    else if (kill (pid, sig) < 0)
        imp_die (1, "kill: %jd sig=%ju: %s",
                    (intmax_t) pid,
                    (uintmax_t) sig,
                    strerror (errno));

    pid_info_destroy (p);
}


/*  Read pid and signal from the privsep pipe, then check if user
 *   is allowed to kill the target process.
 */
int imp_kill_privileged (struct imp_state *imp, struct kv *kv)
{
    int64_t pid;
    int64_t signum;

    if (kv_get (kv, "pid", KV_INT64, &pid) < 0)
        imp_die (1, "kill: failed to get pid");
    if (kv_get (kv, "signal", KV_INT64, &signum) < 0)
        imp_die (1, "kill: failed to get signal");

    check_and_kill_process (imp, pid, signum);
    return 0;
}

/*  Unprivileged process reads signal and pid from cmdline and
 *   sends to parent over privsep pipe. If not running privileged,
 *   try killing as requesting user (used for testing).
 */
int imp_kill_unprivileged (struct imp_state *imp, struct kv *kv)
{
    char *p = NULL;
    int64_t pid = 0;
    int64_t signum = -1;

    if (imp->argc < 4)
        imp_die (1, "kill: Usage flux-imp kill SIGNAL PID");

    errno = 0;
    if ((signum = strtol (imp->argv[2], &p, 10)) < 0
        || errno != 0
        || *p != '\0')
        imp_die (1, "kill: invalid SIGNAL %s", imp->argv[2]);

    /*  PID of 0 is explicitly forbidden here as it could be used
     *   to inadvertently kill our parent.
     */
    if ((pid = strtol (imp->argv[3], &p, 10)) == 0
        || *p != '\0')
        imp_die (1, "kill: invalid PID %s", imp->argv[3]);

    if (kv_put (kv, "pid", KV_INT64, pid) < 0)
        imp_die (1, "kill: kv_put pid: %s", strerror (errno));
    if (kv_put (kv, "signal", KV_INT64, signum) < 0)
        imp_die (1, "kill: kv_put signum: %s", strerror (errno));

    if (!imp->ps)
        check_and_kill_process (imp, pid, signum);
    else if (privsep_write_kv (imp->ps, kv) < 0)
        imp_die (1, "kill: failed to communicate with privsep parent");

    return 0;
}

/* vi: ts=4 sw=4 expandtab
 */

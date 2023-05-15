/************************************************************\
 * Copyright 2023 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#ifndef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "src/libutil/argsplit.h"
#include "safe_popen.h"
#include "imp_log.h"

struct safe_popen {
    pid_t pid;
    FILE *fp;
};

void safe_popen_destroy (struct safe_popen *sp)
{
    if (sp) {
        int saved_errno = errno;
        fclose (sp->fp);
        free (sp);
        errno = saved_errno;
    }
}

struct safe_popen * safe_popen (const char *cmd)
{
    struct safe_popen *sp;
    int pfds[2] = {-1, -1};

    if (cmd == NULL || strlen (cmd) == 0) {
        errno = EINVAL;
        return NULL;
    }

    if (!(sp = calloc (1, sizeof (*sp)))
        || pipe (pfds) < 0
        || !(sp->fp = fdopen (pfds[0], "r"))
        || (sp->pid = fork ()) < 0) {
        imp_warn ("Failed to setup child for popen: %s", strerror (errno));
        goto error;
    }

    if (sp->pid == 0) {
        /*  Child process: Use pfds[1] as stdout
         */
        char **argv = argsplit (cmd);
        if (!argv) {
            fprintf (stderr, "imp: popen: failed to tokenize '%s'\n", cmd);
            _exit (126);
        }
        if (dup2 (pfds[1], STDOUT_FILENO) < 0) {
            fprintf (stderr, "imp: popen: dup2: %s\n", strerror (errno));
            _exit (126);
        }
        (void) close (pfds[0]);
        (void) close (pfds[1]);
        setsid ();
        execvp (argv[0], argv);
        fprintf (stderr, "imp: popen: %s: %s\n", argv[0], strerror (errno));
        if (errno == ENOENT)
            _exit (127);
        _exit (126);
    }

    /* Parent
     */
    (void) close (pfds[1]);

    return sp;
error:
    safe_popen_destroy (sp);
    if (pfds[0] > 0) {
        (void) close (pfds[0]);
        (void) close (pfds[1]);
    }
    return NULL;
}

FILE *safe_popen_fp (struct safe_popen *sp)
{
    if (!sp || !sp->fp) {
        errno = EINVAL;
        return NULL;
    }
    return sp->fp;
}

int safe_popen_wait (struct safe_popen *sp, int *statusp)
{
    pid_t pid;

    if (!sp || sp->pid <= (pid_t) 0) {
        errno = EINVAL;
        return -1;
    }
    do {
        pid = waitpid (sp->pid, statusp, 0);
    } while (pid == -1 && errno == EINTR);

    return pid == -1 ? -1 : 0;
}

/* vi: ts=4 sw=4 expandtab
 */

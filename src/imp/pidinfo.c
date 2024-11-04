/************************************************************\
 * Copyright 2022 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

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
#include <stdbool.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <signal.h>

#include "pidinfo.h"
#include "imp_log.h"

static int parse_pid (const char *s, pid_t *ppid)
{
    unsigned long val;
    char *endptr;

    if (s == NULL || *s == '\0') {
        errno = EINVAL;
        return -1;
    }

    errno = 0;
    val = strtoul (s, &endptr, 10);

    if (errno != 0 && (val == 0 || val == ULONG_MAX))
        return -1;

    if ((*endptr != '\0' && *endptr != '\n') || endptr == s) {
        errno = EINVAL;
        return -1;
    }

    *ppid = (pid_t) val;
    return 0;
}

static pid_t pid_ppid (pid_t pid)
{
    char path [64];
    char *line = NULL;
    const int len = sizeof (path);
    int n;
    size_t size = 0;
    FILE *fp = NULL;
    pid_t ppid = -1;
    int saved_errno;

    /*  /proc/%ju/status is guaranteed to fit in 64 bytes
     */
    (void) snprintf (path, len, "/proc/%ju/status", (uintmax_t) pid);
    if (!(fp = fopen (path, "r")))
        return (pid_t) -1;

    while ((n = getline (&line, &size, fp)) >= 0) {
        if (strncmp (line, "PPid:", 5) == 0) {
            char *p = line + 5;
            while (isspace (*p))
                ++p;
            if (parse_pid (p, &ppid) < 0)
                imp_warn ("parse_pid (%s): %s", p, strerror (errno));
            break;
        }
    }
    saved_errno = errno;
    free (line);
    fclose (fp);
    errno = saved_errno;
    return ppid;
}

int pid_kill_children_fallback (pid_t parent, int sig)
{
    int count = 0;
    int rc = 0;
    int saved_errno = 0;
    DIR *dirp = NULL;
    struct dirent *dent;
    pid_t pid;
    pid_t ppid;

    if (parent <= (pid_t) 0 || sig < 0) {
        errno = EINVAL;
        return -1;
    }

    if (!(dirp = opendir ("/proc")))
        return -1;

    while ((dent = readdir (dirp))) {
        if (parse_pid (dent->d_name, &pid) < 0)
            continue;
        if ((ppid = pid_ppid (pid)) < 0) {
            /* ENOENT is an expected error since a process on the system
             *  could have exited between when we read the /proc dirents
             *  and when we are checking for /proc/PID/status.
             */
            if (errno != ENOENT) {
                saved_errno = errno;
                rc = -1;
                imp_warn ("Failed to get ppid of %lu: %s\n",
                          (unsigned long) pid,
                          strerror (errno));

            }
            continue;
        }
        if (ppid != parent)
            continue;
        if (kill (pid, sig) < 0) {
            saved_errno = errno;
            rc = -1;
            imp_warn ("Failed to send signal %d to pid %lu: %s\n",
                      sig,
                      (unsigned long) pid,
                      strerror (errno));
            continue;
        }
        count++;
    }
    closedir (dirp);
    if (rc < 0 && count == 0) {
        count = -1;
        errno = saved_errno;
    }
    return count;
}

int pid_kill_children (pid_t pid, int sig)
{
    int count = 0;
    int rc = 0;
    int saved_errno = 0;
    char path [128];
    FILE *fp;
    unsigned long child;

    if (pid <= (pid_t) 0 || sig < 0) {
        errno = EINVAL;
        return -1;
    }

    (void) snprintf (path, sizeof (path),
                    "/proc/%ju/task/%ju/children",
                    (uintmax_t) pid,
                    (uintmax_t) pid);

    if (!(fp = fopen (path, "r"))) {
        if (errno == ENOENT)
            return pid_kill_children_fallback (pid, sig);
        return -1;
    }
    while (fscanf (fp, " %lu", &child) == 1) {
        if (kill ((pid_t) child, sig) < 0) {
            saved_errno = errno;
            rc = -1;
            imp_warn ("Failed to send signal %d to pid %lu",
                      sig,
                      child);
            continue;
        }
        count++;
    }
    fclose (fp);
    if (rc < 0 && count == 0) {
        count = -1;
        errno = saved_errno;
    }
    return count;
}

/* vi: ts=4 sw=4 expandtab
 */

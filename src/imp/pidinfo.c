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
#include <sys/vfs.h>
#ifdef HAVE_LINUX_MAGIC_H
#include <linux/magic.h>
#endif
#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0x01021994 /* from linux/magic.h */
#endif
#ifndef CGROUP_SUPER_MAGIC
#define CGROUP_SUPER_MAGIC 0x27e0eb
#endif

#include <pwd.h>
#include <signal.h>

#include "src/libutil/strlcpy.h"

#include "pidinfo.h"
#include "imp_log.h"

struct cgroup_info {
    char mount_dir[PATH_MAX + 1];
    bool unified;
};

/*  Determine if this system is using the unified (v2) or legacy (v1)
 *   cgroups hierarchy (See https://systemd.io/CGROUP_DELEGATION/)
 *   and mount point for systemd managed cgroups.
 */
static int cgroup_info_init (struct cgroup_info *cg)
{
    struct statfs fs;

    (void) strlcpy (cg->mount_dir, "/sys/fs/cgroup", sizeof (cg->mount_dir));
    cg->unified = true;

    if (statfs (cg->mount_dir, &fs) < 0)
        return -1;

#ifdef CGROUP2_SUPER_MAGIC
    /* if cgroup2 fs mounted: unified hierarchy for all users of cgroupfs
     */
    if (fs.f_type == CGROUP2_SUPER_MAGIC)
        return 0;
#endif /* CGROUP2_SUPER_MAGIC */

    /*  O/w, if /sys/fs/cgroup is mounted as tmpfs, we need to check
     *   for /sys/fs/cgroup/systemd mounted as cgroupfs (legacy).
     *   We do not support hybrid mode (/sys/fs/cgroup/systemd or
     *   /sys/fs/cgroup/unified mounted as cgroup2fs), since there were
     *   no systems on which to test this configuration.
     */
    if (fs.f_type == TMPFS_MAGIC) {

        (void) strlcpy (cg->mount_dir,
                        "/sys/fs/cgroup/systemd",
                        sizeof (cg->mount_dir));
        if (statfs (cg->mount_dir, &fs) == 0
            && fs.f_type == CGROUP_SUPER_MAGIC) {
            cg->unified = false;
            return 0;
            }
    }

    /*  Unable to determine cgroup mount point and/or unified vs legacy */
    return -1;
}


/*  Store the command name from /proc/PID/comm into buffer 'buf' of size 'len'.
 */
static int pid_command (pid_t pid, char *buf, int len)
{
    int rc = -1;
    FILE *fp = NULL;
    int n;
    size_t size = 0;
    char *line = NULL;
    char file [64];
    int saved_errno;

    if (buf == NULL || len <= 0) {
        errno = EINVAL;
        return -1;
    }

    /*  64 bytes is guaranteed to hold /proc/%ju/comm, assuming largest
     *   unsigned integer pid would be 21 characters (2^64-1) + 11 characters
     *   for "/proc/" + "/comm" + some slack.
     */
    (void) snprintf (file, sizeof (file), "/proc/%ju/comm", (uintmax_t) pid);

    if (!(fp = fopen (file, "r")))
        return -1;
    if (getline (&line, &size, fp) < 0)
        goto out;
    if ((n = strlen (line)) > len) {
        errno = ENOSPC;
        goto out;
    }
    /*
     *  Remove trailing newline and copy command into destination buffer.
     *   No need to check return code since size of destination was already
     *   checked above.
     */
    if (line[n-1] == '\n')
        line[n-1] = '\0';
    (void) strlcpy (buf, line, len);

    rc = 0;
out:
    saved_errno = errno;
    free (line);
    fclose (fp);
    errno = saved_errno;
    return rc;
}

/*
 *  Looks up the 'name=systemd'[*] subsystem relative cgroup path in
 *   /proc/PID/cgroups and prepends `cgroup_mount_dir` to get the
 *   full path.
 *
 *  [*] perhaps could also use the "pids" cgroup.
 */
static int pid_systemd_cgroup_path (pid_t pid, char *buf, int len)
{
    int rc = -1;
    FILE *fp;
    size_t size = 0;
    int n;
    char file [64];
    char *line = NULL;
    struct cgroup_info cgroup;
    int saved_errno;

    if (cgroup_info_init (&cgroup) < 0)
        return -1;

    /*  64 bytes is guaranteed to hold /proc/%ju/comm, assuming largest
     *   unsigned integer pid would be 21 characters (2^64-1) + 13 characters
     *   for "/proc/" + "/cgroup" + some slack.
     */
    (void) snprintf (file, sizeof (file), "/proc/%ju/cgroup", (uintmax_t) pid);
    if (!(fp = fopen (file, "r")))
        return -1;

    while ((n = getline (&line, &size, fp)) >= 0) {
        char *nl;
        char *relpath = NULL;
        char *subsys = strchr (line, ':');
        if ((nl = strchr (line, '\n')))
            *nl = '\0';
        if (subsys == NULL || *(++subsys) == '\0'
            || !(relpath = strchr (subsys, ':')))
            continue;
        /* Nullify subsys, relpath is already nul-terminated at newline */
        *(relpath++) = '\0';
        if (cgroup.unified || strcmp (subsys, "name=systemd") == 0) {
            n = snprintf (buf, len, "%s%s", cgroup.mount_dir, relpath);
            if ((n > 0) && (n < len))
                rc = 0;
            break;
        }
    }

    if (rc < 0)
        errno = ENOENT;

    saved_errno = errno;
    free (line);
    fclose (fp);
    errno = saved_errno;
    return rc;
}

/*  return the file owner of 'path'
 */
static uid_t path_owner (const char *path)
{
    struct stat st;
    if (stat (path, &st) < 0)
        return ((uid_t) -1);
    return st.st_uid;
}

/*  return the owner of pid. -1 on failure.
 */
static uid_t pid_owner (pid_t pid)
{
    char path [64];

    /*  /proc/%ju is guaranteed to fit in 64 bytes:
     */
    (void) snprintf (path, sizeof (path), "/proc/%ju", (uintmax_t) pid);
    return path_owner (path);
}

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

void pid_info_destroy (struct pid_info *pi)
{
    if (pi) {
        int saved_errno = errno;
        free (pi);
        errno = saved_errno;
    }
}

struct pid_info *pid_info_create (pid_t pid)
{
    struct pid_info *pi;

    if (pid == 0) {
        errno = EINVAL;
        return NULL;
    }
    if (!(pi = calloc (1, sizeof (*pi))))
        return NULL;
    if (pid < 0)
        pid = -pid;
    pi->pid = pid;
    if ((pi->pid_owner = pid_owner (pid)) == (uid_t) -1)
        goto err;
    if (pid_systemd_cgroup_path (pid, pi->cg_path, sizeof (pi->cg_path)) < 0)
        goto err;
    if ((pi->cg_owner = path_owner (pi->cg_path)) == (uid_t) -1)
        goto err;
    if (pid_command (pid, pi->command, sizeof (pi->command)) < 0)
        goto err;
    return pi;
err:
    pid_info_destroy (pi);
    return NULL;
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

/************************************************************\
 * Copyright 2021 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */
#include <stdio.h>
#include <libgen.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "path.h"
#include "strlcpy.h"

static void __attribute__ ((format (printf, 2, 3)))
errprintf (struct path_error *error, const char *fmt, ...)
{
    va_list ap;
    int saved_errno = errno;

    if (error) {
        memset (error, 0, sizeof (*error));
        va_start (ap, fmt);
        (void)vsnprintf (error->text, sizeof (error->text), fmt, ap);
        va_end (ap);
    }
    errno = saved_errno;
}

static bool parent_dir_is_secure (const char *path,
                                  struct path_error *error)
{
    struct stat st;
    char buf [PATH_MAX + 1];
    char *dir;

    if (strlcpy (buf, path, sizeof (buf)) >= sizeof (buf)
        || !(dir = dirname (buf))) {
        errno = ENAMETOOLONG;
        errprintf (error, "Unable to get dirname");
        return false;
    }
    if (lstat (dir, &st) < 0) {
        errprintf (error, "Unable to stat parent directory");
        return false;
    }
    if (!S_ISDIR (st.st_mode)) {
        errprintf (error,
                   "Unable to check parent directory. Unexpected file type");
        errno = EINVAL;
        return false;
    }
    if ((st.st_uid != 0)
        && (st.st_uid != geteuid ())) {
        errprintf (error,
                   "Invalid ownership on parent directory");
        errno = EINVAL;
        return false;
    }
    if (st.st_gid != 0
        && st.st_gid != getegid ()
        && (st.st_mode & S_IWGRP)
        && !(st.st_mode & S_ISVTX)) {
        errprintf (error,
                   "parent directory is group-writable without sticky bit");
        errno = EINVAL;
        return false;
    }
    if ((st.st_mode & S_IWOTH)
        && !(st.st_mode & S_ISVTX)) {
        errprintf (error,
                   "parent directory is world-writable without sticky bit");
        errno = EINVAL;
        return false;
    }
    errno = 0;
    return true;
}

bool path_is_secure (const char *path, struct path_error *error)
{
    int is_symlink = 0;
    struct stat st;

    if ((path == NULL) || (*path == '\0')) {
        errprintf (error, "Filename not defined");
        return false;
    }
    if ((lstat (path, &st) == 0) && S_ISLNK (st.st_mode) == 1)
        is_symlink = 1;
    if (stat (path, &st) < 0) {
        errprintf (error, "%s", strerror (errno));
        return false;
    }
    if (!S_ISREG (st.st_mode)) {
        errprintf (error, "File is not a regular file");
        errno = EINVAL;
        return false;
    }
    if (is_symlink) {
        errprintf (error, "symbolic link");
        errno = EINVAL;
        return false;
    }
    if (st.st_uid != 0 && st.st_uid != geteuid ()) {
        errprintf (error, "insecure file ownership");
        errno = EINVAL;
        return false;
    }
    if ((st.st_mode & S_IWOTH)
        || ((st.st_mode & S_IWGRP) && (st.st_gid != getegid ()))) {
        errprintf (error,
                   "bad file permissions (%04o)",
                   (st.st_mode & ~S_IFMT));
        errno = EINVAL;
        return false;
    }
    return parent_dir_is_secure (path, error);
}


/* vi: ts=4 sw=4 expandtab
 */

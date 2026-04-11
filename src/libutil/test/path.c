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
#include "config.h"
#endif
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


#include "src/libtap/tap.h"
#include "path.h"

static void
create_test_dir (const char *dir, char *prefix, char *path, size_t pathlen)
{
    snprintf (path, pathlen, "%s/%s.XXXXXX", dir ? dir : "/tmp", prefix);
    if (!mkdtemp (path))
        BAIL_OUT ("mkdtemp: %s: %s", path, strerror (errno));
}

static void
create_test_file (const char *dir, char *prefix, char *path, size_t pathlen,
                  const char *contents)
{
    int fd;
    snprintf (path, pathlen, "%s/%s.XXXXXX.toml", dir ? dir : "/tmp", prefix);
    fd = mkstemps (path, 5);
    if (fd < 0)
        BAIL_OUT ("mkstemp %s: %s", path, strerror (errno));
    if (write (fd, contents, strlen (contents)) != strlen (contents))
        BAIL_OUT ("write %s: %s", path, strerror (errno));
    if (close (fd) < 0)
        BAIL_OUT ("close %s: %s", path, strerror (errno));
}

void test_path_is_secure (void)
{
    char dir[PATH_MAX + 1];
    char path[PATH_MAX + 1 + 10];  /* padding for "/bad1.toml" */
    char spath[PATH_MAX + 1];
    struct path_error error;

    create_test_dir (getenv ("TMPDIR"), "cf-test", dir, sizeof (dir));
    snprintf (path, sizeof (path), "%s/bad1.toml", dir);

    memset (&error, 0, sizeof (error));

    /*  Test non-regular file */
    if (mknod (path, S_IFIFO|0700, 0) < 0)
        BAIL_OUT ("mknod: %s: %s", path, strerror (errno));
    ok (!path_is_secure (path, &error) && errno == EINVAL,
        "path_is_secure fails on non-regular file: %s",
        error.text);
    if (unlink (path) < 0)
        BAIL_OUT ("unlink %s: %s", path, strerror (errno));

    /*  Test symlink */
    memset (&error, 0, sizeof (error));
    create_test_file (getenv ("TMPDIR"), "linky", spath, sizeof (spath), "foo");

    if (symlink (spath, path) < 0)
        BAIL_OUT ("link %s %s: %s", spath, path, strerror (errno));
    ok (!path_is_secure (path, &error) && errno == EINVAL,
        "path_is_secure fails on symlink: %s",
        error.text);
    if (unlink (path) < 0)
        BAIL_OUT ("unlink %s: %s", path, strerror (errno));
    if (unlink (spath) < 0)
        BAIL_OUT ("unlink %s: %s", path, strerror (errno));

    /*  Test ok permissions */
    memset (&error, 0, sizeof (error));
    create_test_file (dir, "good", path, sizeof (path), "bar");
    if (chmod (path, 0600) < 0)
        BAIL_OUT ("chmod %s: %s", path, strerror (errno));
    ok (path_is_secure (path, &error),
        "path_is_secure works on file with perms 0600");

    /*  Test bad permissions */
    memset (&error, 0, sizeof (error));
    if (chmod (path, 0646) < 0)
        BAIL_OUT ("chmod %s: %s", path, strerror (errno));
    ok (!path_is_secure (path, &error) && errno == EINVAL,
        "path_is_secure fails on world writable file: %s",
        error.text);

    if (unlink (path) < 0)
        BAIL_OUT ("unlink %s: %s", path, strerror (errno));
    if (rmdir (dir) < 0)
        BAIL_OUT ("rmdir %s: %s", path, strerror (errno));
}

static void test_bad_params ()
{
    ok (!path_is_secure (NULL, NULL),
        "path_is_secure() fails on NULL path");
    ok (!path_is_secure ("", NULL),
        "path_is_secure() fails on empty path");
    ok (!path_is_secure ("/noexist", NULL),
        "path_is_secure() fails on nonexistent path");
}

int main (int argc, char *argv[])
{
    plan (NO_PLAN);

    test_bad_params ();
    test_path_is_secure ();

    done_testing ();
}

/*
 * vi: ts=4 sw=4 expandtab
 */

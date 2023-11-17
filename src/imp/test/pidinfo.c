/************************************************************\
 * Copyright 2022 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>

#include "pidinfo.h"

#include "src/libtap/tap.h"

static pid_t testchild_create (int nchildren)
{
    int pfd[2];
    pid_t pid;
    char c;

    if (pipe (pfd) < 0)
        BAIL_OUT ("pipe: %s", strerror (errno));

    pid = fork ();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        pid_t cpid[nchildren];

        /* Child must also have some children */
        int status;
        int exitcode = 4;

        /*  Close parent end of pipe */
        close (pfd[0]);

        /*  Close stderr/out to avoid confusing libtap */
        close (STDERR_FILENO);
        close (STDOUT_FILENO);

        for (int i = 0; i < nchildren; i++) {
            cpid[i] = fork ();
            if (cpid[i] < 0)
                exit (2);
            if (cpid[i] == 0) {
                close (pfd[1]);
                pause ();
                exit (1);
            }

        }
        alarm (5);
        /*  Close child end of pipe */
        close (pfd[1]);
        for (int i = 0; i < nchildren; i++) {
            int code = -1;
            if (waitpid (cpid[i], &status, 0) < 0)
                exit (3);
            if (WIFEXITED (status))
                code = WEXITSTATUS (status);
            else if (WIFSIGNALED (status))
                code = WTERMSIG (status) + 128;
            if (code > exitcode)
                exitcode = code;
        }
        exit (exitcode);
    }
    close (pfd[1]);

    /* block until children close pipe */
    if (read (pfd[0], &c, 1) != 0)
        BAIL_OUT ("read from child pipe failed: %s", strerror (errno));
    close (pfd[0]);
    return pid;
}

static void pid_kill_tests (void)
{
    pid_t pid;
    int status;

    errno = 0;
    ok (pid_kill_children (-1, 0) < 0 && errno == EINVAL,
        "pid_kill_children with invalid args returns EINVAL: got %d", errno);
    errno = 0;
    ok (pid_kill_children_fallback (-1, 0) < 0 && errno == EINVAL,
        "pid_kill_children_fallback with invalid args returns EINVAL");

    /*  pid_kill_children(): 1 child per test-child */
    if ((pid = testchild_create (1)) < 0)
        BAIL_OUT ("testchild_create failed!");

    diag ("created test child %d", (int) pid);

    ok (pid_kill_children (pid, SIGTERM) == 1,
        "pid_kill_children %d returned 1", (int) pid);
    ok (waitpid (pid, &status, 0) == pid,
        "waitpid returned %d",
        pid);
    ok (WIFEXITED (status) && WEXITSTATUS (status) == SIGTERM + 128,
        "child exited with 128 + SIGTERM");

    /*  pid_kill_children(): 3 children per test-child */
    if ((pid = testchild_create (3)) < 0)
        BAIL_OUT ("testchild_create failed!");

    diag ("created test child %d", (int) pid);

    ok (pid_kill_children (pid, SIGTERM) == 3,
        "pid_kill_children %d returned 3", (int) pid);
    ok (waitpid (pid, &status, 0) == pid,
        "waitpid returned %d",
        pid);
    ok (WIFEXITED (status) && WEXITSTATUS (status) == SIGTERM + 128,
        "child exited with 128 + SIGTERM");

    /*  pid_kill_children_fallback(): 1 child per test-child */
    if ((pid = testchild_create (1)) < 0)
        BAIL_OUT ("testchild_create failed!");

    ok (pid_kill_children_fallback (pid, SIGTERM) == 1,
        "pid_kill_children_fallback (%d) returned 1", (int) pid);
    ok (waitpid (pid, &status, 0) == pid,
        "waitpid returned %d",
        pid);
    ok (WIFEXITED (status) && WEXITSTATUS (status) == SIGTERM + 128,
        "child exited with 128 + SIGTERM");

    /*  pid_kill_children_fallback(): 3 children per test-child */
    if ((pid = testchild_create (3)) < 0)
        BAIL_OUT ("testchild_create failed!");

    ok (pid_kill_children_fallback (pid, SIGTERM) == 3,
        "pid_kill_children_fallback (%d) returned 3", (int) pid);
    ok (waitpid (pid, &status, 0) == pid,
        "waitpid returned %d",
        pid);
    ok (WIFEXITED (status) && WEXITSTATUS (status) == SIGTERM + 128,
        "child exited with 128 + SIGTERM");

}

int main (void)
{
    struct pid_info *p;

    ok (pid_info_create (0) == NULL && errno == EINVAL,
        "pid_info_create (0) fails with EINVAL");

    ok ((p = pid_info_create (getpid ())) != NULL,
        "pid_info_create (getpid ()) works");
    ok (p->pid == getpid (),
        "p->pid is expected");
    ok (p->pid_owner == getuid (),
        "p->pid_owner is expected");
    diag ("p->cg_path = %s", p->cg_path);
    diag ("p->cg_owner = %d", (int) p->cg_owner);
    pid_info_destroy (p);

    ok ((p = pid_info_create (-getpid ())) != NULL,
        "pid_info_create (-getpid ()) works");
    ok (p->pid == getpid (),
        "p->pid is expected");
    ok (p->pid_owner == getuid (),
        "p->pid_owner is expected");
    diag ("p->cg_path = %s", p->cg_path);
    diag ("p->cg_owner = %d", (int) p->cg_owner);
    pid_info_destroy (p);

    pid_kill_tests ();

    done_testing ();
}

/*
 * vi: ts=4 sw=4 expandtab
 */

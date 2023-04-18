/************************************************************\
 * Copyright 2017 Lawrence Livermore National Security, LLC
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

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

/*  Max size of KV array allowed to be sent over privsep pipe */
#define PRIVSEP_MAX_KVLEN 1024*1024*4

#include "privsep.h"
#include "imp_log.h"

struct privsep {
    bool enabled;

    pid_t cpid;    /* unprivileged child pid */
    pid_t ppid;    /* privileged parent pid  */

    int upfds[2];  /* unpriv child pipefds (cpfd[0] is child read fd)      */
    int ppfds[2];  /* priv parent pipefds (ppfd[0] is priv parent read fd) */

    int wfd;       /* Copy of current process' write fd */
    int rfd;       /* Copy of current process' read fd  */
};

static int wakeup_child (privsep_t *ps)
{
    char c = 0;
    assert (privsep_is_parent (ps));
    if (write (ps->wfd, &c, sizeof (c)) != sizeof (c))
        return (-1);
    return (0);
}

static int wait_for_parent (privsep_t *ps)
{
    char c;
    assert (privsep_is_child (ps));
    if (read (ps->rfd, &c, sizeof (c)) != sizeof (c))
        return (-1);
    return (0);
}

void drop_privileges ()
{
    uid_t ruid = -1, euid, suid;
    gid_t rgid = -1, egid, sgid;

    if (  (getresuid (&ruid, &euid, &suid) < 0)
       || (getresgid (&rgid, &egid, &sgid) < 0))
        imp_die (1, "getresuid/getresgid");

    if (setresgid (rgid, rgid, rgid) < 0)
        imp_die (1, "setresgid");
    if (setresuid (ruid, ruid, ruid) < 0)
        imp_die (1, "setresuid");

     /*  Verify privilege cannot be restored */
    if (setreuid (-1, 0) == 0)
        imp_die (1, "irreversible switch to uid %ju failed", (uintmax_t) ruid);
}

static void child_pfds_setup (privsep_t *ps)
{
    /* Set child read and write fds to read end of upfds and
     *  write end of ppfds respectively. Then close fds we don't want
     *  to bother passing to the unprivilged child.
     */
    ps->rfd = ps->upfds[0];
    ps->wfd = ps->ppfds[1];

    close (ps->upfds[1]);
    ps->upfds[1] = -1;
    close (ps->ppfds[0]);
    ps->ppfds[0] = -1;
}

static void parent_pfds_setup (privsep_t *ps)
{
    /* Set parent read and write fds to read end of ppfds and
     *  write end of ppfds respectively. Close fds we no longer need
     *  in parent, since they are only used in the child.
     */
    ps->rfd = ps->ppfds[0];
    ps->wfd = ps->upfds[1];
    close (ps->ppfds[1]);
    ps->ppfds[1] = -1;
    close (ps->upfds[0]);
    ps->upfds[0] = -1;
}

static int
run_unprivileged_child (privsep_t *ps, privsep_child_f fn, void *arg)
{
    if ((ps->cpid = fork ()) < 0) {
        imp_warn ("fork: %s\n", strerror (errno));
        return (-1);
    }

    if (ps->cpid == 0) {
        /* Now drop privileges. This is fatal on error */
        drop_privileges ();
        child_pfds_setup (ps);
        if (wait_for_parent (ps) < 0)
            imp_die (1, "wait_for_parent: %s", strerror (errno));
        fn (ps, arg);
        exit (0);
    }
    /*  Only parent returns from this function */

    parent_pfds_setup (ps);
    return (0);
}

privsep_t * privsep_init (privsep_child_f fn, void *arg)
{
    privsep_t *ps;

    if (geteuid () == getuid () || geteuid() != 0) {
        imp_warn ("privsep_init: called when not setuid");
        errno = EINVAL;
        return (NULL);
    }
    if (!(ps = calloc (1, sizeof (*ps)))) {
        imp_warn ("privsep_init: Out of memory");
        return (NULL);
    }
    ps->ppid = getpid ();
    ps->wfd = -1;
    ps->rfd = -1;

    if (pipe2 (ps->upfds, O_CLOEXEC) < 0
        || pipe2 (ps->ppfds, O_CLOEXEC) < 0) {
        imp_warn ("privsep_init: pipe: %s\n", strerror (errno));
        privsep_destroy (ps);
        return (NULL);
    }

    if (run_unprivileged_child (ps, fn, arg) < 0) {
        privsep_destroy (ps);
        return (NULL);
    }

    if (wakeup_child (ps) < 0) {
        imp_warn ("wakeup_child: %s", strerror (errno));
        privsep_destroy (ps);
        return (NULL);
    }
    return (ps);
}

int privsep_wait (privsep_t *ps)
{
    int status = 0;
    if (privsep_is_parent (ps)) {
        if (ps->cpid > (pid_t) 0) {
            kill (SIGTERM, ps->cpid);
            if (waitpid (ps->cpid, &status, 0) < 0)
                status = -1;
            ps->cpid = (pid_t) -1;
        }
    }
    return (status == 0 ? 0 : -1);
}

void privsep_destroy (privsep_t *ps)
{
    if (ps) {
        if (ps->wfd >= 0)
            close (ps->wfd);
        if (ps->rfd >= 0)
            close (ps->rfd);
        free (ps);
    }
}

bool privsep_is_parent (privsep_t *ps)
{
    return (getpid () == ps->ppid);
}
bool privsep_is_child (privsep_t *ps)
{
    return (getpid () != ps->ppid && ps->cpid == 0);
}

ssize_t privsep_write (privsep_t *ps, const void *buf, size_t count)
{
    const char *p;
    size_t nleft;

    if (!ps || !buf || ps->wfd < 0) {
        errno = EINVAL;
        return (-1);
    }

    p = buf;
    nleft = count;
    while (nleft > 0) {
        ssize_t n = write (ps->wfd, p, nleft);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            else
                return (-1);
        }
        nleft -= n;
        p += n;
    }
    return (count);
}

ssize_t privsep_read (privsep_t *ps, void *buf, size_t count)
{
    char *p;
    size_t nleft;

    if (!ps || !buf || ps->rfd < 0) {
        errno = EINVAL;
        return (-1);
    }

    p = buf;
    nleft = count;
    while (nleft > 0) {
        ssize_t n = read (ps->rfd, p, nleft);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            else
                return (-1);
        }
        else if (n == 0)
            break;

        nleft -= n;
        p += n;
    }
    return (count - nleft);
}

struct kv * privsep_read_kv (privsep_t *ps)
{
    struct kv *kv = NULL;
    char *buf;
    int len;

    /*
     *  First read length of kv that is being sent
     */
    if (privsep_read (ps, &len, sizeof (len)) != sizeof (len))
        return (NULL);

    if (len <= 0 || len > PRIVSEP_MAX_KVLEN) {
        errno = E2BIG;
        return (NULL);
    }

    /*
     *  Allocate buffer big enough to fit incoming kv structure:
     */
    if ((buf = calloc (1, len)) == NULL)
        return (NULL);

    /*
     *  Read all of the new struct kv in raw form
     */
    if (privsep_read (ps, buf, len) < len) {
        int saved_errno = errno;
        free (buf);
        errno = saved_errno;
        return (NULL);
    }

    kv = kv_decode (buf, len);
    free (buf);
    return (kv);
}

ssize_t privsep_write_kv (privsep_t *ps, struct kv *kv)
{
    int n;
    int len;
    const char *buf;

    if (kv_encode (kv, &buf, &len) < 0)
        return (-1);

    if (len <= 0 || len > PRIVSEP_MAX_KVLEN) {
        errno = E2BIG;
        return (-1);
    }

    /*  Write length first */
    if (privsep_write (ps, &len, sizeof (len)) != sizeof (len))
        return (-1);

    /*  Then write encoded kv structure */
    if ((n = privsep_write (ps, buf, len)) != len)
        return (-1);

    return (n);
}

/*
 * vi: ts=4 sw=4 expandtab
 */

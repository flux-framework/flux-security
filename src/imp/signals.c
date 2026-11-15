/************************************************************\
 * Copyright 2024 Lawrence Livermore National Security, LLC
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

#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <poll.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/prctl.h>

#include "src/libutil/macros.h"

#include "signals.h"
#include "pidinfo.h"
#include "imp_log.h"

#if CODE_COVERAGE_ENABLED
void __gcov_dump (void);
#endif

static const struct imp_state *imp_state = NULL;
static volatile sig_atomic_t imp_child = -1;
static volatile sig_atomic_t kill_pending = 0;

/* Signal mask used while waiting in imp_signal_wait(). Forwarded signals
 * and SIGCHLD are only unblocked while waiting, so signal handlers never
 * interrupt other code.
 */
static sigset_t wait_mask;

void imp_set_signal_child (pid_t child)
{
    imp_child = child;
}

void imp_sigblock_all (void)
{
    sigset_t mask;
    sigfillset (&mask);
    if (sigprocmask (SIG_SETMASK, &mask, NULL) < 0)
        imp_die (1, "failed to block signals: %s", strerror (errno));
}

static void reset_ignored_signals (void)
{
    struct sigaction sa;
    int i;

    memset (&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    sa.sa_flags = 0;
    sigemptyset (&sa.sa_mask);

    for (i = 1; i < SIGRTMIN; i++) {
        /* Note: it is expected that some signals will fail sigaction(2)
         * here (e.g. SIGKILL). Just ignore these errors.
         */
        (void) sigaction (i, &sa, NULL);
    }
}

void imp_sigunblock_all (void)
{
    sigset_t mask;
    sigemptyset (&mask);
    if (sigprocmask (SIG_SETMASK, &mask, NULL) < 0)
        imp_die (1, "failed to unblock signals: %s", strerror (errno));

    /* Also need to reset any signals that may be currently ignored
     */
    reset_ignored_signals ();
}

static void kill_container (void)
{
    int count = -1;

    /* RFC 15 specifies that SIGUSR1 is a surrogate for SIGKILL, and
     * that the IMP SHALL deliver the signal to all processes in the
     * job's container (using cgroup.procs if able).
     */
    if (imp_state->cgroup->use_cgroup_kill)
        count = cgroup_kill (imp_state->cgroup, SIGKILL);

    /* If cgroup wasn't used or fails, try with pid_kill_children
     */
    if (count < 0)
        count = pid_kill_children (getpid (), SIGKILL);

    /* O/w, log an error, not much more to do
     */
    if (count < 0)
        imp_warn ("Failed to forward SIGKILL: %s", strerror (errno));
}

/* Only async-signal-safe functions may be called here, so SIGUSR1 is
 * handled by imp_signal_wait() after the handler returns.
 */
static void fwd_signal (int signum)
{
    if (signum == SIGUSR1)
        kill_pending = 1;
    else if (imp_child != -1)
        ERRNO_SAFE_WRAP (kill, imp_child, signum);
}

static void sigchld_handler (int signum __attribute__ ((unused)))
{
    /* Nothing to do. SIGCHLD only needs to interrupt imp_signal_wait() */
}

void imp_setup_signal_forwarding (struct imp_state *imp)
{
    struct sigaction sa;
    int i;
    int signals[] = {
        SIGTERM,
        SIGINT,
        SIGHUP,
        SIGCONT,
        SIGALRM,
        SIGWINCH,
        SIGTTIN,
        SIGTTOU,
        SIGUSR1,
    };
    int nsignals =  sizeof (signals) / sizeof (signals[0]);

    imp_state = imp;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = fwd_signal;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);

    sigfillset (&wait_mask);
    for (i = 0; i < nsignals; i++) {
        sigdelset (&wait_mask, signals[i]);
        if (sigaction(signals[i], &sa, NULL) < 0)
            imp_warn ("sigaction (signal=%d): %s",
                      signals[i],
                      strerror (errno));
    }

    sa.sa_handler = sigchld_handler;
    sigdelset (&wait_mask, SIGCHLD);
    if (sigaction (SIGCHLD, &sa, NULL) < 0)
        imp_warn ("sigaction (SIGCHLD): %s", strerror (errno));

    /* Block all signals outside of imp_signal_wait() */
    imp_sigblock_all ();
}

void imp_sigunblock_forwarded (void)
{
    sigset_t mask = wait_mask;

    sigaddset (&mask, SIGCHLD);
    if (sigprocmask (SIG_SETMASK, &mask, NULL) < 0)
        imp_die (1, "failed to unblock signals: %s", strerror (errno));
}

int imp_signal_wait (double timeout)
{
    struct timespec ts;
    struct timespec *tsp = NULL;
    int rc;

    if (timeout >= 0.) {
        ts.tv_sec = (time_t) timeout;
        ts.tv_nsec = (long) ((timeout - ts.tv_sec) * 1e9);
        tsp = &ts;
    }
    rc = ppoll (NULL, 0, tsp, &wait_mask);
    if (kill_pending) {
        int saved_errno = errno;
        kill_pending = 0;
        kill_container ();
        errno = saved_errno;
    }
    return rc;
}

pid_t imp_waitpid (pid_t pid, int *status)
{
    pid_t rc;

    /* If the child exits after waitpid(2) returns 0, SIGCHLD remains
     * pending and interrupts imp_signal_wait() immediately.
     */
    while ((rc = waitpid (pid, status, WNOHANG)) == 0) {
        if (imp_signal_wait (-1.) < 0 && errno != EINTR)
            return -1;
    }
    /* Child pid may now be reused, so stop forwarding signals to it */
    if (rc == pid)
        imp_set_signal_child (-1);
    return rc;
}

void imp_raise (int sig)
{
    sigset_t mask;

    signal (sig, SIG_DFL);

    /*  sig may be blocked by imp_setup_signal_forwarding(), in which case
     *  raise(3) would leave it pending.
     */
    sigemptyset (&mask);
    sigaddset (&mask, sig);
    (void) sigprocmask (SIG_UNBLOCK, &mask, NULL);

#if CODE_COVERAGE_ENABLED
    /*  Coverage data is normally written at exit, which will not happen
     *  if the IMP is terminated by sig, so write it now.
     */
    __gcov_dump ();
#endif

    /*  sig is the signal that terminated the IMP's child (e.g. the job
     *  shell), so it may be chosen by an unprivileged user. Do not let it
     *  cause the privileged IMP to dump core.
     */
    (void) prctl (PR_SET_DUMPABLE, 0);

    /*  Since sig is unblocked, it is delivered before raise(3) returns.
     *  If we get here, either raise(3) failed or the default action of sig
     *  does not terminate the process. Exit with standard 128+sig.
     */
    (void) raise (sig);
    imp_die (128 + sig, "failed to raise signal %d", sig);
}

/* vi: ts=4 sw=4 expandtab
 */

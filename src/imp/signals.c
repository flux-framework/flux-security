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

#include <signal.h>
#include <errno.h>
#include <string.h>

#include "signals.h"
#include "imp_log.h"

static const struct imp_state *imp_state = NULL;
static pid_t imp_child = (pid_t) -1;

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

void imp_sigunblock_all (void)
{
    sigset_t mask;
    sigemptyset (&mask);
    if (sigprocmask (SIG_SETMASK, &mask, NULL) < 0)
        imp_die (1, "failed to unblock signals: %s", strerror (errno));
}

static void fwd_signal (int signum)
{
    if (imp_child > 0)
        kill (imp_child, signum);
}

void imp_setup_signal_forwarding (struct imp_state *imp)
{
    struct sigaction sa;
    sigset_t mask;
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
    };
    int nsignals =  sizeof (signals) / sizeof (signals[0]);

    imp_state = imp;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = fwd_signal;
    sa.sa_flags = SA_RESTART;
    sigemptyset(&sa.sa_mask);

    sigfillset (&mask);
    for (i = 0; i < nsignals; i++) {
        sigdelset (&mask, signals[i]);
        if (sigaction(signals[i], &sa, NULL) < 0)
            imp_warn ("sigaction (signal=%d): %s",
                      signals[i],
                      strerror (errno));
    }
    if (sigprocmask (SIG_SETMASK, &mask, NULL) < 0)
       imp_die (1, "failed to block signals: %s", strerror (errno));
}

/* vi: ts=4 sw=4 expandtab
 */

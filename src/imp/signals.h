/************************************************************\
 * Copyright 2024 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#ifndef HAVE_IMP_SIGNALS_H
#define HAVE_IMP_SIGNALS_H 1

#include <sys/types.h>
#include "imp_state.h"

/*  Set the target of IMP signal forwarding. `pid` may be less than -1,
 *  in which case the entire process group `-pid` will be signaled.
 *  Set `pid` to -1 to disable forwarding, e.g. once the child is reaped.
 */
void imp_set_signal_child (pid_t pid);

/*  Setup RFC 15 standard IMP signal forwarding. All signals are blocked
 *  on return. Forwarded signals are only delivered in imp_signal_wait().
 */
void imp_setup_signal_forwarding (struct imp_state *imp);

/*  Unblock forwarded signals (but not SIGCHLD) outside of
 *  imp_signal_wait(), e.g. before running helpers that inherit the
 *  signal mask. Must be called after imp_setup_signal_forwarding().
 */
void imp_sigunblock_forwarded (void);

/*  Wait up to timeout seconds (forever if timeout < 0) for a forwarded
 *  signal or SIGCHLD. Must be called after imp_setup_signal_forwarding().
 *  If SIGUSR1 was received, send SIGKILL to all processes in the job's
 *  container before returning. Returns 0 on timeout, or -1 with errno set
 *  to EINTR if interrupted by a signal.
 */
int imp_signal_wait (double timeout);

/*  Like waitpid(2), but deliver forwarded signals while waiting. Once
 *  pid has been reaped, signal forwarding is disabled.
 */
pid_t imp_waitpid (pid_t pid, int *status);

void imp_sigblock_all (void);

void imp_sigunblock_all (void);

/*  Set default signal disposition and then raise signal 'sig'.
 *  If raise fails for any reason, then exit with standard 128+sig.
 */
void imp_raise (int sig) __attribute__ ((noreturn));;

#endif /* !HAVE_IMP_SIGNALS_H */

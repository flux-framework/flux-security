/************************************************************\
 * Copyright 2022 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#ifndef HAVE_PIDINFO_H
#define HAVE_PIDINFO_H 1

/*  Send signal to any children of pid.
 *  Returns the number of children signaled or -1 if an error occurred.
 */
int pid_kill_children (pid_t pid, int sig);

/*  Like pid_kill_children(), but uses fallback mechanism when
 *   /proc/PID/task/PID/children does not exist.
 */
int pid_kill_children_fallback (pid_t parent, int sig);

#endif /* !HAVE_PIDINFO_H */

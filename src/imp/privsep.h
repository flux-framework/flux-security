/************************************************************\
 * Copyright 2017 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#ifndef HAVE_PRIVSEP_H
#define HAVE_PRIVSEP_H 1

#include <stdbool.h>
#include <unistd.h>

#include "src/libutil/kv.h"

typedef struct privsep privsep_t;

typedef void (*privsep_child_f) (privsep_t *ps, void *arg);

/*  Spawn an unprivliged child running child_fn from a setuid program,
 *   connected to the current process with pipes for IPC.
 *
 *  Parent returns valid privsep_t on success, child calls function fn
 *   and does not return.
 */
privsep_t * privsep_init (privsep_child_f fn, void *arg);

/*  If this is the parent process, wait for child to exit.
 *  Returns 0 if child exited normally, -1 if not.
 */
int privsep_wait (privsep_t *ps);

/*  Free memory associated with privsep handle and close associated
 *   file descriptors to parent/child.
 */
void privsep_destroy (privsep_t *ps);

/*  Return true if running in child.
 */
bool privsep_is_child (privsep_t *ps);

/*  Return true if running in parent
 */
bool privsep_is_parent (privsep_t *ps);

/*
 *  Read up to count bytes from privsep connection into buffer buf.
 *  Returns number of bytes read into buf or -1 on error.
 */
ssize_t privsep_read (privsep_t *ps, void *buf, size_t count);

/*
 *  Write count bytes from buf over privsep channel in `ps`.
 *  Returns number of bytes written (always == count) or -1 on failure
 */
ssize_t privsep_write (privsep_t *ps, const void *buf, size_t count);

/*
 *  Write a struct kv over privsep pipe, returning size of the kv
 *   written on success, -1 on failure.
 *
 *  Specific errno values include:
 *    EINVAL  - Invalid argument (bad privsep handle or struct kv)
 *    E2BIG   - Encoded size of kv too large for privsep_write_kv()
 */
ssize_t privsep_write_kv (privsep_t *ps, struct kv *kv);

/*
 *  Read a struct kv from privsep pipe. Returns kv on success or NULL
 *   on failure with errno set.
 *
 *  Specific errno values include:
 *    EINVAL  - Invalid privsep handle
 *    E2BIG   - Remote tried to send kv that was too large
 */
struct kv * privsep_read_kv (privsep_t *ps);

#endif /* !HAVE_PRIVSEP_H */


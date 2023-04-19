/************************************************************\
 * Copyright 2023 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#ifndef HAVE_IMP_EXEC_SAFE_POPEN_H
#define HAVE_IMP_EXEC_SAFE_POPEN_H 1

#include <stdio.h>

struct safe_popen;

/*  Safer and simpler version of popen(3):
 *  - does not invoke shell
 *  - splits `cmd` on whitespace only
 *
 *  Returns a new safe_popen object on success, NULL with errno set
 *   on failure.
 *  EINVAL - cmd is NULL or an empty string.
 *  ENOMEM - out of memory
 */
struct safe_popen *safe_popen (const char *cmd);

/*  Return FILE * associated with safe_popen object */
FILE *safe_popen_fp (struct safe_popen *sp);

/*  Call waitpid(2) on process spawned by safe_popen(), placing process
 *  status in `status` if non-NULL.
 *  Returns 0 on success or -1 with errno set on error.
 *  Special exit codes:
 *   - 127: exec failed to find command
 *   - 126: exec failed for other reason
 *   - 125: internal error in child process before exec
 */
int safe_popen_wait (struct safe_popen *sp, int *status);

/*  Destroy safe_popen object. Close open file descriptor and free
 *   associated memory.
 */
void safe_popen_destroy (struct safe_popen *sp);

#endif /* !HAVE_IMP_EXEC_SAFE_POPEN_H */

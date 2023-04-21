/************************************************************\
 * Copyright 2023 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#ifndef HAVE_ARGSPLIT_H
#define HAVE_ARGSPLIT_H

/*  Split a string on whitespace, returning an array on success.
 *  Caller must free returned arg array, e.g. via args_free() below.
 */
char **argsplit (const char *str);

/*  Convenience function to destroy an allocated array of char *
 */
void args_free (char **args);

#endif /* !HAVE_ARGSPLIT_H */

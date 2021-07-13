/************************************************************\
 * Copyright 2018 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#ifndef _FLUX_SECURITY_CONTEXT_H
#define _FLUX_SECURITY_CONTEXT_H

#ifdef __cplusplus
extern "C" {
#endif

enum {
    FLUX_SECURITY_DISABLE_PATH_PARANOIA     = 0x1,
    FLUX_SECURITY_FORCE_PATH_PARANOIA       = 0x2,
};

typedef struct flux_security flux_security_t;

typedef void (*flux_security_free_f)(void *arg);

flux_security_t *flux_security_create (int flags);
void flux_security_destroy (flux_security_t *ctx);

const char *flux_security_last_error (flux_security_t *ctx);
int flux_security_last_errnum (flux_security_t *ctx);

int flux_security_configure (flux_security_t *ctx, const char *pattern);

int flux_security_aux_set (flux_security_t *ctx, const char *name,
		           void *data, flux_security_free_f freefun);

void *flux_security_aux_get (flux_security_t *ctx, const char *name);

#ifdef __cplusplus
}
#endif

#endif /* !_FLUX_SECURITY_CONTEXT_H */

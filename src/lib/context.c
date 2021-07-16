/************************************************************\
 * Copyright 2018 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include "src/libutil/cf.h"
#include "src/libutil/aux.h"

#include "context.h"
#include "context_private.h"

struct flux_security {
    cf_t *config;
    int flags;
    struct aux_item *aux;
    char error[200];
    int errnum;
};

/* Capture errno in ctx->errno, and an error message in ctx->error.
 * If 'fmt' is non-NULL, build message; otherwise use strerror (errno).
 */
void security_error (flux_security_t *ctx, const char *fmt, ...)
{
    if (ctx) {
        size_t sz = sizeof (ctx->error);
        ctx->errnum = errno;
        if (fmt) {
            va_list ap;
            va_start (ap, fmt);
            vsnprintf (ctx->error, sz, fmt, ap);
            va_end (ap);
        }
        else
            snprintf (ctx->error, sz, "%s", strerror (ctx->errnum));
        errno = ctx->errnum;
    }
}

static bool valid_flags (int flags)
{
    /*  Currently valid flags:
     *   Only one of FLUX_SECURITY_DISABLE_PATH_PARANOIA or
     *   FLUX_SECURITY_FORCE_PATH_PARANOIA may be set at a time.
     *   O/w, flags must be unset.
     */
    if (flags == 0
        || flags == FLUX_SECURITY_DISABLE_PATH_PARANOIA
        || flags == FLUX_SECURITY_FORCE_PATH_PARANOIA)
        return true;
    return false;
}

flux_security_t *flux_security_create (int flags)
{
    flux_security_t *ctx;

    if (!valid_flags (flags)) {
        errno = EINVAL;
        return NULL;
    }
    if (!(ctx = calloc (1, sizeof (*ctx))))
        return NULL;
    ctx->flags = flags;
    return ctx;
}

void flux_security_destroy (flux_security_t *ctx)
{
    if (ctx) {
        aux_destroy (&ctx->aux);
        cf_destroy (ctx->config);
        free (ctx);
    }
}

const char *flux_security_last_error (flux_security_t *ctx)
{
    return (ctx && *ctx->error) ? ctx->error : NULL;
}

int flux_security_last_errnum (flux_security_t *ctx)
{
    return ctx ? ctx->errnum : 0;
}

int flux_security_configure (flux_security_t *ctx, const char *pattern)
{
    struct cf_error cfe;
    int n;
    cf_t *cf = NULL;

    if (!ctx) {
        errno = EINVAL;
        return -1;
    }
    if (!pattern)
        pattern = INSTALLED_CF_PATTERN;
    if (!(cf = cf_create ())) {
        security_error (ctx, NULL);
        return -1;
    }
    fprintf (stderr, "ctx->flags = 0x%x\n", ctx->flags);
    if (((ctx->flags & FLUX_SECURITY_DISABLE_PATH_PARANOIA)
        && cf_update_pack (cf,
                           &cfe,
                           "{s:b}",
                           "disable-path-paranoia", true) < 0)
        || ((ctx->flags & FLUX_SECURITY_FORCE_PATH_PARANOIA)
            && cf_update_pack (cf,
                               &cfe,
                               "{s:b}",
                               "enable-path-paranoia", true) < 0)) {
        security_error (ctx,
                        "%s: failed to apply ctx flags: %s",
                        pattern,
                        cfe.errbuf);
        goto error;

    }
    if ((n = cf_update_glob (cf, pattern, &cfe)) < 0) {
        security_error (ctx, "%s::%d: %s",
                        cfe.filename, cfe.lineno, cfe.errbuf);
        goto error;
    }
    if (n == 0) {
        errno = EINVAL;
        security_error (ctx, "pattern %s matched nothing", pattern);
        goto error;
    }
    cf_destroy (ctx->config);
    ctx->config = cf;
    return 0;
error:
    cf_destroy (cf);
    errno = flux_security_last_errnum (ctx);
    return -1;
}

int flux_security_aux_set (flux_security_t *ctx, const char *name,
                           void *data, flux_security_free_f freefun)
{
    if (!ctx) {
        errno = EINVAL;
        goto error;
    }
    if (aux_set (&ctx->aux, name, data, freefun) < 0)
        goto error;
    return 0;
error:
    security_error (ctx, NULL);
    return -1;
}

void *flux_security_aux_get (flux_security_t *ctx, const char *name)
{
    void *val;

    if (!ctx) {
        errno = EINVAL;
        goto error;
    }
    if (!(val = aux_get (ctx->aux, name)))
        goto error;
    return val;
error:
    security_error (ctx, NULL);
    return NULL;
}

const cf_t *security_get_config (flux_security_t *ctx, const char *key)
{
    const cf_t *cf;

    if (!ctx) {
        errno = EINVAL;
        security_error (ctx, NULL);
        return NULL;
    }
    if (!ctx->config) {
        errno = EINVAL;
        security_error (ctx, "configuration has not been loaded");
        return NULL;
    }
    if (key == NULL)
        cf = ctx->config;
    else if (!(cf = cf_get_in (ctx->config, key))) {
        security_error (ctx, "configuration object '%s' not found", key);
        return NULL;
    }
    return cf;

}

int security_set_config (flux_security_t *ctx, const cf_t *cf)
{
    cf_t *new;
    if (!ctx || !cf) {
        errno = EINVAL;
        security_error (ctx, NULL);
        return (-1);
    }
    if (!(new = cf_copy (cf))) {
        errno = ENOMEM;
        security_error (ctx, "Failed to copy config object");
        return (-1);
    }
    cf_destroy (ctx->config);
    ctx->config = new;
    return (0);
}

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */

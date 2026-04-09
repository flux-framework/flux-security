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
#include <errno.h>
#include <string.h>
#include <munge.h>
#include <assert.h>

#include "src/libutil/sha256.h"

#include "context.h"
#include "context_private.h"
#include "sign.h"
#include "sign_mech.h"

struct sign_munge {
    munge_ctx_t munge;
    int64_t max_ttl;
};

/* Single byte codes to indicate hash type used.
 */
enum {
    HASH_TYPE_INVALID = 0,
    HASH_TYPE_SHA256 = 1,
};

/* [sign.munge] table is optional since it contains
 * only optional keys at this point.
 */
static const struct cf_option munge_opts[] = {
    {"socket-path",     CF_STRING,      false},
    CF_OPTIONS_TABLE_END,
};

static const char *auxname = "flux::sign_munge";

static void sm_destroy (struct sign_munge *sm)
{
    if (sm) {
        int saved_errno = errno;
        if (sm->munge)
            munge_ctx_destroy (sm->munge);
        free (sm);
        errno = saved_errno;
    }
}

static int op_init (flux_security_t *ctx, const cf_t *cf)
{
    struct sign_munge *sm = flux_security_aux_get (ctx, auxname);
    const cf_t *munge_config;
    const char *socket_path = NULL;

    if (sm != NULL)
        return 0;
    if (!(sm = calloc (1, sizeof (*sm))))
        goto error;
    if (!(sm->munge = munge_ctx_create ()))
        goto error;
    if (flux_security_aux_set (ctx, auxname, sm,
                               (flux_security_free_f)sm_destroy) < 0)
        goto error;
    sm->max_ttl = cf_int64 (cf_get_in (cf, "max-ttl"));
    if ((munge_config = cf_get_in (cf, "munge"))) {
        struct cf_error cfe;
        const cf_t *entry;
        if (cf_check (munge_config, munge_opts, CF_STRICT, &cfe) < 0) {
            security_error (ctx, "sign-munge-init: %s", cfe.errbuf);
            goto error_nomsg;
        }
        if ((entry = cf_get_in (munge_config, "socket-path")))
            socket_path = cf_string (entry);
    }
    if (socket_path) {
        munge_err_t e;
        e = munge_ctx_set (sm->munge, MUNGE_OPT_SOCKET, socket_path);
        if (e != EMUNGE_SUCCESS) {
            security_error (ctx, "sign-munge-init: munge_opt_set %s: %s",
                            socket_path, munge_ctx_strerror (sm->munge));
            goto error_nomsg;
        }
    }
    return 0;
error:
    security_error (ctx, NULL);
error_nomsg:
    sm_destroy (sm);
    return -1;
}

/* Compute hash over HEADER.PAYLOAD (input), then "sign" the hash,
 * producing a munge credential.
 * Reserve first byte of munge payload to indicate which hash algorithm.
 */
static char *op_sign (flux_security_t *ctx,
                      const char *input, int inputsz, int flags)
{
    struct sign_munge *sm = flux_security_aux_get (ctx, auxname);
    BYTE digest[SHA256_BLOCK_SIZE + 1] = { HASH_TYPE_SHA256 };
    SHA256_CTX shx;
    char *cred;
    munge_err_t e;

    assert (sm != NULL);
    sha256_init (&shx);
    sha256_update (&shx, (const BYTE *)input, inputsz);
    sha256_final (&shx, digest + 1);
    e = munge_encode (&cred, sm->munge, digest, sizeof (digest));
    if (e != EMUNGE_SUCCESS) {
        errno = EINVAL;
        security_error (ctx, "sign-munge-sign: %s",
                        munge_ctx_strerror (sm->munge));
        return NULL;
    }
    return cred;
}

/* Recompute hash over HEADER.PAYLOAD portion of input, then munge_decode
 * the SIGNATURE portion of input as a munge cred, and check:
 * - munge cred's payload matches the computed hash
 * - security header userid matches munge cred uid
 * - munge encode time plus configured max-ttl is not past.
 */
static int op_verify (flux_security_t *ctx, const struct kv *header,
                      const char *input, int inputsz,
                      const char *signature, int flags)
{
    struct sign_munge *sm = flux_security_aux_get (ctx, auxname);
    munge_err_t e;
    char *indigest = NULL;
    int indigestsz = 0;
    uid_t uid;
    uint64_t userid;
    time_t now;
    time_t encode_time;
    int saved_errno;

    assert (sm != NULL);

    e = munge_decode (signature, sm->munge, (void **)&indigest,
                                                     &indigestsz, &uid, NULL);
    /*  EMUNGE_CRED_REPLAYED is intentionally accepted: credentials may be
     *  legitimately reused more than once per node (e.g. in testing when
     *  running multiple brokers per node).  TTL checking below provides
     *  the primary replay protection.
     *  EMUNGE_CRED_EXPIRED is intentionally accepted: TTL is managed
     *  independently by the flux-security max-ttl configuration.
     */
    if (e != EMUNGE_SUCCESS && e != EMUNGE_CRED_REPLAYED
                            && e != EMUNGE_CRED_EXPIRED) {
        errno = EINVAL;
        security_error (ctx, "sign-munge-verify: munge_decode: %s",
                        munge_ctx_strerror (sm->munge));
        goto error;
    }

    switch (indigestsz > 0 ? indigest[0] : HASH_TYPE_INVALID) {
        case HASH_TYPE_SHA256: {
            BYTE refdigest[SHA256_BLOCK_SIZE + 1] = { HASH_TYPE_SHA256 };
            SHA256_CTX shx;

            sha256_init (&shx);
            sha256_update (&shx, (const BYTE *)input, inputsz);
            sha256_final (&shx, refdigest + 1);

            if (indigestsz != sizeof (refdigest)
                        || memcmp (refdigest, indigest, indigestsz) != 0) {
                errno = EINVAL;
                security_error (ctx, "sign-munge-verify: SHA256 hash mismatch");
                goto error;
            }
            break;
        }
        default:
            errno = EINVAL;
            security_error (ctx, "sign-munge-verify: unknown hash type");
            goto error;
    }

    if (kv_get (header, "userid", KV_INT64, &userid) < 0 || userid != uid) {
        errno = EINVAL;
        security_error (ctx, "sign-munge-verify: uid mismatch");
        goto error;
    }
    e = munge_ctx_get (sm->munge, MUNGE_OPT_ENCODE_TIME, &encode_time);
    if (e != EMUNGE_SUCCESS) {
        errno = EINVAL;
        security_error (ctx, "sign-munge-verify: munge_ctx_get ENCODE_TIME: %s",
                        munge_ctx_strerror (sm->munge));
        goto error;
    }
    if ((now = time (NULL)) == (time_t)-1)
        goto error;
    if (encode_time + sm->max_ttl < now) {
        errno = EINVAL;
        security_error (ctx, "sign-munge-verify: max-ttl exceeded");
        goto error;
    }
    free (indigest);
    return 0;
error:
    saved_errno = errno;
    free (indigest);
    errno = saved_errno;
    return -1;
}

const struct sign_mech sign_mech_munge = {
    .name = "munge",
    .init = op_init,
    .prep = NULL,
    .sign = op_sign,
    .verify = op_verify,
};

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */

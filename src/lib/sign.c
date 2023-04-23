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
#include <unistd.h>
#include <sys/types.h>
#include <sodium.h>

#include "src/libutil/cf.h"
#include "src/libutil/kv.h"
#include "src/libutil/macros.h"

#include "context.h"
#include "context_private.h"
#include "sign.h"
#include "sign_mech.h"

struct sign {
    const cf_t *config;
    void *wrapbuf;
    int wrapbufsz;
    void *unwrapbuf;
    int unwrapbufsz;
};

static const int64_t sign_version = 1;

static const struct cf_option sign_opts[] = {
    {"max-ttl",             CF_INT64,       true},
    {"default-type",        CF_STRING,      true},
    {"allowed-types",       CF_ARRAY,       true},
    CF_OPTIONS_TABLE_END,
};

static const struct sign_mech *lookup_mech (const char *name)
{
    if (!strcmp (name, "none"))
        return &sign_mech_none;
    if (!strcmp (name, "munge"))
        return &sign_mech_munge;
    if (!strcmp (name, "curve"))
        return &sign_mech_curve;
    return NULL;
}

/* Grow *buf to newsz if *bufsz is less than that.
 * Return 0 on success, -1 on failure with errno set.
 */
static int grow_buf (void **buf, int *bufsz, int newsz)
{
    if (*bufsz < newsz) {
        void *new = realloc (*buf, newsz);
        if (!new)
            return -1;
        *buf = new;
        *bufsz = newsz;
    }
    return 0;
}

static void sign_destroy (struct sign *sign)
{
    if (sign) {
        int saved_errno = errno;
        free (sign->wrapbuf);
        free (sign->unwrapbuf);
        free (sign);
        errno = saved_errno;
    }
}

static bool validate_mech_array (flux_security_t *ctx, const cf_t *mechs)
{
    int i;
    const cf_t *el;

    for (i = 0; (el = cf_get_at (mechs, i)) != NULL; i++) {
        if (cf_typeof (el) != CF_STRING) {
            errno = EINVAL;
            security_error (ctx, "sign: allowed-types[%d] not a string", i);
            return false;
        }
        if (!lookup_mech (cf_string (el))) {
            errno = EINVAL;
            security_error (ctx, "sign: unknown mechanism=%s", cf_string (el));
            return false;
        }
    }
    if (i == 0) {
        errno = EINVAL;
        security_error (ctx, "sign: allowed-types array is empty");
        return false;
    }

    return true;
}

static struct sign *sign_create (flux_security_t *ctx)
{
    struct sign *sign;
    struct cf_error e;
    const char *default_type;
    const cf_t *allowed_types;
    int64_t max_ttl;

    if (!(sign = calloc (1, sizeof (*sign)))) {
        security_error (ctx, NULL);
        return NULL;
    }
    if (!(sign->config = security_get_config (ctx, "sign")))
        goto error;
    if (cf_check (sign->config, sign_opts, CF_STRICT | CF_ANYTAB, &e) < 0) {
        security_error (ctx, "sign: config error: %s", e.errbuf);
        goto error;
    }
    /* Allow -100 for testing
     */
    max_ttl = cf_int64 (cf_get_in (sign->config, "max-ttl"));
    if (max_ttl <= 0 && max_ttl != -100) {
        errno = EINVAL;
        security_error (ctx, "sign: max-ttl should be greater than zero");
        goto error;
    }
    allowed_types = cf_get_in (sign->config, "allowed-types");
    if (!validate_mech_array (ctx, allowed_types))
        goto error;
    default_type = cf_string (cf_get_in (sign->config, "default-type"));
    if (!lookup_mech (default_type))
        goto error;
    return sign;
error:
    sign_destroy (sign);
    return NULL;
}

static struct sign *sign_init (flux_security_t *ctx)
{
    const char *auxname = "flux::sign";
    struct sign *sign = flux_security_aux_get (ctx, auxname);

    if (!sign) {
        if (!(sign = sign_create (ctx)))
            goto error_nomsg;
        if (flux_security_aux_set (ctx, auxname, sign,
                                   (flux_security_free_f)sign_destroy) < 0)
            goto error;
    }
    return sign;
error:
    security_error (ctx, NULL);
error_nomsg:
    sign_destroy (sign);
    return NULL;
}

/* Convert header to base64, storing in buf/bufsz, growing as needed.
 * Any existing content is overwritten.  Result is NULL terminated.
 * Return 0 on success, -1 on failure with errno set.
 */
static int header_encode_cpy (struct kv *header, void **buf, int *bufsz)
{
    const char *src;
    int srclen;
    char *dst;
    size_t dstlen;

    if (kv_encode (header, &src, &srclen) < 0)
        return -1;
    dstlen = sodium_base64_encoded_len (srclen,
                                        sodium_base64_VARIANT_ORIGINAL);
    if (grow_buf (buf, bufsz, dstlen) < 0)
        return -1;
    dst = *buf;
    sodium_bin2base64 (dst, dstlen, (const unsigned char *)src, srclen,
                       sodium_base64_VARIANT_ORIGINAL);
    return 0;
}

/* Convert payload to base64, then append with "." prefix to buf/bufsz,
 * growing as needed.  Result is NULL-terminated.
 * This must be called after header_encode_cpy().
 * Return 0 on success, -1 on failure with errno set.
 */
static int payload_encode_cat (const void *pay, int paysz,
                               void **buf, int *bufsz)
{
    int len;
    int dstlen;
    char *dst;

    len = strlen (*buf);
    dstlen = sodium_base64_encoded_len (paysz,
                                        sodium_base64_VARIANT_ORIGINAL);
    if (grow_buf (buf, bufsz, dstlen + len + 1) < 0)
        return -1;
    dst = (char *)*buf + len;
    *dst++ = '.';
    sodium_bin2base64 (dst, dstlen, pay, paysz,
                       sodium_base64_VARIANT_ORIGINAL);
    return 0;
}

/* Append pre-encoded (string) signature with "." prefix to buf/bufsz,
 * growing as needed.  Result is NULL-terminated.
 * This must be called after payload_encode_cat().
 * Return 0 on success, -1 on failure with errno set.
 */
static int signature_cat (const char *sig, void **buf, int *bufsz)
{
    int len = strlen (*buf);
    char *dst;

    /* Grow buffer large enough to contain:
     * current header (len), '.' separator, signature, and final NUL.
     */
    if (grow_buf (buf, bufsz, strlen(sig) + len + 2) < 0)
        return -1;
    dst = (char *)*buf + len;
    *dst++ = '.';
    strcpy (dst, sig);
    return 0;
}

const char *flux_sign_wrap_as (flux_security_t *ctx,
                               int64_t userid,
                               const void *pay, int paysz,
                               const char *mech_type, int flags)
{
    struct sign *sign;
    struct kv *header = NULL;
    char *sig = NULL;
    const struct sign_mech *mech;
    int saved_errno;

    if (!ctx || userid < 0 || flags != 0
        || paysz < 0 || (paysz > 0 && pay == NULL)) {
        errno = EINVAL;
        security_error (ctx, NULL);
        return NULL;
    }
    if (!(sign = sign_init (ctx)))
        return NULL;
    if (!mech_type)
        mech_type = cf_string (cf_get_in (sign->config, "default-type"));
    if (!(mech = lookup_mech (mech_type))) {
        errno = EINVAL;
        security_error (ctx, "sign-wrap: unknown mechanism: %s", mech_type);
        return NULL;
    }
    if (mech->init) {
        if (mech->init (ctx, sign->config) < 0)
            return NULL;
    }

    /* Create security header.
     */
    if (!(header = kv_create ()))
        goto error;
    if (kv_put (header, "version", KV_INT64, sign_version) < 0)
        goto error;
    if (kv_put (header, "mechanism", KV_STRING, mech->name) < 0)
        goto error;
    if (kv_put (header, "userid", KV_INT64, userid) < 0)
        goto error;
    /* Call mech->prep, which adds mechanism-specific data to header, if any.
     */
    if (mech->prep) {
        if (mech->prep (ctx, header, flags) < 0)
            goto error_msg;
    }
    /* Serialize to HEADER.PAYLOAD.SIGNATURE
     */
    if (header_encode_cpy (header, &sign->wrapbuf, &sign->wrapbufsz) < 0)
        goto error;
    if (payload_encode_cat (pay, paysz, &sign->wrapbuf, &sign->wrapbufsz) < 0)
        goto error;
    if (!(sig = mech->sign (ctx, sign->wrapbuf, strlen (sign->wrapbuf), flags)))
        goto error_msg;
    if (signature_cat (sig, &sign->wrapbuf, &sign->wrapbufsz) < 0)
        goto error;

    free (sig);
    kv_destroy (header);
    return sign->wrapbuf;
error:
    security_error (ctx, NULL);
error_msg:
    kv_destroy (header);
    saved_errno = errno;
    free (sig);
    errno = saved_errno;
    return NULL;
}

const char *flux_sign_wrap (flux_security_t *ctx,
                            const void *pay, int paysz,
                            const char *mech_type, int flags)
{
    return flux_sign_wrap_as (ctx, getuid(), pay, paysz, mech_type, flags);
}

/* Decode HEADER portion of HEADER.PAYLOAD.SIGNATURE
 * Return header on success or NULL on error with errno set.
 * Set 'endptr' to period ('.') delimiter following HEADER.
 */
static struct kv *header_decode (const char *input, char **endptr)
{
    char *p;
    const char *src;
    size_t srclen;
    void *dst;
    size_t dstlen;
    struct kv *header;
    int saved_errno;

    if (!(p = strchr (input, '.'))) {
        errno = EINVAL;
        return NULL;
    }
    src = input;
    srclen = p - input;
    dstlen = BASE64_DECODE_SIZE (srclen);
    if (!(dst = malloc (dstlen)))
        return NULL;
    if (sodium_base642bin (dst, dstlen, src, srclen,
                           NULL, &dstlen, NULL,
                           sodium_base64_VARIANT_ORIGINAL) < 0) {
        errno = EINVAL;
        goto error;
    }
    if (!(header = kv_decode (dst, dstlen)))
        goto error;
    free (dst);
    *endptr = p;
    return header;
error:
    saved_errno = errno;
    free (dst);
    errno = saved_errno;
    return NULL;
}

/* Decode PAYLOAD portion of PAYLOAD.SIGNATURE to buf/bufsz,
 * expanding as needed.  Any existing content is overwritten.
 * Set 'endptr' to period ('.') delimiter following PAYLOAD.
 * Return 0 on success, -1 on failure with errno set.
 */
static int payload_decode_cpy (const char *input, void **buf, int *bufsz,
                               char **endptr)
{
    char *p;
    size_t dstlen;
    size_t srclen;
    const char *src;

    if (!(p = strchr (input, '.'))) {
        errno = EINVAL;
        return -1;
    }
    src = input;
    srclen = p - input;
    dstlen = BASE64_DECODE_SIZE (srclen);
    if (grow_buf (buf, bufsz, dstlen) < 0)
        return -1;
    if (sodium_base642bin (*buf, dstlen, src, srclen,
                           NULL, &dstlen, NULL,
                           sodium_base64_VARIANT_ORIGINAL) < 0) {
        errno = EINVAL;
        return -1;
    }
    *endptr = p;
    return dstlen;
}

/* Return true if mechanism 'name' is present in the 'allowed' array.
 */
static bool mech_allowed (const char *name, const cf_t *allowed)
{
    int i;
    const cf_t *el;

    for (i = 0; (el = cf_get_at (allowed, i)) != NULL; i++) {
        if (!strcmp (cf_string (el), name))
            return true;
    }
    return false;
}

static int sign_unwrap (flux_security_t *ctx,
                        const char *input,
                        const void **payload, int *payloadsz,
                        const char **mech_typep,
                        int64_t *useridp, int flags, bool check_allowed)
{
    struct sign *sign;
    struct kv *header;
    int len;
    int64_t userid;
    int64_t version;
    const char *mechanism;
    const struct sign_mech *mech;
    const cf_t *allowed_types;
    char *endptr;

    if (!ctx || !input || !(flags == 0 || flags == FLUX_SIGN_NOVERIFY)) {
        errno = EINVAL;
        security_error (ctx, NULL);
        return -1;
    }
    if (!(sign = sign_init (ctx)))
        return -1;
    /* Parse and verify generic portion of security header.
     */
    if (!(header = header_decode (input, &endptr))) {
        security_error (ctx, "sign-unwrap: header decode error: %s",
                        strerror (errno));
        return -1;
    }
    if (kv_get (header, "version", KV_INT64, &version) < 0) {
        errno = EINVAL;
        security_error (ctx, "sign-unwrap: header version missing");
        goto error;
    }
    if (version != sign_version) {
        errno = EINVAL;
        security_error (ctx, "sign-unwrap: header version=%d unknown",
                        (int)version);
        goto error;
    }
    if (kv_get (header, "mechanism", KV_STRING, &mechanism) < 0) {
        errno = EINVAL;
        security_error (ctx, "sign-unwrap: header mechanism missing");
        goto error;
    }
    if (!(mech = lookup_mech (mechanism))) {
        errno = EINVAL;
        security_error (ctx, "sign-unwrap: header mechanism=%s unknown",
                        mechanism);
        goto error;
    }
    if (check_allowed) {
        allowed_types = cf_get_in (sign->config, "allowed-types");
        if (!mech_allowed (mechanism, allowed_types)) {
            errno = EINVAL;
            security_error (ctx, "sign-unwrap: header mechanism=%s not allowed",
                            mechanism);
            goto error;
        }
    }
    if (kv_get (header, "userid", KV_INT64, &userid) < 0) {
        errno = EINVAL;
        security_error (ctx, "sign-unwrap: header userid missing");
        goto error;
    }
    /* Decode payload
     */
    len = payload_decode_cpy (endptr + 1, &sign->unwrapbuf, &sign->unwrapbufsz,
                              &endptr);
    if (len < 0) {
        security_error (ctx, "sign-unwrap: payload decode error: %s",
                        strerror (errno));
        goto error;
    }
    /* Mech-specific verification (optional).
     */
    if (!(flags & FLUX_SIGN_NOVERIFY)) {
        int inputsz = endptr - input;
        const char *signature = endptr + 1;
        if (mech->init) {
            if (mech->init (ctx, sign->config) < 0)
                goto error;
        }
        if (mech->verify (ctx, header, input, inputsz, signature, flags) < 0)
            goto error;
    }
    kv_destroy (header);
    if (payload)
        *payload = (len > 0 ? sign->unwrapbuf : NULL);
    if (payloadsz)
        *payloadsz = len;
    if (mech_typep)
        *mech_typep = mech->name;
    if (useridp)
        *useridp = userid;
    return 0;
error:
    kv_destroy (header);
    return -1;
}

int flux_sign_unwrap_anymech (flux_security_t *ctx, const char *input,
                              const void **payload, int *payloadsz,
                              const char **mech_type,
                              int64_t *userid, int flags)
{
    return sign_unwrap (ctx, input, payload, payloadsz,
                        mech_type, userid, flags, false);
}

int flux_sign_unwrap (flux_security_t *ctx, const char *input,
                      const void **payload, int *payloadsz,
                      int64_t *userid, int flags)
{
    return sign_unwrap (ctx, input, payload, payloadsz,
                        NULL, userid, flags, true);
}

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */

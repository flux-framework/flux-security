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
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include "context.h"
#include "context_private.h"
#include "sign.h"
#include "sign_mech.h"
#include "src/libca/sigcert.h"
#include "src/libca/ca.h"

struct sign_curve {
    struct sigcert *cert;
    int64_t max_ttl;
    const cf_t *curve_config;
    struct ca *ca;
};

static const struct cf_option curve_opts[] = {
    {"require-ca",              CF_BOOL,        true},
    {"cert-path",               CF_STRING,      false},
    CF_OPTIONS_TABLE_END,
};

static const char *auxname = "flux::sign_curve";

static void sc_destroy (struct sign_curve *sc)
{
    if (sc) {
        ca_destroy (sc->ca);
        sigcert_destroy (sc->cert);
        free (sc);
    }
}

/* init - one time mechanism initialization
 */
static int op_init (flux_security_t *ctx, const cf_t *cf)
{
    struct sign_curve *sc = flux_security_aux_get (ctx, auxname);
    struct cf_error cfe;

    if (sc != NULL)
        return 0;
    if (!(sc = calloc (1, sizeof (*sc))))
        goto error;
    sc->max_ttl = cf_int64 (cf_get_in (cf, "max-ttl"));
    if (!(sc->curve_config = cf_get_in (cf, "curve"))) {
        security_error (ctx, "sign-curve-init: [sign.curve] config missing");
        goto error_nomsg;
    }
    if (cf_check (sc->curve_config, curve_opts, CF_STRICT, &cfe) < 0) {
        security_error (ctx, "sign-curve-init: [curve] config: %s", cfe.errbuf);
        goto error_nomsg;
    }
    if (flux_security_aux_set (ctx, auxname, sc,
                               (flux_security_free_f)sc_destroy) < 0)
        goto error;
    return 0;
error:
    security_error (ctx, NULL);
error_nomsg:
    sc_destroy (sc);
    return -1;
}

/* Put cert to security header.
 * Return 0 on success, -1 on error with errno set.
 */
static int header_put_cert (struct kv *header, const char *prefix,
                            struct sigcert *cert)
{
    const char *buf;
    int bufsz;
    struct kv *kv = NULL;

    if (sigcert_encode (cert, &buf, &bufsz) < 0)
        return -1;
    if (!(kv = kv_decode (buf, bufsz)))
        return -1;
    if (kv_join (header, kv, prefix) < 0)
        goto error;
    kv_destroy (kv);
    return 0;
error:
    kv_destroy (kv);
    return -1;
}

/* Get cert from security header.
 * Return cert on success, NULL on error with errno set.
 */
static struct sigcert *header_get_cert (const struct kv *header,
                                        const char *prefix)
{
    struct kv *kv;
    const char *buf;
    int len;
    struct sigcert *cert;

    if (!(kv = kv_split (header, prefix)))
        return NULL;
    if (kv_encode (kv, &buf, &len) < 0)
        goto error;
    if (!(cert = sigcert_decode (buf, len)))
        goto error;
    kv_destroy (kv);
    return cert;
error:
    kv_destroy (kv);
    return NULL;
}

/* prep - add to security header
 *   curve.cert    signer's public certificate
 *   curve.ctime   signature creation time
 *   curve.xtime   signature expiration time
 */
static int op_prep (flux_security_t *ctx, struct kv *header, int flags)
{
    struct sign_curve *sc = flux_security_aux_get (ctx, auxname);
    time_t ctime;
    time_t xtime;

    assert (sc != NULL);

    if (!sc->cert) { // load signing cert on first use
        char buf[PATH_MAX + 1];
        int bufsz = sizeof (buf);
        const char *certpath;
        struct sigcert *cert;
        const cf_t *entry;
        if ((entry = cf_get_in (sc->curve_config, "cert-path"))) // test
            certpath = cf_string (entry);
        else {
            uid_t real_uid = getuid ();
            struct passwd *pw = getpwuid (real_uid);
            if (!pw || snprintf (buf, bufsz, "%s/.flux/curve/sig",
                                                    pw->pw_dir) >= bufsz) {
                errno = EINVAL;
                goto error;
            }
            certpath = buf;
        }
        if (!(cert = sigcert_load (certpath, true))) {
            security_error (ctx, "sign-curve-prep: load %s: %s",
                            certpath, strerror (errno));
            goto error_nomsg;
        }
        sigcert_destroy (sc->cert);
        sc->cert = cert;
    }
    if ((ctime = time (NULL)) == (time_t)-1)
        goto error;
    xtime = ctime + sc->max_ttl;
    if (header_put_cert (header, "curve.cert.", sc->cert) < 0
            || kv_put (header, "curve.ctime", KV_TIMESTAMP, ctime) < 0
            || kv_put (header, "curve.xtime", KV_TIMESTAMP, xtime) < 0)
        goto error;
    return 0;
error:
    security_error (ctx, NULL);
error_nomsg:
    return -1;
}

/* sign - sign HEADER.PAYLOAD
 */
static char *op_sign (flux_security_t *ctx,
                      const char *input, int inputsz, int flags)
{
    struct sign_curve *sc = flux_security_aux_get (ctx, auxname);
    char *sign;

    assert (sc != NULL);

    if (!(sign = sigcert_sign_detached (sc->cert, (uint8_t *)input, inputsz))) {
        security_error (ctx, "sign-curve: %s", strerror (errno));
        return NULL;
    }
    return sign;
}

/* Verify that cert authenticates userid, because it exists in that user's
 * home directory.
 */
static int verify_cert_home (flux_security_t *ctx, struct sign_curve *sc,
                             const struct sigcert *cert, int64_t userid)
{
    char buf[PATH_MAX + 1] = "unknown user";
    int bufsz = sizeof (buf);
    struct passwd *pw = getpwuid (userid);
    struct sigcert *ucert = NULL;

    if (!pw || snprintf (buf, bufsz, "%s/.flux/curve/sig", pw->pw_dir) >= bufsz
                                || (!(ucert = sigcert_load (buf, false)))) {
        errno = EINVAL;
        security_error (ctx, "sign-curve-verify: error loading cert from %s",
                        buf);
        return -1;
    }
    if (!sigcert_equal (ucert, cert)) {
        errno = EINVAL;
        security_error (ctx, "sign-curve-verify: cert verification failed");
        sigcert_destroy (ucert);
        return -1;
    }
    sigcert_destroy (ucert);
    return 0;
}

/* Verify that cert authenticates userid, because it was signed by the CA,
 * and the cert contains the same userid.
 */
static int verify_cert_ca (flux_security_t *ctx, struct sign_curve *sc,
                           const struct sigcert *cert, int64_t userid,
                           time_t now, time_t ctime)
{
    int64_t cert_max_sign_ttl;
    int64_t cert_userid;
    ca_error_t e;

    if (!sc->ca) { // load CA context on first use
        const cf_t *ca_config;
        struct ca *ca;

        if (!(ca_config = security_get_config (ctx, "ca"))) {
            security_error (ctx, "sign-curve-verify: [ca] config missing");
            return -1;
        }
        if (!(ca = ca_create (ca_config, e)) || ca_load (ca, false, e)) {
            security_error (ctx, "sign-curve-verify: ca: %s", e);
            ca_destroy (ca);
            return -1;
        }
        sc->ca = ca;
    }
    if (ca_verify (sc->ca, cert, &cert_userid, &cert_max_sign_ttl, e) < 0) {
        security_error (ctx, "sign-curve-verify: ca: %s", e);
        return -1;
    }
    if (cert_userid != userid) {
        security_error (ctx, "sign-curve-verify: ca: userid mismatch");
        return -1;
    }
    if (ctime + cert_max_sign_ttl < now) {
        security_error (ctx, "sign-curve-verify: ca: max-sign-ttl exceeded");
        return -1;
    }
    return 0;
}

/* verify - verify HEADER.PAYLOAD.SIGNATURE, e.g.
 * - enclosed cert created SIGNATURE over HEADER.PAYLOAD
 * - enclosed cert authenticates header userid (two methods)
 * - xtime has not passed
 * - ctime plus configured max-ttl has not passed
 */
static int op_verify (flux_security_t *ctx, const struct kv *header,
                      const char *input, int inputsz,
                      const char *signature, int flags)
{
    struct sign_curve *sc = flux_security_aux_get (ctx, auxname);
    struct sigcert *cert = NULL;
    time_t now;
    time_t ctime;
    time_t xtime;
    int64_t userid;

    assert (sc != NULL);

    if ((now = time (NULL)) == (time_t)-1)
        goto error;

    if (!(cert = header_get_cert (header, "curve.cert."))
            || kv_get (header, "curve.xtime", KV_TIMESTAMP, &xtime) < 0
            || kv_get (header, "curve.ctime", KV_TIMESTAMP, &ctime) < 0
            || kv_get (header, "userid", KV_INT64, &userid) < 0) {
        security_error (ctx, "sign-curve-verify: incomplete header");
        goto error_nomsg;
    }
    if (sigcert_verify_detached (cert, signature,
                                 (uint8_t *)input, inputsz) < 0) {
        security_error (ctx, "sign-curve-verify: verification failure");
        goto error_nomsg;
    }
    if (cf_bool (cf_get_in (sc->curve_config, "require-ca"))) {
        if (verify_cert_ca (ctx, sc, cert, userid, now, ctime) < 0)
            goto error_nomsg;
    }
    else {          // require-ca = false
        if (verify_cert_home (ctx, sc, cert, userid) < 0)
            goto error_nomsg;
    }
    if (xtime < now || ctime + sc->max_ttl < now) {
        errno = EINVAL;
        security_error (ctx, "sign-curve-verify: xtime or max-ttl exceeded");
        goto error_nomsg;
    }
    if (ctime > now) {
        errno = EINVAL;
        security_error (ctx, "sign-curve-verify: ctime is in the future");
        goto error_nomsg;
    }
    sigcert_destroy (cert);
    return 0;
error:
    security_error (ctx, NULL);
error_nomsg:
    sigcert_destroy (cert);
    return -1;
}

const struct sign_mech sign_mech_curve = {
    .name = "curve",
    .init = op_init,
    .prep = op_prep,
    .sign = op_sign,
    .verify = op_verify,
};

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */

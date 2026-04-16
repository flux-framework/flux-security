/************************************************************\
 * Copyright 2017 Lawrence Livermore National Security, LLC
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <uuid.h>
#include <assert.h>

#include "src/libutil/cf.h"
#include "sigcert.h"
#include "ca.h"

#define UUID_STRING_SIZE    37  // see uuid_unparse(3)

struct ca {
    cf_t *cf;                   // config table is cached
    struct sigcert *ca_cert;    // the CA certificate
};

static const struct cf_option ca_opts[] = {
    {"max-cert-ttl",    CF_INT64,    true},
    {"max-sign-ttl",    CF_INT64,    true},
    {"cert-path",       CF_STRING,   true},
    {"revoke-dir",      CF_STRING,   true},
    {"revoke-allow",    CF_BOOL,     true},
    {"domain",          CF_STRING,   true},
    CF_OPTIONS_TABLE_END,
};

/* Update 'e' if non-NULL.
 * If 'fmt' is non-NULL, build message; otherwise use strerror (errno).
 */
static void ca_error (ca_error_t e, const char *fmt, ...)
{
    if (e) {
        size_t sz = sizeof (ca_error_t);
        int saved_errno = errno;
        if (fmt) {
            va_list ap;
            va_start (ap, fmt);
            vsnprintf (e, sz, fmt, ap);
            va_end (ap);
        }
        else
            snprintf (e, sz, "%s", strerror (errno));
        errno = saved_errno;
    }
}

static struct ca *ca_alloc (const cf_t *cf)
{
    struct ca *ca;

    if (!(ca = calloc (1, sizeof (*ca))))
        return NULL;
    if (!(ca->cf = cf_copy (cf))) {
        ca_destroy (ca);
        return NULL;
    }
    return ca;
}

/* N.B. ensure 'error' (if set) is valid on EINVAL return
 */
struct ca *ca_create (const cf_t *cf, ca_error_t e)
{
    struct ca *ca;
    struct cf_error error;

    if (!cf) {
        errno = EINVAL;
        goto error;
    }
    if (cf_check (cf, ca_opts, CF_STRICT, &error) < 0) {
        if (errno == EINVAL) {
            ca_error (e, "%s", error.errbuf);
            return NULL;
        }
        goto error;
    }
    if (!(ca = ca_alloc (cf))) {
        goto error;
    }
    return ca;
error:
    ca_error (e, NULL);
    return NULL;
}

void ca_destroy (struct ca *ca)
{
    if (ca) {
        int saved_errno = errno;
        sigcert_destroy (ca->ca_cert);
        cf_destroy (ca->cf);
        free (ca);
        errno = saved_errno;
    }
}

static int sign_with (const struct ca *ca, const struct sigcert *ca_cert,
                      struct sigcert *cert, time_t not_valid_before_time,
                      int64_t ttl, int64_t userid,
                      bool ca_capability, ca_error_t e)
{
    int64_t max_cert_ttl = cf_int64 (cf_get_in (ca->cf, "max-cert-ttl"));
    int64_t max_sign_ttl = cf_int64 (cf_get_in (ca->cf, "max-sign-ttl"));
    const char *domain = cf_string (cf_get_in (ca->cf, "domain"));
    uuid_t uuid_bin;
    char uuid[UUID_STRING_SIZE];
    time_t now;
    const char *ca_uuid;

    if (ttl > max_cert_ttl) {
        errno = EINVAL;
        ca_error (e, "ttl must be <= %lld", (long long)max_cert_ttl);
        goto error;
    }
    if (ttl == 0)
        ttl = max_cert_ttl;
    if (time (&now) == (time_t)-1)
        goto error;
    if (not_valid_before_time == 0)
        not_valid_before_time = now;

    uuid_generate (uuid_bin);
    uuid_unparse (uuid_bin, uuid);
    if (sigcert_meta_set (cert, "uuid", SM_STRING, uuid) < 0)
        goto error;
    if (sigcert_meta_set (cert, "not-valid-before-time", SM_TIMESTAMP,
                          not_valid_before_time) < 0)
        goto error;
    if (sigcert_meta_set (cert, "ctime", SM_TIMESTAMP, now) < 0)
        goto error;
    if (sigcert_meta_set (cert, "xtime", SM_TIMESTAMP,
                          not_valid_before_time + ttl) < 0)
        goto error;
    if (sigcert_meta_set (cert, "userid", SM_INT64, userid) < 0)
        goto error;
    if (sigcert_meta_set (cert, "max-sign-ttl", SM_INT64, max_sign_ttl) < 0)
        goto error;
    if (ca_cert != cert) {
        if (sigcert_meta_get (ca_cert, "uuid", SM_STRING, &ca_uuid) < 0)
            goto error;
    }
    else { // self-signed
        ca_uuid = uuid;
    }
    if (sigcert_meta_set (cert, "issuer", SM_STRING, ca_uuid) < 0)
        goto error;
    if (sigcert_meta_set (cert, "domain", SM_STRING, domain) < 0)
        goto error;
    if (sigcert_meta_set (cert, "ca-capability", SM_BOOL, ca_capability) < 0)
        goto error;
    if (sigcert_sign_cert (ca_cert, cert) < 0)
        goto error;
    return 0;
error:
    ca_error (e, NULL);
    return -1;
}

int ca_sign (const struct ca *ca, struct sigcert *cert,
             time_t not_valid_before_time, int64_t ttl,
             int64_t userid, ca_error_t e)
{
    if (!ca || !cert || ttl < 0 || not_valid_before_time < 0 || userid < 0) {
        errno = EINVAL;
        ca_error (e, NULL);
        return -1;
    }
    if (!ca->ca_cert) {
        errno = EINVAL;
        ca_error (e, "CA cert has not been loaded/generated");
        return -1;
    }
    if (!sigcert_has_secret (ca->ca_cert)) {
        errno = EINVAL;
        ca_error (e, "CA cert does not contain secret key");
        return -1;
    }
    return sign_with (ca, ca->ca_cert, cert, not_valid_before_time, ttl,
                      userid, false, e);
}

int ca_revoke (const struct ca *ca, const char *uuid, ca_error_t e)
{
    const char *dir;
    char path[PATH_MAX + 1];
    int fd;

    if (!ca || !uuid || strlen (uuid) == 0) {
        errno = EINVAL;
        goto error;
    }
    if (!cf_bool (cf_get_in (ca->cf, "revoke-allow"))) {
        ca_error (e, "revocation not permitted on this node");
        return -1;
    }
    dir = cf_string (cf_get_in (ca->cf, "revoke-dir"));
    if (mkdir (dir, 0755) < 0) {
        if (errno != EEXIST)
            goto error;
    }
    if (snprintf (path, sizeof (path), "%s/%s", dir, uuid) >= sizeof (path)) {
        errno = EINVAL;
        goto error;
    }
    if ((fd = open (path, O_WRONLY | O_CREAT | O_CLOEXEC, 0644)) < 0) {
        ca_error (e, "%s: %s", path, strerror (errno));
        return -1;
    }
    if (close (fd) < 0) {
        ca_error (e, "%s: %s", path, strerror (errno));
        return -1;
    }
    return 0;
error:
    ca_error (e, NULL);
    return -1;
}

static int check_revocation (const struct ca *ca, const char *uuid,
                             ca_error_t e)
{
    char path[PATH_MAX + 1];
    const char *dir = cf_string (cf_get_in (ca->cf, "revoke-dir"));
    if (snprintf (path, sizeof (path), "%s/%s", dir, uuid) >= sizeof (path)) {
        errno = EINVAL;
        ca_error (e, NULL);
        return -1;
    }
    if (access (path, F_OK) == 0) {
        errno = EINVAL;
        ca_error (e, "cert has been revoked");
        return -1;
    }
    return 0;
}

int ca_verify (const struct ca *ca, const struct sigcert *cert,
               int64_t *useridp, int64_t *max_sign_ttlp, ca_error_t e)
{
    int64_t max_sign_ttl;
    int64_t userid;
    time_t ctime;
    time_t xtime;
    time_t not_valid_before_time;
    time_t now;
    const char *uuid;
    bool ca_capability;

    if (!ca || !cert) {
        errno = EINVAL;
        goto error;
    }
    if (!ca->ca_cert) {
        ca_error (e, "CA cert has not been loaded/generated");
        errno = EINVAL;
        return -1;
    }
    if (sigcert_meta_get (ca->ca_cert, "ca-capability", SM_BOOL,
                          &ca_capability) < 0 || ca_capability == false) {
        errno = EINVAL;
        ca_error (e, "ca certificate lacks ca-capability");
        return -1;
    }
    if (time (&now) == (time_t)-1)
        goto error;
    if (sigcert_verify_cert (ca->ca_cert, cert) < 0) {
        ca_error (e, "signature verification failed");
        errno = EINVAL;
        return -1;
    }
    if (sigcert_meta_get (cert, "uuid", SM_STRING, &uuid) < 0)
        goto error_cert;
    if (sigcert_meta_get (cert, "not-valid-before-time", SM_TIMESTAMP,
                          &not_valid_before_time) < 0)
        goto error_cert;
    if (sigcert_meta_get (cert, "ctime", SM_TIMESTAMP, &ctime) < 0)
        goto error_cert;
    if (sigcert_meta_get (cert, "xtime", SM_TIMESTAMP, &xtime) < 0)
        goto error_cert;
    if (sigcert_meta_get (cert, "userid", SM_INT64, &userid) < 0)
        goto error_cert;
    if (sigcert_meta_get (cert, "max-sign-ttl", SM_INT64, &max_sign_ttl) < 0)
        goto error_cert;
    if (xtime < now) {
        ca_error (e, "cert has expired");
        errno = EINVAL;
        return -1;
    }
    if (not_valid_before_time > now) {
        ca_error (e, "cert is not yet valid");
        errno = EINVAL;
        return -1;
    }
    if (check_revocation (ca, uuid, e) < 0)
        return -1;
    if (useridp)
        *useridp = userid;
    if (max_sign_ttlp)
        *max_sign_ttlp = max_sign_ttl;
    return 0;
error_cert:
    ca_error (e, "required metadata is missing from cert");
    errno = EINVAL;
    return -1;
error:
    ca_error (e, NULL);
    return -1;
}

int ca_keygen (struct ca *ca, time_t not_valid_before_time,
               int64_t ttl, ca_error_t e)
{
    struct sigcert *cert = NULL;

    if (!ca || ttl < 0 || not_valid_before_time < 0) {
        errno = EINVAL;
        ca_error (e, NULL);
        return -1;
    }
    if (!(cert = sigcert_create ())) {
        ca_error (e, NULL);
        return -1;
    }
    /* Self-sign the certificate, adding the same metadata
     * we would add to a user certificate, except that
     * ca-capability = true.
     */
    if (sign_with (ca, cert, cert, not_valid_before_time, ttl,
                   getuid (), true, e) < 0) {
        sigcert_destroy (cert);
        return -1;
    }
    sigcert_destroy (ca->ca_cert);
    ca->ca_cert = cert;
    return 0;
}

int ca_store (const struct ca *ca, ca_error_t e)
{
    const char *path;

    if (!ca) {
        errno = EINVAL;
        ca_error (e, NULL);
        return -1;
    }
    path = cf_string (cf_get_in (ca->cf, "cert-path"));
    if (!ca->ca_cert) {
        errno = EINVAL;
        ca_error (e, "CA cert was not initialized");
        return -1;
    }
    if (!sigcert_has_secret (ca->ca_cert)) {
        errno = EINVAL;
        ca_error (e, "CA cert does not contain secret key");
        return -1;
    }
    if (sigcert_store (ca->ca_cert, path) < 0) {
        ca_error (e, "%s: %s", path, strerror (errno));
        return -1;
    }
    return 0;
}

int ca_load (struct ca *ca, bool secret, ca_error_t e)
{
    const char *path;
    struct sigcert *cert;

    if (!ca) {
        errno = EINVAL;
        ca_error (e, NULL);
        return -1;
    }
    path = cf_string (cf_get_in (ca->cf, "cert-path"));
    if (!(cert = sigcert_load (path, secret))) {
        ca_error (e, "%s: %s", path, strerror (errno));
        return -1;
    }
    sigcert_destroy (ca->ca_cert);
    ca->ca_cert = cert;
    return 0;
}

const struct sigcert *ca_get_cert (struct ca *ca, ca_error_t e)
{
    if (!ca || !ca->ca_cert) {
        errno = EINVAL;
        ca_error (e, NULL);
        return NULL;
    }
    return ca->ca_cert;
}

int ca_set_cert (struct ca *ca, const struct sigcert *ca_cert, ca_error_t e)
{
    struct sigcert *cpy;

    if (!ca || !ca_cert) {
        errno = EINVAL;
        ca_error (e, NULL);
        return -1;
    }
    if (!(cpy = sigcert_copy (ca_cert))) {
        ca_error (e, NULL);
        return -1;
    }
    sigcert_destroy (ca->ca_cert);
    ca->ca_cert = cpy;
    return 0;
}

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */

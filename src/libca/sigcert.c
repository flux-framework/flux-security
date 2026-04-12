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
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <sodium.h>

#include "src/libutil/tomltk.h"
#include "src/libutil/kv.h"
#include "src/libutil/macros.h"

#include "sigcert.h"

/* Place an upper limit on size of a cert that can be read in.
 * If libtomlc99 integer byte offsets wrap, there will be segfaults.
 * If that ever gets fixed, we would OOM.
 */
static const size_t cert_read_limit = (1024*1024*10); // 10mb

/* Define buffer sizes needed to encode public key, private key,
 * and signature with base64 (including NULL).
 */
#define PUBLICKEY_BASE64_SIZE \
    (sodium_base64_ENCODED_LEN (crypto_sign_PUBLICKEYBYTES, \
                                sodium_base64_VARIANT_ORIGINAL))
#define SECRETKEY_BASE64_SIZE \
    (sodium_base64_ENCODED_LEN (crypto_sign_SECRETKEYBYTES, \
                                sodium_base64_VARIANT_ORIGINAL))
#define SIGN_BASE64_SIZE \
    (sodium_base64_ENCODED_LEN (crypto_sign_BYTES, \
                                sodium_base64_VARIANT_ORIGINAL))

#define FLUX_SIGCERT_MAGIC 0x2349c0ed
struct sigcert {
    int magic;

    uint8_t public_key[crypto_sign_PUBLICKEYBYTES];
    uint8_t secret_key[crypto_sign_SECRETKEYBYTES];
    uint8_t signature[crypto_sign_BYTES];

    struct kv *meta;

    bool secret_valid;
    bool signature_valid;

    struct kv *enc;
};

void sigcert_destroy (struct sigcert *cert)
{
    if (cert) {
        int saved_errno = errno;
        assert (cert->magic == FLUX_SIGCERT_MAGIC);
        kv_destroy (cert->enc);
        kv_destroy (cert->meta);
        memset (cert->public_key, 0, crypto_sign_PUBLICKEYBYTES);
        memset (cert->secret_key, 0, crypto_sign_SECRETKEYBYTES);
        memset (cert->signature, 0, crypto_sign_BYTES);
        cert->magic = ~FLUX_SIGCERT_MAGIC;
        free (cert);
        errno = saved_errno;
    }
}

/* sodium_init() must be called before any other libsodium functions.
 * Checking here should be sufficient since there can be no calls from
 * this module without certs, and all certs are created here.
 */
static struct sigcert *sigcert_alloc (void)
{
    struct sigcert *cert;
    static bool sodium_initialized = false;

    if (!sodium_initialized) {
        if (sodium_init () < 0) {
            errno = EINVAL;
            return NULL;
        }
        sodium_initialized = true;
    }
    if (!(cert = calloc (1, sizeof (*cert))))
        return NULL;
    cert->magic = FLUX_SIGCERT_MAGIC;
    if (!(cert->meta = kv_create ())) {
        errno = ENOMEM;
        goto error;
    }
    return cert;
error:
    sigcert_destroy (cert);
    return NULL;
}

struct sigcert *sigcert_create (void)
{
    struct sigcert *cert;

    if (!(cert = sigcert_alloc ()))
        goto error;
    if (crypto_sign_keypair (cert->public_key, cert->secret_key) < 0)
        goto error;
    if (sigcert_meta_set (cert, "algorithm", SM_STRING, "ed25519") < 0)
        goto error;
    cert->secret_valid = true;
    return cert;
error:
    sigcert_destroy (cert);
    return NULL;
}

struct sigcert *sigcert_copy (const struct sigcert *cert)
{
    struct sigcert *cpy;
    struct kv *metacpy;

    if (!cert) {
        errno = EINVAL;
        return NULL;
    }
    if (!(metacpy = kv_copy (cert->meta)))
        return NULL;
    if (!(cpy = malloc (sizeof (*cpy)))) {
        kv_destroy (metacpy);
        return NULL;
    }
    memcpy (cpy, cert, sizeof (*cpy));
    cpy->meta = metacpy;
    return cpy;
}

void sigcert_forget_secret (struct sigcert *cert)
{
    if (cert && cert->secret_valid) {
        memset (cert->secret_key, 0, crypto_sign_SECRETKEYBYTES);
        cert->secret_valid = false;
    }
}

bool sigcert_has_secret (const struct sigcert *cert)
{
    if (cert && cert->secret_valid)
        return true;
    return false;
}

static enum kv_type type_tokv (enum sigcert_meta_type type)
{
    switch (type) {
        case SM_STRING:
            return KV_STRING;
        case SM_INT64:
            return KV_INT64;
        case SM_DOUBLE:
            return KV_DOUBLE;
        case SM_BOOL:
            return KV_BOOL;
        case SM_TIMESTAMP:
            return KV_TIMESTAMP;
        default:
            return KV_UNKNOWN;
    }
}

/* Don't allow '.' in a key or when it's written out to TOML
 * it will look like TOML hierarchy.
 */
static int sigcert_meta_vset (struct sigcert *cert, const char *key,
                              enum sigcert_meta_type type, va_list ap)
{
    if (!cert || !key || strchr (key, '.')) {
        errno = EINVAL;
        return -1;
    }
    return kv_vput (cert->meta, key, type_tokv (type), ap);
}

int sigcert_meta_set (struct sigcert *cert, const char *key,
                      enum sigcert_meta_type type, ...)
{
    int rc;
    va_list ap;

    va_start (ap, type);
    rc = sigcert_meta_vset (cert, key, type, ap);
    va_end (ap);

    return rc;
}

static int sigcert_meta_vget (const struct sigcert *cert, const char *key,
                              enum sigcert_meta_type type, va_list ap)
{
    if (!cert || !key || strchr (key, '.')) {
        errno = EINVAL;
        return -1;
    }
    return kv_vget (cert->meta, key, type_tokv (type), ap);
}

int sigcert_meta_get (const struct sigcert *cert, const char *key,
                      enum sigcert_meta_type type, ...)
{
    int rc;
    va_list ap;

    va_start (ap, type);
    rc = sigcert_meta_vget (cert, key, type, ap);
    va_end (ap);

    return rc;
}

/* Decode a base64 string string to 'dst', a buffer of size 'dstsz'.
 * The decoded size must exactly match 'dstsz'.
 * Return 0 on success, -1 on error.
 */
static int decode_base64_exact (const char *src, uint8_t *dst, size_t dstsz)
{
    int rc = -1;
    size_t srclen;
    size_t dstlen;

    if (!src)
        goto done;
    srclen = strlen (src);
    if (sodium_base642bin (dst, dstsz, src, srclen,
                           NULL, &dstlen, NULL,
                           sodium_base64_VARIANT_ORIGINAL) < 0)
        goto done;
    if (dstlen != dstsz)
        goto done;
    rc = 0;
done:
    return rc;
}

/* fopen(w) with mode parameter
 */
static FILE *fopen_mode (const char *pathname, mode_t mode)
{
    int fd;
    FILE *fp;

    if ((fd = open (pathname, O_WRONLY | O_TRUNC | O_CREAT | O_CLOEXEC, mode)) < 0)
        return NULL;
    if (!(fp = fdopen (fd, "w"))) {
        close (fd);
        return NULL;
    }
    return fp;
}

/* Write secret-key (only) to 'fp' in TOML format.
 */
static int sigcert_fwrite_secret (const struct sigcert *cert, FILE *fp)
{
    char seckey[SECRETKEY_BASE64_SIZE];

    // [curve]
    if (fprintf (fp, "[curve]\n") < 0)
        return -1;
    sodium_bin2base64 (seckey, sizeof (seckey),
                       cert->secret_key, sizeof (cert->secret_key),
                       sodium_base64_VARIANT_ORIGINAL);
    if (fprintf (fp, "    secret-key = \"%s\"\n", seckey) < 0)
        return -1;
    return 0;
}

/* Write public cert contents (not secret-key) to 'fp' in TOML format.
 */
int sigcert_fwrite_public (const struct sigcert *cert, FILE *fp)
{
    const char *key = NULL;

    // [metadata]
    if (fprintf (fp, "[metadata]\n") < 0)
        goto error;
    while ((key = kv_next (cert->meta, key))) {
        switch (kv_typeof (key)) {
            case KV_STRING:
                if (fprintf (fp, "    %s = \"%s\"\n",
                             key, kv_val_string (key)) < 0)
                    goto error;
                break;
            case KV_INT64:
                if (fprintf (fp, "    %s = %" PRIi64 "\n",
                             key, kv_val_int64 (key)) < 0)
                    goto error;
                break;
            case KV_DOUBLE:
                if (fprintf (fp, "    %s = %f\n",
                             key, kv_val_double (key)) < 0)
                    goto error;
                break;
            case KV_BOOL:       // kv_val_string is "true" or "false"
            case KV_TIMESTAMP:  // kv_val_string is ISO 8601 time string
                if (fprintf (fp, "    %s = %s\n",
                             key, kv_val_string (key)) < 0)
                    goto error;
                break;
            default:
                errno = EINVAL;
                goto error;
        }
    }
    if (fprintf (fp, "\n") < 0)
        goto error;

    // [curve]
    if (fprintf (fp, "[curve]\n") < 0)
        goto error;

    char pubkey[PUBLICKEY_BASE64_SIZE];
    sodium_bin2base64 (pubkey, sizeof (pubkey),
                       cert->public_key, sizeof (cert->public_key),
                       sodium_base64_VARIANT_ORIGINAL);
    if (fprintf (fp, "    public-key = \"%s\"\n", pubkey) < 0)
        goto error;

    if (cert->signature_valid) {
        char sign[SIGN_BASE64_SIZE];
        sodium_bin2base64 (sign, sizeof (sign),
                           cert->signature, sizeof (cert->signature),
                           sodium_base64_VARIANT_ORIGINAL);
        if (fprintf (fp, "    signature = \"%s\"\n", sign) < 0)
            goto error;
    }
    return 0;
error:
    return -1;
}

int sigcert_store (const struct sigcert *cert, const char *name)
{
    FILE *fp = NULL;
    char name_pub[PATH_MAX + 1];
    int saved_errno;

    if (!cert || !name || strlen (name) == 0) {
        errno = EINVAL;
        goto error;
    }
    if (snprintf (name_pub, PATH_MAX + 1, "%s.pub", name) >= PATH_MAX + 1)
        goto error;
    if (!(fp = fopen_mode (name_pub, 0644)))
        goto error;
    if (sigcert_fwrite_public (cert, fp) < 0)
        goto error;
    if (fclose (fp) == EOF) {
        fp = NULL;
        goto error;
    }
    if (cert->secret_valid) {
        if (!(fp = fopen_mode (name, 0600)))
            goto error;
        if (sigcert_fwrite_secret (cert, fp) < 0)
            goto error;
        if (fclose (fp) == EOF) {
            fp = NULL;
            goto error;
        }
    }
    return 0;
error:
    saved_errno = errno;
    if (fp)
        (void)fclose (fp);
    errno = saved_errno;
    return -1;
}

/* Decode a TOML string string to 'dst', a buffer of size 'dstsz'.
 * The decoded size must exactly match 'dstsz'.
 * Return 0 on success, -1 on error with errno set.
 */
static int parse_toml_base64_exact (const char *raw, uint8_t *dst, size_t dstsz)
{
    char *s = NULL;
    int rc = -1;

    if (toml_rtos (raw, &s) < 0)
        goto done;
    if (decode_base64_exact (s, dst, dstsz) < 0) {
        errno = EINVAL;
        goto done;
    }
    rc = 0;
done:
    free (s);
    return rc;
}

static int parse_toml_meta_set (const char *raw, struct sigcert *cert,
                                const char *key)
{
    char *s = NULL;
    int rc = -1;
    int64_t i;
    double d;
    int b;
    toml_timestamp_t ts;

    if (toml_rtos (raw, &s) == 0) {
        if (sigcert_meta_set (cert, key, SM_STRING, s) < 0)
            goto done;
    }
    else if (toml_rtob (raw, &b) == 0) {
        if (sigcert_meta_set (cert, key, SM_BOOL, b) < 0)
            goto done;
    }
    else if (toml_rtoi (raw, &i) == 0) {
        if (sigcert_meta_set (cert, key, SM_INT64, i) < 0)
            goto done;
    }
    else if (toml_rtod (raw, &d) == 0) {
        if (sigcert_meta_set (cert, key, SM_DOUBLE, d) < 0)
            goto done;
    }
    else if (toml_rtots (raw, &ts) == 0) {
        time_t t;
        if (tomltk_ts_to_epoch (&ts, &t) < 0)
            goto done;
        if (sigcert_meta_set (cert, key, SM_TIMESTAMP, t) < 0)
            goto done;
    }
    else
        goto done;
    rc = 0;
done:
    free (s);
    return rc;
}

/* Read NULL-terminated buffer, up to 'limit' bytes in length, including NULL.
 */
static char *freads_limited (FILE *fp, size_t limit)
{
    const size_t chunksz = 1024;
    char *buf = NULL;
    size_t bufsz = 0;
    size_t count = 0;
    int saved_errno;

    if (!fp)
        goto inval;
    if (!(buf = malloc (chunksz)))
        return NULL;
    bufsz += chunksz;
    while (!feof (fp)) {
        if (bufsz - count <= 1) { // need a min of NULL + 1 char to continue
            char *newbuf;
            if (!(newbuf = realloc (buf, bufsz + chunksz)))
                goto error;
            buf = newbuf;
            bufsz += chunksz;
        }
        count += fread (buf + count, 1, bufsz - count - 1, fp); // reserve NULL
        if (ferror (fp))
            goto error;
        if (count > limit)
            goto inval;
    }
    assert (count < bufsz);
    buf[count] = '\0';
    return buf;
inval:
    errno = EINVAL;
error:
    saved_errno = errno;
    free (buf);
    errno = saved_errno;
    return NULL;
}

/* Read in secret-key.
 */
static int sigcert_fread_secret (struct sigcert *cert, FILE *fp)
{
    toml_table_t *cert_table = NULL;
    toml_table_t *curve_table;
    const char *raw;
    char errbuf[200];
    char *conf;

    if (!(conf = freads_limited (fp, cert_read_limit)))
        return -1;
    if (!(cert_table = toml_parse (conf, errbuf, sizeof (errbuf))))
        goto inval;
    if (!(curve_table = toml_table_in (cert_table, "curve")))
        goto inval;
    if (!(raw = toml_raw_in (curve_table, "secret-key")))
        goto inval;
    if (parse_toml_base64_exact (raw, cert->secret_key,
                                 sizeof (cert->secret_key)) < 0)
        goto inval;
    cert->secret_valid = true;
    free (conf);
    toml_free (cert_table);
    return 0;
inval:
    free (conf);
    toml_free (cert_table);
    errno = EINVAL;
    return -1;
}

/* Read public cert contents from 'fp' in TOML format.
 */
struct sigcert *sigcert_fread_public (FILE *fp)
{
    struct sigcert *cert;
    toml_table_t *cert_table = NULL;
    toml_table_t *curve_table;
    toml_table_t *meta_table;
    const char *key;
    const char *raw;
    int i;
    char errbuf[200];
    char *conf;

    if (!(cert = sigcert_alloc ()))
        return NULL;
    if (!(conf = freads_limited (fp, cert_read_limit))) {
        sigcert_destroy (cert);
        return NULL;
    }
    if (!(cert_table = toml_parse (conf, errbuf, sizeof (errbuf))))
        goto inval;

    // [metadata]
    if (!(meta_table = toml_table_in (cert_table, "metadata")))
        goto inval;
    for (i = 0; (key = toml_key_in (meta_table, i)); i++) {
        if (!(raw = toml_raw_in (meta_table, key)))
            goto inval;
        if (parse_toml_meta_set (raw, cert, key) < 0)
            goto inval;
    }

    // [curve]
    if (!(curve_table = toml_table_in (cert_table, "curve")))
        goto inval;
    if (!(raw = toml_raw_in (curve_table, "public-key")))
        goto inval;
    if (parse_toml_base64_exact (raw, cert->public_key,
                                 sizeof (cert->public_key)) < 0)
        goto inval;
    if ((raw = toml_raw_in (curve_table, "signature"))) { // optional
        if (parse_toml_base64_exact (raw, cert->signature,
                                     sizeof (cert->signature)) < 0)
            goto inval;
        cert->signature_valid = true;
    }
    free (conf);
    toml_free (cert_table);
    return cert;
inval:
    free (conf);
    toml_free (cert_table);
    sigcert_destroy (cert);
    errno = EINVAL;
    return NULL;
}

struct sigcert *sigcert_load (const char *name, bool secret)
{
    FILE *fp = NULL;
    char name_pub[PATH_MAX + 1];
    int saved_errno;
    struct sigcert *cert = NULL;

    if (!name)
        goto inval;
    if (snprintf (name_pub, PATH_MAX + 1, "%s.pub", name) >= PATH_MAX + 1)
        goto inval;
    // name.pub - public
    if (!(fp = fopen (name_pub, "r")))
        goto error;
    if (!(cert = sigcert_fread_public (fp)))
        goto error;
    if (fclose (fp) < 0) {
        fp = NULL; /* fclose() closes file even on error */
        goto error;
    }
    fp = NULL;
    // name - secret
    if (secret) {
        if (!(fp = fopen (name, "r")))
            goto error;
        if (sigcert_fread_secret (cert, fp) < 0)
            goto error;
        if (fclose (fp) < 0) {
            fp = NULL; /* fclose() closes file even on error */
            goto error;
        }
        fp = NULL;
    }
    return cert;
inval:
    errno = EINVAL;
error:
    saved_errno = errno;
    if (fp)
        (void)fclose (fp);
    sigcert_destroy (cert);
    errno = saved_errno;
    return NULL;
}

/* Decode a kv string key to 'dst', a buffer of size 'dstsz'.
 * The decoded size must exactly match 'dstsz'.
 * Return 0 on success, -1 on error with errno set.
 */
static int get_base64_exact (struct kv *kv, const char *key,
                             uint8_t *dst, size_t dstsz)
{
    const char *src;
    if (kv_get (kv, key, KV_STRING, &src) < 0)
        return -1;
    if (decode_base64_exact (src, dst, dstsz) < 0) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

struct sigcert *sigcert_decode (const char *s, int len)
{
    struct kv *kv;
    struct sigcert *cert;

    if (!s || len == 0) {
        errno = EINVAL;
        return NULL;
    }
    if (!(kv = kv_decode (s, len)))
        return NULL;
    if (!(cert = sigcert_alloc ()))
        goto error;

    kv_destroy (cert->meta);
    if (!(cert->meta = kv_split (kv, "meta.")))
        goto error;
    if (get_base64_exact (kv, "curve.public-key",
                          cert->public_key, sizeof (cert->public_key)) < 0)
        goto error;
    if (get_base64_exact (kv, "curve.signature",
                          cert->signature, sizeof (cert->signature)) == 0)
        cert->signature_valid = true;
    else if (errno != ENOENT)
        goto error;
    kv_destroy (kv);
    return cert;
error:
    kv_destroy (kv);
    sigcert_destroy (cert);
    return NULL;
}

int sigcert_encode (const struct sigcert *cert, const char **buf, int *len)
{
    char pubkey[PUBLICKEY_BASE64_SIZE];

    if (!cert || !buf || !len) {
        errno = EINVAL;
        return -1;
    }
    kv_destroy (cert->enc);
    if (!(((struct sigcert *)(cert))->enc = kv_create()))
        return -1;
    if (kv_join (cert->enc, cert->meta, "meta.") < 0)
        return -1;
    sodium_bin2base64 (pubkey, sizeof (pubkey),
                       cert->public_key, sizeof (cert->public_key),
                       sodium_base64_VARIANT_ORIGINAL);
    if (kv_put (cert->enc, "curve.public-key", KV_STRING, pubkey) < 0)
        return -1;
    if (cert->signature_valid) {
        char sign[SIGN_BASE64_SIZE];
        sodium_bin2base64 (sign, sizeof (sign),
                           cert->signature, sizeof (cert->signature),
                           sodium_base64_VARIANT_ORIGINAL);
        if (kv_put (cert->enc, "curve.signature", KV_STRING, sign) < 0)
            return -1;
    }
    return kv_encode (cert->enc, buf, len);
}

bool sigcert_equal (const struct sigcert *cert1,
                    const struct sigcert *cert2)
{
    if (!cert1 || !cert2)
        return false;
    if (!kv_equal (cert1->meta, cert2->meta))
        return false;
    if (memcmp (cert1->public_key, cert2->public_key,
                                   crypto_sign_PUBLICKEYBYTES) != 0)
        return false;
    if (cert1->secret_valid != cert2->secret_valid)
        return false;
    if (cert1->secret_valid) {
        if (memcmp (cert1->secret_key, cert2->secret_key,
                                       crypto_sign_SECRETKEYBYTES) != 0)
            return false;
    }
    return true;
}

char *sigcert_sign_detached (const struct sigcert *cert,
                             const uint8_t *buf, int len)
{
    uint8_t sig[crypto_sign_BYTES];
    char *sig_base64;

    if (!cert || !cert->secret_valid || len < 0 || (len > 0 && buf == NULL)) {
        errno = EINVAL;
        return NULL;
    }
    if (crypto_sign_detached (sig, NULL, buf, len, cert->secret_key) < 0) {
        errno = EINVAL;
        return NULL;
    }
    if (!(sig_base64 = calloc (1, SIGN_BASE64_SIZE)))
        return NULL;
    sodium_bin2base64 (sig_base64, SIGN_BASE64_SIZE,
                       sig, sizeof (sig),
                       sodium_base64_VARIANT_ORIGINAL);
    return sig_base64;
}

int sigcert_verify_detached (const struct sigcert *cert,
                             const char *signature,
                             const uint8_t *buf, int len)
{
    uint8_t sig[crypto_sign_BYTES];

    if (!cert || !signature || len < 0 || (len > 0 && buf == NULL)) {
        errno = EINVAL;
        return -1;
    }
    if (decode_base64_exact (signature, sig, sizeof (sig)) < 0) {
        errno = EINVAL;
        return -1;
    }
    if (crypto_sign_verify_detached (sig, buf, len, cert->public_key) < 0) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

/* Serialize cert2, excluding secret + signature, sign with cert1.
 * Add 'signature' attribute to [curve] stanza.
 */
int sigcert_sign_cert (const struct sigcert *cert1,
                       struct sigcert *cert2)
{
    struct kv *kv;
    const char *kv_s;
    int kv_len;
    int rc = -1;
    char pubkey[PUBLICKEY_BASE64_SIZE];

    if (!cert1 || !cert2 || !cert1->secret_valid) {
        errno = EINVAL;
        return -1;
    }
    if (!(kv = kv_create()))
        return -1;
    sodium_bin2base64 (pubkey, sizeof (pubkey),
                       cert2->public_key, sizeof (cert2->public_key),
                       sodium_base64_VARIANT_ORIGINAL);
    if (kv_put (kv, "curve.public_key", KV_STRING, pubkey) < 0)
        goto done;
    if (kv_join (kv, cert2->meta, "meta.") < 0)
        goto done;
    if (kv_encode (kv, &kv_s, &kv_len) < 0)
        goto done;
    if (crypto_sign_detached (cert2->signature, NULL,
                              (uint8_t *)kv_s, kv_len,
                              cert1->secret_key) < 0) {
        errno = EINVAL;
        goto done;
    }
    cert2->signature_valid = true;
    rc = 0;
done:
    kv_destroy (kv);
    return rc;
}

int sigcert_verify_cert (const struct sigcert *cert1,
                         const struct sigcert *cert2)
{
    struct kv *kv;
    const char *kv_s;
    int kv_len;
    int rc = -1;
    char pubkey[PUBLICKEY_BASE64_SIZE];

    if (!cert1 || !cert2 || !cert2->signature_valid) {
        errno = EINVAL;
        return -1;
    }
    if (!(kv = kv_create()))
        return -1;
    sodium_bin2base64 (pubkey, sizeof (pubkey),
                       cert2->public_key, sizeof (cert2->public_key),
                       sodium_base64_VARIANT_ORIGINAL);
    if (kv_put (kv, "curve.public_key", KV_STRING, pubkey) < 0)
        goto done;
    if (kv_join (kv, cert2->meta, "meta.") < 0)
        goto done;
    if (kv_encode (kv, &kv_s, &kv_len) < 0)
        goto done;
    if (crypto_sign_verify_detached (cert2->signature,
                                     (uint8_t *)kv_s, kv_len,
                                     cert1->public_key) < 0) {
        errno = EINVAL;
        goto done;
    }
    rc = 0;
done:
    kv_destroy (kv);
    return rc;
}

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */

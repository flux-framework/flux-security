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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <time.h>
#include <stdarg.h>
#include <assert.h>

#include "timestamp.h"
#include "kv.h"
#include "strlcpy.h"

#define KV_CHUNK 4096

struct kv {
    char *buf;
    int bufsz;
    int len;
};

void kv_destroy (struct kv *kv)
{
    if (kv) {
        int saved_errno = errno;
        free (kv->buf);
        free (kv);
        errno = saved_errno;
    }
}

/* Create kv object from 'buf' and 'len'.
 * If len == 0, create an empty object.
 * Returns object on success, NULL on failure with errno set.
 */
static struct kv *kv_create_from (const char *buf, int len)
{
    struct kv *kv;

    if (len < 0 || (len > 0 && !buf)) {
        errno = EINVAL;
        return NULL;
    }
    if (!(kv = calloc (1, sizeof (*kv))))
        return NULL;
    if (len > 0) {
        if (!(kv->buf = malloc (len))) {
            kv_destroy (kv);
            return NULL;
        }
        memcpy (kv->buf, buf, len);
        kv->bufsz = kv->len = len;
    }
    return kv;
}

struct kv *kv_create (void)
{
    return kv_create_from (NULL, 0);
}

struct kv *kv_copy (const struct kv *kv)
{
    if (!kv) {
        errno = EINVAL;
        return NULL;
    }
    return kv_create_from (kv->buf, kv->len);
}

bool kv_equal (const struct kv *kv1, const struct kv *kv2)
{
    if (!kv1 || !kv2)
        return false;
    if (kv1->len != kv2->len)
        return false;
    if (memcmp (kv1->buf, kv2->buf, kv1->len) != 0)
        return false;
    return true;
}

/* Grow kv buffer until it can accommodate 'needsz' new characters.
 * Returns 0 on success, -1 on failure with errno set.
 */
static int kv_expand (struct kv *kv, int needsz)
{
    char *new;
    while (kv->bufsz - kv->len < needsz) {
        if (!(new = realloc (kv->buf, kv->bufsz + KV_CHUNK)))
            return -1;
        kv->buf = new;
        kv->bufsz += KV_CHUNK;
    }
    return 0;
}

static bool valid_key (const char *key)
{
    if (!key || *key == '\0')
        return false;
    return true;
}

/* Look up entry by key (and type if type != KV_UNKNOWN).
 * Returns entry on success, NULL on failure with errno set.
 */
static const char *kv_find (const struct kv *kv, const char *key,
                            enum kv_type type)
{
    const char *entry = NULL;

    if (!kv || !valid_key (key)) {
        errno = EINVAL;
        return NULL;
    }
    while ((entry = kv_next (kv, entry))) {
        if (!strcmp (key, entry)) {
            if (type == KV_UNKNOWN || kv_typeof (entry) == type)
                return entry;
            break;
        }
    }
    errno = ENOENT;
    return NULL;
}

/* Return length, not to exceed maxlen, of entry consisting of key\0Tvalue\0
 * Return -1 on invalid entry.
 */
static int entry_length (const char *entry, int maxlen)
{
    int keylen;
    int vallen; // including T

    keylen = strnlen (entry, maxlen);
    if (keylen == 0 || keylen == maxlen)
        return -1;
    entry += keylen + 1;
    maxlen -= keylen + 1;
    vallen = strnlen (entry, maxlen);
    if (vallen == 0 || vallen == maxlen)
        return -1;
    return keylen + vallen + 2;
}

int kv_delete (struct kv *kv, const char *key)
{
    const char *entry;
    int entry_offset;
    int entry_len;

    if (!(entry = kv_find (kv, key, KV_UNKNOWN)))
        return -1;
    entry_offset = entry - kv->buf;
    entry_len = entry_length (entry, kv->len - entry_offset);
    assert (entry_len >= 0);
    memmove (kv->buf + entry_offset,
             kv->buf + entry_offset + entry_len,
             kv->len - entry_offset - entry_len);
    kv->len -= entry_len;
    return 0;
}

/* Put 'val' of a given type that has been already been converted to a string.
 * Returns 0 on success, -1 on failure with errno set.
 */
static int kv_put_raw (struct kv *kv, const char *key, enum kv_type type,
                       const char *val)
{
    if (!kv || !valid_key (key) || !val) {
        errno = EINVAL;
        return -1;
    }
    if (kv_delete (kv, key) < 0) {
        if (errno != ENOENT)
            return -1;
    }
    int keylen = strlen (key);
    int vallen = strlen (val);
    if (kv_expand (kv, keylen + vallen + 3) < 0) // key\0Tval\0
        return -1;
    strlcpy (&kv->buf[kv->len], key, keylen + 1);
    kv->len += keylen + 1;
    kv->buf[kv->len++] = type;
    strlcpy (&kv->buf[kv->len], val, vallen + 1);
    kv->len += vallen + 1;
    return 0;
}

int kv_vput (struct kv *kv, const char *key, enum kv_type type, va_list ap)
{
    char s[512]; // -DBL_MAX with 6 digit precision + \0 is 318 characters
    const char *val = NULL;

    if (!kv || !valid_key (key))
        goto inval;
    switch (type) {
        case KV_STRING:
            val = va_arg (ap, const char *);
            break;
        case KV_INT64:
            if (vsnprintf (s, sizeof (s), "%" PRIi64, ap) >= sizeof (s))
                goto inval;
            val = s;
            break;
        case KV_DOUBLE:
            if (vsnprintf (s, sizeof (s), "%f", ap) >= sizeof (s))
                goto inval;
            val = s;
            break;
        case KV_BOOL: {
            bool b = va_arg (ap, int); // va promotes bool to int
            val = b ? "true" : "false";
            break;
        }
        case KV_TIMESTAMP: {
            time_t t = va_arg (ap, time_t);
            if (timestamp_tostr (t, s, sizeof (s)) < 0)
                goto inval;
            val = s;
            break;
        }
        default:
            goto inval;
    }
    if (!val)
        goto inval;
    return kv_put_raw (kv, key, type, val);
inval:
    errno = EINVAL;
    return -1;
}

int kv_put (struct kv *kv, const char *key, enum kv_type type, ...)
{
    va_list ap;
    int rc;

    va_start (ap, type);
    rc = kv_vput (kv, key, type, ap);
    va_end (ap);
    return rc;
}

const char *kv_next (const struct kv *kv, const char *key)
{
    int entry_len;
    int entry_offset;

    if (!kv || kv->len == 0)
        return NULL;
    if (!key)
        return kv->buf;
    if (key < kv->buf || key > kv->buf + kv->len)
        return NULL;
    entry_offset = key - kv->buf;
    entry_len = entry_length (key, kv->len - entry_offset);
    if (entry_len < 0 || entry_offset + entry_len == kv->len)
        return NULL;
    return key + entry_len;
}

const char *kv_val_string (const char *key)
{
    if (!key)
        return "";
    return &key[strlen (key) + 2];
}

int64_t kv_val_int64 (const char *key)
{
    return strtoll (kv_val_string (key), NULL, 10);
}

double kv_val_double (const char *key)
{
    return strtod (kv_val_string (key), NULL);
}

bool kv_val_bool (const char *key)
{
    const char *s = kv_val_string (key);
    if (!strcmp (s, "false") || strlen (s) == 0)
        return false;
    else
        return true;
}

time_t kv_val_timestamp (const char *key)
{
    time_t t;
    const char *s = kv_val_string (key);
    if (timestamp_fromstr (s, &t) < 0)
        return 0;
    return t;
}

enum kv_type kv_typeof (const char *key)
{
    if (!key)
        return KV_UNKNOWN;
    enum kv_type type = key[strlen (key) + 1];
    switch (type) {
        case KV_STRING:
        case KV_INT64:
        case KV_DOUBLE:
        case KV_BOOL:
        case KV_TIMESTAMP:
            return type;
        default:
            return KV_UNKNOWN;
    }
}

int kv_vget (const struct kv *kv, const char *key,
             enum kv_type type, va_list ap)
{
    const char *entry = kv_find (kv, key, type);
    if (!entry)
        return -1;
    switch (type) {
        case KV_STRING: {
            const char **val = va_arg (ap, const char **);
            if (val)
                *val = kv_val_string (entry);
            break;
        }
        case KV_INT64: {
            int64_t *val = va_arg (ap, int64_t *);
            if (val)
                *val = kv_val_int64 (entry);
            break;
        }
        case KV_DOUBLE: {
            double *val = va_arg (ap, double *);
            if (val)
                *val = kv_val_double (entry);
            break;
        }
        case KV_BOOL: {
            bool *val = va_arg (ap, bool *);
            if (val)
                *val = kv_val_bool (entry);
            break;
        }
        case KV_TIMESTAMP: {
            time_t *val = va_arg (ap, time_t *);
            if (val)
                *val = kv_val_timestamp (entry);
            break;
        }
        default:
            errno = EINVAL;
            return -1;
    }
    return 0;
}

int kv_get (const struct kv *kv, const char *key, enum kv_type type, ...)
{
    va_list ap;
    int rc;

    va_start (ap, type);
    rc = kv_vget (kv, key, type, ap);
    va_end (ap);
    return rc;
}

/* Validate a just-decoded kv buffer.
 * Return 0 on success, -1 on failure with errno set.
 */
static int kv_check_integrity (struct kv *kv)
{
    int nullcount;
    int i;
    const char *key = NULL;

    /* properly terminated
     */
    if (kv->len > 0 && kv->buf[kv->len - 1] != '\0')
        goto inval;

    /* even number of nulls
     */
    nullcount = 0;
    for (i = 0; i < kv->len; i++) {
        if (kv->buf[i] == '\0')
            nullcount++;
    }
    if (nullcount % 2 != 0)
        goto inval;

    /* nonzero key length
     * value has valid type hint char
     */
    while ((key = kv_next (kv, key))) {
        if (strlen (key) == 0)
            goto inval;
        if (kv_typeof (key) == KV_UNKNOWN)
            goto inval;
    }
    return 0;
inval:
    errno = EINVAL;
    return -1;
}

int kv_encode (const struct kv *kv, const char **buf, int *len)
{
    if (!kv || !buf || !len) {
        errno = EINVAL;
        return -1;
    }
    *buf = kv->buf;
    *len = kv->len;
    return 0;
}

struct kv *kv_decode (const char *buf, int len)
{
    struct kv *kv;

    if (!(kv = kv_create_from (buf, len)))
        return NULL;
    if (kv_check_integrity (kv) < 0) {
        kv_destroy (kv);
        return NULL;
    }
    return kv;
}

/* Wrapper for kv_put_raw() which adds 'prefix' to key, if non-NULL.
 * Returns 0 on success, -1 on failure with errno set (ENOMEM).
 */
static int kv_put_prefix (struct kv *kv, const char *prefix, const char *key,
                          enum kv_type type, const char *val)
{
    char *newkey = NULL;

    if (prefix) {
        if (asprintf (&newkey, "%s%s", prefix, key) < 0)
            return -1;
        key = newkey;
    }
    if (kv_put_raw (kv, key, type, val) < 0) {
        int saved_errno = errno;
        free (newkey);
        errno = saved_errno;
        return -1;
    }
    free (newkey);
    return 0;
}

int kv_join (struct kv *kv1, const struct kv *kv2, const char *prefix)
{
    const char *key = NULL;

    while ((key = kv_next (kv2, key))) {
        if (kv_put_prefix (kv1, prefix, key, kv_typeof (key),
                                             kv_val_string (key)) < 0)
            return -1;
    }
    return 0;
}

struct kv *kv_split (const struct kv *kv1, const char *prefix)
{
    const char *key = NULL;
    struct kv *kv2;
    int n = prefix ? strlen (prefix) : 0;

    if (!(kv2 = kv_create ()))
        return NULL;
    while ((key = kv_next (kv1, key))) {
        if (strlen (key) > n && !strncmp (key, prefix, n)) {
            if (kv_put_raw (kv2, key + n, kv_typeof (key),
                                          kv_val_string (key)) < 0) {
                kv_destroy (kv2);
                return NULL;
            }
        }
    }
    return kv2;
}

void kv_environ_destroy (char ***envp)
{
    if (envp) {
        int saved_errno = errno;
        char **env = *envp;
        while (*env != NULL)
            free (*env++);
        free (*envp);
        *envp = NULL;
        errno = saved_errno;
    }
}

int kv_expand_environ (const struct kv *kv, char ***envp)
{
    char **env, **p;
    const char *var = NULL;
    int size = 0;

    if (kv == NULL || envp == NULL) {
        errno = EINVAL;
        return -1;
    }

    while ((var = kv_next (kv, var)))
        size++;
    if (!(env = calloc (size+1, sizeof (char *))))
        return -1;
    p = env;
    while ((var = kv_next (kv, var))) {
        char *entry;
        if (asprintf (&entry, "%s=%s", var, kv_val_string (var)) < 0)
            goto error;
        (*p++) = entry;
    }
    *envp = env;
    return 0;
error:
    kv_environ_destroy (&env);
    return -1;
}

void kv_argv_destroy (char ***argvp)
{
    kv_environ_destroy (argvp);
}

int kv_expand_argv (const struct kv *kv, char ***argvp)
{
    char **argv, **p;
    const char *var = NULL;
    int argc = 0;

    if (kv == NULL || argvp == NULL) {
        errno = EINVAL;
        return -1;
    }

    while ((var = kv_next (kv, var)))
        argc++;

    if (!(argv = calloc (argc+1, sizeof (char *))))
        return -1;

    p = argv;
    while ((var = kv_next (kv, var))) {
        if (!(*p = strdup (kv_val_string (var))))
            goto error;
        p++;
    }
    *argvp = argv;
    return 0;
error:
    kv_argv_destroy (&argv);
    return -1;
}

struct kv *kv_encode_argv (const char **argv)
{
    struct kv * kv;
    if (!argv) {
        errno = EINVAL;
        return NULL;
    }
    if (!(kv = kv_create ()))
        return NULL;
    for (int i = 0; argv[i] != NULL; i++) {
        char key [21];
        (void) sprintf (key, "%d", i);
        if (kv_put (kv, key, KV_STRING, argv[i]) < 0)
            goto error;
    }
    return kv;
error:
    kv_destroy (kv);
    return NULL;
}

/*
 * vi:tabstop=4 shiftwidth=4 expandtab
 */

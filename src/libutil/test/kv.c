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
#include "config.h"
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#include "src/libtap/tap.h"
#include "kv.h"

static void diag_kv (struct kv *kv)
{
    const char *buf;
    int len;
    int i;

    if (kv_encode (kv, &buf, &len) < 0)
        BAIL_OUT ("diag_kv: %s", strerror (errno));
    printf ("# ");
    for (i = 0; i < len; i++) {
        if (buf[i] == '\0')
            printf ("\\0");
        else
            putchar (buf[i]);
    }
    putchar ('\n');
}

static void simple_test (void)
{
    struct kv *kv;
    struct kv *kv2;
    struct kv *kv3;
    const char *s;
    int64_t i;
    double d;
    bool b;
    time_t t;
    const char *key;
    int len;
    time_t now;

    if (time (&now) < 0)
        BAIL_OUT ("time() failed: %s", strerror (errno));

    /* Create kv object and set a=foo, b=bar, c=baz.
     * Validate values.
     */
    kv = kv_create ();
    ok (kv != NULL,
        "kv_create works");
    ok (kv_put (kv, "a", KV_STRING, "foo") == 0,
        "kv_put a=foo works");
    ok (kv_get (kv, "a", KV_STRING, &s) == 0 && !strcmp (s, "foo"),
        "kv_get a retrieves correct value");
    ok (kv_put (kv, "b", KV_INT64, 42LL) == 0,
        "kv_put b=42 works");
    ok (kv_put (kv, "c", KV_DOUBLE, 3.14) == 0,
        "kv_put c=3.14 works");
    ok (kv_put (kv, "d", KV_BOOL, true) == 0,
        "kv_put d=true works");
    ok (kv_put (kv, "e", KV_TIMESTAMP, now) == 0,
        "kv_put e=(now) works");
    diag_kv (kv);

    ok (kv_get (kv, "a", KV_STRING, &s) == 0 && !strcmp (s, "foo"),
        "kv_get a retrieves correct value");
    ok (kv_get (kv, "b", KV_INT64, &i) == 0 && i == 42,
        "kv_get b retrieves correct value");
    ok (kv_get (kv, "c", KV_DOUBLE, &d) == 0 && d == 3.14,
        "kv_get c retrieves correct value");
    ok (kv_get (kv, "d", KV_BOOL, &b) == 0 && b == true,
        "kv_get d retrieves correct value");
    ok (kv_get (kv, "e", KV_TIMESTAMP, &t) == 0 && t == now,
        "kv_get e retrieves correct value");
    errno = 0;
    ok (kv_get (kv, "f", KV_STRING, &s) < 0 && errno == ENOENT,
        "kv_get f fails with ENOENT");

    /* Iterate over entries.
     */
    key = kv_next (kv, NULL);
    ok (key != NULL && !strcmp (key, "a"),
        "kv_next returned correct key");
    ok (kv_typeof (key) == KV_STRING,
        "kv_typeof return KV_STRING");
    ok (!strcmp (kv_val_string (key), "foo"),
        "kv_val_string returned correct value");

    key = kv_next (kv, key);
    ok (key != NULL && !strcmp (key, "b"),
        "kv_next returned correct key");
    ok (kv_typeof (key) == KV_INT64,
        "kv_typeof return KV_INT64");
    ok (kv_val_int64 (key) == 42,
        "kv_val_int64 returned correct value");

    key = kv_next (kv, key);
    ok (key != NULL && !strcmp (key, "c"),
        "kv_next returned correct key");
    ok (kv_typeof (key) == KV_DOUBLE,
        "kv_typeof returned KV_DOUBLE");
    ok (kv_val_double (key) == 3.14,
        "kv_val_double returned correct value");

    key = kv_next (kv, key);
    ok (key != NULL && !strcmp (key, "d"),
        "kv_next returned correct key");
    ok (kv_typeof (key) == KV_BOOL,
        "kv_typeof returned KV_BOOL");
    ok (kv_val_bool (key) == true,
        "kv_val_bool returned correct value");

    key = kv_next (kv, key);
    ok (key != NULL && !strcmp (key, "e"),
        "kv_next returned correct key");
    ok (kv_typeof (key) == KV_TIMESTAMP,
        "kv_typeof returned KV_TIMESTAMP");
    ok (kv_val_timestamp (key) == now,
        "kv_val_timestamp returned correct value");

    ok (kv_next (kv, key) == NULL,
        "kv_next returned NULL at end");

    /* Create a new copy through kv_copy() and check for equality.
     */
    kv2 = kv_copy (kv);
    ok (kv2 != NULL,
        "kv_copy works");
    ok (kv_equal (kv, kv2),
        "kv_equal says new copy is identical");

    /* Create a new copy through raw "codec" and check for equality.
     */
    ok (kv_encode (kv, &s, &len) == 0,
        "kv_encode works");
    kv3 = kv_decode (s, len);
    ok (kv3 != NULL,
        "kv_decode works");
    ok (kv_equal (kv, kv3),
        "kv_equal says new copy is identical");

    kv_destroy (kv);
    kv_destroy (kv2);
    kv_destroy (kv3);
}

static void empty_object (void)
{
    struct kv *kv, *kv2;
    const char *buf;
    int len;

    kv = kv_create ();
    ok (kv != NULL,
        "kv_create works");
    ok (kv_next (kv, NULL) == NULL,
        "kv_next key=NULL returns NULL");
    ok (kv_encode (kv, &buf, &len) == 0,
        "kv_encode works");

    kv2 = kv_decode (buf, len);
    ok (kv2 != NULL,
        "kv_decode works");
    ok (kv_equal (kv, kv2),
        "kv_equal says they are identical");

    kv_destroy (kv);
    kv_destroy (kv2);
}

static void check_expansion (void)
{
    struct kv *kv;
    char keybuf[64];
    char valbuf[64];
    const char *s;
    int i;

    kv = kv_create ();
    ok (kv != NULL,
        "kv_create works");

    /* Add entries
     * Each entry will be 32+3 + 1 + 32 + 1 = 69 bytes.
     * Add 100 of them to ensure 4096 byte "chunk size" is exceeded,
     * so object has to grow at least once.
     */
    for (i = 0; i < 100; i++) {
        snprintf (keybuf, sizeof (keybuf), "key%032d", i);
        snprintf (valbuf, sizeof (valbuf), "%032d", i);
        if (kv_put (kv, keybuf, KV_STRING, valbuf) < 0)
            break;
    }
    ok (i == 100,
        "kv_put added 100 69-byte entries");

    for (i = 0; i < 100; i++) {
        snprintf (keybuf, sizeof (keybuf), "key%032d", i);
        snprintf (valbuf, sizeof (valbuf), "%032d", i);
        if (kv_get (kv, keybuf, KV_STRING, &s) < 0 || strcmp (s, valbuf) != 0)
            break;
    }
    ok (i == 100,
        "kv_get verified 100 69-byte entries");

    kv_destroy (kv);
}

static void bad_parameters (void)
{
    struct kv *kv;
    struct kv *kv2;
    const char *s;
    const char *entry;
    int len;

    /* Create two kv objects:  kv (empty), and kv2 (non-empty).
     */
    if (!(kv = kv_create ()))
        BAIL_OUT ("kv_create failed");
    if (!(kv2 = kv_create ()))
        BAIL_OUT ("kv_create failed");
    if (kv_put (kv2, "foo", KV_STRING, "bar") < 0)
        BAIL_OUT ("kv_put failed");
    if (!(entry = kv_next (kv2, NULL)))
        BAIL_OUT ("kv_next kv=(one entry) key=NULL returned NULL");

    /* kv_copy
     */
    errno = 0;
    ok (kv_copy (NULL) == NULL && errno == EINVAL,
        "kv_copy kv=NULL fails with EINVAL");

    /* kv_equal
     */
    ok (kv_equal (kv, NULL) == false,
        "kv_equal kv1=NULL returns false");
    ok (kv_equal (NULL, kv) == false,
        "kv_equal kv2=NULL returns false");
    ok (kv_equal (NULL, NULL) == false,
        "kv_equal kv1=NULL kv2=NULL returns false");

    /* kv_put
     */
    errno = 0;
    ok (kv_put (NULL, "foo", KV_STRING, "bar") < 0 && errno == EINVAL,
        "kv_put kv=NULL fails with EINVAL");
    errno = 0;
    ok (kv_put (kv, NULL, KV_STRING, "bar") < 0 && errno == EINVAL,
        "kv_put key=NULL fails with EINVAL");
    errno = 0;
    ok (kv_put (kv, "", KV_STRING, NULL) < 0 && errno == EINVAL,
        "kv_put key="" fails with EINVAL");
    errno = 0;
    ok (kv_put (kv, "foo", KV_STRING, NULL) < 0 && errno == EINVAL,
        "kv_put_string val=NULL fails with EINVAL");

    errno = 0;
    ok (kv_put (kv, "foo", KV_TIMESTAMP, (time_t)-1) < 0 && errno == EINVAL,
        "kv_put_timestamp val=-1 fails with EINVAL");

    /* kv_get
     */
    errno = 0;
    ok (kv_get (NULL, "foo", KV_STRING, &s) < 0 && errno == EINVAL,
        "kv_get kv=NULL fails with EINVAL");
    errno = 0;
    ok (kv_get (kv, NULL, KV_STRING, &s) < 0 && errno == EINVAL,
        "kv_get key=NULL fails with EINVAL");
    errno = 0;
    ok (kv_get (kv, "", KV_STRING, &s) < 0 && errno == EINVAL,
        "kv_get_string key="" fails with EINVAL");

    /* iteration
     */
    ok (kv_next (NULL, entry) == NULL,
       "kv_next kv=NULL returns NULL");
    ok (kv_next (kv2, entry) == NULL,
       "kv_next kv=(one entry) returns NULL");
    ok (kv_next (kv2, entry - 4096) == NULL,
       "kv_next entry=(< lower bound) == NULL");
    ok (kv_next (kv2, entry + 4096) == NULL,
       "kv_next entry=(> upper bound) == NULL");

    ok (kv_typeof (NULL) == KV_UNKNOWN,
        "kv_typeof key=NULL returns KV_UNKNOWN");
    s = kv_val_string (NULL);
    ok (s != NULL && !strcmp (s, ""),
        "kv_val_string key=NULL returns empty string");
    ok (kv_val_int64 (NULL) == 0,
        "kv_val_int64 key=NULL returns 0");
    ok (kv_val_double (NULL) == 0.,
        "kv_val_double key=NULL returns 0.");
    ok (kv_val_double (NULL) == 0.,
        "kv_val_bool key=NULL returns false");
    ok (kv_val_timestamp (NULL) == 0.,
        "kv_val_timestamp key=NULL returns 0");

    /* kv_encode
     */
    errno = 0;
    ok (kv_encode (NULL, &s, &len) < 0 && errno == EINVAL,
        "kv_encode kv=NULL fails with EINVAL");
    errno = 0;
    ok (kv_encode (kv, NULL, &len) < 0 && errno == EINVAL,
        "kv_encode buf=NULL fails with EINVAL");
    errno = 0;
    ok (kv_encode (kv, &s, NULL) < 0 && errno == EINVAL,
        "kv_encode len=NULL fails with EINVAL");

    /* kv_decode
     */
    errno = 0;
    ok (kv_decode ("foo\0sbar\0", -1) == NULL && errno == EINVAL,
        "kv_decode len=-1 fails with EINVAL");
    errno = 0;
    ok (kv_decode (NULL, 1) == NULL && errno == EINVAL,
        "kv_decode buf=NULL len=1 fails with EINVAL");
    errno = 0;
    ok (kv_decode ("foo\0sbar", 8) == NULL && errno == EINVAL,
        "kv_decode buf=(unterm) fails with EINVAL");
    errno = 0;
    ok (kv_decode ("foo\0sbar\0foobar\0", 16) == NULL && errno == EINVAL,
        "kv_decode buf=(no delim entry) fails with EINVAL");
    errno = 0;
    ok (kv_decode ("foo\0sbar\0\0sfoobar\0", 18) == NULL && errno == EINVAL,
        "kv_decode buf=(empty key entry) fails with EINVAL");

    kv_destroy (kv);
    kv_destroy (kv2);
}

void key_deletion (void)
{
    struct kv *kv;

    if (!(kv = kv_create ()))
        BAIL_OUT ("kv_create failed");
    ok (kv_put (kv, "foo", KV_STRING, "bar") == 0,
        "kv_put foo=bar works");
    ok (kv_delete (kv, "foo") == 0,
        "kv_delete foo works");
    errno = 0;
    ok (kv_delete (kv, "foo") < 0,
        "kv_delete foo a second time fails with ENOENT");
    ok (kv_put (kv, "foo", KV_STRING, "baz") == 0,
        "kv_put foo=baz works");

    kv_destroy (kv);
}

void key_update (void)
{
    struct kv *kv;
    const char *val;

    if (!(kv = kv_create ()))
        BAIL_OUT ("kv_create failed");

    ok (kv_put (kv, "foo", KV_STRING, "bar") == 0,
        "kv_put foo=bar works");

    /* Update first (only) entry
     */
    ok (kv_put (kv, "foo", KV_STRING, "baz") == 0,
        "kv_put foo=baz works");
    ok (kv_get (kv, "foo", KV_STRING, &val) == 0 && !strcmp (val, "baz"),
        "kv_get foo returns baz");

    ok (kv_put (kv, "bar", KV_STRING, "xxx") == 0,
        "kv_put bar=xxx works");

    /* Update first (of two) entry
     */
    ok (kv_put (kv, "foo", KV_STRING, "yyy") == 0,
        "kv_put foo=yyy works");
    ok (kv_get (kv, "foo", KV_STRING, &val) == 0 && !strcmp (val, "yyy"),
        "kv_get foo returns yyy");

    /* Update second (of two) entry
     */
    ok (kv_put (kv, "bar", KV_STRING, "zzz") == 0,
        "kv_put bar=zzz works");
    ok (kv_get (kv, "bar", KV_STRING, &val) == 0 && !strcmp (val, "zzz"),
        "kv_get bar returns zzz");

    ok (kv_put (kv, "baz", KV_STRING, "qqq") == 0,
        "kv_put baz=qqq works");

    /* Update second (of three) entry
     */
    ok (kv_put (kv, "bar", KV_STRING, "111") == 0,
        "kv_put_string bar=111 works");
    ok (kv_get (kv, "bar", KV_STRING, &val) == 0 && !strcmp (val, "111"),
        "kv_get bar returns 111");

    kv_destroy (kv);
}

static struct kv *create_test_kv (void)
{
    struct kv *kv;
    if (!(kv = kv_create ()))
        BAIL_OUT ("kv_create failed");
    if (kv_put (kv, "a", KV_STRING, "foo") < 0
        || kv_put (kv, "b", KV_INT64, 42LL) < 0
        || kv_put (kv, "c", KV_DOUBLE, 3.14) < 0
        || kv_put (kv, "d", KV_BOOL, true) < 0)
        BAIL_OUT ("kv_put failed");
    return kv;
}


void join_split (void)
{
    struct kv *kv;
    struct kv *kv1;
    struct kv *kv2;
    struct kv *kv_cpy;

    if (!(kv = kv_create()))
        BAIL_OUT ("kv_create failed");

    /* kv = foo.kv1 + bar.kv2
     */
    kv1 = create_test_kv();
    kv2 = create_test_kv();
    ok (kv_join (kv, kv1, "foo.") == 0,
        "kv_join added foo");
    ok (kv_join (kv, kv2, "bar.") == 0,
        "kv_join added bar");
    diag_kv (kv);

    /* kv_cpy = kv.bar
     */
    ok ((kv_cpy = kv_split (kv, "bar.")) != NULL && kv_equal (kv_cpy, kv2),
        "kv_split bar works");
    kv_destroy (kv_cpy);

    /* kv_cpy = kv.foo
     */
    ok ((kv_cpy = kv_split (kv, "foo.")) != NULL && kv_equal (kv_cpy, kv1),
        "kv_split foo works");
    kv_destroy (kv_cpy);

    kv_destroy (kv);

    /* kv = kv1 + kv1 */
    if (!(kv = kv_create ()))
        BAIL_OUT ("kv_create failed");
    ok (kv_join (kv, kv1, NULL) == 0,
        "kv_join kv = kv1");
    ok (kv_join (kv, kv1, NULL) == 0,
        "kv_join jv += kv1 (again)");
    ok (kv_equal (kv, kv1),
        "kv_equal says kv == kv1");

    kv_destroy (kv1);
    kv_destroy (kv2);
    kv_destroy (kv);
}

static void test_expand (void)
{
    char **env;
    struct kv *kv;

    ok (kv_expand_environ (NULL, NULL) < 0,
        "kv_expand_environ (NULL, NULL) fails");
    ok (kv_expand_environ (NULL, &env) < 0,
        "kv_expand_environ (NULL, &env) fails");

    if (!(kv = kv_create ()))
        BAIL_OUT ("kv_create failed");

    ok (kv_expand_environ (kv, NULL) < 0,
        "kv_expand_environ (kv, NULL) fails");

    ok (kv_expand_environ (kv, &env) == 0,
        "kv_expand_environ works with empty kv");
    ok (env[0] == NULL,
        "returned environ array is valid but empty");
    kv_destroy (kv);
    kv_environ_destroy (&env);

    if (!(kv = kv_create ()))
        BAIL_OUT ("kv_create failed");
    if (kv_put (kv, "PATH", KV_STRING, "/bin:/usr/bin") < 0
        || kv_put (kv, "TEST_JOB_ID", KV_STRING, "ƒAAUKAY4Co") < 0
        || kv_put (kv, "TEST_INT64", KV_INT64, 42LL) < 0
        || kv_put (kv, "TEST_DOUBLE", KV_DOUBLE, 3.14) < 0
        || kv_put (kv, "TEST_BOOL", KV_BOOL, true) < 0)
        BAIL_OUT ("kv_put failed");

    ok (kv_expand_environ (kv, &env) == 0,
        "kv_expand_environ works");
    ok (env[0] && strcmp (env[0], "PATH=/bin:/usr/bin") == 0,
        "env[0] is correct");
    ok (env[1] && strcmp (env[1], "TEST_JOB_ID=ƒAAUKAY4Co") == 0,
        "env[1] is correct");
    ok (env[2] && strcmp (env[2], "TEST_INT64=42") == 0,
        "env[2] is correct");
    ok (env[3] && strcmp (env[3], "TEST_DOUBLE=3.140000") == 0,
        "env[3] is correct");
    ok (env[4] && strcmp (env[4], "TEST_BOOL=true") == 0,
        "env[4] is correct");
    ok (env[5] == NULL,
        "env[5] is NULL");

    kv_destroy (kv);
    kv_environ_destroy (&env);
}

static void test_argv ()
{
    char **argv;
    struct kv *kv;
    const char *key = NULL;

    ok (kv_expand_argv (NULL, NULL) < 0 && errno == EINVAL,
        "kv_expand_argv (NULL, NULL) fails");
    ok (kv_expand_argv (NULL, &argv) < 0 && errno == EINVAL,
        "kv_expand_argv (NULL, &env) fails");
    ok (kv_encode_argv (NULL) == NULL && errno == EINVAL,
        "kv_encode_argv (NULL) fails");

    if (!(kv = kv_create ()))
        BAIL_OUT ("kv_create failed");

    ok (kv_expand_argv (kv, NULL) < 0,
        "kv_expand_argv (kv, NULL) fails");
    ok (kv_expand_argv (kv, &argv) == 0,
        "kv_expand_argv works with empty kv");
    ok (argv[0] == NULL,
        "resulting argv has no entries");

    kv_argv_destroy (&argv);
    ok (argv == NULL,
        "argv is NULL after destroy");

    ok (kv_put (kv, "0", KV_STRING, "foo") == 0,
        "kv_put first element works");
    ok (kv_put (kv, "1", KV_STRING, "--test") == 0,
        "kv_put second element works");
    ok (kv_put (kv, "3", KV_STRING, "bar") == 0,
        "kv_put third element works");

    ok (kv_expand_argv (kv, &argv) == 0,
        "kv_expand_argv works");

    is (argv[0], "foo",
        "argv[0] is correct");
    is (argv[1], "--test",
        "argv[1] is correct");
    is (argv[2], "bar",
        "argv[2] is correct");
    ok (argv[3] == NULL,
        "argv is properly terminated");

    kv_destroy (kv);
    kv_argv_destroy (&argv);

    const char *test_empty[] = { NULL };

    ok ((kv = kv_encode_argv (test_empty)) != NULL,
        "kv_encode_argv of empty argv works");
    diag_kv (kv);
    ok (kv_next (kv, NULL) == NULL,
        "returned kv is empty");

    kv_destroy (kv);

    const char *test_argv[] = {
        "test",
        "--foo",
        "baz",
        NULL,
    };
    const char *expected_keys[] = { "0", "1", "2" };

    ok ((kv = kv_encode_argv (test_argv)) != NULL,
        "kv_encode_argv works");
    diag_kv (kv);

    key = NULL;
    int i = 0;
    while ((key = kv_next (kv, key))) {
        is (key, expected_keys[i],
            "key %d is %s",
            i, expected_keys[i]);
        is (kv_val_string (key), test_argv[i],
            "value %d is %s",
            i, test_argv[i]);
        i++;
    }
    kv_destroy (kv);

}

int main (int argc, char *argv[])
{
    plan (NO_PLAN);

    simple_test ();
    empty_object ();
    check_expansion ();
    bad_parameters ();
    key_deletion ();
    key_update ();
    join_split ();
    test_expand ();
    test_argv ();

    done_testing ();
}

/*
 * vi: ts=4 sw=4 expandtab
 */

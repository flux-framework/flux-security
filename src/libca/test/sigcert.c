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
#include "sigcert.h"

static char scratch[PATH_MAX + 1];
static char keypath[PATH_MAX + 1];

/* Create a scratch directory in /tmp
 */
static void new_scratchdir (void)
{
    unsigned int n;
    const char *tmpdir = getenv ("TMPDIR");
    if (!tmpdir)
        tmpdir = "/tmp";
    n = snprintf (scratch, sizeof (scratch), "%s/sigcert.XXXXXX", tmpdir);
    if (n >= sizeof (scratch))
        BAIL_OUT ("scratch directory overflow");
    if (!mkdtemp (scratch))
        BAIL_OUT ("mkdtemp %s failed", scratch);
}

/* Remove scratch directory, assuming it is empty now.
 */
static void cleanup_scratchdir (void)
{
    if (rmdir (scratch) < 0)
        BAIL_OUT ("rmdir %s failed: %s", strerror (errno));
}

/* Construct a path relative to scratch directory.
 * Overwrites last result.
 */
static const char *new_keypath (const char *name)
{
    unsigned int n;

    if (strlen (scratch) == 0)
        BAIL_OUT ("keypath cannot be called before new_scratchdir");
    n = snprintf (keypath, sizeof (keypath), "%s/%s", scratch, name);
    if (n >= sizeof (keypath))
        BAIL_OUT ("keypath overflow");
    return keypath;
}

/* Construct and unlink a path relative to scratch directory.
 * Overwrites last result.
 */
static void cleanup_keypath (const char *name)
{
    const char *path = new_keypath (name);
    (void)unlink (path);
}

void test_meta (void)
{
    struct sigcert *cert;
    const char *s;
    int64_t i;
    double d;
    bool b;
    time_t t;
    time_t tnow = time (NULL);

    cert = sigcert_create ();
    ok (cert != NULL,
        "sigcert_create works");

    /* Check hardwired metadata
     */
    ok (sigcert_meta_get (cert, "algorithm", SM_STRING, &s) == 0
       && !strcmp (s, "ed25519"),
       "algorithm=ed25519 is set");

    ok (sigcert_meta_set (cert, "foo", SM_STRING, "bar") == 0,
        "sigcert_meta_set foo=bar");
    ok (sigcert_meta_set (cert, "baz", SM_INT64, 42LL) == 0,
        "sigcert_meta_set baz=42");
    ok (sigcert_meta_set (cert, "bar", SM_DOUBLE, 3.14159) == 0,
        "sigcert_meta_set bar=3.14159");
    ok (sigcert_meta_set (cert, "baf", SM_BOOL, true) == 0,
        "sigcert_meta_set baf=true");
    ok (sigcert_meta_set (cert, "ts", SM_TIMESTAMP, tnow) == 0,
        "sigcert_meta_set ts=(now)");
    ok (sigcert_meta_get (cert, "foo", SM_STRING, &s) == 0
        && !strcmp (s, "bar"),
        "sigcert_meta_get foo works");
    ok (sigcert_meta_get (cert, "baz", SM_INT64, &i) == 0
        && i == 42,
        "sigcert_meta_get baz works");
    ok (sigcert_meta_get (cert, "bar", SM_DOUBLE, &d) == 0 && d == 3.14159,
        "sigcert_meta_get bar works");
    ok (sigcert_meta_get (cert, "baf", SM_BOOL, &b) == 0 && b == true,
        "sigcert_meta_get baf works");
    ok (sigcert_meta_get (cert, "ts", SM_TIMESTAMP, &t) == 0 && t == tnow,
        "sigcert_meta_get ts works");

    sigcert_destroy (cert);
}

void test_load_store (void)
{
    struct sigcert *cert;
    struct sigcert *cert2;
    const char *name;

    /* Create a certificate.
     * Create another one and make sure keys are different.
     */
    cert = sigcert_create ();
    ok (cert != NULL,
        "sigcert_create works");
    cert2 = sigcert_create ();
    ok (cert2 != NULL && sigcert_equal (cert, cert2) == false,
        "a second cert is different");
    sigcert_destroy (cert2);

    /* Store the first certificate as TOML files (test, test.pub).
     * Load it back into a different cert, and make sure keys are the same.
     */
    name = new_keypath ("test");
    ok (sigcert_meta_set (cert, "foo", SM_STRING, "bar") == 0,
        "sigcert_meta_set foo=bar");
    ok (sigcert_meta_set (cert, "bar", SM_INT64, -55LL) == 0,
        "sigcert_meta_set bar=-55");
    ok (sigcert_meta_set (cert, "baz", SM_DOUBLE, 2.718) == 0,
        "sigcert_meta_set baz=2.718");
    ok (sigcert_meta_set (cert, "flag", SM_BOOL, false) == 0,
        "sigcert_meta_set flag=false");
    ok (sigcert_meta_set (cert, "time", SM_TIMESTAMP, time (NULL)) == 0,
        "sigcert_meta_set time=(now)");
    ok (sigcert_store (cert, name) == 0,
        "sigcert_store test, test.pub worked");
    ok ((cert2 = sigcert_load (name, true)) != NULL,
        "sigcert_load test worked");
    ok (sigcert_equal (cert, cert2) == true,
        "loaded cert is same as the original");
    sigcert_destroy (cert2);

    /* Verify file mode on certs.
     */
    struct stat sb;
    name = new_keypath ("test");
    ok (stat (name, &sb) == 0 && !(sb.st_mode & (S_IRGRP|S_IROTH))
                              && !(sb.st_mode & (S_IWGRP|S_IWOTH)),
        "secret cert file is not read/writable by group,other");
    name = new_keypath ("test.pub");
    ok (stat (name, &sb) == 0 && !(sb.st_mode & (S_IWGRP|S_IWOTH)),
        "public cert file mode not writable by group,other");

    /* Load just the public key and verify keys are different
     */
    name = new_keypath ("test");
    ok ((cert2 = sigcert_load (name, false)) != NULL,
        "sigcert_load test.pub worked");
    ok (sigcert_equal (cert, cert2) == false,
        "pub cert differs from secret one");
    sigcert_destroy (cert2);

    /* Store new cert on top of existing one.
     */
    name = new_keypath ("test"); // exists
    cert2 = sigcert_create ();
    if (!cert2)
        BAIL_OUT ("sigcert_create: %s", strerror (errno));
    ok (sigcert_store (cert2, name) == 0,
        "sigcert_store overwrites existing cert");
    sigcert_destroy (cert2);

    /* Store cert using relative path.
     */
    char cwd[PATH_MAX + 1];
    if (!getcwd (cwd, sizeof (cwd)))
        BAIL_OUT ("getcwd: %s", strerror (errno));
    if (chdir (scratch) < 0)
        BAIL_OUT ("chdir %s: %s", scratch, strerror (errno));
    ok (sigcert_store (cert, "foo") == 0,
        "sigcert_store works with relative path");
    cert2 = sigcert_load ("foo", true);
    ok (cert2 != NULL,
        "sigcert_load works with relative path");
    if (chdir (cwd) < 0)
        BAIL_OUT ("chdir %s: %s", cwd, strerror (errno));
    sigcert_destroy (cert2);

    sigcert_destroy (cert);

    cleanup_keypath ("test");
    cleanup_keypath ("test.pub");
    cleanup_keypath ("foo");
    cleanup_keypath ("foo.pub");
}

void test_fread_fwrite (void)
{
    struct sigcert *cert;
    struct sigcert *cert2;
    const char *name;
    FILE *fp;

    name = new_keypath ("test");

    if (!(cert = sigcert_create ()))
        BAIL_OUT ("sigcert_create: %s", strerror (errno));
    sigcert_forget_secret (cert);

    /* write cert to name */
    if (!(fp = fopen (name, "w+")))
        BAIL_OUT ("fopen %s: %s", name, strerror (errno));
    ok (sigcert_fwrite_public (cert, fp) == 0,
        "sigcert_fwrite_public works");
    if (fclose (fp) != 0)
        BAIL_OUT ("fclose %s: %s", name, strerror (errno));

    /* read cert2 from name */
    if (!(fp = fopen (name, "r")))
        BAIL_OUT ("fopen %s: %s", name, strerror (errno));
    cert2 = sigcert_fread_public (fp);
    ok (cert2 != NULL,
        "sigcert_fread_public works");
    fclose (fp);

    /* compare */
    ok (sigcert_equal (cert, cert2),
        "new cert is identical to original");

    sigcert_destroy (cert);
    sigcert_destroy (cert2);

    cleanup_keypath ("test");
}

void test_sign_verify_detached (void)
{
    struct sigcert *cert1;
    struct sigcert *cert2;
    uint8_t message[] = "foo-bar-baz";
    uint8_t tampered[] = "foo-KITTENS-baz";
    char *sig, *sig2;

    if (!(cert1 = sigcert_create ()))
        BAIL_OUT ("sigcert_create: %s", strerror (errno));
    if (!(cert2 = sigcert_create ()))
        BAIL_OUT ("sigcert_create: %s", strerror (errno));

    /* Sign message with cert1.
     */
    sig = sigcert_sign_detached (cert1, message, sizeof (message));
    ok (sig != NULL,
        "sigcert_sign works");
    diag ("%s", sig ? sig : "NULL");

    /* Verify with cert1.
     * cert2 cannot verify message signed by cert1.
     * cert1 cannot verify tampered message.
     */
    ok (sigcert_verify_detached (cert1, sig, message, sizeof (message)) == 0,
        "sigcert_verify_detached cert=good works");
    errno = 0;
    ok (sigcert_verify_detached (cert2, sig, message, sizeof (message)) < 0
        && errno == EINVAL,
        "sigcert_verify_detached cert=bad fails with EINVAL");
    errno = 0;
    ok (sigcert_verify_detached (cert1, sig, tampered, sizeof (tampered)) < 0
        && errno == EINVAL,
        "sigcert_verify_detached tampered fails with EINVAL");
    errno = 0;
    free (sig);

    /* Sign tampered message with cert2.
     * Verify that this signature cannot verify message.
     */
    sig2 = sigcert_sign_detached (cert1, tampered, sizeof (tampered));
    ok (sig2 != NULL,
        "sigcert_sign_detached works");
    errno = 0;
    ok (sigcert_verify_detached (cert1, sig2, message, sizeof (message)) < 0
        && errno == EINVAL,
        "sigcert_verify_detached sig=wrong fails with EINVAL");
    free (sig2);

    /* Sign/verify a zero-length message.
     */
    sig2 = sigcert_sign_detached (cert1, NULL, 0);
    ok (sig2 != NULL,
        "sigcert_sign_detached works on zero-length message");
    ok (sigcert_verify_detached (cert1, sig2, NULL, 0) == 0,
        "sigcert_verify_detached works on zero-length message");
    free (sig2);

    sigcert_destroy (cert1);
    sigcert_destroy (cert2);
}

void test_codec (void)
{
    struct sigcert *cert;
    struct sigcert *cert_pub;
    struct sigcert *cert2;
    const char *s;
    int len;

    /* Create cert, cert_pub
     */
    if (!(cert = sigcert_create ()))
        BAIL_OUT ("sigcert_create");
    ok (sigcert_meta_set (cert, "foo", SM_STRING, "bar") == 0,
        "sigcert_meta_set foo=bar");
    ok (sigcert_meta_set (cert, "bar", SM_INT64, 42LL) == 0,
        "sigcert_meta_set bar=42");
    ok (sigcert_meta_set (cert, "baz", SM_DOUBLE, 42e-27) == 0,
        "sigcert_meta_set bar=42");
    ok (sigcert_meta_set (cert, "nerf", SM_BOOL, true) == 0,
        "sigcert_meta_set nerf=true");
    ok (sigcert_meta_set (cert, "time", SM_TIMESTAMP, time (NULL)) == 0,
        "sigcert_meta_set time=(now)");
    cert_pub = sigcert_copy (cert);
    ok (cert_pub != NULL,
        "sigcert_copy worked");
    ok (sigcert_has_secret (cert_pub) == true,
        "sigcert_has_secret returns true before forget");
    sigcert_forget_secret (cert_pub);
    ok (sigcert_has_secret (cert_pub) == false,
        "sigcert_has_secret returns false after forget");

    /* Encode cert_pub, then decode as cert2.
     * Test for equality.
     * Everything was properly marshaled.
     */
    ok (sigcert_encode (cert_pub, &s, &len) == 0,
        "sigcert_encode works");
    cert2 = sigcert_decode (s, len);
    if (!cert2)
        diag ("sigcert_decode: %s", strerror (errno));
    ok (cert2 != NULL,
        "sigcert_decode works");
    ok (sigcert_equal (cert2, cert_pub) == true,
        "the two certs are equal");

    sigcert_destroy (cert);
    sigcert_destroy (cert_pub);
    sigcert_destroy (cert2);
}

void test_corner (void)
{
    struct sigcert *cert;
    const char *s;
    int len;

    if (!(cert = sigcert_create ()))
        BAIL_OUT ("sigcert_create: %s", strerror (errno));
    if (sigcert_meta_set (cert, "test-s", SM_STRING, "foo") < 0)
        BAIL_OUT ("meta_set failed");
    if (sigcert_meta_set (cert, "test-i", SM_INT64, 42LL) < 0)
        BAIL_OUT ("meta_set failed");
    if (sigcert_meta_set (cert, "test-d", SM_DOUBLE, 3.14) < 0)
        BAIL_OUT ("meta_set failed");
    if (sigcert_meta_set (cert, "test-b", SM_BOOL, true) < 0)
        BAIL_OUT ("meta_set failed");
    if (sigcert_meta_set (cert, "test-ts", SM_TIMESTAMP, time (NULL)) < 0)
        BAIL_OUT ("meta_set failed");

    /* Load/store corner cases
     */
    errno = 0;
    ok (sigcert_store (cert, NULL) < 0 && errno == EINVAL,
        "sigcert_store name=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_store (cert, "") < 0 && errno == EINVAL,
        "sigcert_store name=\"\" fails with EINVAL");
    errno = 0;
    ok (sigcert_store (NULL, "foo") < 0 && errno == EINVAL,
        "sigcert_store cert=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_load (NULL, true) == NULL && errno == EINVAL,
        "sigcert_load name=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_load ("/noexist", true) == NULL && errno == ENOENT,
        "sigcert_load name=/noexist fails with ENOENT");
    ok (sigcert_equal (NULL, cert) == false,
        "sigcert_load cert1=NULL returns false");
    ok (sigcert_equal (cert, NULL) == false,
        "sigcert_load cert2=NULL returns false");
    ok (sigcert_equal (NULL, NULL) == false,
        "sigcert_load both=NULL returns false");
    ok (sigcert_equal (cert, cert) == true,
        "sigcert_load both=same returns true");

    /* Sign/verify corner cases
     */
    uint8_t data[] = "foo";
    errno = 0;
    ok (sigcert_sign_detached (NULL, NULL, 0) == NULL && errno == EINVAL,
        "flux_sigcert_sign_detached cert=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_sign_detached (cert, data, -1) == NULL && errno == EINVAL,
        "flux_sigcert_sign_detached len<0 fails with EINVAL");
    errno = 0;
    ok (sigcert_sign_detached (cert, NULL, 1) == NULL && errno == EINVAL,
        "flux_sigcert_sign_detached len>0 buf=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_verify_detached (NULL, "foo", NULL, 0) < 0 && errno == EINVAL,
        "sigcert_verify_detached cert=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_verify_detached (cert, NULL, NULL, 0) < 0 && errno == EINVAL,
        "sigcert_verify_detached sig=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_verify_detached (cert, "foo", NULL, -1) < 0 && errno == EINVAL,
        "sigcert_verify_detached len<0 fails with EINVAL");
    errno = 0;
    ok (sigcert_verify_detached (cert, "foo", NULL, 1) < 0 && errno == EINVAL,
        "sigcert_verify_detached len>0 buf=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_verify_detached (cert, "....", NULL, 0) < 0 && errno == EINVAL,
        "sigcert_verify_detached sig=invalid fails with EINVAL");

    /* encode/decode corner cases
     */
    errno = 0;
    ok (sigcert_encode (NULL, &s, &len) < 0 && errno == EINVAL,
        "sigcert_encode cert=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_decode (NULL, 0) == NULL && errno == EINVAL,
        "sigcert_decode s=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_decode ("", 1) == NULL && errno == EINVAL,
        "sigcert_decode s=empty fails with EINVAL");

    /* General meta get/set corner cases
     */
    errno = 0;
    ok (sigcert_meta_set (NULL, "a", SM_STRING, "b") < 0 && errno == EINVAL,
        "sigcert_meta_set cert=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_set (cert, NULL, SM_STRING, "b") < 0 && errno == EINVAL,
        "sigcert_meta_set key=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_set (cert, "a.b", SM_STRING, "b") < 0 && errno == EINVAL,
        "sigcert_meta_set key=a.b fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_get (NULL, "a", SM_STRING, &s) < 0 && errno == EINVAL,
        "sigcert_meta_get cert=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_get (cert, NULL, SM_STRING, &s) < 0 && errno == EINVAL,
        "sigcert_meta_get key=NULL fails with EINVAL");
    errno = 0;
    ok (sigcert_meta_get (cert, ".", SM_STRING, &s) < 0 && errno == EINVAL,
        "sigcert_meta_get key=. fails with EINVAL");

    /* meta get/set SM_STRING corner cases
     */
    errno = 0;
    ok (sigcert_meta_set (cert, "a", SM_STRING, NULL) < 0 && errno == EINVAL,
        "sigcert_meta_set SM_STRING value=NULL fails with EINVAL");
    ok (sigcert_meta_get (cert, "test-s", SM_STRING, NULL) == 0,
        "sigcert_meta_get SM_STRING value=NULL works");
    /* wrong type */
    errno = 0;
    ok (sigcert_meta_get (cert, "test-i", SM_STRING, &s) < 0 && errno == ENOENT,
        "sigcert_meta_get SM_STRING on int fails with ENOENT");
    errno = 0;
    ok (sigcert_meta_get (cert, "test-d", SM_STRING, &s) < 0 && errno == ENOENT,
        "sigcert_meta_get SM_STRING on double fails with ENOENT");
    errno = 0;
    ok (sigcert_meta_get (cert, "test-b", SM_STRING, &s) < 0 && errno == ENOENT,
        "sigcert_meta_get SM_STRING on boolean fails with ENOENT");
    errno = 0;
    ok (sigcert_meta_get (cert, "test-ts", SM_STRING, &s) < 0
        && errno == ENOENT,
        "sigcert_meta_get SM_STRING on timestamp fails with ENOENT");

    /* meta get/set SM_INT64 corner cases
     */
    int64_t i;
    ok (sigcert_meta_get (cert, "test-i", SM_INT64, NULL) == 0,
        "sigcert_meta_get SM_INT64 value=NULL works");
    /* wrong type */
    errno = 0;
    ok (sigcert_meta_get (cert, "test-s", SM_INT64, &i) < 0 && errno == ENOENT,
        "sigcert_meta_get SM_INT64 on string fails with ENOENT");
    errno = 0;
    ok (sigcert_meta_get (cert, "test-d", SM_INT64, &i) < 0 && errno == ENOENT,
        "sigcert_meta_get SM_INT64 on double fails with ENOENT");
    errno = 0;
    ok (sigcert_meta_get (cert, "test-b", SM_INT64, &i) < 0 && errno == ENOENT,
        "sigcert_meta_get SM_INT64 on boolean fails with ENOENT");
    errno = 0;
    ok (sigcert_meta_get (cert, "test-ts", SM_INT64, &i) < 0 && errno == ENOENT,
        "sigcert_meta_get SM_INT64 on timestamp fails with ENOENT");

    /* meta get/set SM_DOUBLE corner cases
     */
    double d;
    ok (sigcert_meta_get (cert, "test-d", SM_DOUBLE, NULL) == 0,
        "sigcert_meta_get SM_DOUBLE value=NULL works");
    /* wrong type */
    errno = 0;
    ok (sigcert_meta_get (cert, "test-s", SM_DOUBLE, &d) < 0 && errno == ENOENT,
        "sigcert_meta_get SM_DOUBLE on string fails with ENOENT");
    errno = 0;
    ok (sigcert_meta_get (cert, "test-i", SM_DOUBLE, &d) < 0 && errno == ENOENT,
        "sigcert_meta_get SM_DOUBLE on int fails with ENOENT");
    errno = 0;
    ok (sigcert_meta_get (cert, "test-b", SM_DOUBLE, &d) < 0 && errno == ENOENT,
        "sigcert_meta_get SM_DOUBLE on boolean fails with ENOENT");
    errno = 0;
    ok (sigcert_meta_get (cert, "test-ts", SM_DOUBLE, &d) < 0
        && errno == ENOENT,
        "sigcert_meta_get SM_DOUBLE on timestamp fails with ENOENT");

    /* meta getb/setb corner cases
     */
    bool b;
    ok (sigcert_meta_get (cert, "test-b", SM_BOOL, NULL) == 0,
        "sigcert_meta_get SM_BOOL value=NULL works");
    /* wrong type */
    errno = 0;
    ok (sigcert_meta_get (cert, "test-s", SM_BOOL, &b) < 0 && errno == ENOENT,
        "sigcert_meta_get SM_BOOL on string fails with ENOENT");
    errno = 0;
    ok (sigcert_meta_get (cert, "test-i", SM_BOOL, &b) < 0 && errno == ENOENT,
        "sigcert_meta_get SM_BOOL on int fails with ENOENT");
    errno = 0;
    ok (sigcert_meta_get (cert, "test-d", SM_BOOL, &b) < 0 && errno == ENOENT,
        "sigcert_meta_get SM_BOOL on double fails with ENOENT");
    errno = 0;
    ok (sigcert_meta_get (cert, "test-ts", SM_BOOL, &b) < 0 && errno == ENOENT,
        "sigcert_meta_get SM_BOOL on timestamp fails with ENOENT");

    /* meta getts/setts corner cases
     */
    time_t t;
    errno = 0;
    ok (sigcert_meta_set (cert, "a", SM_TIMESTAMP, (time_t)-1) < 0
        && errno == EINVAL,
        "sigcert_meta_set SM_TIMESTAMP value=-1 fails with EINVAL");
    ok (sigcert_meta_get (cert, "test-ts", SM_TIMESTAMP, NULL) == 0,
        "sigcert_meta_get SM_TIMESTAMP value=NULL works");
    /* wrong type */
    errno = 0;
    ok (sigcert_meta_get (cert, "test-s", SM_TIMESTAMP, &t) < 0
        && errno == ENOENT,
        "sigcert_meta_get SM_TIMESTAMP on string fails with ENOENT");
    errno = 0;
    ok (sigcert_meta_get (cert, "test-i", SM_TIMESTAMP, &t) < 0
        && errno == ENOENT,
        "sigcert_meta_get SM_TIMESTAMP on int fails with ENOENT");
    errno = 0;
    ok (sigcert_meta_get (cert, "test-d", SM_TIMESTAMP, &t) < 0
        && errno == ENOENT,
        "sigcert_meta_get SM_TIMESTAMP on double fails with ENOENT");
    errno = 0;
    ok (sigcert_meta_get (cert, "test-b", SM_TIMESTAMP, &t) < 0
        && errno == ENOENT,
        "sigcert_meta_get SM_TIMESTAMP on boolean fails with ENOENT");

    /* Destroy NULL
     */
    lives_ok ({sigcert_destroy (NULL);},
        "sigcert_destroy cert=NULL doesn't crash");

    sigcert_destroy (cert);
}

void test_sign_cert (void)
{
    struct sigcert *cert, *cert2;
    struct sigcert *ca;
    const char *name;
    const char *s;
    int len;

    if (!(cert = sigcert_create ()))
        BAIL_OUT ("sigcert_create: %s", strerror (errno));
    if (sigcert_meta_set (cert, "username", SM_STRING, "itsme") < 0)
        BAIL_OUT ("meta_sets failed");
    if (!(ca = sigcert_create ()))
        BAIL_OUT ("sigcert_create: %s", strerror (errno));

    /* Verification of an unsigned cert fails.
     */
    errno = 0;
    ok (sigcert_verify_cert (ca, cert) < 0 && errno == EINVAL,
        "sigcert_verify_cert fails with EINVAL");

    /* CA signs and verifies cert.
     */
    ok (sigcert_sign_cert (ca, cert) == 0,
        "sigcert_sign_cert works");
    ok (sigcert_verify_cert (ca, cert) == 0,
        "sigcert_verify_cert works");

    /* Verification of a signed cert still works after serialization.
     */
    ok (sigcert_encode (cert, &s, &len) == 0,
        "sigcert_encode works on signed cert");
    cert2 = sigcert_decode (s, len);
    ok (cert2 != NULL,
        "sigcert_decode works on signed cert");
    ok (sigcert_verify_cert (ca, cert2) == 0,
        "sigcert_verify_cert works after JSON dumps/loads");
    sigcert_destroy (cert2);

    /* Verification of a signed cert still works after TOML serialization.
     */
    name = new_keypath ("test");
    ok (sigcert_store (cert, name) == 0,
        "sigcert_store works on signed cert");
    cert2 = sigcert_load (name, false);
    ok (cert2 != NULL,
        "sigcert_load works on signed cert");
    ok (sigcert_verify_cert (ca, cert2) == 0,
        "sigcert_verify_cert works on reloaded cert");
    sigcert_destroy (cert2);
    cleanup_keypath ("test");
    cleanup_keypath ("test.pub");

    /* Verification of a signed but modified cert fails.
     */
    ok (sigcert_meta_set (cert, "username", SM_STRING, "noitsme") == 0,
        "sigcert_meta_set changes signed cert");
    errno = 0;
    ok (sigcert_verify_cert (ca, cert) < 0 && errno == EINVAL,
        "sigcert_verify_cert fails with EINVAL");

    sigcert_destroy (cert);
    sigcert_destroy (ca);
}

static const char *goodcert_pub =
  "[metadata]\n"
  "[curve]\n"
  "    public-key = \"/Q5g8sj5Hl4XUF9GKn4mNjnwbC/0gTYAG2d9yReTJwc=\"\n";

static const char *goodcert =
  "[curve]\n"
  "    secret-key = \"j+UF7qPPkehuwBz/DZjW4NE4lKcdXG+eM+828J30UwOr3vgDNB1IA+C/fauW2XnPdGVv730JGig3lAiRRYzqVA==\"\n";

static const char *badcerts_secret[] = {
  // 0 - no secret key
  "[curve]\n",

  // 1 - no curve section
  "\n",

  // 2 - invalid base64 secret-key
  "[curve]\n"
  "    secret-key = \"j+UF7qPPkehuwBz/DZjW4NE4lKcdXG+eM+8.8J30UwOr3vgDNB1IA+C/fauW2XnPdGVv730JGig3lAiRRYzqVA==\"\n",

  // 3 - short secret-key (but valid base64)
  "[curve]\n"
  "    secret-key = \"j+UF7qPPkehuwBz/DZjW4NE4lKcdXG+eM+828J30UwOr3vgDNB1IA+C/fauW2XnPdGVv730JGig3lAiRRYzq\n",

  // 4 - long secret-key (but valid base64)
  "[curve]\n"
  "    secret-key = \"j+UF7qPPkehuwBz/DZjW4NE4lKcdXG+eM+828J30UwOr3vgDNB1IA+C/fauW2XnPdGVv730JGig3lAiRRYzqVGE=\n",

};
static const int badcerts_secret_count = sizeof (badcerts_secret)
                                        / sizeof (badcerts_secret[0]);

static const char *badcerts[] = {
  // 0 - no public key
  "[metadata]\n"
  "[curve]\n",

  // 1 - no metadata section
  "[curve]\n"
  "    public-key = \"/Q5g8sj5Hl4XUF9GKn4mNjnwbC/0gTYAG2d9yReTJwc=\"\n"
  "    signature = \"lemKu7wjG/KpLFaOPVt+axUvMzXRf/GoE7vQJDPH7iePXwKrDmOLZ3uQq4qQATOUHRuSDerdWyM6qokyKziiAg==\"\n",

  // 2 - no curve section
  "[metadata]\n",

  // 3 - invalid base64 public-key
  "[metadata]\n"
  "[curve]\n"
  "    public-key = \"/Q5g8sj5Hl4XUF9GKn4m.jnwbC/0gTYAG2d9yReTJwc=\"\n",

  // 4 - short public-key (but valid base64)
  "[metadata]\n"
  "[curve]\n"
  "    public-key = \"/Q5g8sj5Hl4XUF9GKn4mNjnwbC/0gTYAG2d9yReTJw==\"\n",

  // 5 - long public-key (but valid base64)
  "[metadata]\n"
  "[curve]\n"
  "    public-key = \"/Q5g8sj5Hl4XUF9GKn4mNjnwbC/0gTYAG2d9yReTJwdh\"\n",

  // 6 - invalid base64 signature
  "[metadata]\n"
  "[curve]\n"
  "    public-key = \"/Q5g8sj5Hl4XUF9GKn4mNjnwbC/0gTYAG2d9yReTJwc=\"\n"
  "    signature = \"lemKu7wjG/KpLFaOPVt+axUvMzXRf/G.E7vQJDPH7iePXwKrDmOLZ3uQq4qQATOUHRuSDerdWyM6qokyKziiAg==\"\n",

  // 6 - short signature (but valid base64)
  "[metadata]\n"
  "[curve]\n"
  "    public-key = \"/Q5g8sj5Hl4XUF9GKn4mNjnwbC/0gTYAG2d9yReTJwc=\"\n"
  "    signature = \"lemKu7wjG/KpLFaOPVt+axUvMzXRf/GoE7vQJDPH7iePXwKrDmOLZ3uQq4qQATOUHRuSDerdWyM6qokyKzii\"\n",

  // 7 - long signature (but valid base64)
  "[metadata]\n"
  "[curve]\n"
  "    public-key = \"/Q5g8sj5Hl4XUF9GKn4mNjnwbC/0gTYAG2d9yReTJwc=\"\n"
  "    signature = \"lemKu7wjG/KpLFaOPVt+axUvMzXRf/GoE7vQJDPH7iePXwKrDmOLZ3uQq4qQATOUHRuSDerdWyM6qokyKziiAmE=\"\n",
};
static const int badcerts_count = sizeof (badcerts) / sizeof (badcerts[0]);

void create_file_content (const char *path, const void *content, size_t size)
{
    FILE *fp = fopen (path, "w+");
    if (!fp)
        BAIL_OUT ("%s: fopen: %s", path, strerror (errno));
    if (fwrite (content, size, 1, fp) != 1)
        BAIL_OUT ("%s: fwrite: %s", path, strerror (errno));
    if (fclose (fp) < 0)
        BAIL_OUT ("%s: fclose: %s", path, strerror (errno));
}

bool check_public_file (const char *content)
{
    struct sigcert *cert;
    bool valid = false;
    const char *name;

    name = new_keypath ("test.pub");
    create_file_content (name, content, strlen (content));

    name = new_keypath ("test");
    if ((cert = sigcert_load (name, false))) {
        sigcert_destroy (cert);
        valid = true;
    }
    cleanup_keypath ("test");
    cleanup_keypath ("test.pub");
    return valid;
}

bool check_secret_file (const char *content)
{
    struct sigcert *cert;
    bool valid = false;
    const char *name;

    name = new_keypath ("test.pub");
    create_file_content (name, goodcert_pub, strlen (goodcert_pub));

    name = new_keypath ("test");
    create_file_content (name, content, strlen (content));

    if ((cert = sigcert_load (name, true))) {
        sigcert_destroy (cert);
        valid = true;
    }
    cleanup_keypath ("test");
    cleanup_keypath ("test.pub");
    return valid;
}

void test_badcert (void)
{
    int i;

    ok (check_public_file (goodcert_pub) == true,
        "sanity check good public cert");
    ok (check_secret_file (goodcert) == true,
        "sanity check good secret cert");

    for (i = 0; i < badcerts_count; i++) {
        ok (check_public_file (badcerts[i]) == false,
            "sigcert_load failed on bad public cert %d", i);
    }
    for (i = 0; i < badcerts_secret_count; i++) {
        ok (check_secret_file (badcerts_secret[i]) == false,
            "sigcert_load failed on bad secret cert %d", i);
    }
}

int main (int argc, char *argv[])
{
    plan (NO_PLAN);
    new_scratchdir ();

    test_meta ();
    test_load_store ();
    test_sign_verify_detached ();
    test_codec ();
    test_corner ();
    test_sign_cert ();
    test_badcert ();
    test_fread_fwrite ();

    cleanup_scratchdir ();
    done_testing ();
}

/*
 * vi: ts=4 sw=4 expandtab
 */

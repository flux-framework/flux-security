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
#include <errno.h>
#include <string.h>
#include <sys/param.h>
#include <sodium.h>

#include "src/libtap/tap.h"
#include "src/libutil/kv.h"

#include "src/lib/sign.h"

const char *conf = \
"[sign]\n" \
"max-ttl = 30\n" \
"default-type = \"none\"\n" \
"allowed-types = [ \"none\" ]\n";

const char *badconf_neg_ttl = \
"[sign]\n" \
"max-ttl = -1\n" \
"default-type = \"none\"\n" \
"allowed-types = [ \"none\" ]\n";

const char *badconf_missing_sign = "";

const char *badconf_missing_default_type = \
"[sign]\n" \
"max-ttl = 31\n" \
"allowed-types = [ \"none\" ]\n";

const char *badconf_unknown_default_type = \
"[sign]\n" \
"max-ttl = 32\n" \
"default-type = \"foo\"\n" \
"allowed-types = [ \"none\" ]\n";

const char *badconf_missing_allowed_types = \
"[sign]\n" \
"max-ttl = 30\n" \
"default-type = \"none\"\n";

const char *badconf_empty_allowed_types = \
"[sign]\n" \
"max-ttl = 30\n" \
"default-type = \"none\"\n" \
"allowed-types = [ ]\n";

const char *badconf_unknown_allowed_types = \
"[sign]\n" \
"max-ttl = 30\n" \
"default-type = \"none\"\n" \
"allowed-types = [ \"foo\" ]\n";

const char *badconf_nonstring_allowed_types = \
"[sign]\n" \
"max-ttl = 30\n" \
"default-type = \"none\"\n" \
"allowed-types = [ 1 ]\n";


static char tmpdir[PATH_MAX + 1];
static char cfpath[PATH_MAX + 1];

void cfpath_init (void)
{
    const char *t = getenv ("TMPDIR");
    int n;

    n = sizeof (tmpdir);
    if (snprintf (tmpdir, n, "%s/sign-XXXXXX", t ? t : "/tmp") >= n)
        BAIL_OUT ("tmpdir buffer overflow");
    if (!mkdtemp (tmpdir))
        BAIL_OUT ("mkdtemp: %s", strerror (errno));
    n = sizeof (cfpath);
    if (snprintf (cfpath, n, "%s/conf.toml", tmpdir) >= n)
        BAIL_OUT ("cfpath buffer overflow");
}

void cfpath_fini (void)
{
    (void)unlink (cfpath);
    if (rmdir (tmpdir) < 0)
        BAIL_OUT ("rmdir %s: %s", tmpdir, strerror (errno));
}

flux_security_t *context_init (const char *config_buf)
{
    FILE *f;
    int n;
    char pattern[PATH_MAX + 1];
    flux_security_t *ctx;
    size_t len = strlen (config_buf);

    if (!(f = fopen (cfpath, "w")))
        BAIL_OUT ("fopen %s: %s", cfpath, strerror (errno));
    if (fwrite (config_buf, 1, len, f) != len)
        BAIL_OUT ("fwrite failed");
    if (fclose (f) != 0)
        BAIL_OUT ("fclose failed");

    if (!(ctx = flux_security_create (0)))
        BAIL_OUT ("flux_security_create failed");
    n = sizeof (pattern);
    if (snprintf (pattern, n, "%s/*.toml", tmpdir) >= n)
        BAIL_OUT ("pattern buffer overflow");
    if (flux_security_configure (ctx, pattern) < 0)
        BAIL_OUT ("config error: %s", flux_security_last_error (ctx));

    return ctx;
}

void test_config (void)
{
    flux_security_t *ctx;

    if (!(ctx = context_init (badconf_neg_ttl)))
        BAIL_OUT ("failed to set up test config");
    errno = 0;
    ok (flux_sign_wrap (ctx, "foo", 3, NULL, 0) == NULL && errno == EINVAL,
        "flux_sign_wrap with neg max-ttl config fails with EINVAL");
    diag ("%s", flux_security_last_error (ctx));
    flux_security_destroy (ctx);

    if (!(ctx = context_init (badconf_missing_sign)))
        BAIL_OUT ("failed to set up test config");
    errno = 0;
    ok (flux_sign_wrap (ctx, "foo", 3, NULL, 0) == NULL && errno == ENOENT,
        "flux_sign_wrap with missing [sign] config fails with ENOENT");
    diag ("%s", flux_security_last_error (ctx));
    flux_security_destroy (ctx);

    if (!(ctx = context_init (badconf_missing_default_type)))
        BAIL_OUT ("failed to set up test config");
    errno = 0;
    ok (flux_sign_wrap (ctx, "foo", 3, NULL, 0) == NULL && errno == EINVAL,
        "flux_sign_wrap with missing default-type config fails with EINVAL");
    diag ("%s", flux_security_last_error (ctx));
    flux_security_destroy (ctx);

    if (!(ctx = context_init (badconf_unknown_default_type)))
        BAIL_OUT ("failed to set up test config");
    errno = 0;
    ok (flux_sign_wrap (ctx, "foo", 3, NULL, 0) == NULL && errno == EINVAL,
        "flux_sign_wrap with unknown default-type config fails with EINVAL");
    diag ("%s", flux_security_last_error (ctx));
    flux_security_destroy (ctx);

    if (!(ctx = context_init (badconf_missing_allowed_types)))
        BAIL_OUT ("failed to set up test config");
    errno = 0;
    ok (flux_sign_wrap (ctx, "foo", 3, NULL, 0) == NULL && errno == EINVAL,
        "flux_sign_wrap with missing allowed-types config fails with EINVAL");
    diag ("%s", flux_security_last_error (ctx));
    flux_security_destroy (ctx);

    if (!(ctx = context_init (badconf_empty_allowed_types)))
        BAIL_OUT ("failed to set up test config");
    errno = 0;
    ok (flux_sign_wrap (ctx, "foo", 3, NULL, 0) == NULL && errno == EINVAL,
        "flux_sign_wrap with empty allowed-types config fails with EINVAL");
    diag ("%s", flux_security_last_error (ctx));
    flux_security_destroy (ctx);

    if (!(ctx = context_init (badconf_unknown_allowed_types)))
        BAIL_OUT ("failed to set up test config");
    errno = 0;
    ok (flux_sign_wrap (ctx, "foo", 3, NULL, 0) == NULL && errno == EINVAL,
        "flux_sign_wrap with unknown allowed-types config fails with EINVAL");
    diag ("%s", flux_security_last_error (ctx));
    flux_security_destroy (ctx);

    if (!(ctx = context_init (badconf_nonstring_allowed_types)))
        BAIL_OUT ("failed to set up test config");
    errno = 0;
    ok (flux_sign_wrap (ctx, "foo", 3, NULL, 0) == NULL && errno == EINVAL,
        "flux_sign_wrap with nonstring allowed-types config fails with EINVAL");
    diag ("%s", flux_security_last_error (ctx));
    flux_security_destroy (ctx);
}

void test_basic (flux_security_t *ctx)
{
    const char *inmsg = "hello world";
    int inmsgsz = sizeof (inmsg);
    const char *outmsg;
    int outmsgsz;
    const char *s;
    int64_t userid;

    /* Sign
     */
    s = flux_sign_wrap (ctx, inmsg, inmsgsz, NULL, 0);
    ok (s != NULL,
        "flux_sign_wrap works");
    diag ("%s", s);

    /* Unwrap + verify
     */
    outmsgsz = 0;
    outmsg = NULL;
    ok (flux_sign_unwrap (ctx, s, (const void **)&outmsg,
                                                 &outmsgsz, &userid, 0) == 0,
        "flux_sign_unwrap works");
    ok (outmsgsz == inmsgsz,
        "unwrapped size matches wrapped size");
    ok (outmsg != NULL && memcmp (outmsg, inmsg, inmsgsz) == 0,
        "unwrapped message matches wrapped message");

    /* Unwrap without verify
     */
    outmsgsz = 0;
    outmsg = NULL;
    ok (flux_sign_unwrap (ctx, s, (const void **)&outmsg,
                                   &outmsgsz, &userid, FLUX_SIGN_NOVERIFY) == 0,
        "flux_sign_unwrap NOVERIFY works");
    ok (outmsgsz == inmsgsz,
        "unwrapped size matches wrapped size");
    ok (outmsg != NULL && memcmp (outmsg, inmsg, inmsgsz) == 0,
        "unwrapped message matches wrapped message");

    /* Sign/verify zero-length payload
     */
    s = flux_sign_wrap (ctx, NULL, 0, NULL, 0);
    ok (s != NULL,
        "flux_sign_wrap payload=NULL works");
    diag ("%s", s);
    ok (flux_sign_unwrap (ctx, s, (const void **)&outmsg,
                                   &outmsgsz, NULL, 0) == 0,
        "flux_sign_unwrap works on empty payload");
    ok (outmsg == NULL,
        "returned payload=NULL");
    ok (outmsgsz == 0,
        "returned payloadsz=NULL");

    /* Sign-as
     */
    s = flux_sign_wrap_as (ctx, 42, inmsg, inmsgsz, NULL, 0);
    ok (s != NULL,
        "flux_sign_wrap_as works");
    diag ("%s", s);

    /* Unwrap no verify
     */
    outmsgsz = 0;
    outmsg = NULL;
    ok (flux_sign_unwrap (ctx, s, (const void **)&outmsg,
                          &outmsgsz, &userid, FLUX_SIGN_NOVERIFY) == 0,
        "flux_sign_unwrap NOVERIFY works with flux_sign_wrap_as()");
    ok (outmsgsz == inmsgsz,
        "unwrapped size matches wrapped size");
    ok (outmsg != NULL && memcmp (outmsg, inmsg, inmsgsz) == 0,
        "unwrapped message matches wrapped message");
    ok (userid == 42,
        "userid matches argument to flux_sign_wrap_as()");

    ok (flux_sign_unwrap (ctx, s, (const void **)&outmsg,
                          &outmsgsz, &userid, 0) < 0,
        "flux_sign_unwrap VERIFY fails with flux_sign_wrap_as()");
    diag ("%s", flux_security_last_error (ctx));
}

void test_mechselect (flux_security_t *ctx)
{
    const char *inmsg = "hello world";
    int inmsgsz = sizeof (inmsg);
    const char *outmsg;
    int outmsgsz;
    const char *s;
    int64_t userid;
    const char *mech;

    /* Sign with "none" mech
     */
    s = flux_sign_wrap (ctx, inmsg, inmsgsz, "none", 0);
    ok (s != NULL,
        "flux_sign_wrap mech=none works");
    diag ("%s", s);

    /* Unwrap + verify
     */
    outmsgsz = 0;
    outmsg = NULL;
    mech = NULL;
    ok (flux_sign_unwrap_anymech (ctx, s, (const void **)&outmsg,
                                  &outmsgsz, &mech, &userid, 0) == 0,
        "flux_sign_unwrap_anymech works");
    ok (outmsgsz == inmsgsz,
        "unwrapped size matches wrapped size");
    ok (outmsg != NULL && memcmp (outmsg, inmsg, inmsgsz) == 0,
        "unwrapped message matches wrapped message");
    ok (mech != NULL && !strcmp (mech, "none"),
        "mech=none");

    /* Sign with unknown mech
     */
    errno = EINVAL;
    s = flux_sign_wrap (ctx, inmsg, inmsgsz, "unknown", 0);
    ok (s == NULL && errno == EINVAL,
        "flux_sign_wrap mech=unknown fails with EINVAL");
    diag ("%s", flux_security_last_error (ctx));
}

/* Construct a HEADER for testing
 */
char *make_header (int64_t version, const char *mechanism, int64_t userid)
{
    struct kv *header;
    const char *src;
    int srclen;
    char *dst;
    int dstlen;

    if (!(header = kv_create ()))
        BAIL_OUT ("kv_create: %s", strerror (errno));
    if (version != -1) {
        if (kv_put (header, "version", KV_INT64, version) < 0)
            BAIL_OUT ("kv_put version: %s", strerror (errno));
    }
    if (userid != -1) {
        if (kv_put (header, "userid", KV_INT64, userid) < 0)
            BAIL_OUT ("kv_put userid: %s", strerror (errno));
    }
    if (mechanism) {
        if (kv_put (header, "mechanism", KV_STRING, mechanism) < 0)
            BAIL_OUT ("kv_put mechanism: %s", strerror (errno));
    }
    if (kv_encode (header, &src, &srclen) < 0)
       BAIL_OUT ("kv_encode: %s", strerror (errno));

    dstlen = sodium_base64_ENCODED_LEN (srclen,
                                        sodium_base64_VARIANT_ORIGINAL);
    if (!(dst = malloc (dstlen)))
        BAIL_OUT ("malloc failed");
    sodium_bin2base64 (dst, dstlen, (const unsigned char *)src, srclen,
                       sodium_base64_VARIANT_ORIGINAL);
    kv_destroy (header);
    return dst;
}

/* N.B. "aGk=" is base64 for "hi" */

void test_badheader (flux_security_t *ctx)
{
    char *header;
    char input[2048];

    errno = 0;
    ok (flux_sign_unwrap (ctx, "&&.aGkK.none", NULL, NULL, NULL, 0) < 0
        && errno == EINVAL,
        "flux_sign_unwrap fails on not-base64 HEADER with EINVAL");
    diag ("%s", flux_security_last_error (ctx));

    errno = 0;
    ok (flux_sign_unwrap (ctx, ".aGkK.none", NULL, NULL, NULL, 0) < 0
        && errno == EINVAL,
        "flux_sign_unwrap fails on empty HEADER with EINVAL");
    diag ("%s", flux_security_last_error (ctx));

    errno = 0;
    ok (flux_sign_unwrap (ctx, "aGkK.none", NULL, NULL, NULL, 0) < 0
        && errno == EINVAL,
        "flux_sign_unwrap fails on missing HEADER delim with EINVAL");
    diag ("%s", flux_security_last_error (ctx));

    errno = 0;
    ok (flux_sign_unwrap (ctx, "aGkK.none", NULL, NULL, NULL, 0) < 0
        && errno == EINVAL,
        "flux_sign_unwrap fails on missing HEADER delim with EINVAL");
    diag ("%s", flux_security_last_error (ctx));

    /* Test that we can make a working header
     */
    header = make_header (1, "none", getuid ());
    snprintf (input, sizeof (input), "%s.aGkK.none", header);
    ok (flux_sign_unwrap (ctx, input, NULL, NULL, NULL, 0) == 0,
        "flux_sign_unwrap works on test-constructed header");
    free (header);

    header = make_header (-1, "none", getuid ());
    snprintf (input, sizeof (input), "%s.aGkK.none", header);
    errno = 0;
    ok (flux_sign_unwrap (ctx, input, NULL, NULL, NULL, 0) < 0
        && errno == EINVAL,
        "flux_sign_unwrap version=missing fails with EINVAL");
    diag ("%s", flux_security_last_error (ctx));
    free (header);

    header = make_header (2, "none", getuid ());
    snprintf (input, sizeof (input), "%s.aGkK.none", header);
    errno = 0;
    ok (flux_sign_unwrap (ctx, input, NULL, NULL, NULL, 0) < 0
        && errno == EINVAL,
        "flux_sign_unwrap version=wrong fails with EINVAL");
    diag ("%s", flux_security_last_error (ctx));
    free (header);

    header = make_header (1, NULL, getuid ());
    snprintf (input, sizeof (input), "%s.aGkK.none", header);
    errno = 0;
    ok (flux_sign_unwrap (ctx, input, NULL, NULL, NULL, 0) < 0
        && errno == EINVAL,
        "flux_sign_unwrap mech=missing fails with EINVAL");
    diag ("%s", flux_security_last_error (ctx));
    free (header);

    header = make_header (1, "foo", getuid ());
    snprintf (input, sizeof (input), "%s.aGkK.none", header);
    errno = 0;
    ok (flux_sign_unwrap (ctx, input, NULL, NULL, NULL, 0) < 0
        && errno == EINVAL,
        "flux_sign_unwrap mech=unknown fails with EINVAL");
    diag ("%s", flux_security_last_error (ctx));
    free (header);

    header = make_header (1, "none", -1);
    snprintf (input, sizeof (input), "%s.aGkK.none", header);
    errno = 0;
    ok (flux_sign_unwrap (ctx, input, NULL, NULL, NULL, 0) < 0
        && errno == EINVAL,
        "flux_sign_unwrap userid=missing fails with EINVAL");
    diag ("%s", flux_security_last_error (ctx));
    free (header);

    header = make_header (1, "none", getuid () + 1);
    snprintf (input, sizeof (input), "%s.aGkK.none", header);
    errno = 0;
    ok (flux_sign_unwrap (ctx, input, NULL, NULL, NULL, 0) < 0
        && errno == EINVAL,
        "flux_sign_unwrap userid=real+1 fails with EINVAL");
    diag ("%s", flux_security_last_error (ctx));
    free (header);
}

void test_badpayload (flux_security_t *ctx)
{
    char *header;
    char input[2048];

    header = make_header (1, "none", getuid ()); // good

    snprintf (input, sizeof (input), "%s.&&.none", header);
    errno = 0;
    ok (flux_sign_unwrap (ctx, input, NULL, NULL, NULL, 0) < 0
        && errno == EINVAL,
        "flux_sign_unwrap fails on not-base64 PAYLOAD with EINVAL");
    diag ("%s", flux_security_last_error (ctx));

    snprintf (input, sizeof (input), "%s", header);
    errno = 0;
    ok (flux_sign_unwrap (ctx, input, NULL, NULL, NULL, 0) < 0
        && errno == EINVAL,
        "flux_sign_unwrap fails on no delims with EINVAL");
    diag ("%s", flux_security_last_error (ctx));

    snprintf (input, sizeof (input), "%s.", header);
    errno = 0;
    ok (flux_sign_unwrap (ctx, input, NULL, NULL, NULL, 0) < 0
        && errno == EINVAL,
        "flux_sign_unwrap fails on missing PAYLOAD.SIG with EINVAL");
    diag ("%s", flux_security_last_error (ctx));

    /* Test empty payload section (double dots) - regression test for
     * fuzzer-found bug where empty base64 section caused NULL pointer
     * to be passed to sodium_base642bin()
     */
    snprintf (input, sizeof (input), "%s..none", header);
    errno = 0;
    ok (flux_sign_unwrap (ctx, input, NULL, NULL, NULL, 0) == 0,
        "flux_sign_unwrap succeeds on empty PAYLOAD section (..none)");
    ok (flux_sign_unwrap (ctx, input, NULL, NULL, NULL, FLUX_SIGN_NOVERIFY) == 0,
        "flux_sign_unwrap NOVERIFY succeeds on empty PAYLOAD section");

    free (header);
}

void test_badsignature (flux_security_t *ctx)
{
    char *header;
    char input[2048];

    header = make_header (1, "none", getuid ()); // good

    snprintf (input, sizeof (input), "%s.aGkK", header);
    errno = 0;
    ok (flux_sign_unwrap (ctx, input, NULL, NULL, NULL, 0) < 0
        && errno == EINVAL,
        "flux_sign_unwrap fails on missing SIGNATURE delim with EINVAL");
    diag ("%s", flux_security_last_error (ctx));

    snprintf (input, sizeof (input), "%s.aGkK.", header);
    errno = 0;
    ok (flux_sign_unwrap (ctx, input, NULL, NULL, NULL, 0) < 0
        && errno == EINVAL,
        "flux_sign_unwrap fails on missing SIGNATURE with EINVAL");
    diag ("%s", flux_security_last_error (ctx));

    snprintf (input, sizeof (input), "%s.aGkK.foo", header);
    errno = 0;
    ok (flux_sign_unwrap (ctx, input, NULL, NULL, NULL, 0) < 0
        && errno == EINVAL,
        "flux_sign_unwrap fails on incorrect SIGNATURE with EINVAL");
    diag ("%s", flux_security_last_error (ctx));

    free (header);
}

void test_corner (flux_security_t *ctx)
{
    const char *s;
    char *cpy;

    /* Sign something and strdup - to be used as valid input
     */
    if (!(s = flux_sign_wrap (ctx, "foo", 3, NULL, 0)))
        BAIL_OUT ("flux_sign_wrap: %s", flux_security_last_error (ctx));
    if (!(cpy = strdup (s)))
        BAIL_OUT ("strdup failed");

    errno = 0;
    ok (flux_sign_wrap (NULL, "foo", 3, NULL, 0) == NULL && errno == EINVAL,
        "flux_sign_wrap ctx=NULL fails with EINVAL");
    errno = 0;
    ok (flux_sign_wrap (ctx, "foo", 3, NULL, 0xff) == NULL && errno == EINVAL,
        "flux_sign_wrap flags=0xff fails with EINVAL");
    errno = 0;
    ok (flux_sign_wrap (ctx, NULL, 3, NULL, 0) == NULL && errno == EINVAL,
        "flux_sign_wrap pay=NULL paysz > 0 fails with EINVAL");

    errno = 0;
    ok (flux_sign_unwrap (NULL, cpy, NULL, NULL, NULL, 0) < 0
        && errno == EINVAL,
        "flux_sign_unwrap ctx=NULL fails with EINVAL");
    errno = 0;
    ok (flux_sign_unwrap (ctx, NULL, NULL, NULL, NULL, 0) < 0
        && errno == EINVAL,
        "flux_sign_unwrap input=NULL fails with EINVAL");
    errno = 0;
    ok (flux_sign_unwrap (ctx, cpy, NULL, NULL, NULL, 0xff) < 0
        && errno == EINVAL,
        "flux_sign_unwrap flags=0xff fails with EINVAL");

    errno = 0;
    ok (flux_sign_wrap_as (ctx, -1, "foo", 3, NULL, 0) == NULL
        && errno == EINVAL,
        "flux_sign_unwrap_as userid=-1 fails with EINVAL");

    free (cpy);
}

int main (int argc, char *argv[])
{
    flux_security_t *ctx;

    plan (NO_PLAN);

    cfpath_init ();

    test_config ();

    ctx = context_init (conf);
    test_basic (ctx);
    test_mechselect (ctx);
    test_badheader (ctx);
    test_badpayload (ctx);
    test_badsignature (ctx);
    test_corner (ctx);
    flux_security_destroy (ctx);

    cfpath_fini ();

    done_testing ();
}

/*
 * vi: ts=4 sw=4 expandtab
 */

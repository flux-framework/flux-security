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

#include "src/libtap/tap.h"

#include "src/lib/context.h"
#include "src/lib/context_private.h"

const char *conf = "foo = 42\n";

static char tmpdir[PATH_MAX + 1];
static char cfpath[PATH_MAX + 1];

void conf_init (void)
{
    const char *t = getenv ("TMPDIR");
    FILE *f;
    int n;

    n = sizeof (tmpdir);
    if (snprintf (tmpdir, n, "%s/context-XXXXXX", t ? t : "/tmp") >= n)
        BAIL_OUT ("tmpdir buffer overflow");
    if (!mkdtemp (tmpdir))
        BAIL_OUT ("mkdtemp: %s", strerror (errno));
    n = sizeof (cfpath);
    if (snprintf (cfpath, n, "%s/conf.toml", tmpdir) >= n)
        BAIL_OUT ("cfpath buffer overflow");
    if (!(f = fopen (cfpath, "w")))
        BAIL_OUT ("fopen %s: %s", cfpath, strerror (errno));
    if (fwrite (conf, 1, strlen (conf), f) != strlen (conf))
        BAIL_OUT ("fwrite failed");
    if (fclose (f) != 0)
        BAIL_OUT ("fclose failed");
}

void conf_fini (void)
{
    (void)unlink (cfpath);
    if (rmdir (tmpdir) < 0)
        BAIL_OUT ("rmdir %s: %s", tmpdir, strerror (errno));
}

void test_basic (void)
{
    flux_security_t *ctx;
    char pattern[PATH_MAX + 1];
    int n;
    const cf_t *cf;

    ctx = flux_security_create (0);
    ok (ctx != NULL,
        "flux_security_create works");
    n = sizeof (pattern);
    if (snprintf (pattern, n, "%s/*.toml", tmpdir) >= n)
        BAIL_OUT ("pattern buffer overflow");
    ok (flux_security_configure (ctx, pattern) == 0,
        "flux_security_configure works");
    cf = security_get_config (ctx, "foo");
    ok (cf != NULL && cf_typeof (cf) == CF_INT64 && cf_int64 (cf) == 42,
        "security_get_config retrieved valid object");
    errno = 0;
    ok (security_get_config (ctx, "wrongname") == NULL && errno == ENOENT,
        "security_get_config key=wrongname fails with ENOENT");
    cf = security_get_config (ctx, NULL);
    ok (cf != NULL && cf_typeof (cf) == CF_TABLE && cf_get_in (cf, "foo"),
        "security_get_config with NULL argument returns whole config");

    flux_security_destroy (ctx);
}

void test_set_config (void)
{
    flux_security_t *ctx;
    const cf_t *cf1;
    cf_t *cf;

    ok ((ctx = flux_security_create (0)) != NULL,
        "flux_security_create");
    ok ((cf = cf_create ()) != NULL,
        "cf_create");
    ok (cf_update (cf, conf, strlen (conf), NULL) == 0,
        "cf_update");
    ok (security_set_config (ctx, cf) == 0,
        "security_set_config (cf)");
    cf_destroy (cf);

    cf1 = security_get_config (ctx, "foo");
    ok (cf1 != NULL && cf_typeof (cf1) == CF_INT64 && cf_int64 (cf1) == 42,
        "security_get_config retrieved valid object");

    ok (security_set_config (ctx, cf1) == 0,
        "security_set_config replaces existing config");
    /* No need to destroy cf1 since it was owned by ctx->config (cf)
     */

    cf1 = security_get_config (ctx, NULL);
    ok (cf1 != NULL && cf_typeof (cf1) == CF_INT64 && cf_int64 (cf1) == 42,
        "security_get_config retrieved correct object");

    errno = 0;
    ok (security_set_config (ctx, NULL) < 0 && errno == EINVAL,
        "security_set_config fails with NULL cf");
    errno = 0;
    ok (security_set_config (NULL, cf1) < 0 && errno == EINVAL,
        "security_set_config fails with NULL ctx argument");

    flux_security_destroy (ctx);
}

void test_error (void)
{
    flux_security_t *ctx;
    const char *s;

    if (!(ctx = flux_security_create (0)))
        BAIL_OUT ("flux_security_create failed");

    ok (flux_security_last_errnum (ctx) == 0,
        "flux_security_last_errnum initially returns zero");
    ok (flux_security_last_error (ctx) == NULL,
        "flux_security_last_error initially returns NULL");

    errno = EINVAL;
    security_error (ctx, NULL);
    ok (errno == EINVAL,
        "security_error fmt=NULL preserved errno");
    ok (flux_security_last_errnum (ctx) == EINVAL,
        "security_error fmt=NULL set errnum");
    s = flux_security_last_error (ctx);
    ok (s != NULL && !strcmp (s, strerror (EINVAL)),
        "security_error fmt=NULL set system error string");

    errno = 123456;
    security_error (ctx, "%s", "error-foo");
    ok (errno == 123456,
        "security_error fmt=string preserved errno");
    ok (flux_security_last_errnum (ctx) == 123456,
        "security_error fmt=string set errnum");
    s = flux_security_last_error (ctx);
    ok (s != NULL && !strcmp (s, "error-foo"),
        "security_error fmt=string set error string");

    flux_security_destroy (ctx);
}

static int free_flag = 0;
void aux_free (void *data)
{
    free (data);
    free_flag++;
}

void test_aux (void)
{
    flux_security_t *ctx;
    char *s, *p, *q;

    if (!(ctx = flux_security_create (0)))
        BAIL_OUT ("flux_security_create failed");
    if (!(s = strdup ("hello")))
        BAIL_OUT ("strdup failed");
    if (!(p = strdup ("goodbye")))
        BAIL_OUT ("strdup failed");
    if (!(q = strdup ("goodbye, again")))
        BAIL_OUT ("strdup failed");

    ok (flux_security_aux_get (ctx, "unknown") == NULL,
        "flux_security_aux_get key=unknown returns NULL");

    ok (flux_security_aux_set (ctx, "foo", s, aux_free) == 0,
        "flux_security_aux_set works");
    ok (flux_security_aux_get (ctx, "foo") == s,
        "flux_security_aux_get retrieves data");

    ok (flux_security_aux_set (ctx, "bar", p, aux_free) == 0,
        "flux_security_aux_set works again");
    ok (flux_security_aux_get (ctx, "bar") == p,
        "flux_security_aux_get retrieves data");

    ok (flux_security_aux_set (ctx, "foo", q, aux_free) == 0,
        "flux_security_aux_set key=existing works");
    ok (free_flag == 1,
        "destructor was called");

    flux_security_destroy (ctx);

    ok (free_flag == 3,
        "flux_security_destroy called aux destructor for each item");
}

void test_corner (void)
{
    flux_security_t *ctx;

    if (!(ctx = flux_security_create (0)))
        BAIL_OUT ("flux_security_create failed");

    errno = 0;
    ok (flux_security_create (128) == NULL && errno == EINVAL,
        "flux_security_create with unknown flag fails with EINVAL");

    errno = 0;
    ok (flux_security_configure (NULL, "/bad/path") < 0 && errno == EINVAL,
        "flux_security_configure ctx=NULL fails with EINVAL");

    errno = 0;
    ok (flux_security_configure (ctx, "/bad/path") < 0 && errno == EINVAL,
        "flux_security_configure on a bad path fails with EINVAL");
    diag ("%s", flux_security_last_error (ctx));
    ok (flux_security_last_errnum (ctx) == EINVAL,
        "flux_security_last_errnum returns EINVAL");

    errno = 0;
    ok (flux_security_aux_set (NULL, "foo", ctx, NULL) < 0 && errno == EINVAL,
        "flux_security_aux_set ctx=NULL fails with EINVAL");

    errno = 0;
    ok (flux_security_aux_set (NULL, "foo", NULL, NULL) < 0 && errno == EINVAL,
        "flux_security_aux_set data=NULL fails with EINVAL");

    errno = 0;
    ok (flux_security_aux_set (ctx, NULL, ctx, NULL) < 0 && errno == EINVAL,
        "flux_security_aux_set key=NULL fails with EINVAL");

    errno = 0;
    ok (flux_security_aux_get (NULL, "foo") == NULL && errno == EINVAL,
        "flux_security_aux_get ctx=NULL fails with EINVAL");

    errno = 0;
    ok (flux_security_aux_get (ctx, NULL) == NULL && errno == EINVAL,
        "flux_security_aux_get key=NULL fails with EINVAL");

    errno = 0;
    ok (security_get_config (NULL, "foo") == NULL && errno == EINVAL,
        "security_get_config ctx=NULL fails with EINVAL");
    errno = 0;
    ok (security_get_config (ctx, NULL) == NULL && errno == EINVAL,
        "security_get_config key=NULL fails with EINVAL");
    errno = 0;
    ok (security_get_config (ctx, "foo") == NULL && errno == EINVAL,
        "security_get_config without loading config fails with EINVAL");
    diag ("%s", flux_security_last_error (ctx));

    flux_security_destroy (ctx);

}

int main (int argc, char *argv[])
{
    plan (NO_PLAN);

    conf_init ();

    test_basic ();
    test_set_config ();
    test_error ();
    test_aux ();
    test_corner ();

    conf_fini ();

    done_testing ();
}

/*
 * vi: ts=4 sw=4 expandtab
 */

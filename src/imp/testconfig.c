/************************************************************\
 * Copyright 2017 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#include <stdlib.h>

#include "testconfig.h"
#include "src/libutil/cf.h"
#include "src/lib/context.h"

/*
 *  For build-tree/test IMP only! Return config pattern from environment
 *   if set, otherwise use built-in "test" configuration pattern, which
 *   will point to src/imp/imp.conf.d
 */
const char * imp_get_config_pattern (void)
{
    const char *p = getenv ("FLUX_IMP_CONFIG_PATTERN");
    if (p == NULL)
         p = imp_config_pattern; /* From testconfig.h */
    return (p);
}

/*
 *  For build-tree/test IMP only!
 *
 *  Configure cf loader to ignore path permissions unless
 *   FLUX_TEST_IMP_PATH_PARANOIA is set in environment.
 *   This allows most system tests to run with IMP config
 *   in sharness trash directory, even when using sudo to
 *   run the IMP.
 */
int imp_conf_init (cf_t *cf, struct cf_error *error)
{
    if (!getenv ("FLUX_TEST_IMP_PATH_PARANOIA")) {
        return cf_update_pack (cf,
                               error,
                               "{s:b}",
                               "disable-path-paranoia", true);
    }
    return 0;
}

/*  For build-tree/test IMP, return the same config path for
 *   libflux-security as flux-imp. This is what the tests expect
 *   and makes test writing easier (only one env var needed to
 *   override config)
 */
const char * imp_get_security_config_pattern (void)
{
    return imp_get_config_pattern ();
}

int imp_get_security_flags (void)
{
    if (!getenv ("FLUX_TEST_IMP_PATH_PARANOIA"))
        return FLUX_SECURITY_DISABLE_PATH_PARANOIA;
    return 0;
}

/*
 *  vi: ts=4 sw=4 expandtab
 */

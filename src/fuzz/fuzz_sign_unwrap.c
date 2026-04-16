/************************************************************\
 * Copyright 2026 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

/* AFL fuzzing harness for flux_sign_unwrap ()
 * Tests full signature verification path.
 */

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "src/lib/context.h"
#include "src/lib/sign.h"

/* Config pattern for .toml files.
 * Use environment variable FUZZ_CONFIG_PATH or default paths.
 * Note: For curve mechanism to work, you need a valid cert file.
 * For munge mechanism, munged must be running.
 */
#ifndef FUZZ_CONFIG_PATH
#define FUZZ_CONFIG_PATH "src/fuzz/conf.d/*.toml"
#endif
#define FUZZ_CONFIG_PATH_ALT "conf.d/*.toml"

__AFL_FUZZ_INIT ();

int main (void)
{
    flux_security_t *ctx;
    const void *payload;
    int payloadsz;
    int64_t userid;
    unsigned char *buf;
    const char *config_path;
    int configured;

    /* Initialize AFL fork server FIRST, before any setup that might fail
     */
    __AFL_INIT ();
    buf = __AFL_FUZZ_TESTCASE_BUF;

    /* Suppress error messages for cleaner fuzzing (unless debugging)
     */
    if (!getenv ("FUZZ_DEBUG"))
        close (STDERR_FILENO);

    /* Create context - if this fails, we can't fuzz but AFL is already
     * initialized.
     */
    ctx = flux_security_create (0);
    if (!ctx)
        return 1;

    /* Try to configure - try multiple paths to find config.
     * Configuration is CRITICAL for proper fuzzing coverage.
     * Set FUZZ_CONFIG_PATH env var to override.
     */
    config_path = getenv ("FUZZ_CONFIG_PATH");
    configured = 0;

    if (config_path) {
        configured = (flux_security_configure (ctx, config_path) == 0);
    }
    else {
        /* Try default location (from project root)
         */
        if (flux_security_configure (ctx, FUZZ_CONFIG_PATH) == 0)
            configured = 1;
        /* Try alternate location (from src/fuzz dir)
         */
        else if (flux_security_configure (ctx, FUZZ_CONFIG_PATH_ALT) == 0)
            configured = 1;
    }

    /* If config failed, print error and exit - otherwise we waste CPU
     */
    if (!configured) {
        fprintf (stderr,
                 "FATAL: Could not load config. "
                 "Set FUZZ_CONFIG_PATH or create conf.d/sign.toml\n");
        fprintf (stderr, "Tried: %s and %s\n",
                 FUZZ_CONFIG_PATH,
                 FUZZ_CONFIG_PATH_ALT);
        flux_security_destroy (ctx);
        return 1;
    }

    while (__AFL_LOOP (10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        char *input;

        /* Limit input size to prevent memory exhaustion during fuzzing.
         * 1MB chosen as reasonable upper bound for signed payload parsing:
         * - Typical signed payloads are <1KB (job descriptions, configs)
         * - Base64 encoding inflates size by ~33%
         * - Prevents AFL from wasting cycles on unrealistically large inputs
         * - Prevents OOM when fuzzer generates huge test cases
         * Production code does not enforce this limit (handled by caller).
         */
        if (len > 1048576)  /* 1MB max */
            continue;

        input = malloc (len + 1);
        if (!input)
            continue;
        memcpy (input, buf, len);
        input[len] = '\0';

        /* Fuzz: attempt to unwrap (with full verification).
         * This will test parsing + signature verification.
         */
        (void)flux_sign_unwrap (ctx,
                                input,
                                &payload,
                                &payloadsz,
                                &userid,
                                0);

        free (input);
    }

    flux_security_destroy (ctx);
    return 0;
}

/*
 * vi: ts=4 sw=4 expandtab
 */

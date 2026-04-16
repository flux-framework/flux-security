/************************************************************\
 * Copyright 2026 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

/* AFL fuzzing harness for cf (configuration) interface.
 *
 * This fuzzer targets the cf_t interface used by IMP for parsing TOML
 * configuration files. The cf layer sits on top of libtomlc99 and jansson,
 * providing parsing, validation, and type-safe access to configs.
 *
 * Bugs in this layer could allow privilege escalation since IMP configs
 * control security-critical settings (allowed-users, allowed-shells).
 *
 * Attack surfaces:
 * - cf_update(): TOML parsing and conversion to JSON
 * - cf_check(): Schema validation and type checking
 * - cf_get_in(): Nested table lookup
 * - cf_string(), cf_int64(), etc.: Type coercion and conversion
 * - cf_array_contains(): Array searching with pattern matching
 */

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include "src/libutil/cf.h"

__AFL_FUZZ_INIT ();

/* IMP-like configuration schema for realistic testing */
static const struct cf_option imp_opts[] = {
    {"allow-sudo",              CF_BOOL,     false},
    {"allow-unprivileged-exec", CF_BOOL,     false},
    {"pam-support",             CF_BOOL,     false},
    {"exec",                    CF_TABLE,    false},
    {"run",                     CF_TABLE,    false},
    {"sign",                    CF_TABLE,    false},
    CF_OPTIONS_TABLE_END,
};

static const struct cf_option exec_opts[] = {
    {"allowed-users",  CF_ARRAY,  false},
    {"allowed-shells", CF_ARRAY,  false},
    CF_OPTIONS_TABLE_END,
};

static const struct cf_option sign_opts[] = {
    {"max-ttl",        CF_INT64,  false},
    {"default-type",   CF_STRING, false},
    {"allowed-types",  CF_ARRAY,  false},
    CF_OPTIONS_TABLE_END,
};

/* Exercise all cf accessors on a table */
static void fuzz_exercise_table (const cf_t *cf)
{
    if (!cf || cf_typeof (cf) != CF_TABLE)
        return;

    /* Try accessing common config keys */
    const char *test_keys[] = {
        "allow-sudo", "allow-unprivileged-exec", "pam-support",
        "exec", "run", "sign", "allowed-users", "allowed-shells",
        "max-ttl", "default-type", "allowed-types",
        NULL
    };

    for (int i = 0; test_keys[i]; i++) {
        const cf_t *val = cf_get_in (cf, test_keys[i]);

        if (val) {
            /* Try all type accessors - should handle mismatches gracefully */
            (void)cf_bool (val);
            (void)cf_int64 (val);
            (void)cf_double (val);
            (void)cf_string (val);
            (void)cf_timestamp (val);
            (void)cf_typeof (val);

            /* Array operations */
            int size = cf_array_size (val);
            for (int j = 0; j < size && j < 100; j++) {
                const cf_t *elem = cf_get_at (val, j);
                if (elem) {
                    (void)cf_string (elem);
                    (void)cf_int64 (elem);
                }
            }

            /* Test array search functions */
            (void)cf_array_contains (val, "test");
            (void)cf_array_contains (val, "root");
            (void)cf_array_contains_match (val, "*.sh");
        }
    }

    /* Exercise nested table access */
    const cf_t *exec = cf_get_in (cf, "exec");
    if (exec) {
        (void)cf_get_in (exec, "allowed-users");
        (void)cf_get_in (exec, "allowed-shells");
    }

    const cf_t *sign = cf_get_in (cf, "sign");
    if (sign) {
        (void)cf_get_in (sign, "max-ttl");
        (void)cf_get_in (sign, "default-type");
        (void)cf_get_in (sign, "allowed-types");
    }
}

int main (void)
{
    unsigned char *buf;

    __AFL_INIT ();
    buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP (10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        struct cf_error error;
        cf_t *cf;

        /* Limit input size to prevent memory exhaustion during fuzzing.
         * 1MB chosen as reasonable upper bound for TOML config parsing:
         * - libtomlc99 has known issues with large files causing hangs
         *   and integer overflow in byte offsets (see validate_toml_syntax)
         * - Typical flux-security configs are 10-100 lines (~1-10KB)
         * - Prevents AFL from wasting cycles on unrealistically large inputs
         * - Prevents OOM when fuzzer generates huge test cases
         * Production code validates input before parsing (MAX_LINES in tomltk.c).
         */
        if (len > 1048576)  /* 1MB max */
            continue;

        /* Create cf object (JSON table internally) */
        cf = cf_create ();
        if (!cf)
            continue;

        /* Fuzz: Parse TOML and update cf object.
         * This exercises:
         * - TOML syntax parsing (libtomlc99)
         * - TOML-to-JSON conversion (tomltk_table_to_json)
         * - JSON deep merge (jansson)
         * - Error handling for malformed input
         */
        if (cf_update (cf, (char *)buf, len, &error) == 0) {
            /* Successfully parsed - now exercise validation and accessors */

            /* Test schema validation with different strictness levels */
            (void)cf_check (cf, imp_opts, 0, &error);
            (void)cf_check (cf, imp_opts, CF_STRICT, &error);
            (void)cf_check (cf, imp_opts, CF_ANYTAB, &error);

            /* Validate nested tables if present */
            const cf_t *exec = cf_get_in (cf, "exec");
            if (exec) {
                (void)cf_check (exec, exec_opts, CF_STRICT, &error);
            }

            const cf_t *sign = cf_get_in (cf, "sign");
            if (sign) {
                (void)cf_check (sign, sign_opts, CF_STRICT, &error);
            }

            /* Exercise all accessor functions */
            fuzz_exercise_table (cf);

            /* Test cf_copy() */
            cf_t *copy = cf_copy (cf);
            if (copy) {
                fuzz_exercise_table (copy);
                cf_destroy (copy);
            }
        }
        /* If parsing failed, that's fine - error handling was exercised */

        cf_destroy (cf);
    }

    return 0;
}

/*
 * vi: ts=4 sw=4 expandtab
 */

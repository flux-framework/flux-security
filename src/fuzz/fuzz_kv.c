/************************************************************\
 * Copyright 2026 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

/* AFL fuzzing harness for kv_decode ().
 * Direct fuzzing of the custom KV serialization format.
 *
 * Format: key\0Tvalue\0key\0Tvalue\0...
 * Where T is a type hint character:
 *   s=string, i=int64, d=double, b=bool, t=timestamp
 */

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "src/libutil/kv.h"

__AFL_FUZZ_INIT ();

int main (void)
{
    unsigned char *buf;

    __AFL_INIT ();
    buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP (10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        struct kv *kv;

        /* Limit input size to prevent memory exhaustion during fuzzing.
         * 1MB chosen as reasonable upper bound for KV structure parsing:
         * - KV format used for privsep communication between IMP processes
         * - Typical KV messages are <4KB (see PRIVSEP_MAX_KVLEN in privsep.c)
         * - Prevents AFL from wasting cycles on unrealistically large inputs
         * - Prevents OOM when fuzzer generates huge test cases
         * Production privsep code enforces 4MB limit (PRIVSEP_MAX_KVLEN).
         */
        if (len > 1048576)  /* 1MB max */
            continue;

        /* Fuzz: attempt to decode KV structure.
         * This tests:
         * - kv_check_integrity: null termination, even nulls, key length
         * - kv_next: iteration over key-value pairs
         * - type validation and value parsing
         */
        kv = kv_decode ((char *)buf, len);

        if (kv) {
            const char *key = NULL;

            /* Exercise the parser by iterating and accessing values.
             * This ensures all code paths are executed.
             */
            while ((key = kv_next (kv, key))) {
                enum kv_type type = kv_typeof (key);

                /* Access value to trigger any parsing/conversion
                 */
                switch (type) {
                    case KV_STRING:
                        (void)kv_val_string (key);
                        break;
                    case KV_INT64:
                        (void)kv_val_int64 (key);
                        break;
                    case KV_DOUBLE:
                        (void)kv_val_double (key);
                        break;
                    case KV_BOOL:
                        (void)kv_val_bool (key);
                        break;
                    case KV_TIMESTAMP:
                        (void)kv_val_timestamp (key);
                        break;
                    default:
                        break;
                }
            }
            kv_destroy (kv);
        }
    }

    return 0;
}

/*
 * vi: ts=4 sw=4 expandtab
 */

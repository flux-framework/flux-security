/************************************************************\
 * Copyright 2026 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <jansson.h>

#include "exec/device.h"
#include "imp_log.h"
#include "src/libutil/kv.h"

#include "src/libtap/tap.h"

static int diag_output (int level, const char *msg,
                        void *arg __attribute__((unused)))
{
    diag ("%s: %s", imp_log_strlevel (level), msg);
    return 0;
}

/* Build an options object with optional DevicePolicy and DeviceAllow.
 * policy may be NULL to omit.  allow_arr may be NULL to omit.
 * Caller owns the returned object.
 */
static json_t *make_options (const char *policy, json_t *allow_arr)
{
    json_t *obj = json_object ();
    if (!obj)
        return NULL;
    if (policy) {
        if (json_object_set_new (obj, "DevicePolicy",
                                 json_string (policy)) < 0)
            goto error;
    }
    if (allow_arr) {
        if (json_object_set_new (obj, "DeviceAllow", allow_arr) < 0)
            goto error;
    }
    return obj;
error:
    json_decref (obj);
    return NULL;
}

/* Return true if da contains an entry matching type, major, minor, access.
 * Pass -2 for major or minor to skip that field.
 */
static bool da_contains (const struct device_allow *da,
                          char type,
                          int major,
                          int minor,
                          const char *access)
{
    for (int i = 0; i < da->count; i++) {
        const struct device_allow_entry *e = &da->entries[i];
        if (e->type == type
            && (major == -2 || e->major == major)
            && (minor == -2 || e->minor == minor)
            && strcmp (e->access, access) == 0)
            return true;
    }
    return false;
}

/* ---- device_allow_from_options tests ---- */

static void test_null_options (void)
{
    struct device_allow *da = NULL;

    ok (device_allow_from_options (NULL, &da) == 0 && da == NULL,
        "from_options: NULL options returns 0 with NULL da (no containment)");
}

static void test_null_dap (void)
{
    json_t *opts = make_options (NULL, NULL);
    if (!opts)
        BAIL_OUT ("make_options failed");

    errno = 0;
    ok (device_allow_from_options (opts, NULL) < 0 && errno == EINVAL,
        "from_options: NULL dap fails with EINVAL");
    json_decref (opts);
}

static void test_auto_no_allow (void)
{
    json_t *opts = make_options ("auto", NULL);
    struct device_allow *da = NULL;
    if (!opts)
        BAIL_OUT ("make_options failed");

    ok (device_allow_from_options (opts, &da) == 0 && da == NULL,
        "from_options: auto + absent DeviceAllow returns NULL da");
    json_decref (opts);
}

static void test_auto_empty_allow (void)
{
    json_t *opts = make_options ("auto", json_array ());
    struct device_allow *da = NULL;
    if (!opts)
        BAIL_OUT ("make_options failed");

    ok (device_allow_from_options (opts, &da) == 0 && da == NULL,
        "from_options: auto + empty DeviceAllow returns NULL da");
    json_decref (opts);
}

static void test_invalid_policy (void)
{
    json_t *opts = make_options ("bogus", NULL);
    struct device_allow *da = NULL;
    if (!opts)
        BAIL_OUT ("make_options failed");

    errno = 0;
    ok (device_allow_from_options (opts, &da) < 0 && errno == EINVAL,
        "from_options: invalid DevicePolicy fails with EINVAL");
    device_allow_destroy (da);
    json_decref (opts);
}

static void test_path_entry (void)
{
    /* /dev/null is char major=1 minor=3 on all Linux systems */
    json_t *allow = json_pack ("[[ss]]", "/dev/null", "rw");
    json_t *opts = make_options ("strict", allow);
    struct device_allow *da = NULL;
    if (!opts)
        BAIL_OUT ("make_options failed");

    ok (device_allow_from_options (opts, &da) == 0 && da != NULL,
        "from_options: strict /dev/null returns 0 with non-NULL da");
    ok (da && da_contains (da, 'c', 1, 3, "rw"),
        "from_options: /dev/null resolved to {c, 1, 3, \"rw\"}");
    device_allow_destroy (da);
    json_decref (opts);
}

static void test_class_entry (void)
{
    /* char-pts should appear in /proc/devices on any system with a terminal */
    json_t *allow = json_pack ("[[ss]]", "char-pts", "rw");
    json_t *opts = make_options ("strict", allow);
    struct device_allow *da = NULL;
    if (!opts)
        BAIL_OUT ("make_options failed");

    ok (device_allow_from_options (opts, &da) == 0 && da != NULL,
        "from_options: strict char-pts returns 0 with non-NULL da");
    ok (da && da->count > 0,
        "from_options: char-pts resolved to at least one entry");
    ok (da && da_contains (da, 'c', -2, -1, "rw"),
        "from_options: char-pts entry has type='c', minor=-1 (wildcard)");
    device_allow_destroy (da);
    json_decref (opts);
}

static void test_block_class_entry (void)
{
    /* block-loop (major 7) should appear in /proc/devices on any Linux system */
    json_t *allow = json_pack ("[[ss]]", "block-loop", "rw");
    json_t *opts = make_options ("strict", allow);
    struct device_allow *da = NULL;
    if (!opts)
        BAIL_OUT ("make_options failed");

    ok (device_allow_from_options (opts, &da) == 0 && da != NULL,
        "from_options: strict block-loop returns 0 with non-NULL da");
    ok (da && da->count > 0,
        "from_options: block-loop resolved to at least one entry");
    ok (da && da_contains (da, 'b', 7, -1, "rw"),
        "from_options: block-loop entry has type='b', major=7, minor=-1 (wildcard)");
    device_allow_destroy (da);
    json_decref (opts);
}

static void test_nonexistent_path (void)
{
    /* Non-existent path is a warning, not an error (fail-closed: skip entry) */
    json_t *allow = json_pack ("[[ss]]", "/dev/nonexistent_flux_test", "rw");
    json_t *opts = make_options ("strict", allow);
    struct device_allow *da = NULL;
    if (!opts)
        BAIL_OUT ("make_options failed");

    ok (device_allow_from_options (opts, &da) == 0 && da != NULL,
        "from_options: nonexistent path returns 0 (skip, not fatal)");
    ok (da && da->count == 0,
        "from_options: nonexistent path produces empty allow list");
    device_allow_destroy (da);
    json_decref (opts);
}

static void test_invalid_access (void)
{
    /* Invalid access string is a warning, not an error */
    json_t *allow = json_pack ("[[ss]]", "/dev/null", "z");
    json_t *opts = make_options ("strict", allow);
    struct device_allow *da = NULL;
    if (!opts)
        BAIL_OUT ("make_options failed");

    ok (device_allow_from_options (opts, &da) == 0 && da != NULL,
        "from_options: invalid access returns 0 (skip, not fatal)");
    ok (da && da->count == 0,
        "from_options: invalid access produces empty allow list");
    device_allow_destroy (da);
    json_decref (opts);
}

static void test_unknown_specifier (void)
{
    /* Unknown specifier (not /dev/, char-, or block-) is warned and skipped */
    json_t *allow = json_pack ("[[ss]]", "unknownspec", "rw");
    json_t *opts = make_options ("strict", allow);
    struct device_allow *da = NULL;
    if (!opts)
        BAIL_OUT ("make_options failed");

    ok (device_allow_from_options (opts, &da) == 0 && da != NULL,
        "from_options: unknown specifier returns 0 (skip, not fatal)");
    ok (da && da->count == 0,
        "from_options: unknown specifier produces empty allow list");
    device_allow_destroy (da);
    json_decref (opts);
}

static void test_closed_standard_devices (void)
{
    /* closed policy with empty DeviceAllow should include standard devices */
    json_t *opts = make_options ("closed", json_array ());
    struct device_allow *da = NULL;
    if (!opts)
        BAIL_OUT ("make_options failed");

    ok (device_allow_from_options (opts, &da) == 0 && da != NULL,
        "from_options: closed + empty DeviceAllow returns non-NULL da");
    ok (da && da->count > 0,
        "from_options: closed policy includes standard devices");
    ok (da && da_contains (da, 'c', 1, 3, "rwm"),
        "from_options: closed policy includes /dev/null {c,1,3,rwm}");
    ok (da && da_contains (da, 'c', 1, 5, "rwm"),
        "from_options: closed policy includes /dev/zero {c,1,5,rwm}");
    device_allow_destroy (da);
    json_decref (opts);
}

static void test_strict_no_standard_devices (void)
{
    /* strict policy should not add standard devices */
    json_t *allow = json_pack ("[[ss]]", "/dev/null", "rw");
    json_t *opts = make_options ("strict", allow);
    struct device_allow *da = NULL;
    if (!opts)
        BAIL_OUT ("make_options failed");

    ok (device_allow_from_options (opts, &da) == 0 && da != NULL,
        "from_options: strict policy returns non-NULL da");
    ok (da && da->count == 1,
        "from_options: strict policy has exactly the listed entry, no extras");
    device_allow_destroy (da);
    json_decref (opts);
}

static void test_closed_standard_devices_first (void)
{
    /* Standard devices are prepended before user entries */
    json_t *allow = json_pack ("[[ss]]", "/dev/null", "rw");
    json_t *opts = make_options ("closed", allow);
    struct device_allow *da = NULL;
    if (!opts)
        BAIL_OUT ("make_options failed");

    ok (device_allow_from_options (opts, &da) == 0 && da != NULL,
        "from_options: closed + user entry returns non-NULL da");
    ok (da && da->count > 1,
        "from_options: closed policy has user entry plus standard devices");
    ok (da && da->entries[0].major == 1 && da->entries[0].minor == 3,
        "from_options: standard devices precede user entries");
    device_allow_destroy (da);
    json_decref (opts);
}

/* ---- encode/decode round-trip tests ---- */

static void test_encode_decode_roundtrip (void)
{
    struct device_allow *orig = calloc (1, sizeof (*orig));
    struct device_allow *decoded = NULL;
    struct kv *kv;

    if (!orig)
        BAIL_OUT ("calloc failed");
    orig->count = 2;
    if (!(orig->entries = calloc (2, sizeof (orig->entries[0]))))
        BAIL_OUT ("calloc failed");

    orig->entries[0].type = 'c';
    orig->entries[0].major = 195;
    orig->entries[0].minor = 0;
    strcpy (orig->entries[0].access, "rw");

    orig->entries[1].type = 'b';
    orig->entries[1].major = 8;
    orig->entries[1].minor = -1;
    strcpy (orig->entries[1].access, "rwm");

    if (!(kv = kv_create ()))
        BAIL_OUT ("kv_create failed");

    ok (device_allow_encode (orig, kv) == 0,
        "encode/decode: device_allow_encode succeeds");
    ok (device_allow_decode (kv, &decoded) == 0 && decoded != NULL,
        "encode/decode: device_allow_decode returns non-NULL da");
    ok (decoded && decoded->count == 2,
        "encode/decode: count == 2");
    ok (decoded && decoded->entries[0].type == 'c'
        && decoded->entries[0].major == 195
        && decoded->entries[0].minor == 0
        && strcmp (decoded->entries[0].access, "rw") == 0,
        "encode/decode: entry[0] round-trips correctly");
    ok (decoded && decoded->entries[1].type == 'b'
        && decoded->entries[1].major == 8
        && decoded->entries[1].minor == -1
        && strcmp (decoded->entries[1].access, "rwm") == 0,
        "encode/decode: entry[1] round-trips correctly (wildcard minor)");

    device_allow_destroy (orig);
    device_allow_destroy (decoded);
    kv_destroy (kv);
}

static void test_decode_absent (void)
{
    struct kv *kv = kv_create ();
    struct device_allow *da = NULL;

    if (!kv)
        BAIL_OUT ("kv_create failed");
    ok (device_allow_decode (kv, &da) == 0 && da == NULL,
        "decode_absent: absent device.count returns 0 with NULL da");
    kv_destroy (kv);
}

static void test_decode_negative_count (void)
{
    struct kv *kv = kv_create ();
    struct device_allow *da = NULL;

    if (!kv)
        BAIL_OUT ("kv_create failed");
    if (kv_put (kv, "device.count", KV_INT64, (int64_t)-1) < 0)
        BAIL_OUT ("kv_put failed");
    errno = 0;
    ok (device_allow_decode (kv, &da) < 0 && errno == ERANGE,
        "decode_negative: negative count fails with ERANGE");
    kv_destroy (kv);
}

static void test_decode_count_too_large (void)
{
    struct kv *kv = kv_create ();
    struct device_allow *da = NULL;

    if (!kv)
        BAIL_OUT ("kv_create failed");
    if (kv_put (kv, "device.count", KV_INT64,
                (int64_t)(DEVICE_ALLOW_MAX_ENTRIES + 1)) < 0)
        BAIL_OUT ("kv_put failed");
    errno = 0;
    ok (device_allow_decode (kv, &da) < 0 && errno == ERANGE,
        "decode_too_large: count > %d fails with ERANGE",
        DEVICE_ALLOW_MAX_ENTRIES);
    kv_destroy (kv);
}

static void test_options_allow_not_array (void)
{
    json_t *opts = json_pack ("{s:s}", "DeviceAllow", "notanarray");
    struct device_allow *da = NULL;
    if (!opts)
        BAIL_OUT ("json_pack failed");

    errno = 0;
    ok (device_allow_from_options (opts, &da) < 0 && errno == EINVAL,
        "from_options: DeviceAllow not-an-array fails with EINVAL");
    device_allow_destroy (da);
    json_decref (opts);
}

static void test_options_policy_not_string (void)
{
    json_t *opts = json_pack ("{s:i}", "DevicePolicy", 42);
    struct device_allow *da = NULL;
    if (!opts)
        BAIL_OUT ("json_pack failed");

    errno = 0;
    ok (device_allow_from_options (opts, &da) < 0 && errno == EINVAL,
        "from_options: DevicePolicy not-a-string fails with EINVAL");
    device_allow_destroy (da);
    json_decref (opts);
}

static void test_null_encode_decode_params (void)
{
    struct kv *kv = kv_create ();
    struct device_allow empty = { .count = 0, .entries = NULL };
    struct device_allow *da = NULL;

    if (!kv)
        BAIL_OUT ("kv_create failed");

    errno = 0;
    ok (device_allow_encode (NULL, kv) < 0 && errno == EINVAL,
        "encode: NULL da fails with EINVAL");
    errno = 0;
    ok (device_allow_encode (&empty, NULL) < 0 && errno == EINVAL,
        "encode: NULL kv fails with EINVAL");
    errno = 0;
    ok (device_allow_decode (NULL, &da) < 0 && errno == EINVAL,
        "decode: NULL kv fails with EINVAL");
    errno = 0;
    ok (device_allow_decode (kv, NULL) < 0 && errno == EINVAL,
        "decode: NULL dap fails with EINVAL");

    kv_destroy (kv);
}

/* Encode an entry with type='x' (invalid).  entry_encode does not
 * validate, so encode succeeds; decode must reject the invalid type.
 */
static void test_encode_invalid_entry (void)
{
    struct device_allow *da = calloc (1, sizeof (*da));
    struct kv *kv = kv_create ();
    struct device_allow *decoded = NULL;

    if (!da || !kv)
        BAIL_OUT ("allocation failed");
    da->count = 1;
    if (!(da->entries = calloc (1, sizeof (da->entries[0]))))
        BAIL_OUT ("calloc failed");
    da->entries[0].type = 'x';
    da->entries[0].major = 1;
    da->entries[0].minor = 0;
    strcpy (da->entries[0].access, "rw");

    ok (device_allow_encode (da, kv) == 0,
        "encode: invalid entry type='x' encodes without error");
    errno = 0;
    ok (device_allow_decode (kv, &decoded) < 0 && errno == EINVAL,
        "decode: kv with invalid entry type fails with EINVAL");

    device_allow_destroy (da);
    device_allow_destroy (decoded);
    kv_destroy (kv);
}

static void test_decode_entry_not_string (void)
{
    struct kv *kv = kv_create ();
    struct device_allow *da = NULL;

    if (!kv)
        BAIL_OUT ("kv_create failed");
    if (kv_put (kv, "device.count", KV_INT64, (int64_t)1) < 0)
        BAIL_OUT ("kv_put failed");
    if (kv_put (kv, "device.0", KV_INT64, (int64_t)42) < 0)
        BAIL_OUT ("kv_put failed");
    ok (device_allow_decode (kv, &da) < 0,
        "decode: entry stored as INT64 instead of STRING fails");
    device_allow_destroy (da);
    kv_destroy (kv);
}

int main (void)
{
    plan (NO_PLAN);

    imp_openlog ();
    imp_log_add ("tap", IMP_LOG_DEBUG, diag_output, NULL);
    imp_log_set_level (NULL, IMP_LOG_DEBUG);

    test_null_options ();
    test_null_dap ();
    test_auto_no_allow ();
    test_auto_empty_allow ();
    test_invalid_policy ();
    test_path_entry ();
    test_class_entry ();
    test_block_class_entry ();
    test_nonexistent_path ();
    test_invalid_access ();
    test_unknown_specifier ();
    test_closed_standard_devices ();
    test_strict_no_standard_devices ();
    test_closed_standard_devices_first ();
    test_encode_decode_roundtrip ();
    test_decode_absent ();
    test_decode_negative_count ();
    test_decode_count_too_large ();
    test_options_allow_not_array ();
    test_options_policy_not_string ();
    test_null_encode_decode_params ();
    test_encode_invalid_entry ();
    test_decode_entry_not_string ();

    done_testing ();
    return 0;
}

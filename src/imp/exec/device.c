/************************************************************\
 * Copyright 2026 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

/* device.c - process DevicePolicy and DeviceAllow from input helper
 *
 * The IMP implements device containment on behalf of systemd because
 * the systemd user instance doesn't have permission to load BPF programs.
 * The IMP exec helper reads the following systemd properties and provides
 * them to the IMP as input:
 *
 * DevicePolicy (string) may be set to
 *   strict - allow only DeviceAllow
 *   closed - allow DeviceAllow plus standard pseudo-devices
 *   auto (default) - closed, but allow all if DeviceAllow is missing/empty
 *
 * DeviceAllow (array) is a list of (specifier, access) tuples
 *
 * In a DeviceAllow entry:
 *
 * specifier (string) may be set to
 *   /dev/... - path to special file
 *   char-NAME - matches all char devices of the named class (/proc/devices)
 *   block-NAME - matches all block devices of the named class (/proc/devices)
 *
 * and access (string) may be set to a combination of
 *   r - read
 *   w - write
 *   m - mknod
 *
 * Error handling is fail-closed.
 *
 * If a DeviceAllow entry cannot be matched/processed, log a warning
 * and continue on.  This is consistent with fail-closed operation.
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <jansson.h>
#include <stdbool.h>
#include <ctype.h>

#include "src/libutil/strlcpy.h"
#include "src/libutil/macros.h"
#include "imp_log.h"
#include "device.h"

static bool access_is_valid (const char *access)
{
    int len = strlen (access);

    if (len < 1 || len > 3)
        return false;
    while (*access) {
        if (*access != 'r' && *access != 'w' && *access != 'm')
            return false;
        access++;
    }
    return true;
}

struct device_spec {
    char *spec;
    char *access;
};

/* This list initially mirrors systemd's bpf_devices_allow_list_static()
 */
static struct device_spec standard_devices[] = {
    { "/dev/null", "rwm" },
    { "/dev/zero", "rwm" },
    { "/dev/full", "rwm" },
    { "/dev/random", "rwm" },
    { "/dev/urandom", "rwm" },
    { "/dev/tty", "rwm" },
    { "/dev/ptmx", "rwm" },
    { "char-pts", "rw" },
};

static int device_entry_append (struct device_allow *da,
                                struct device_allow_entry entry)
{
    struct device_allow_entry *nentries;
    size_t nsize = sizeof (da->entries[0]) * (da->count + 1);

    if (!(nentries = realloc (da->entries, nsize)))
        return -1;
    da->entries = nentries;
    da->entries[da->count++] = entry;
    return 0;
}

static void strip_trailing_whitespace (char *s)
{
    for (int i = strlen(s) - 1; i >= 0; i--) {
        if (!isspace (s[i]))
            break;
        s[i] = '\0';
    }
}

static int device_class_append (struct device_allow *da,
                                const char *spec,
                                const char *access)
{
    const char *name;
    char type;
    FILE *fp;
    char line[256];
    bool in_target_section = false;
    int count = 0;

    if (strstarts (spec, "char-")) {
        name = spec + 5;
        type = 'c';
    }
    else if (strstarts (spec, "block-")) {
        name = spec + 6;
        type = 'b';
    }
    else {
        imp_warn ("device: ignore %s (%s): invalid device node specifier",
                  spec,
                  access);
        return 0;
    }
    if (!(fp = fopen ("/proc/devices", "r"))) {
        imp_warn ("device: ignore %s (%s): /proc/devices: %s",
                  spec,
                  access,
                  strerror (errno));
        return 0;
    }
    while (fgets (line, sizeof (line), fp)) {
        strip_trailing_whitespace (line);
        if (streq (line, "Character devices:"))
            in_target_section = type == 'c' ? true : false;
        else if (streq (line, "Block devices:"))
            in_target_section = type == 'b' ? true : false;
        else if (in_target_section) {
            int maj;
            char devname[64];

            if (sscanf (line, " %d %63s", &maj, devname) == 2
                && streq (devname, name)) {
                struct device_allow_entry entry;

                entry.type = type;
                entry.major = maj;
                entry.minor = -1;
                strlcpy (entry.access, access, sizeof (entry.access));
                if (device_entry_append (da, entry) < 0)
                    goto error;
                count++;
            }
        }
    }
    if (count == 0) {
        imp_warn ("device: ignore %s (%s): not found in /proc/devices",
                  spec,
                  access);
    }
    fclose (fp);
    return count;
error:
    ERRNO_SAFE_WRAP (fclose, fp);
    return -1;
}

static int device_path_append (struct device_allow *da,
                               const char *spec,
                               const char *access)
{
    struct stat st;
    struct device_allow_entry entry;

    if (stat (spec, &st) < 0) {
        imp_warn ("device: ignore %s (%s): %s",
                  spec,
                  access,
                  strerror (errno));
        return 0;
    }
    if (S_ISCHR (st.st_mode))
        entry.type = 'c';
    else if (S_ISBLK (st.st_mode))
        entry.type = 'b';
    else {
        imp_warn ("device: ignore %s (%s): not a device", spec, access);
        return 0;
    }
    entry.minor = minor (st.st_rdev);
    entry.major = major (st.st_rdev);
    strlcpy (entry.access, access, sizeof (entry.access));

    if (device_entry_append (da, entry) < 0)
        return -1;
    return 1;
}


static int device_append (struct device_allow *da,
                          const char *spec,
                          const char *access)
{
    int count = 0;

    if (!access_is_valid (access)) {
        imp_warn ("device: ignore %s (%s): invalid access key",
                  spec,
                  access);
    }
    else if (strstarts (spec, "char-") || strstarts (spec, "block-"))
        count = device_class_append (da, spec, access);
    else if (strstarts (spec, "/dev/"))
        count = device_path_append (da, spec, access);
    else
        imp_warn ("device: ignore %s (%s): unknown specifier", spec, access);

    if (count > 0)
        imp_debug ("device: allow %s (%s)", spec, access);

    return count;
}

static int device_parse_options (json_t *options,
                                 const char **policyp,
                                 json_t **allowp)
{
    const char *policy = "auto"; // default
    json_t *allow = NULL;

    if (json_unpack (options,
                     "{s?s s?o}",
                     "DevicePolicy", &policy,
                     "DeviceAllow", &allow) < 0)
        goto error;

    if (!streq (policy, "auto")
        && !streq (policy, "closed")
        && !streq (policy, "strict"))
        goto error;

    if (allow) {
        if (!json_is_array (allow))
            goto error;
    }

    *policyp = policy;
    *allowp = allow;
    return 0;
error:
    errno = EINVAL;
    return -1;
}

int device_allow_from_options (json_t *options, struct device_allow **dap)
{
    const char *policy = "auto";
    json_t *allow;
    struct device_allow *da = NULL;

    if (!dap) {
        errno = EINVAL;
        return -1;
    }
    if (!options)
        goto allow_all;
    if (device_parse_options (options, &policy, &allow) < 0)
        return -1;
    if (streq (policy, "auto") && (!allow || json_array_size (allow) == 0))
        goto allow_all;
    if (!(da = calloc (1, sizeof (*da))))
        return -1;
    imp_debug ("device: %s", policy);
    if (!streq (policy, "strict")) {
        for (size_t i = 0; i < ARRAY_SIZE (standard_devices); i++) {
            if (device_append (da,
                               standard_devices[i].spec,
                               standard_devices[i].access) < 0)
                goto error;
        }
    }
    if (allow) {
        size_t index;
        json_t *entry;

        json_array_foreach (allow, index, entry) {
            const char *spec;
            const char *access;

            if (json_unpack (entry, "[ss]", &spec, &access) < 0) {
                errno = EINVAL;
                goto error;
            }
            if (device_append (da, spec, access) < 0)
                goto error;
        }
    }
    *dap = da;
    return 0;
error:
    device_allow_destroy (da);
    return -1;
allow_all:
    imp_debug ("device: allow all");
    *dap = NULL;
    return 0;
}

/* Encode one entry as "c:195:0:rw" */
static int entry_encode (const struct device_allow_entry *e,
                         char *buf,
                         size_t size)
{
    int n = snprintf (buf,
                      size,
                      "%c:%d:%d:%s",
                      e->type,
                      e->major,
                      e->minor,
                      e->access);
    if (n < 0 || (size_t)n >= size) {
        errno = EOVERFLOW;
        return -1;
    }
    return 0;
}

static int entry_decode (const char *s, struct device_allow_entry *e)
{
    char type;
    int major, minor;
    char access[4];

    if (sscanf (s, "%c:%d:%d:%3s", &type, &major, &minor, access) != 4
        || (type != 'c' && type != 'b')
        || !access_is_valid (access)) {
        errno = EINVAL;
        return -1;
    }
    e->type = type;
    e->major = major;
    e->minor = minor;
    strlcpy (e->access, access, sizeof (e->access));
    return 0;
}

int device_allow_encode (const struct device_allow *da, struct kv *kv)
{
    char key[32];
    char val[32];

    if (!da || !kv) {
        errno = EINVAL;
        return -1;
    }
    if (kv_put (kv, "device.count", KV_INT64, (int64_t)da->count) < 0)
        return -1;
    for (int i = 0; i < da->count; i++) {
        snprintf (key, sizeof (key), "device.%d", i);
        if (entry_encode (&da->entries[i], val, sizeof (val)) < 0)
            return -1;
        if (kv_put (kv, key, KV_STRING, val) < 0)
            return -1;
    }
    return 0;
}

int device_allow_decode (const struct kv *kv, struct device_allow **dap)
{
    struct device_allow *da = NULL;
    int64_t count;
    char key[32];

    if (!kv || !dap) {
        errno = EINVAL;
        return -1;
    }
    if (kv_get (kv, "device.count", KV_INT64, &count) < 0) {
        *dap = NULL;  /* absent == no containment */
        return 0;
    }
    if (count < 0 || count > DEVICE_ALLOW_MAX_ENTRIES) {
        errno = ERANGE;
        return -1;
    }
    if (!(da = calloc (1, sizeof (*da))))
        return -1;
    if (count > 0) {
        if (!(da->entries = calloc (count, sizeof (*da->entries))))
            goto error;
        for (int i = 0; i < (int)count; i++) {
            const char *val;
            snprintf (key, sizeof (key), "device.%d", i);
            if (kv_get (kv, key, KV_STRING, &val) < 0)
                goto error;
            if (entry_decode (val, &da->entries[i]) < 0)
                goto error;
        }
    }
    da->count = (int)count;
    *dap = da;
    return 0;
error:
    device_allow_destroy (da);
    return -1;
}

void device_allow_destroy (struct device_allow *da)
{
    if (da) {
        free (da->entries);
        free (da);
    }
}

// vi: ts=4 sw=4 expandtab

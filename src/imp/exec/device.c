/************************************************************\
 * Copyright 2026 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "src/libutil/strlcpy.h"
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

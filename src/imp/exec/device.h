/************************************************************\
 * Copyright 2026 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#ifndef IMP_EXEC_DEVICE_H
#define IMP_EXEC_DEVICE_H

#include "src/libutil/kv.h"

#define DEVICE_ALLOW_MAX_ENTRIES 512

/* A single resolved device allow entry.
 * type is 'c' (char) or 'b' (block).
 * major/minor are device numbers; minor == -1 means wildcard.
 * access is a subset of "rwm" as a null-terminated string.
 */
struct device_allow_entry {
    char type;
    int major;
    int minor;
    char access[4];
};

struct device_allow {
    struct device_allow_entry *entries;
    int count;
};

/* Decode device_allow from a kv namespace.
 * Returns 0 with *dap set to NULL if "device.count" is absent (no containment).
 * Returns 0 with *dap set on success.
 * Returns -1 with errno set on error.
 */
int device_allow_decode (const struct kv *kv, struct device_allow **dap);

void device_allow_destroy (struct device_allow *da);

/* Encode device_allow into kv namespace for privsep transfer.
 * Returns 0 on success, -1 on error with errno set.
 */
int device_allow_encode (const struct device_allow *da, struct kv *kv);

#endif /* IMP_EXEC_DEVICE_H */

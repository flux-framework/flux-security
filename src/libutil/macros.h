/************************************************************\
 * Copyright 2017 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#ifndef LIBUTIL_MACROS_H
#define LIBUTIL_MACROS_H 1

/* Maximum size of buffer needed to decode a base64 string of length 'x',
 * where 4 characters are decoded into 3 bytes.  Add 3 bytes to ensure a
 * partial 4-byte chunk will be accounted for during integer division.
 * This size is safe for use with all (4) libsodium base64 variants.
 * N.B. unlike @dun's base64 implementation from the munge project,
 * this size does not include room for a \0 string terminator.
 */
#define BASE64_DECODE_SIZE(x) ((((x) + 3) / 4) * 3)


#ifndef streq
#define streq(x,y) (strcmp((x),(y)) == 0)
#endif

#ifndef strstarts
#define strstarts(x,y) (strncmp((x),(y),strlen(y)) == 0)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof((x)) / sizeof((x)[0]))
#endif

#ifndef ERRNO_SAFE_WRAP
#define ERRNO_SAFE_WRAP(fun, ...) do { \
        int saved_errno = errno; \
        (fun)(__VA_ARGS__); \
        errno = saved_errno; \
} while (0)
#endif

#endif

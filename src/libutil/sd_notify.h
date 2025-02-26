/* SPDX-License-Identifier: MIT-0 */
/* Implement the systemd notify protocol without external dependencies.
 * Supports both readiness notification on startup and on reloading,
 * according to the protocol defined at:
 * https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html
 * This protocol is guaranteed to be stable as per:
 * https://systemd.io/PORTABILITY_AND_STABILITY/ */

/* From https://www.man7.org/linux/man-pages/man3/sd_notify.3.html
 * Modified for Flux - 2025-02-26 jg */

#ifndef LIBUTIL_SD_NOTIFY_H
#define LIBUTIL_SD_NOTIFY_H

#include <stdarg.h>

int sd_notify (int flag, const char *message);
int sd_notifyf (int flag, const char *fmt, ...);

#endif //!LIBUTIL_SD_NOTIFY_H

// vi:ts=4 sw=4 expandtab

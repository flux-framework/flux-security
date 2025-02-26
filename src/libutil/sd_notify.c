/* SPDX-License-Identifier: MIT-0 */
/* Implement the systemd notify protocol without external dependencies.
 * Supports both readiness notification on startup and on reloading,
 * according to the protocol defined at:
 * https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html
 * This protocol is guaranteed to be stable as per:
 * https://systemd.io/PORTABILITY_AND_STABILITY/ */

/* From https://www.man7.org/linux/man-pages/man3/sd_notify.3.html
 * Modified for Flux - 2025-02-26 jg */

#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "sd_notify.h"

#define _cleanup_(f) __attribute__((cleanup(f)))

static void closep(int *fd)
{
	if (!fd || *fd < 0)
        return;
    close(*fd);
    *fd = -1;
}

// flag is currently ignored
int sd_notify (int flag, const char *message)
{
    union sockaddr_union {
        struct sockaddr sa;
        struct sockaddr_un sun;
    } socket_addr = {
        .sun.sun_family = AF_UNIX,
    };
    size_t path_length, message_length;
    _cleanup_ (closep) int fd = -1;
    const char *socket_path;

    /* Verify the argument first */
    if (!message)
        return -EINVAL;

    message_length = strlen (message);
    if (message_length == 0)
        return -EINVAL;

    /* If the variable is not set, the protocol is a noop */
    socket_path = getenv ("NOTIFY_SOCKET");
    if (!socket_path)
        return 0; /* Not set? Nothing to do */

    /* Only AF_UNIX is supported, with path or abstract sockets */
    if (socket_path[0] != '/' && socket_path[0] != '@')
        return -EAFNOSUPPORT;

    path_length = strlen(socket_path);
    /* Ensure there is room for NUL byte */
    if (path_length >= sizeof(socket_addr.sun.sun_path))
        return -E2BIG;

    memcpy (socket_addr.sun.sun_path, socket_path, path_length);

    /* Support for abstract socket */
    if (socket_addr.sun.sun_path[0] == '@')
        socket_addr.sun.sun_path[0] = 0;

    fd = socket (AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -errno;

    if (connect (fd,
                 &socket_addr.sa,
                 offsetof(struct sockaddr_un, sun_path) + path_length) != 0)
        return -errno;

    ssize_t written = write (fd, message, message_length);
    if (written != (ssize_t)message_length)
        return written < 0 ? -errno : -EPROTO;

    return 1; /* Notified! */
}

int sd_notifyf (int flag, const char *fmt, ...)
{
    va_list ap;
    char *message = NULL;
    int rc;

    va_start (ap, fmt);
    rc = vasprintf (&message, fmt, ap);
    va_end (ap);
    if (rc < 0)
        return -errno;

    rc = sd_notify (flag, message);
    free (message);
    return rc;
}

// vi:ts=4 sw=4 expandtab

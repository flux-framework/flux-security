/************************************************************\
 * Copyright 2017 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include "imp_log.h"
#include "libutil/hash.h"

#define PROVIDER_MAX_NAMELEN 32

struct log_output {
    char name [PROVIDER_MAX_NAMELEN+1];
    int level;
    imp_log_output_f outf;
    void *arg;
};

struct log_msg {
    int level;
    const char *msg;
};

struct imp_logger {
    int level;
    const char *prefix;
    hash_t outputs;
};

static struct imp_logger imp_logger;

/*
 *  Static functions:
 */
static struct log_output * log_output_create (const char *name, int level,
                                              imp_log_output_f outf, void *arg)
{
    struct log_output *p;
    if (strlen (name) >  PROVIDER_MAX_NAMELEN) {
        errno = EINVAL;
        return NULL;
    }
    if (!(p = calloc (1, sizeof (*p))))
        return NULL;
    strcpy (p->name, name);
    p->outf = outf;
    p->level = level;
    p->arg = arg;

    return (p);
}

static void log_output_destroy (struct log_output *o)
{
    memset (o, 0, sizeof (*o));
    free (o);
}

static int
log_output_call (struct log_output *o, const char *x __attribute__ ((unused)),
                 struct log_msg *m)
{
    if (m->level > o->level)
        return (0);
    if (o->outf (m->level, m->msg, o->arg) < 0)
        return (0);
    return (1);
}

static int find_by_name (void *data __attribute__ ((unused)),
                         const char *key, const char *name)
{
    return (!strcmp (key, name));
}


/*
 *  Log initialization and log output registration functions:
 */
void imp_openlog ()
{
    extern char *__progname; /* or glibc program_invocation_short_name */

    memset (&imp_logger, 0, sizeof (struct imp_logger));
    imp_logger.prefix = __progname;

    imp_logger.outputs = hash_create (0, (hash_key_f) hash_key_string,
                                         (hash_cmp_f) strcmp,
                                         (hash_del_f) log_output_destroy);
    imp_logger.level = IMP_LOG_INFO;
    return;
}

void imp_closelog ()
{
    hash_destroy (imp_logger.outputs);
    memset (&imp_logger, 0, sizeof (struct imp_logger));
}

int imp_log_add (const char *name, int level, imp_log_output_f fn, void *arg)
{
    struct log_output *p;

    if ((level < 0) || (level > IMP_LOG_DEBUG)) {
        errno = EINVAL;
        return (-1);
    }
    if (hash_find (imp_logger.outputs, name)) {
        errno = EEXIST;
        return (-1);
    }
    if (!(p = log_output_create (name, level, fn, arg)) ||
        !hash_insert (imp_logger.outputs, p->name, p))
        return (-1);
    return (0);
}

int imp_log_remove (char *name)
{
    int count = hash_delete_if (imp_logger.outputs,
                                (hash_arg_f) find_by_name,
                                name);
    if (count > 0)
        return (0);
    if (count == 0)
        errno = ENOENT;
    return (-1);
}

int imp_log_set_level (const char *name, int level)
{
    struct log_output *p;

    if ((level < 0) || (level > IMP_LOG_DEBUG)) {
        errno = EINVAL;
        return (-1);
    }

    /*  Set global logger level if name == NULL
     */
    if (name == NULL) {
        imp_logger.level = level;
        return (0);
    }

    /*  Otherwise, set log level for named output only:
     */
    if (!(p = hash_find (imp_logger.outputs, name))) {
        errno = ENOENT;
        return (-1);
    }
    p->level = level;
    return (0);
}


/*
 *   Logging interface functions
 */
static void vlog_msg (int level, const char *format, va_list ap,
                      hash_t outputs)
{
    struct log_msg arg = { .level = level, .msg = NULL };
    char  buf [4096];
    int   n = 0;
    int   len = sizeof (buf);

    if (format == NULL)
        return;

    n = vsnprintf (buf, len, format, ap);
    if ((n < 0) || (n >= len)) {
        /*  Add suffix of '+' to message to indicate truncation
         */
        char *q;
        const char *suffix = "+";
        q = buf + sizeof (buf) - 1 - strlen (suffix);
        strcpy (q, suffix);
        q += strlen (suffix);
        *q = '\0';
    }

    arg.msg = buf;
    hash_for_each (outputs, (hash_arg_f) log_output_call, (void *) &arg);
}

void imp_say (const char *fmt, ...)
{
    va_list ap;
    int saved_errno;
    if (imp_logger.level < IMP_LOG_INFO)
        return;
    saved_errno = errno;
    va_start (ap, fmt);
    vlog_msg (IMP_LOG_INFO, fmt, ap, imp_logger.outputs);
    va_end (ap);
    errno = saved_errno;
}

void imp_warn (const char *fmt, ...)
{
    va_list ap;
    int saved_errno;
    if (imp_logger.level < IMP_LOG_WARNING)
        return;
    saved_errno = errno;
    va_start (ap, fmt);
    vlog_msg (IMP_LOG_WARNING, fmt, ap, imp_logger.outputs);
    va_end (ap);
    errno = saved_errno;
}

void imp_debug (const char *fmt, ...)
{
    va_list ap;
    int saved_errno;
    if (imp_logger.level < IMP_LOG_DEBUG)
        return;
    saved_errno = errno;
    va_start (ap, fmt);
    vlog_msg (IMP_LOG_DEBUG, fmt, ap, imp_logger.outputs);
    va_end (ap);
    errno = saved_errno;
}

void imp_die (int code, const char *fmt, ...)
{
    va_list ap;
    if (imp_logger.level >= IMP_LOG_FATAL) {
        va_start (ap, fmt);
        vlog_msg (IMP_LOG_FATAL, fmt, ap, imp_logger.outputs);
        va_end (ap);
    }
    exit (code);
}

const char *imp_log_strlevel (int level)
{
    if (level == IMP_LOG_FATAL)
        return ("Fatal");
    else if (level == IMP_LOG_WARNING)
        return ("Warning");
    else if (level == IMP_LOG_INFO)
        return ("Notice");
    else if (level == IMP_LOG_DEBUG)
        return ("Debug");
    else
        return NULL;
}

/*
 * vi: ts=4 sw=4 expandtab
 */

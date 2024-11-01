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
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "imp_state.h"
#include "imp_log.h"
#include "impcmd.h"
#include "sudosim.h"

/*
 *  External function used to return current default config pattern.
 */
extern const char *imp_get_config_pattern (void);

/*  External function used to initialize imp config object */
extern int imp_conf_init (cf_t *cf, struct cf_error *error);

/*  Static prototypes:
 */
static void initialize_logging ();
static int  imp_state_init (struct imp_state *imp, int argc, char **argv);
static cf_t * imp_conf_load (const char *pattern);
static bool imp_is_privileged ();
static bool imp_is_setuid ();
static void initialize_sudo_support (cf_t *conf);

static void imp_child (privsep_t *ps, void *arg);
static void imp_parent (struct imp_state *imp);

int main (int argc, char *argv[])
{
    int exit_code = 0;
    struct imp_state imp;

    initialize_logging ();

    if (imp_state_init (&imp, argc, argv) < 0)
        imp_die (1, "Initialization error");

    /*  Configuration:
     */
    if (!(imp.conf = imp_conf_load (imp_get_config_pattern ())))
        imp_die (1, "Failed to load configuration");

    /*  Get current IMP cgroup information:
     */
    if (!(imp.cgroup = cgroup_info_create ()))
        imp_die (1, "Failed to get current cgroup info");

    /*  Audit subsystem initialization
     */
    // Skip.

    /*  Security architecture initialization
     */
    if (imp_is_privileged ()) {

        /*  Simulate setuid under sudo(8) if configured */
        initialize_sudo_support (imp.conf);

        if (!imp_is_setuid ())
            imp_die (1, "Refusing to run as root");

        /*  Initialize privilege separation (required for now)
         */
        if (!(imp.ps = privsep_init (imp_child, &imp)))
            imp_die (1, "Privilege separation initialization failed");

        imp_parent (&imp);

        /*  Wait for child to exit. Exit with failure if child did so.
         */
        if (privsep_wait (imp.ps) < 0)
            exit_code = 1;
    }
    else {
        /*  Not running with privilege, run child half of function only */
        imp_child (NULL, &imp);
    }

    privsep_destroy (imp.ps);
    cf_destroy (imp.conf);
    imp_closelog ();
    exit (exit_code);
}

static int log_stderr (int level, const char *str,
                       void *arg __attribute__ ((unused)))
{
    if (level == IMP_LOG_INFO)
        fprintf (stderr, "flux-imp: %s\n", str);
    else
        fprintf (stderr, "flux-imp: %s: %s\n", imp_log_strlevel (level), str);
    return (0);
}

static void initialize_logging (void)
{
    imp_openlog ();
    if (imp_log_add ("stderr", IMP_LOG_INFO, log_stderr, NULL) < 0) {
        fprintf (stderr, "flux-imp: Fatal: Failed to initialize logging.\n");
        exit (1);
    }
}

static int imp_state_init (struct imp_state *imp, int argc, char *argv[])
{
    memset (imp, 0, sizeof (*imp));
    imp->argc = argc;
    imp->argv = argv;
    return (0);
}

/*
 *  Load IMP configuration from glob(7) `pattern`. Fatal error if configuration
 *   fails to load.
 */
static cf_t * imp_conf_load (const char *pattern)
{
    int rc;
    struct cf_error err;
    cf_t *cf = NULL;

    if (pattern == NULL)
        imp_die (1, "imp_conf_load: Internal error");

    if (!(cf = cf_create ()))
        return (NULL);

    memset (&err, 0, sizeof (err));
    if (imp_conf_init (cf, &err) < 0
        || (rc = cf_update_glob (cf, pattern, &err)) < 0) {
        imp_warn ("loading config: %s: %d: %s",
                 err.filename, err.lineno, err.errbuf);
        cf_destroy (cf);
        return (NULL);
    }
    else if (rc == 0) {
        imp_warn ("%s: No config file(s) found", pattern);
        cf_destroy (cf);
        return (NULL);
    }
    return (cf);
}

/*
 *  Return true if effective UID is 0.
 */
static bool imp_is_privileged ()
{
    return (geteuid() == 0);
}

/*
 *  Return true if effective UID is 0, but real UID is non-zero
 */
static bool imp_is_setuid ()
{
    return (geteuid() == 0 && getuid() > 0);
}

/*  Simulate setuid installation when run under sudo if "allow-sudo" is
 *   set to true in configuration. If `allow-sudo` is not set and the
 *   process appears to be run under sudo, or the sudo simulate call fails
 *   then this is a fatal error.
 */
static void initialize_sudo_support (cf_t *conf)
{
    const cf_t *cf;
    if (sudo_is_active ()) {
        if (!(cf = cf_get_in (conf, "allow-sudo")) || !cf_bool (cf))
            imp_die (1, "sudo support not enabled");
        else if (sudo_simulate_setuid () < 0)
            imp_die (1, "Failed to enable sudo support");
    }
}

static struct kv * kv_encode_cmd (const char * cmd)
{
    struct kv *kv = kv_create ();
    if (kv == NULL)
        return (NULL);
    if (kv_put (kv, "cmd", KV_STRING, cmd) < 0) {
        kv_destroy (kv);
        return (NULL);
    }
    return (kv);
}


/*  IMP unprivileged child.
 */
static void imp_child (privsep_t *ps, void *arg)
{
    struct kv *kv;
    struct imp_state *imp = arg;
    imp_cmd_f cmd = NULL;

    assert (imp != NULL);

    /*  Be sure to assign privsep handle to imp->ps since this has not
     *   been done yet (only in parent)
     */
    imp->ps = ps;

    if (imp->argc <= 1)
        imp_die (1, "command required");

    if (!(cmd = imp_cmd_find_child (imp->argv[1])))
        imp_die (1, "Unknown IMP command: %s", imp->argv[1]);

    if (!(kv = kv_encode_cmd (imp->argv[1])))
        imp_die (1, "Failed to encode IMP command: %s", strerror (errno));

    if (((*cmd) (imp, kv)) < 0)
        exit (1);

    kv_destroy (kv);
}

static void imp_parent (struct imp_state *imp)
{
    struct kv * kv = privsep_read_kv (imp->ps);
    if (kv) {
        const char *cmdname = NULL;
        imp_cmd_f cmd = NULL;
        if (kv_get (kv, "cmd", KV_STRING, &cmdname) < 0)
            imp_die (1, "Failed to read command from privsep child");
        if ((cmd = imp_cmd_find_parent (cmdname)) != NULL) {
            if (((*cmd) (imp, kv)) < 0)
                exit (1);
        }
        kv_destroy (kv);
    }
}

/*
 * vi: ts=4 sw=4 expandtab
 */

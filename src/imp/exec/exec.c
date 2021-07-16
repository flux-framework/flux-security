/************************************************************\
 * Copyright 2020 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

/* exec - given valid signed 'J', execute a job shell as user
 *
 * Usage: flux-imp exec /path/to/job/shell arg
 *
 * Input:
 *
 * Signed J as key "J" in JSON object on stdin, path to requested
 *  job shell and single argument on cmdline.
 *
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <jansson.h>


#include "src/libutil/kv.h"
#include "src/lib/context.h"
#include "src/lib/sign.h"

#include "imp_log.h"
#include "imp_state.h"
#include "impcmd.h"
#include "privsep.h"
#include "passwd.h"
#include "user.h"

struct imp_exec {
    struct passwd *imp_pwd;
    struct imp_state *imp;
    flux_security_t *sec;
    const cf_t *conf;

    uid_t userid;
    json_t *input;

    const char *J;
    const char *shell;
    const char *arg;
    const void *spec;
    int specsz;
};

extern const char *imp_get_security_config_pattern (void);
extern int imp_get_security_flags (void);

static flux_security_t *sec_init (void)
{
    flux_security_t *sec = flux_security_create (imp_get_security_flags ());
    const char *conf_pattern = imp_get_security_config_pattern ();

    if (!sec || flux_security_configure (sec, conf_pattern) < 0) {
        imp_die (1, "exec: Error loading security context: %s",
                    sec ? flux_security_last_error (sec) : strerror (errno));
    }
    return sec;
}

static bool imp_exec_user_allowed (struct imp_exec *exec)
{
    return cf_array_contains (cf_get_in (exec->conf, "allowed-users"),
                              exec->imp_pwd->pw_name);
}

static bool imp_exec_shell_allowed (struct imp_exec *exec)
{
    return cf_array_contains (cf_get_in (exec->conf, "allowed-shells"),
                              exec->shell);
}

static bool imp_exec_unprivileged_allowed (struct imp_exec *exec)
{
    return cf_bool (cf_get_in (exec->conf, "allow-unprivileged-exec"));
}

static void imp_exec_destroy (struct imp_exec *exec)
{
    if (exec) {
        flux_security_destroy (exec->sec);
        json_decref (exec->input);
        passwd_destroy (exec->imp_pwd);
        free (exec);
    }
}

static struct imp_exec *imp_exec_create (struct imp_state *imp)
{
    struct imp_exec *exec = calloc (1, sizeof (*exec));
    if (exec) {
        exec->userid = (uid_t) -1;
        exec->imp = imp;
        exec->sec = sec_init ();
        exec->conf = cf_get_in (imp->conf, "exec");

        if (!(exec->imp_pwd = passwd_from_uid (getuid ())))
            imp_die (1, "exec: failed to find IMP user");
    }
    return exec;
}

static void imp_exec_unwrap (struct imp_exec *exec, const char *J)
{
    int64_t userid;

    if (flux_sign_unwrap (exec->sec,
                          J,
                          &exec->spec,
                          &exec->specsz,
                          &userid,
                          0) < 0)
        imp_die (1, "exec: signature validation failed: %s",
                 flux_security_last_error (exec->sec));

    exec->userid = (uid_t) userid;
}

static void imp_exec_init_kv (struct imp_exec *exec, struct kv *kv)
{
    assert (exec != NULL && kv != NULL);

    if (kv_get (kv, "J", KV_STRING, &exec->J) < 0)
        imp_die (1, "exec: Error decoding J");
    if (kv_get (kv, "shell_path", KV_STRING, &exec->shell) < 0)
        imp_die (1, "exec: Failed to get job shell path");
    if (kv_get (kv, "arg", KV_STRING, &exec->arg) < 0)
        imp_die (1, "exec: Failed to get job shell arg");

    imp_exec_unwrap (exec, exec->J);
}

static void imp_exec_init_stream (struct imp_exec *exec, FILE *fp)
{
    struct imp_state *imp;
    json_error_t err;

    assert (exec != NULL && exec->imp != NULL && fp != NULL);

    imp = exec->imp;

    /* shell path and `arg` come from imp->argv */
    if (imp->argc < 4)
        imp_die (1, "exec: missing arguments to exec subcommand");

    exec->shell = imp->argv[2];

    /*  Only a single argument to the shell is currently supported */
    exec->arg = imp->argv[3];

    /* Get input from JSON on stdin */
    if (!(exec->input = json_loadf (fp, 0, &err))
        || json_unpack_ex (exec->input,
                           &err,
                           0,
                           "{s:s}",
                           "J", &exec->J) < 0)
        imp_die (1, "exec: invalid json input: %s", err.text);

    imp_exec_unwrap (exec, exec->J);
}

static void __attribute__((noreturn)) imp_exec (struct imp_exec *exec)
{
    const char *args[3];
    int exit_code;

    /* Setup minimal environment */

    /* Move to "safe" path (XXX: user's home directory?) */
    if (chdir ("/") < 0)
        imp_die (1, "exec: failed to chdir to /");

    args[0] = exec->shell;
    args[1] = exec->arg;
    args[2] = NULL;
    execvp (exec->shell, (char **) args);

    if (errno == EPERM || errno == EACCES)
        exit_code =  126;
    exit_code = 127;
    imp_die (exit_code, "%s: %s", exec->shell, strerror (errno));
}

int imp_exec_privileged (struct imp_state *imp, struct kv *kv)
{
    struct imp_exec *exec = imp_exec_create (imp);
    if (!exec)
        imp_die (1, "exec: failed to initialize state");

    if (!imp_exec_user_allowed (exec))
        imp_die (1, "exec: user %s not in allowed-users list",
                    exec->imp_pwd->pw_name);

    /* Init IMP input from kv object */
    imp_exec_init_kv (exec, kv);

    /* Paranoia checks
     */
    if (exec->userid == 0)
        imp_die (1, "exec: switching to user root not supported");
    if (!imp_exec_shell_allowed (exec))
        imp_die (1, "exec: shell not in allowed-shells list");

    /* Ensure child exited with nonzero status */
    if (privsep_wait (imp->ps) < 0)
        exit (1);

    /* Call privileged IMP plugins/containment */

    /* Irreversibly switch to user */
    imp_switch_user (exec->userid);

    /* execute shell (NORETURN) */
    imp_exec (exec);

    return (-1);
}

/* Put all data from imp_exec into kv struct `kv`
 */
static void imp_exec_put_kv (struct imp_exec *exec,
                                   struct kv *kv)
{
    if (kv_put (kv, "J", KV_STRING, exec->J) < 0)
        imp_die (1, "exec: Error decoding J");
    if (kv_put (kv, "shell_path", KV_STRING, exec->shell) < 0)
        imp_die (1, "exec: Failed to get job shell path");
    if (kv_put (kv, "arg", KV_STRING, exec->arg) < 0)
        imp_die (1, "exec: Failed to get job shell arg");
}

int imp_exec_unprivileged (struct imp_state *imp, struct kv *kv)
{
    struct imp_exec *exec = imp_exec_create (imp);
    if (!exec)
        imp_die (1, "exec: initialization failure");

    if (!imp_exec_user_allowed (exec))
        imp_die (1, "exec: user %s not in allowed-users list",
                    exec->imp_pwd->pw_name);

    /* Read input from stdin, cmdline: */
    imp_exec_init_stream (exec, stdin);

    /* XXX; Parse jobspec if necessary, disabled for now: */
    //if (!(jobspec = json_loads (spec, 0, &err)))
    //   imp_die (1, "exec: failed to parse jobspec: %s", err.text);

    if (imp->ps) {
        if (!imp_exec_shell_allowed (exec))
            imp_die (1, "exec: shell not in allowed-shells");

        /* In privsep mode, write kv to privileged parent and exit */
        imp_exec_put_kv (exec, kv);

        if (privsep_write_kv (imp->ps, kv) < 0)
            imp_die (1, "exec: failed to communicate with privsep parent");
        imp_exec_destroy (exec);
        exit (0);
    }

    if (!imp_exec_unprivileged_allowed (exec))
        imp_die (1, "exec: IMP not installed setuid, operation disabled.");

    /* Unprivileged exec allowed. Issue warning and process input for
     *  testing purposes.
     */
    imp_warn ("Running without privilege, userid switching not available");

    imp_exec (exec);

    /* imp_exec() does not return */
    return -1;
}

/* vi: ts=4 sw=4 expandtab
 */

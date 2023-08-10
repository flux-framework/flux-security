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
 * If FLUX_IMP_EXEC_HELPER is set, then execute the value of this
 *  variable and read input from there.
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
#include <sys/types.h>
#include <wait.h>
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
#include "safe_popen.h"

#if HAVE_PAM
#include "pam.h"
#endif

struct imp_exec {
    struct passwd *imp_pwd;
    struct imp_state *imp;
    flux_security_t *sec;
    const cf_t *conf;

    struct passwd *user_pwd;
    json_t *input;

    const char *J;
    const char *shell;
    struct kv *args;
    const void *spec;
    int specsz;
};

static pid_t imp_child = (pid_t) -1;

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


/* Check for PAM support, but default to not using PAM for now.
 */
static bool imp_supports_pam (struct imp_exec *exec) {
    return cf_bool (cf_get_in (exec->conf, "pam-support"));
}

static void imp_exec_destroy (struct imp_exec *exec)
{
    if (exec) {
        flux_security_destroy (exec->sec);
        json_decref (exec->input);
        passwd_destroy (exec->user_pwd);
        passwd_destroy (exec->imp_pwd);
        kv_destroy (exec->args);
        free (exec);
    }
}

static struct imp_exec *imp_exec_create (struct imp_state *imp)
{
    struct imp_exec *exec = calloc (1, sizeof (*exec));
    if (exec) {
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

    if (!(exec->user_pwd = passwd_from_uid (userid))) {
        char hostname[1024] = "unknown";
        (void)gethostname (hostname, sizeof (hostname));
        imp_die (1,
                 "exec: userid %d is invalid on %s",
                 (int)userid,
                 hostname);
    }
}

static void imp_exec_init_kv (struct imp_exec *exec, struct kv *kv)
{
    assert (exec != NULL && kv != NULL);

    if (kv_get (kv, "J", KV_STRING, &exec->J) < 0)
        imp_die (1, "exec: Error decoding J");
    if (kv_get (kv, "shell_path", KV_STRING, &exec->shell) < 0)
        imp_die (1, "exec: Failed to get job shell path");

    /*  Split shell argv from struct kv */
    if (!(exec->args = kv_split (kv, "args")))
        imp_die (1, "exec: Failed to get job shell arguments");

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

    if (!(exec->args = kv_encode_argv ((const char **) &imp->argv[2])))
        imp_die (1, "exec: failed to encode shell arguments");

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
    char **argv;
    int exit_code;

    /* Setup minimal environment */

    /* Move to "safe" path (XXX: user's home directory?) */
    if (chdir ("/") < 0)
        imp_die (1, "exec: failed to chdir to /");

    if (kv_expand_argv (exec->args, &argv) < 0)
        imp_die (1, "exec: failed to expand argv");

    execvp (exec->shell, argv);

    if (errno == EPERM || errno == EACCES)
        exit_code =  126;
    exit_code = 127;
    imp_die (exit_code, "%s: %s", exec->shell, strerror (errno));
}

static void fwd_signal (int signal)
{
    if (imp_child > 0)
        kill (imp_child, signal);
}

/*  Setup signal handlers in the IMP for common signals which
 *   we want to forward to any child process.
 */
static void setup_signal_forwarding (void)
{
    struct sigaction sa;
    sigset_t mask;
    int i;
    int signals[] = {
        SIGTERM,
        SIGINT,
        SIGHUP,
        SIGCONT,
        SIGALRM,
        SIGWINCH,
        SIGTTIN,
        SIGTTOU,
    };
    int nsignals =  sizeof (signals) / sizeof (signals[0]);

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = fwd_signal;
    sa.sa_flags = SA_RESTART;
    sigemptyset(&sa.sa_mask);

    sigfillset (&mask);
    for (i = 0; i < nsignals; i++) {
        sigdelset (&mask, signals[i]);
        if (sigaction(signals[i], &sa, NULL) < 0)
            imp_warn ("sigaction (signal=%d): %s",
                      signals[i],
                      strerror (errno));
    }
    if (sigprocmask (SIG_SETMASK, &mask, NULL) < 0)
       imp_die (1, "failed to block signals: %s", strerror (errno));
}

static void sigblock_all (void)
{
    sigset_t mask;
    sigfillset (&mask);
    if (sigprocmask (SIG_SETMASK, &mask, NULL) < 0)
        imp_die (1, "failed to block signals: %s", strerror (errno));
}

static void sigunblock_all (void)
{
    sigset_t mask;
    sigemptyset (&mask);
    if (sigprocmask (SIG_SETMASK, &mask, NULL) < 0)
        imp_die (1, "failed to unblock signals: %s", strerror (errno));
}

int imp_exec_privileged (struct imp_state *imp, struct kv *kv)
{
    int status;
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
    if (exec->user_pwd->pw_uid == 0)
        imp_die (1, "exec: switching to user root not supported");
    if (!imp_exec_shell_allowed (exec))
        imp_die (1, "exec: shell not in allowed-shells list");

    /* Ensure child exited with nonzero status */
    if (privsep_wait (imp->ps) < 0)
        exit (1);

    /* Call privileged IMP plugins/containment */
    if (imp_supports_pam (exec)) {
#if HAVE_PAM
        if (pam_setup (exec->user_pwd->pw_name) < 0)
            imp_die (1, "exec: PAM stack failure");
#else
        imp_die (1,
                 "exec: pam-support=true, but IMP was built without "
                 "--enable-pam");
#endif /* HAVE_PAM */
    }

    /* Block signals so parent IMP isn't unduly terminated */
    sigblock_all ();

    if ((imp_child = fork ()) < 0)
        imp_die (1, "exec: fork: %s", strerror (errno));

    if (imp_child == 0) {

        /* unblock all signals */
        sigunblock_all ();

        /* Irreversibly switch to user */
        imp_switch_user (exec->user_pwd->pw_uid);

        /* execute shell (NORETURN) */
        imp_exec (exec);
    }

    /* Ensure common signals received by this IMP are forwarded to
     *  the child process
     */
    setup_signal_forwarding ();

    /* Parent: wait for child to exit */
    while (waitpid (imp_child, &status, 0) != imp_child) {
        if (errno != EINTR)
            imp_die (1, "waitpid: %s", strerror (errno));
    }

#if HAVE_PAM
    /* Call privliged IMP plugins/containment finalization */
    if (imp_supports_pam (exec))
        pam_finish ();
#endif /* HAVE_PAM */

    /* Exit with status of the child process */
    if (WIFEXITED (status))
        exit (WEXITSTATUS (status));
    else if (WIFSIGNALED (status))
        exit (WTERMSIG (status) + 128);
    else
        exit (1);

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
    if (kv_join (kv, exec->args, "args") < 0)
        imp_die (1, "exec: Failed to set job shell arguments");
}

/*  Read IMP input using a helper process
 */
static void imp_exec_init_helper (struct imp_exec *exec,
                                  char *helper)
{
        int status;
        struct safe_popen *sp;

        if (!(sp = safe_popen (helper)))
            imp_die (1, "exec: failed to invoke helper: %s", helper);

        imp_exec_init_stream (exec, safe_popen_fp (sp));

        if (safe_popen_wait (sp, &status) < 0
            || status != 0)
            imp_die (1, "exec: helper %s failed with status=0x%04x",
                     helper,
                     status);

        safe_popen_destroy (sp);
}

int imp_exec_unprivileged (struct imp_state *imp, struct kv *kv)
{
    char *helper;
    struct imp_exec *exec = imp_exec_create (imp);
    if (!exec)
        imp_die (1, "exec: initialization failure");

    if (!imp_exec_user_allowed (exec))
        imp_die (1, "exec: user %s not in allowed-users list",
                    exec->imp_pwd->pw_name);

    if ((helper = getenv ("FLUX_IMP_EXEC_HELPER"))) {
        if (strlen (helper) == 0)
            imp_die (1, "exec: FLUX_IMP_EXEC_HELPER is empty");
        /* Read input from helper command */
        imp_exec_init_helper (exec, helper);
    }
    else {
        /* Read input from stdin, cmdline: */
        imp_exec_init_stream (exec, stdin);
    }

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

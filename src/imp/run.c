/************************************************************\
 * Copyright 2021 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

/* flux-imp run
 *
 * PURPOSE:
 *
 *  Allow a non-privileged Flux instance to execute a configured
 *   named executable in the [run] section (e.g. "prolog" or "epilog")
 *
 * OPERATION
 *
 *  Unprivileged child reads "command" requested to execute on command line,
 *   and any allowed environment variables and sends kv struct to parent
 *
 *  Lookup configuration for "command"
 *    - ensure calling user is allowed to execute "command"
 *    - set absolute path for command
 *    - capture allowed environment variables based on allowed-environment
 *
 *  Environment variables set by IMP:
 *  - FLUX_OWNER_USERID - uid of the user running the IMP
 *  - PATH - "/usr/sbin:/usr/bin:/sbin:/bin"
 *  - HOME
 *  - USER
 *
 *  - switch uid and gid to effective uid gid
 *
 *  - wait for child to terminate successfully
 *
 *  - execute command
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pwd.h>
#include <signal.h>

#include "src/libutil/kv.h"
#include "src/libutil/path.h"

#include "imp_log.h"
#include "imp_state.h"
#include "impcmd.h"
#include "privsep.h"
#include "signals.h"

extern char **environ;

#if CODE_COVERAGE_ENABLED
void __gcov_dump (void);
void __gcov_reset (void);
#endif

static const cf_t *imp_run_lookup (struct imp_state *imp,
                                   const char *name)
{
    struct path_error error;
    const char *path;
    const cf_t *cf;
    const cf_t *run = cf_get_in (imp->conf, "run");

    /*  Check for [run.name] configuration table:
     */
    if (!run || !(cf = cf_get_in (run, name)))
        imp_die (1, "run: %s: no configuration found", name);

    /*  Check for required members of [run.name]:
     *   - 'path' must exist and be an absolute path
     */
    if (!(path = cf_string (cf_get_in (cf, "path")))
        || path[0] == '\0'
        || path[0] != '/')
        imp_die (1, "run: %s: path is missing or invalid", name);

    if (!path_is_secure (path, &error))
        imp_die (1, "run: %s: %s", path, error.text);

    return cf;
}

static bool run_user_allowed (const cf_t *cf_run)
{
    struct passwd *pwd;

    if (!(pwd = getpwuid (getuid ())) || !pwd->pw_name)
        imp_die (1, "Unable to lookup user");

    return cf_array_contains (cf_get_in (cf_run, "allowed-users"),
                              pwd->pw_name);
}

static bool run_env_var_allowed (const cf_t *allowed_env,
                                 const char *name)
{
    if (strcmp (name, "FLUX_JOB_ID") == 0
        || strcmp (name, "FLUX_JOB_USERID") == 0)
        return true;
    return cf_array_contains_match (allowed_env, name);
}

/*  Return a kv structure with the environment for this run command.
 */
static struct kv *get_run_env (struct kv *kv, const cf_t *allowed_env)
{
    struct kv *kv_env;
    const char *var = NULL;

    if (!(kv_env = kv_split (kv, "IMP_RUN_ENV_")))
        return NULL;

    while ((var = kv_next (kv_env, var))) {
        if (!run_env_var_allowed (allowed_env, var))
            kv_delete (kv_env, var);
    }

    /*  Capture uid that ran the imp as the "owner" */
    if (kv_put (kv_env,
                "FLUX_OWNER_USERID",
                KV_INT64,
                (int64_t) getuid()) < 0)
        imp_die (1, "failed to put FLUX_IMP_USERID in environment");

    return kv_env;
}

static void __attribute__((noreturn))
imp_run (struct imp_state *imp,
         const char *name,
         const cf_t *run_cf,
         struct kv *kv_env)
{
    const char *path;
    struct passwd *pwd;
    char **env;
    const char *args[2];
    int exit_code;
    int status;
    pid_t child;

    if (!(path = cf_string (cf_get_in (run_cf, "path")))
        || path[0] != '/')
        imp_die (1, "run: %s: invalid path", name);

    if (path[0] != '/')
        imp_die (1, "run %s: relative path not allowed", name);

    /*  Get passwd entry for current user to set HOME and USER */
    if (!(pwd = getpwuid (getuid ())))
        imp_die (1, "run: failed to find target user");

    /*  Set HOME and USER */
    if (kv_put (kv_env, "HOME", KV_STRING, pwd->pw_dir) < 0
        || kv_put (kv_env, "USER", KV_STRING, pwd->pw_name) < 0)
        imp_die (1, "run: failed to set HOME and USER in environment");

    /*  Set PATH to a sane default */
    if (kv_put (kv_env,
                "PATH",
                KV_STRING,
                "/usr/sbin:/usr/bin:/sbin:/bin") < 0)
        imp_die (1, "failed to put default PATH in environment");

    if (kv_expand_environ (kv_env, &env) < 0)
        imp_die (1, "Unable to set %s environment", name);

    if (chdir ("/") < 0)
        imp_die (1, "run: failed to chdir to /");

    /* Block signals so parent isn't terminated
     */
    imp_sigblock_all ();

    if ((child = fork ()) < 0)
        imp_die (1, "run: fork: %s", strerror (errno));

    imp_set_signal_child (child);

    if (child == 0) {
        /* unblock all signals */
        imp_sigunblock_all ();

        args[0] = path;
        args[1] = NULL;
#if CODE_COVERAGE_ENABLED
        __gcov_dump ();
        __gcov_reset ();
#endif
        execve (path, (char **) args, env);

        if (errno == EPERM || errno == EACCES)
            exit_code = 126;
        else
            exit_code = 127;
        imp_die (exit_code, "%s: %s", path, strerror (errno));
    }

    /* Parent:
     */
    imp_setup_signal_forwarding (imp);

    /* Parent: wait for child to exit */
    while (waitpid (child, &status, 0) != child) {
        if (errno != EINTR)
            imp_die (1, "waitpid: %s", strerror (errno));
    }

    /* Exit with status of the child process */
    if (WIFEXITED (status))
        exit (WEXITSTATUS (status));
    else if (WIFSIGNALED (status))
        imp_raise (WTERMSIG (status));
    else
        exit (1);
}


/*
 *  Read command to run from privsep pipe
 *  Check if user is allowed to run command
 */
int imp_run_privileged (struct imp_state *imp,
                        struct kv *kv)
{
    struct kv *kv_env;
    const char *name;
    const cf_t *cf_run;

    /*  Nullify environment. The environment for the target command
     *   will be set explicitly in get_run_env() from variables passed
     *   by the unprivileged child in struct kv.
     */
    environ = NULL;


    if (privsep_wait (imp->ps) < 0)
        imp_die (1, "run: unprivileged process exited abnormally");

    /*  Get command to run as sent by child
     */
    if (kv_get (kv, "command", KV_STRING, &name) < 0
        || name[0] == '\0')
        imp_die (1, "run: command required");

    /*  Ensure requesting user is allowed to run this command
     */
    cf_run = imp_run_lookup (imp, name);
    if (!run_user_allowed (cf_run))
        imp_die (1, "run: permission denied");

    kv_env = get_run_env (kv, cf_get_in (cf_run, "allowed-environment"));
    if (!kv_env)
        imp_die (1, "run: error processing command environment");

    if (setuid (geteuid()) < 0
        || setgid (getegid()) < 0)
        imp_die (1, "setuid: %s", strerror (errno));

    imp_run (imp, name, cf_run, kv_env);

    return 0;
}

/*  Put all environment variables that match any entry in allowed_env
 *   into `kv` as `IMP_RUN_ENV_${name}` for later inclusion in final
 *   environment of run command by privileged parent process.
 */
static void imp_run_kv_putenv (struct kv *kv, const cf_t *allowed_env)
{
    char **env = environ;
    char *p;
    char name[129];

    while (*env != NULL) {
        if ((p = strchr (*env, '='))) {
            size_t namelen = p - *env;

            /*  Skip environment variables with excessively long names
             */
            if (namelen < sizeof (name)) {

                /*  We know env var name will fit into name[] since length
                 *   has already been checked. Use memcpy() and explicit
                 *   NUL termination:
                 */
                memcpy (name, *env, namelen);
                name[namelen] = '\0';

                /*  If environment variable is allowed, create new 'name'
                 *   with IMP_RUN_ENV_ prepended so the environment variable
                 *   list can be split out by parent with kv_split()
                 */
                if (run_env_var_allowed (allowed_env, name)) {
                    /*  We know name is <= 128 characters, add length
                     *   of string "IMP_RUN_ENV_" to `var` to ensure there
                     *   is space for the prepended kv key. Then it is
                     *   safe to use sprintf(3).
                     */
                    char key[129 + 12];
                    sprintf (key, "IMP_RUN_ENV_%s", name);
                    kv_put (kv, key, KV_STRING, p+1);
                }
            }
        }
        env++;
    }
}

static void imp_run_put_kv (const char *name,
                            const cf_t *cf_run,
                            struct kv *kv)
{
    const cf_t *allowed_env;

    /*  Send command to parent
     */
    if (kv_put (kv, "command", KV_STRING, name) < 0)
        imp_die (1, "run: failed to send command to parent");

    /*  Pass allowed current environment as IMP_RUN_ENV_*
     */
    if ((allowed_env = cf_get_in (cf_run, "allowed-environment")))
        imp_run_kv_putenv (kv, allowed_env);
}

int imp_run_unprivileged (struct imp_state *imp, struct kv *kv)
{
    const char *name;
    const cf_t *cf_run;
    struct kv *kv_env;

   /*  Ensure a command name to run was given on command line
     */
   if (imp->argc < 3
        || !(name = imp->argv[2])
        || name[0] == '\0')
        imp_die (1, "run: nothing to run");

    cf_run = imp_run_lookup (imp, imp->argv[2]);

    imp_run_put_kv (name, cf_run, kv);

    if (imp->ps) {
        if (privsep_write_kv (imp->ps, kv) < 0)
            imp_die (1, "run: failed to communicate with privsep parent");
        exit (0);
    }

    /*  Unprivileged imp run for testing
     */

    /*  Ensure user is allowed for parity with privileged `flux-imp run`:
     */
    if (!run_user_allowed (cf_run))
        imp_die (1, "run: permission denied");

    kv_env = get_run_env (kv, cf_get_in (cf_run, "allowed-environment"));
    imp_run (imp, imp->argv[2], cf_run, kv_env);

    return 0;
}

/* vi: ts=4 sw=4 expandtab
 */

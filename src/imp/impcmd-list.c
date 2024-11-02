/************************************************************\
 * Copyright 2017 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#include "src/libutil/kv.h"
#include "impcmd.h"

extern int imp_cmd_version (struct imp_state *imp, struct kv *);
extern int imp_whoami_unprivileged (struct imp_state *imp, struct kv *);
extern int imp_whoami_privileged (struct imp_state *imp, struct kv *);
extern int imp_casign_unprivileged (struct imp_state *imp, struct kv *);
extern int imp_casign_privileged (struct imp_state *imp, struct kv *);
extern int imp_exec_unprivileged (struct imp_state *imp, struct kv *);
extern int imp_exec_privileged (struct imp_state *imp, struct kv *);
extern int imp_run_unprivileged (struct imp_state *imp, struct kv *);
extern int imp_run_privileged (struct imp_state *imp, struct kv *);

/*  List of supported imp commands, curated by hand for now.
 *   For each named command, the `child_fn` runs unprivileged and the
 *   `parent_fn` runs privileged. The child function communicates to
 *   the parent using privsep_write/read.
 *
 */
struct impcmd impcmd_list[] = {
	{ "version",
	  imp_cmd_version, NULL },
	{ "whoami",
	  imp_whoami_unprivileged,
      imp_whoami_privileged },
	{ "casign",
	  imp_casign_unprivileged,
      imp_casign_privileged },
    { "exec",
      imp_exec_unprivileged,
      imp_exec_privileged },
    { "run",
      imp_run_unprivileged,
      imp_run_privileged },
	{ NULL, NULL, NULL}
};

/* vi: ts=4 sw=4 expandtab
 */

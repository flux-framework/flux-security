/************************************************************\
 * Copyright 2026 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

/* Exit 0 if BPF_PROG_TYPE_CGROUP_DEVICE programs can be loaded,
 * nonzero otherwise.  Used as a prereq probe in the test suite.
 */

#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

int main (void)
{
    struct bpf_insn prog[] = {
        { .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 1 },
        { .code = BPF_JMP | BPF_EXIT },
    };
    union bpf_attr attr = {
        .prog_type = BPF_PROG_TYPE_CGROUP_DEVICE,
        .insn_cnt  = 2,
        .insns     = (__u64)(uintptr_t)prog,
        .license   = (__u64)(uintptr_t)"GPL",
    };
    int fd = (int)syscall (SYS_bpf, BPF_PROG_LOAD, &attr, sizeof (attr));
    if (fd < 0)
        return 1;
    close (fd);
    return 0;
}

/* vi: ts=4 sw=4 expandtab
 */

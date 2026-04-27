/************************************************************\
 * Copyright 2026 Lawrence Livermore National Security, LLC
 * (c.f. AUTHORS, NOTICE.LLNS, COPYING)
 *
 * This file is part of the Flux resource manager framework.
 * For details, see https://github.com/flux-framework.
 *
 * SPDX-License-Identifier: LGPL-3.0
\************************************************************/

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <limits.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <linux/bpf.h>
#include <sys/syscall.h>

#include "cgroup_device.h"
#include "imp_log.h"

/*
 * BPF instruction building macros.
 * Macro parameters are named foff/fimm (not off/imm) to avoid collision with
 * struct bpf_insn field names in designated initializers — the preprocessor
 * substitutes macro parameters before the compiler sees the field names.
 *
 * access_type field layout per struct bpf_cgroup_dev_ctx:
 *   upper 16 bits: BPF_DEVCG_ACC_* (MKNOD=1, READ=2, WRITE=4)
 *   lower 16 bits: BPF_DEVCG_DEV_* (BLOCK=1, CHAR=2)
 */
#define DEV_INSN_LDX_W(dst, src, foff) \
    ((struct bpf_insn){ \
        .code    = BPF_LDX | BPF_W | BPF_MEM, \
        .dst_reg = (dst), \
        .src_reg = (src), \
        .off     = (foff), \
        .imm     = 0 })
#define DEV_INSN_MOV32_REG(dst, src) \
    ((struct bpf_insn){ \
        .code    = BPF_ALU | BPF_MOV | BPF_X, \
        .dst_reg = (dst), \
        .src_reg = (src), \
        .off     = 0, \
        .imm     = 0 })
#define DEV_INSN_RSH32_IMM(dst, fimm) \
    ((struct bpf_insn){ \
        .code    = BPF_ALU | BPF_RSH | BPF_K, \
        .dst_reg = (dst), \
        .src_reg = 0, \
        .off     = 0, \
        .imm     = (fimm) })
#define DEV_INSN_AND32_IMM(dst, fimm) \
    ((struct bpf_insn){ \
        .code    = BPF_ALU | BPF_AND | BPF_K, \
        .dst_reg = (dst), \
        .src_reg = 0, \
        .off     = 0, \
        .imm     = (fimm) })
#define DEV_INSN_JNE_IMM(dst, fimm, foff) \
    ((struct bpf_insn){ \
        .code    = BPF_JMP | BPF_JNE | BPF_K, \
        .dst_reg = (dst), \
        .src_reg = 0, \
        .off     = (foff), \
        .imm     = (fimm) })
#define DEV_INSN_MOV64_IMM(dst, fimm) \
    ((struct bpf_insn){ \
        .code    = BPF_ALU64 | BPF_MOV | BPF_K, \
        .dst_reg = (dst), \
        .src_reg = 0, \
        .off     = 0, \
        .imm     = (fimm) })
#define DEV_INSN_EXIT() \
    ((struct bpf_insn){ \
        .code    = BPF_JMP | BPF_EXIT, \
        .dst_reg = 0, \
        .src_reg = 0, \
        .off     = 0, \
        .imm     = 0 })

/* Number of BPF instructions emitted per device_allow_entry.
 * Each entry is 10 instructions without a minor check, 11 with one.
 */
static int entry_insn_count (const struct device_allow_entry *e)
{
    return e->minor == -1 ? 10 : 11;
}

/* Convert access string ("rwm") to BPF_DEVCG_ACC_* bitmask */
static int access_to_mask (const char *access)
{
    int mask = 0;
    for (const char *p = access; *p; p++) {
        switch (*p) {
            case 'r': mask |= BPF_DEVCG_ACC_READ; break;
            case 'w': mask |= BPF_DEVCG_ACC_WRITE; break;
            case 'm': mask |= BPF_DEVCG_ACC_MKNOD; break;
        }
    }
    return mask;
}

/* Build a BPF cgroup device filter program from a device_allow list.
 * The program allows accesses matching any entry and denies all others.
 * Returns allocated insn array with *countp set, or NULL with errno set.
 *
 * Program structure per entry:
 *   check device type (lower 16 bits of access_type)
 *   check major
 *   check minor (if not wildcard)
 *   check access (upper 16 bits of access_type)
 *   if all match: return 1 (allow)
 * Default: return 0 (deny)
 */
static struct bpf_insn *
bpf_prog_build (struct device_allow *da, size_t *countp)
{
    size_t n_insns = 3 + 2;  /* prologue (3) + epilogue (2) */
    struct bpf_insn *insns;
    size_t pos = 0;

    for (int i = 0; i < da->count; i++)
        n_insns += entry_insn_count (&da->entries[i]);

    if (!(insns = calloc (n_insns, sizeof (*insns))))
        return NULL;

    /* Prologue: load context fields into dedicated registers.
     *   r2 = major, r3 = minor, r4 = access_type
     * Offsets match struct bpf_cgroup_dev_ctx field order.
     */
    insns[pos++] = DEV_INSN_LDX_W (BPF_REG_2, BPF_REG_1, 4); /* major */
    insns[pos++] = DEV_INSN_LDX_W (BPF_REG_3, BPF_REG_1, 8); /* minor */
    insns[pos++] = DEV_INSN_LDX_W (BPF_REG_4, BPF_REG_1, 0); /* access_type */

    for (int i = 0; i < da->count; i++) {
        const struct device_allow_entry *e = &da->entries[i];
        int n = entry_insn_count (e);
        int dev_type = (e->type == 'b') ? BPF_DEVCG_DEV_BLOCK
                                        : BPF_DEVCG_DEV_CHAR;
        int allowed = access_to_mask (e->access);
        int deny_mask = ~allowed & 0x7;

        /* Check device type (lower 16 bits of access_type) */
        insns[pos++] = DEV_INSN_MOV32_REG (BPF_REG_5, BPF_REG_4);
        insns[pos++] = DEV_INSN_AND32_IMM (BPF_REG_5, 0xffff);
        insns[pos++] = DEV_INSN_JNE_IMM (BPF_REG_5, dev_type, n - 3);
        /* Check major */
        insns[pos++] = DEV_INSN_JNE_IMM (BPF_REG_2, e->major, n - 4);
        /* Check minor if not wildcard */
        if (e->minor != -1)
            insns[pos++] = DEV_INSN_JNE_IMM (BPF_REG_3, e->minor, n - 5);
        /* Check access: deny if requested bits exceed allowed */
        insns[pos++] = DEV_INSN_MOV32_REG (BPF_REG_5, BPF_REG_4);
        insns[pos++] = DEV_INSN_RSH32_IMM (BPF_REG_5, 16);
        insns[pos++] = DEV_INSN_AND32_IMM (BPF_REG_5, deny_mask);
        insns[pos++] = DEV_INSN_JNE_IMM (BPF_REG_5, 0, 2);
        /* Allow */
        insns[pos++] = DEV_INSN_MOV64_IMM (BPF_REG_0, 1);
        insns[pos++] = DEV_INSN_EXIT ();
    }

    /* Epilogue: default deny */
    insns[pos++] = DEV_INSN_MOV64_IMM (BPF_REG_0, 0);
    insns[pos++] = DEV_INSN_EXIT ();

    assert (pos == n_insns);
    *countp = n_insns;
    return insns;
}

static int cgroup_open (struct cgroup_info *cgroup)
{
    int fd = open (cgroup->path, O_RDONLY | O_DIRECTORY);
    if (fd < 0)
        return -1;
    return fd;
}

int cgroup_device_apply (struct cgroup_info *cgroup,
                         struct device_allow *da)
{
    int cgroup_fd = -1;
    int prog_fd = -1;
    int rc = -1;
    struct bpf_insn *insns = NULL;
    size_t n_insns;
    if (!da)
        return 0;
    if (!cgroup) {
        errno = EINVAL;
        return -1;
    }
    if ((cgroup_fd = cgroup_open (cgroup)) < 0) {
        imp_warn ("device: failed to open cgroup %s: %s",
                  cgroup->path,
                  strerror (errno));
        return -1;
    }
    if (!(insns = bpf_prog_build (da, &n_insns))) {
        imp_warn ("device: failed to build BPF program: %s", strerror (errno));
        goto done;
    }

    union bpf_attr load_attr = {
        .prog_type = BPF_PROG_TYPE_CGROUP_DEVICE,
        .insn_cnt  = (__u32)n_insns,
        .insns     = (__u64)(uintptr_t)insns,
        .license   = (__u64)(uintptr_t)"LGPL",
    };
    if ((prog_fd = syscall (SYS_bpf,
                            BPF_PROG_LOAD,
                            &load_attr,
                            sizeof (load_attr))) < 0) {
        imp_warn ("device: failed to load BPF program: %s", strerror (errno));
        goto done;
    }

    union bpf_attr attach_attr = {
        .target_fd     = cgroup_fd,
        .attach_bpf_fd = prog_fd,
        .attach_type   = BPF_CGROUP_DEVICE,
    };
    if (syscall (SYS_bpf,
                 BPF_PROG_ATTACH,
                 &attach_attr,
                 sizeof (attach_attr)) < 0) {
        imp_warn ("device: failed to attach BPF program to cgroup: %s",
                  strerror (errno));
        goto done;
    }
    rc = 0;

done:
    free (insns);
    if (prog_fd >= 0)
        close (prog_fd);
    close (cgroup_fd);
    return rc;
}

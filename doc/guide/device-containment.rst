.. _device-containment:

##################
Device Containment
##################

The IMP supports optional device containment for jobs using a BPF
cgroup device filter.  When active, only explicitly allowed devices are
accessible to processes in the job's cgroup; all other device accesses
are denied.

The motivating use case is GPU containment on systems where multiple
jobs share a node: each job should have access only to the GPUs
assigned to it, not to those assigned to other jobs.  Device
containment falls to the IMP because it cannot currently be delegated
to the systemd user instance running as the flux user — applying a
cgroup device policy requires privilege that the user instance does not
hold.

*********
IMP Input
*********

The flux-core execution system sets the systemd ``DevicePolicy`` and
``DeviceAllow`` unit properties [5]_ when launching a job.  These are
currently ignored by systemd since the user instance lacks the
privilege to enforce them.

Per :doc:`RFC 15 <rfc:spec_15>` [7]_, the IMP takes its input from a helper
program provided by flux-core, pointed to by :envvar:`FLUX_IMP_EXEC_HELPER`.
The helper reads the systemd properties and passes them to the IMP as-is
under an ``options`` key in the JSON object alongside the signed job
specification ``J``.  For example:

.. code-block:: json

    {
      "J": "<signed jobspec>",
      "options": {
        "DevicePolicy": "closed",
        "DeviceAllow": [
          ["/dev/nvidia0", "rw"],
          ["char-pts", "rw"]
        ]
      }
    }

``DevicePolicy`` may be ``strict``, ``closed``, or ``auto`` (the default).
Each ``DeviceAllow`` entry is a two-element array of specifier and access
string, mirroring the systemd unit property format.  The specifier may be
a path such as ``/dev/null``, or a device class such as ``char-pts`` or
``block-loop``.  Access is a combination of ``r``, ``w``, and ``m`` for
:linux:man2:`read`, :linux:man2:`write`, and :linux:man2:`mknod`.

**********
Data Flow
**********

The policy travels through several IMP layers before reaching the kernel:

#. The unprivileged IMP child reads JSON from the helper and parses
   ``DevicePolicy`` and ``DeviceAllow`` from the ``options`` object.
   It resolves each specifier — stat(2)-ing path-based entries and
   scanning ``/proc/devices`` for class-based entries — into a flat
   list of ``{type, major, minor, access}`` tuples in a
   :c:struct:`device_allow`.  Standard pseudo-devices are appended for
   ``closed`` and ``auto`` policies.

#. The unprivileged child encodes the resolved list into the privsep ``kv``
   struct using a compact per-entry format (e.g. ``c:195:0:rw``) and
   sends it to the privileged parent.  The ``kv`` encoding is defined
   in :doc:`RFC 38 <rfc:spec_38>` [6]_.

#. The privileged parent decodes the ``kv`` struct back into a
   :c:struct:`device_allow` and calls :c:func:`cgroup_device_apply`.

#. :c:func:`cgroup_device_apply` builds a BPF instruction array, loads it
   into the kernel with ``BPF_PROG_LOAD``, and attaches it to the job
   cgroup fd with ``BPF_PROG_ATTACH``.

The IMP enforces the policy by attaching a BPF [4]_ program of type
:c:macro:`BPF_PROG_TYPE_CGROUP_DEVICE` to the job's cgroup directory fd
before any job processes are created.

***************
Design Notes
***************

**No libbpf dependency.**  The BPF program is loaded and attached using
:linux:man2:`bpf` [1]_ directly rather than through libbpf.  Since the
IMP is a setuid binary, minimizing shared library dependencies reduces
the attack surface: a compromised or replaced ``libbpf.so`` could
otherwise be a privilege escalation vector.  Using the syscall interface
directly also keeps the policy enforcement code self-contained and
auditable without reference to an external library.

**Fail-closed error handling.**  If device containment is requested but
cannot be applied — whether due to a kernel BPF error, a cgroup fd
problem, or any other failure — the IMP terminates before forking any
job processes.  A job that escapes its intended device policy is treated
as worse than a job that does not start.

**Normalization in the unprivileged child.**  Policy interpretation —
resolving ``DevicePolicy`` rules and normalizing device specifiers to
``{type, major, minor, access}`` tuples — is performed by the
unprivileged IMP child before data crosses the privsep boundary.  The
privileged IMP parent receives a pre-validated allowlist in a simple
numeric form, minimizing the complexity and attack surface of the code
that runs with elevated privilege.

*********************
BPF Program Structure
*********************

The BPF program is built as a flat instruction array [2]_ by
:c:func:`bpf_prog_build`.  The program structure is:

.. code-block:: none

    prologue:
        r2 = ctx->major
        r3 = ctx->minor
        r4 = ctx->access_type

    for each allow entry:
        if (r4 & 0xffff) != dev_type: skip to next entry
        if r2 != major: skip to next entry
        if minor != -1 and r3 != minor: skip to next entry
        if r4 >> 16 has bits set outside allowed access: skip to next entry
        r0 = 1; exit  (allow)

    epilogue:
        r0 = 0; exit  (default deny)

The ``access_type`` field of :c:struct:`bpf_cgroup_dev_ctx` packs the
device type into the lower 16 bits (:c:macro:`BPF_DEVCG_DEV_BLOCK`,
:c:macro:`BPF_DEVCG_DEV_CHAR`) and the requested access into the upper
16 bits (:c:macro:`BPF_DEVCG_ACC_MKNOD`, :c:macro:`BPF_DEVCG_ACC_READ`,
:c:macro:`BPF_DEVCG_ACC_WRITE`).

Each allow entry emits 10 instructions without a minor check, or 11
with one; the jump offsets within each entry are computed accordingly.

**************
Error Handling
**************

Any failure that would violate fail-closed error handling is fatal.
The IMP logs errors to stderr, which is captured in the job's standard
error output.  On a fatality, it terminates before forking processes.

.. list-table::
   :header-rows: 1
   :widths: 20 60 20

   * - Failure class
     - Description
     - Strategy
   * - Input parsing
     - | The ``options`` object, ``DevicePolicy``,
       | or ``DeviceAllow`` key is malformed.
     - fatal
   * - DeviceAllow entry
     - | Device containment is requested but a
       | ``DeviceAllow`` entry is malformed or
       | could not be found.
     - | Log warning,
       | ignore entry
   * - kv encoding/decoding
     - Privsep boundary communication failed.
     - fatal
   * - Cgroup access
     - Job cgroup directory cannot be opened.
     - fatal
   * - BPF program load
     - The kernel BPF verifier [3]_ rejects program.
     - fatal
   * - BPF program attach
     - The program cannot be attached to the job cgroup.
     - fatal

When ``DevicePolicy`` is absent or ``auto`` and ``DeviceAllow`` is absent
or empty, no containment is applied, and the job proceeds with full device
access.

**********
References
**********

.. [1] Linux man-pages project, :linux:man2:`bpf`, Linux Programmer's Manual.

.. [2] Linux kernel contributors, `eBPF Instruction Set Specification
   <https://docs.kernel.org/bpf/standardization/instruction-set.html>`_,
   Linux kernel documentation.

.. [3] Linux kernel contributors, `BPF Verifier
   <https://docs.kernel.org/bpf/verifier.html>`_,
   Linux kernel documentation.

.. [4] Linux kernel contributors, `Classic BPF vs eBPF
   <https://docs.kernel.org/bpf/classic_vs_extended.html>`_,
   Linux kernel documentation.

.. [5] systemd contributors, `systemd.resource-control(5)
   <https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html>`_,
   freedesktop.org.

.. [6] flux-framework contributors, :doc:`rfc:spec_38`, flux-rfc.

.. [7] flux-framework contributors, :doc:`rfc:spec_15`, flux-rfc.

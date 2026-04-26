===========================
flux-config-security-imp(5)
===========================


DESCRIPTION
===========

The Flux Independent Minister of Privilege (IMP or :man8:`flux-imp`) is
a setuid helper used by multi-user Flux instances to launch, monitor,
and control processes running as users other than the instance owner.
By default, the IMP is installed in a safe mode where it does not implement
any of this functionality. In order to enable a multi-user system instance,
the IMP requires some basic configuration.

At startup, the IMP reads its configuration from a compiled in
:linux:man7:`glob` pattern ``${sysconfdir}/flux/imp/conf.d/*.toml``.
The configuration files in this directory are security sensitive, and as such,
should be installed with ``root`` ownership and without global write
permissions. The parent directory should also have ``root`` ownership
and no global write permissions without the sticky bit set. On startup,
the IMP will validate file and path ownership and permissions and will
emit an error if it finds any issues.

For basic IMP functionality, at least one user must be allowed to use
the ``flux-imp exec`` command (see ``exec.allowed-users``), and the
IMP has to be configured with at least one allowed job shell (see
``exec.allowed-shells``).

The full list of supported tables and keys in the IMP configuration are
detailed below.

KEYS
====

The following are keys in the ``[exec]`` table, required for configuring
``flux-imp exec`` support:

exec.allowed-users
   An array of users allowed to utilize the IMP ``exec`` functionality.
   This is required for multi-user Flux instance support.

exec.allowed-shells
   An array of absolute paths to job shells which the IMP will execute on
   behalf of an instance owner as the guest user in a multi-user instance.
   Typically, only the system-installed job shell should be listed here,
   but multiple shells are supported in the event that an experimental
   job shell or multiple Flux versions need to be supported.

exec.allow-unprivileged-exec
   A boolean value which, if true, tells the IMP to fall back to
   execution of the job shell as the instance owner when the IMP is not
   installed setuid. This is disabled by default and should only be used
   for testing.  If set in a real system instance, this would allow users
   to execute arbitrary commands as the Flux system instance owner userid
   (e.g. ``flux``)

exec.pam-support
   A boolean value which, if true, enables PAM support for the IMP exec
   subcommand, allowing a ``flux`` PAM stack to be executed for multi
   user jobs. If enabled, the ``flux`` PAM stack must exist and have
   at least one ``auth`` and one ``session`` module configured, e.g.::

     auth    required pam_localuser.so
     session required pam_limits.so

   This option requires that the flux-security project was built with
   ``--enable-pam``.

The following keys in the ``[run]`` table configure ``flux-imp run``
support, which is used to configure the ``flux-imp run`` command, which
is used to allow the Flux system instance user to execute a prolog,
epilog or other script with elevated privileges:

[run]
   The run table consists of a dictionary of tables, each of which
   configures a new ``flux-imp run`` command. In the common case the
   sub-tables might be ``[run.prolog]`` and ``[run.epilog]``, but arbitrary
   commands can also be placed here, for example if a node health check
   script or other command needs to be run with privileges.

Each sub-table under ``[run]`` further supports the following keys:

run.<name>.path
   The absolute executable path to invoke for ``flux-imp run <name>``.

run.<name>.allowed-users
   An array of users allowed to invoke command ``<name>``.

run.<name>.allowed-environment
   An array of environment variables or :linux:man7:`glob` patters of
   environment variables which will be passed through to the executed
   command. By default, only ``FLUX_JOB_ID`` and ``FLUX_JOB_USERID``
   will be passed to the executed command.

The following top-level keys are also supported:

allow-sudo
   Set to true if the IMP should simulate a setuid installation when run
   under :linux:man8:`sudo`. This option is only useful for testing.

log-level
   Set the logging verbosity to ``warning``, ``info`` (default), or
   ``debug``. Setting ``debug`` enables diagnostic messages useful for
   testing and troubleshooting. This option should not be set in
   production.

EXAMPLE
=======

::

   [exec]
   allowed-users = [ "flux" ]
   allowed-shells = [ "/usr/libexec/flux/flux-shell" ]

   [run.prolog]
   allowed-environment = [ "FLUX_*" ]
   allowed-users = [ "flux" ]
   path = "/etc/flux/system/prolog"

   [run.epilog]
   allowed-environment = [ "FLUX_*" ]
   allowed-users = [ "flux" ]
   path = "/etc/flux/system/epilog"


RESOURCES
=========

Flux: http://flux-framework.org

RFC 15: Independent Minister of Privilege for Flux: The Security IMP: https://flux-framework.readthedocs.io/projects/flux-rfc/en/latest/spec_15.html


SEE ALSO
========

:man5:`flux-config-security`, :core:man5:`flux-config`, :man8:`flux-imp`

===========
flux-imp(8)
===========

SYNOPSIS
========

**flux-imp** *COMMAND* [*OPTIONS*...]


DESCRIPTION
===========

**flux-imp** is an optional component of Flux which, when installed
setuid and configured appropriately, enables a Flux instance to execute
and control jobs run as users other than the instance owner.

For details on the background and design of **flux-imp** see:

RFC 15: Independent Minister of Privilege for Flux: The Security IMP: https://flux-framework.readthedocs.io/projects/flux-rfc/en/latest/spec_15.html

COMMANDS
========

**version**
  Display **flux-imp** version.

**whoami**
  Display the real and effective user and group ids of the **flux-imp**
  process. **flux-imp whoami** can be used to verify that **flux-imp**
  is installed with appropriate setuid permissions for a given calling
  user.

**exec**
  The **flux-imp exec** command is invoked by a multi-user instance to
  execute a the job shell as the appropriate user. Description of the
  **exec** command configuration can be found in
  :man5:`flux-config-security-imp`.

**run**
  The **flux-imp run** command is used by a Flux instance to execute
  arbitrary commands with privilege, typically a job prolog or epilog.
  Description of **run** command configuration can be found in
  :man5:`flux-config-security-imp`.


SECURITY NOTES
==============

**flux-imp** should only be installed setuid if multi-user Flux is
required. Single user Flux instances do not use **flux-imp**.

File permissions, access controls, or SELinux policy of **flux-imp**
should be configured such that access is restricted to only those users
that require multi-user Flux capability. For example, for a system instance
running as user ``flux``, it is suggested that permissions for **flux-imp**
be set such that only the ``flux`` user or group has execute permission.

RESOURCES
=========

RFC 15: Independent Minister of Privilege for Flux: The Security IMP: https://flux-framework.readthedocs.io/projects/flux-rfc/en/latest/spec_15.html


SEE ALSO
========

:man5:`flux-config-security-imp`

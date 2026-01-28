=======================
flux-config-security(5)
=======================


DESCRIPTION
===========

The ``flux-security`` project concentrates the security sensitive portions
of Flux.  To maintain isolation, it implements two independent TOML
configuration hierarchies, separate from the rest of Flux.  Their paths are
set when ``flux-security`` is built and cannot be altered at runtime:

``${sysconfdir}/flux/imp/conf.d/*.toml``
   Configuration file(s) for :man8:`flux-imp`, described in
   :man5:`flux-config-security-imp`.

``${sysconfdir}/flux/security/conf.d/*.toml``
   Configuration file(s) for the signing library, described in
   :man5:`flux-config-security-sign`.

As with :core:man5:`flux-config`, Flux security configuration files follow the
TOML file format, with configuration subdivided by function into separate TOML
tables.  The tables for each hierarchy may all appear in a single ``.toml``
file or be fragmented in multiple files that match the appropriate
:linux:man7:`glob` pattern.  The configuration is assumed to be identical for
all Flux components across a given Flux instance.

Security configuration files, including the ``conf.d`` directory and individual
``.toml`` files, must be appropriately locked down:

- owner of ``root``
- group of ``root``
- must not be writable by others
- must not be a symbolic link
- ``.toml`` files must be regular files

There is no mechanism to tell Flux components to reread the Flux security
configurations when they change.  Most Flux security users such as
:core:man1:`flux-submit` or :man8:`flux-imp` are short lived and read the latest
configuration on each invocation.  There are two considerations to be aware
of when updating the signing configuration, however:

- The ``job-ingest`` service validates the signatures of job requests.  As a :core:man1:`flux-broker` plugin, it runs for the duration of the rank 0 broker and could reject job submissions if a mismatched signing configuration is picked up by the job submission tools.
- Pending jobs could fail to start if the signing configuration used when they were submitted no longer matches the signing configuration read by the IMP at job startup.

It is therefore recommended that the Flux instance be cleared of pending jobs
and fully stopped when updating the signing configuration.


RESOURCES
=========

Flux: http://flux-framework.org

Flux Administrator's Guide: https://flux-framework.readthedocs.io/en/latest/adminguide.html

TOML: Tom's Obvious Minimal Language: https://toml.io/en/

RFC 15: Independent Minister of Privilege for Flux: The Security IMP: https://flux-framework.readthedocs.io/projects/flux-rfc/en/latest/spec_15.html


SEE ALSO
========

:core:man5:`flux-config`, :man5:`flux-config-security-imp`, :man5:`flux-config-security-sign`

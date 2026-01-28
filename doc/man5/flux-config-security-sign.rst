============================
flux-config-security-sign(5)
============================


DESCRIPTION
===========

Flux jobs are signed by job submission tools like :core:man1:`flux-submit`.
The signature is verified upon receipt by the Flux ``job-ingest`` service,
and at launch time by :man8:`flux-imp`.  A signing library provided by the
``flux-security`` project performs the cryptographic signing and verification.
The library is configured by the ``security`` configuration hierarchy, as
described in :man5:`flux-config-security`.  One of three signing mechanisms
may be configured:

munge
   The job request is enclosed in a MUNGE credential whose originating UID
   can be verified at any location within the MUNGE domain.  This is the
   preferred mechanism as it has undergone the most extensive auditing.

curve
   The job request is signed and verified using public key signatures
   as implemented by libsodium.  This mechanism was implemented as a proof
   of concept during design and has not yet received adequate review to be
   considered secure on a real system.

none
   No-op mechanism.  This mechanism is used when the submitting user and
   Flux instance owner are the same, as in a single user instance where
   signature verification is not required.  DO NOT list it in the
   ``allowed-types`` key described below.

This page describes the keys that may be listed in the ``[sign]`` table:

KEYS
====

max-ttl
   An integer value that defines the length of time, in seconds, that a
   signature should remain valid.  In effect, it limits the amount of time
   a job can be pending in the queue.   Recommended value: 1209600 (2 weeks).

default-type
   A string value that defines the default mechanism used to sign jobs if the
   submitting user is not the instance owner.  Recommended value: ``"munge"``.

allowed-types
   A list of mechanisms that may be considered for signature verification.
   Recommended value: ``[ "munge" ]``.

The following keys apply only to the ``munge`` mechanism:

munge.socket-path
   A string value that overrides the default MUNGE socket path.  This is
   needed only if the MUNGE daemon used to sign Flux jobs is running on
   a socket path other than the one compiled into ``libmunge``.

The following keys apply only to the ``curve`` mechanism:

curve.require-ca
   A boolean value that determines whether the signing certificate should
   be validated against a certificate authority before use.

curve.cert-path
   A string value that overrides the signing certificate path, normally
   ``.flux/curve/sig`` in the user's home directory.


EXAMPLE
=======

::

   [sign]
   max-ttl = 1209600  # 2 weeks
   default-type = "munge"
   allowed-types = [ "munge" ]


RESOURCES
=========

Flux: http://flux-framework.org

RFC 15: Independent Minister of Privilege for Flux: The Security IMP: https://flux-framework.readthedocs.io/projects/flux-rfc/en/latest/spec_15.html

MUNGE (MUNGE Uid 'N' Gid Emporium) https://dun.github.io/munge/

libsodium https://doc.libsodium.org/


SEE ALSO
========

:man5:`flux-config-security`

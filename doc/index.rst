flux-security
=============

flux-security provides the security infrastructure required for multi-user
Flux instances.  It includes a signing library that allows Flux to
authenticate job requests across nodes, and a setuid helper called the IMP
(Independent Minister of Privilege) that enables Flux to launch jobs as
arbitrary users without requiring the broker to run as root.

flux-security is a required companion to flux-core in production HPC
deployments where Flux is deployed as a multi-user system service.  It is
designed with a minimal privilege footprint: the IMP is the only component
that runs as root, and it does so only for the narrow operations required
to launch and signal jobs on behalf of authenticated
users.

Related Information
===================

flux-security is designed to be deployed alongside flux-core.  Those wishing
to understand Flux security in a broader context may benefit from the
following material:

.. list-table::
   :header-rows: 1

   * - Description
     - Links

   * - Main Flux Documentation Pages
     - `Github <https://github.com/flux-framework>`_

       `Docs <https://flux-framework.readthedocs.io/en/latest/index.html>`_

   * - flux-core — the primary Flux framework project
     - `Github <https://github.com/flux-framework/flux-core>`_

       `Docs <https://flux-framework.readthedocs.io/projects/flux-core>`_

   * - Flux Request for Comments Specifications
     - `Github <https://github.com/flux-framework/rfc>`_

       `Docs <https://flux-framework.readthedocs.io/projects/flux-rfc/en/latest/index.html>`_

Table of Contents
=================

.. toctree::
   :maxdepth: 2

   index_man
   guide/internals

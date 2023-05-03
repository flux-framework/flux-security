# flux-security
Independent project for Flux security code and APIs.

#### Build Requirements

flux-security requires the following packages to build:

**redhat**	| **ubuntu**		| **version** | **notes**
----------	| ----------		| ----------- | ---------
autoconf	| autoconf		|             |
automake	| automake		|             |
libtool		| libtool		|             |
make		| make			|             |
pkgconfig	| pkg-config	        |             |
libsodium-devel	| libsodium-dev		| >= 1.0.14   |
jansson-devel	| libjansson-dev	|             |
libuuid-devel	| uuid-dev		|             |
munge-devel	| libmunge-dev		|             |
pam-devel	| libpam0g-dev		|             | for --enable-pam


##### Installing RedHat/CentOS Packages
```
yum install autoconf automake libtool make pkgconfig libsodium-devel jansson-devel libuuid-devel munge-devel
```

##### Installing Ubuntu Packages
```
apt install autoconf automake libtool make pkg-config libsodium-dev libjansson-dev uuid-dev libmunge-dev
```

#### Release

SPDX-License-Identifier: LGPL-3.0

LLNL-CODE-764420


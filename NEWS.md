flux-security version 0.9.0 - 2023-05-15
----------------------------------------

## New Features

 * imp: support helper to get input to exec command (#163)

## Fixes

 * imp: fix kill operation when /proc is mounted with hidepid=2 (#155)

# Build/Test

 * build: add 'make deb' target to build test debian package (#161, #162, #166)
 * detect typos during CI (#164)
 * Add CodeQL workflow for GitHub code scanning (#156)
 * ensure LICENSE is included in distribution tarball (#165)
 * github: update actions workflow (#157)


flux-security version 0.8.0 - 2022-09-13
----------------------------------------

## New Features

 * allow privileged IMP to linger during a job (#150)
 * imp: exec: add PAM session support (#151)

## Cleanup

 * imp: address code review comments (#152)
 * ci: remove fedora33 add fedora35 to ci builds (#149)
 * github: fix typo in deploy action (#146)

flux-security version 0.7.0 - 2022-06-06
----------------------------------------

## New Features

 * document signing API (#137)

## Fixes

 * imp: fix kill functionality with unified cgroups hierarchy (#142)
 * doc: fix manpage typo (#139)
 * fix readthedocs build (#143)
 * testsuite: fix spell checker and some spelling errors (#136)
 * fix auto-deploy of flux-security release on tag (#135)


flux-security version 0.6.0 - 2022-01-31
----------------------------------------

## New Features

 * imp: support multiple arguments to job shell in exec (#128)
 * doc: add infrastructure for sphinx-generated docs and section 5 and 8
   manual pages (#131)

## Testing

 * mergify:  replace strict merge with queue+rebase (#129)
 * ci: add fedora 34 and -fanalyzer build to ci checks (#125)
 * ci: rename centos7/8 to el7/8 (#134)

## Cleanup

 * README: update LLNL-CODE (#126)
 * build: use automake foreign mode (#132)

flux-security version 0.5.0 - 2021-09-03
----------------------------------------

## New Features

 * imp: add run command for prolog/epilog support (#123)
 * check file permissions and ownership of files when running
   privileged code (#122)

## Testing
 
 * ci: switch to github actions (#121)
 * bump minimum jansson version to 2.10 (#114)


flux-security version 0.4.0 - 2020-03-19
----------------------------------------

## New Features

 * lib: add `flux_sign_wrap_as(3)` (#108)
 * imp: add support for IMP exec command (#104, #109)
 * imp: add support for IMP kill command (#110, #111)
 * update internal libtomlc99 to latest (#98)

## Testing

 * build/test under asan and ubsan, fix errors (#97)
 * fix tests when run on nosuid filesystems (#100)


flux-security version 0.3.0 - 2019-01-11
----------------------------------------

### Fixes

 * lib: make aux get/set interface like flux-core api (#88)

### New Features

 * license: re-publish project under LGPLv3 (#87, #89, #91)
 * lib: add interface to query flux-security version (#86)
 * lib: support library versioning for libflux-security.so (#93)

### Cleanup

 * convert to libsodium base64 implementation (#85)


flux-security version 0.2.0 - 2018-08-22
----------------------------------------

### New Features

 * add mechanism argument to `flux_sign_wrap(3)` (#75)
 * add new function `flux_sign_unwrap_anymech(3)` (#75)
 * move default config file to `$sysconfdir/flux/security/conf.d`
   and add a default config file for signing (#76)
 * add sign_curve signing mechanism (#68)

### Cleanup

 * add pkg-config m4 to support side-installed autotools (#77)


flux-security version 0.1.0 - 2018-05-22
----------------------------------------

 * Initial bare-bones release, signing and context API only.


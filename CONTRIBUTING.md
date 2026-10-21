# Contributing

Thanks for helping make patch verification easier and more trustworthy.

## The one hard rule: this is a self-check tool

`phpcheck` only ever inspects a server **you control**, from that server
(`php -v` + the installed package's changelog). It reads what the operator
already has access to, sends no exploit, and contacts no remote host.

**Contributions that turn it into a remote scanner will be declined.** That
means no "enter any URL and we'll tell you if it's vulnerable", no bulk
host enumeration, no exploit or proof-of-concept payloads, and no feature
whose main use is probing machines the operator doesn't own. During an active
RCE window a list of exposed third-party hosts is a target list regardless of
intent — this project stays on the defensive side of that line, on purpose.

Everything else is welcome:

- More accurate backport detection for specific distros/vendors.
- Detecting the version of the SAPI actually serving requests (FPM, Apache
  module), not just the CLI.
- Container-aware checks.
- Clearer reporting and fewer false "verify" results.
- Tests.

## How to propose a change

1. Open an issue describing the case (distro, PHP version, what the current
   output gets wrong).
2. Keep `phpcheck.sh` dependency-free (POSIX-ish bash, standard tools).
3. Include the before/after output in your PR.

By contributing you agree your work is licensed under the repo's MIT license.

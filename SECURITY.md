# Security policy

## Reporting a NextAudit vulnerability

Use GitHub's **Report a vulnerability** / private security advisory flow for this repository, if enabled. Otherwise, contact the repository maintainer privately through their published contact channel. Do **not** include sensitive findings in a public issue.

## Supported versions

The newest release receives security fixes. Older versions are not guaranteed to receive patches.

## Safe usage

NextAudit may disclose application paths and code patterns in reports. Keep reports private unless they have been reviewed and redacted. Test only systems you own or have explicit written permission to audit. The standard `scan` and `access` tools are non-destructive and bounded but still generate requests; review scope and load limits. The `race` and `payment-lab` tools must only be used with disposable staging fixtures.

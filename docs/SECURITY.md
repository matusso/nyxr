# Security policy

## Supported versions

nyxr is pre-1.0. Security fixes go into the latest minor release only.

| Version | Supported |
| --- | --- |
| Latest `v0.x` release | Yes |
| Older releases | No; upgrade to the latest release |

## Reporting a vulnerability

Please do **not** open a public issue for a security problem.

Report it privately through GitHub:
**[Security → Report a vulnerability](https://github.com/matusso/nyxr/security/advisories/new)**.

Include:

- The affected version (`nyxr version`) and platform.
- The component: CLI, `nyxr serve` (API or web UI), `nyxr-packetd`, a packet
  decoder or parser, or the release artifacts.
- Steps to reproduce, and a proof of concept if you have one. Use
  documentation address ranges or your own lab, never third-party systems.
- The impact you observed or expect.

What to expect:

| Step | Target |
| --- | --- |
| Acknowledgement | Within 7 days |
| Initial assessment | Within 14 days |
| Fix or mitigation | Depends on severity; you will be kept informed |

Reporters are credited in the advisory unless they ask otherwise.

## Scope

Of particular interest:

- Privilege boundaries: anything that lets an unprivileged client gain raw
  packet access beyond what `nyxr-packetd` allows, or that makes `nyxr serve`
  act with elevated privileges.
- The API and web UI: authentication bypass, DNS rebinding, CSRF, or script
  injection through scanned data.
- Parsers: crashes, hangs or memory exhaustion triggered by hostile packets,
  capture files, probe definitions or `nmap-service-probes` files.
- Safety controls: ways to send traffic outside `ot-safe` or `research`
  allowlists and rate limits.

Out of scope: findings that require the operator to deliberately disable a
safeguard (for example `--allow-privileged`), and the expected behavior of a
network scanner when it is pointed at a target.

## Responsible use

nyxr is a network security tool. Scan only systems you own or are explicitly
authorized to test.

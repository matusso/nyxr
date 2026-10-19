# Interrupted routed Windows study v1, 2026-10-19

`horizon-windows-routed-controlled/v1` (commit `fd37fa6`) put the native
Windows 11 target behind a FreeBSD layer-3 hop. Dummynet shaped the forwarded
SYN-ACKs for its loss/jitter stratum. The FreeBSD router panicked during
shaping, so the study stopped after 7 of 27 planned native IPv4 runs. No other
phase started. v2 is a new registration without router shaping, and its
[corpus](../2026-10-19-windows-routed-arm64/RESULTS.md) is not pooled with this one.

| Stratum (native IPv4) | Planned | Valid | Invalid | Missing | Unresolved valid | Correct |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Clean | 12 | 3 | 0 | 9 | 0 | 3 |
| Loss/jitter | 12 | 3 | 1 | 8 | 3 | 0 |
| DROP | 3 | 0 | 0 | 3 | 0 | 0 |

The three clean runs had 12 complete treatment-only SACK pairs each
(p=0.00048828125). The three valid loss/jitter runs lost one or two replies
(10–11 complete pairs, all treatment-only, p=0.00098–0.00195). The strict
complete-pair rule leaves such runs unresolved, matching the Linux
impairment results. The fourth loss/jitter run is invalid: the router panicked
mid-run, so its after-run truth is missing. All seven ordinary scanner checks
reported open.

## Router failures

The router was FreeBSD 15.1-RELEASE-p4 GENERIC ARM64 on VMware Fusion, with
`vmx0` for this run.

| Time (CEST) | NIC | Context | Panic | Faulting symbol |
| --- | --- | --- | --- | --- |
| 11:37:04 | em0 | Earlier v1 setup attempt, 1 min after shaping began; no run directory survived | `vm_fault failed: 0xffff0000006d49fc error 1` | `in_lltable_lookup` |
| 13:38:11 | vmx0 | This collection, loss/jitter run 4 | `vm_fault failed: 0xffff0000006d1c4c error 1` | `in_localip_fib` |

Both faults are in the IPv4 forwarding path while dummynet re-injected
delayed packets; clean forwarding had no failures. The 2026-10-12/13 VNET
studies on the same VM also had panics with this signature. Kernel stacks
were unrecoverable (`corrupt stack`), so no causal claim is made. A second
v1 setup at 11:57 on `vmx0` was ended by an operator restart of both VMs at
12:08, before any collection.

## Recovery

After the 13:38 panic, the router was unreachable, so the collector could not
send `STOP` to the Windows helper. The helper's scheduled task was ended and
only its two fixture-named rules were removed. The procedure and the before and
after rule lists are recorded. Windows routed addresses and routes were then
torn down. The router reboot had already discarded its runtime state;
forwarding, redirects, modules and the tunable were verified back at their
recorded values. The earlier attempts' leftover router state, Windows setup
snapshot and orphaned rules are archived under `earlier-attempts/`.

## Verification and archive

The six valid canonical reports replayed identically. The 174 raw files passed
SHA-256 checks after extraction, and frozen-source re-analysis reproduced the
stored summary, including the invalid run. Archive SHA-256:
`c018b857e5a33ae5180dfed343b2d09af229b352e0c132d1f26916b6f9466a5c`. The
same declared path and route redactions as the v2 corpus were applied
before hashing.

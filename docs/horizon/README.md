# HORIZON HZ-001 proof of concept

HORIZON is an opt-in experiment runner. Both SYN arms offer MSS 1460;
**only treatment adds SACK permission**. It retains direct TCP replies and
compares whether those replies offer SACK permission. It does not identify
an OS, firewall, NAT, proxy or shared state.

See the [implementation plan](implementation-plan.md),
[integration map and assumptions](assumptions.md), and
[full roadmap](../HORIZON_ROADMAP.md).

## Unprivileged demonstration

Build with `make build`. Simulation opens no socket and sends no network
traffic. Documentation addresses are used only inside the synthetic transport.
The sample rate is 3 packets/s including cleanup, so a run takes about 16 s.

```sh
./nyxr horizon resolve --experiment lab/horizon/hz-001.yaml \
  --allow-targets 192.0.2.0/24 --allow-ports 443 --dry-run

./nyxr horizon resolve --experiment lab/horizon/hz-001.yaml \
  --allow-targets 192.0.2.0/24 --allow-ports 443 \
  --simulate sack --output horizon-sack.json

./nyxr horizon explain horizon-sack.json
./nyxr horizon replay horizon-sack.json > horizon-replayed.json
```

`sack` returns SACK only when offered: 12 treatment-only discordant pairs,
two-sided exact p-value 0.00048828125. `stable` returns the same MSS-only reply
for both arms and reports `no detectable difference in SACK permission`.
`loss` drops all replies and `noise` duplicates replies; both are unresolved.

Use different output names: `--output` creates mode-0600 files and refuses
overwrites. JSON also goes to stdout. Replay opens no packet backend, verifies
integrity and experiment identity, validates raw SYN/RST profiles and
reply-to-trial correlation, and recomputes features and comparison.
SHA-256 is corruption detection: **reports are not digitally signed**.

## Scoped live lab

Edit the YAML target, port and both `dstPort` values for an explicitly
authorized lab. Choose suitable response/washout windows and budgets: the
100 ms sample window is for simulation, not a universal network timeout.
Use the target MAC on the same subnet or gateway MAC for a routed target.

```sh
./nyxr horizon resolve --experiment lab-local.yaml \
  --allow-targets 10.77.0.2/32 --allow-ports 443 --dry-run

# Run the existing packet daemon in a separate terminal:
sudo ./nyxr-packetd --socket /tmp/nyxr-horizon.sock --interface hz-host
./nyxr horizon resolve --experiment lab-local.yaml \
  --allow-targets 10.77.0.2/32 --allow-ports 443 \
  --interface hz-host --source-ip 10.77.0.1 \
  --next-hop-mac 02:00:00:00:00:02 \
  --packetd /tmp/nyxr-horizon.sock --output horizon-live.json
```

Direct raw I/O uses the same platform backend; omit `--packetd` when the CLI
has the required privileges. The source must be assigned to the interface.
Unmapped Npcap adapters require `--source-mac`. Ethernet IPv4/IPv6 direct
TCP replies are supported; loopback is not a raw Ethernet lab.
macOS/Windows live behavior depends on existing BPF/Npcap capabilities.
**No privileged live lab was validated on the macOS development host.**

See [Linux namespace lab instructions](../../lab/horizon/README.md).
Capture independently with `tcpdump`; the source kernel can generate its own
RSTs and the target can retransmit. The traffic budget counts runner-emitted
packets, not all kernel/target traffic.

## Supported DSL and bounds

The [structural JSON Schema](experiment-v1alpha1.schema.json) describes the
supported wire format; the compiler additionally enforces authorization and
cross-field constraints. Omitted seed/washout fields normalize to zero.

`horizon.nyxr.io/v1alpha1`, kind `Experiment`: one global unicast literal IP
and one nonzero TCP port. Each arm has one TCP SYN `send` followed by one
`observe`. Profiles: `baseline` versus `sack-permitted`;
`changedVariable: sackPermitted`. Unknown fields, duplicate keys, aliases,
anchors, additional documents, nested sequences and arbitrary packet controls
fail closed. This is a strict subset of the illustrative roadmap DSL.

Independent `--allow-targets` and `--allow-ports` are mandatory, even for
dry-run. Empty authorization is rejected. Optional `--target`/`--ports` assert
the DSL scope without silently changing it.

Bounds: 2–50 randomized pairs, 1–10 transmitted packets/s, one flow,
10–5000 ms equal response windows, 0–5000 ms washout, 1–1800 s deadline,
4096 bytes–8 MiB raw evidence. Compile-time reservation includes four packets
per pair (two SYNs and two possible RST cleanups) and conservative elapsed
time. Execution re-admits and enforces all bounds. Received work is capped at
4096 frames/arm; more than 16 correlated replies stops with a quality flag
after preserving the triggering packet. Frames larger than 2048 bytes stop
capture. Serialized JSON is larger than the raw-byte capture budget.

Ctrl-C, caller cancellation and deadlines stop new transmissions. Errors
return nonzero and export partial evidence when available. There are no
retries. Cleanup follows the receive window and shares the rate gate.
Cancellation/errors can prevent cleanup; remote SYN state then expires later.

## Interpretation and reproducibility

Response class, TTL, RTT, options and raw frames are **observations**.
Comparisons are **inferred** or **unresolved**. Only SACK permission is tested;
other features remain descriptive. At least eight good complete pairs are
required, every planned pair must complete, and backend drops must be zero.
The two-sided exact paired sign test uses alpha 0.05. Missing replies,
duplicates, capture gaps and incomplete runs gate inference. No detectable
difference means lack of evidence, not stack equivalence or absence of coupling.

The test assumes independent stationary pairs; those assumptions are not
established by this PoC. Associations do not establish a causal mechanism.
RTT includes userspace/backend queues; timestamp precision and transport
checksums are not calibrated. ICMP, NAT/path shifts and topology probabilities
are not implemented. No broad false-positive or causal-validity claim is made.

The seed reproduces arm ordering and the compiled hash, not live frames or
timestamps. Run IDs and flow tokens use fresh randomness. Arms in a pair use
the same source port and different sequence/IP ID tokens. Build/backend/run
provenance and every retained packet are included in the report.

## Verification

```sh
make check build
go test -race ./internal/horizon/... ./cmd/nyxr
go test -run '^$' -fuzz '^FuzzAdmission$' -fuzztime=5s -parallel=2 ./internal/horizon/dsl
go test -run '^$' -fuzz '^FuzzReplay$' -fuzztime=5s -parallel=2 ./internal/horizon
go test -run '^$' -fuzz '^FuzzCorrelation$' -fuzztime=5s -parallel=2 ./internal/horizon
```

`make fuzz` includes these three HORIZON campaigns in the existing CI workflow.

Coverage includes deterministic compilation, unsafe admission, stable/effect/
loss/duplicate fixtures, replay/tampering, capture caps, failed sends,
cancellation, deadlines and stale correlation. Synthetic acceptance is not
live topology validation; that remains issue #66.

## Reference adapter

`nyxr horizon references report.json` imports a sealed report through offline
replay validation and prints a `nyxr/v1` reference-only record. Keep the input
file's exact bytes: references hash that envelope and retain its run, experiment
hash, trial pair/arm, flow ID and evidence pointers. This does not copy captures
into the inventory, merge assets or enable live experiment/API capabilities.
See the [source contract](../reference/output-records.md#source-references).

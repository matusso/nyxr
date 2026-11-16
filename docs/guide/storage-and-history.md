# Storage and history

Every scan is stored in a local SQLite database, so results accumulate into an
asset inventory you can query, rescan and prune.

## Database location

| Setting | Effect |
| --- | --- |
| Default | `~/.nyxr/nyxr.db`, created on first use. Under `sudo`, the directory belongs to the invoking user |
| `--name NAME` (scan), `--network NAME` (history, serve) | Use the database of that [network](#networks), next to the default one |
| `--db FILE` | Use another database |
| `--no-db` | Store nothing for this scan |

`nyxr scan`, `nyxr history` and `nyxr serve` all use the same default, so the
CLI and the web UI see the same data.

The driver is pure Go, so every release binary can open the database. The
schema is versioned with forward-only migrations; a database written by a newer
nyxr is refused rather than modified.

## What is stored

| Table | Content |
| --- | --- |
| Scans | ID, name, profile, timing, status, counters and the planned scope (targets and ports) |
| Assets | Each address with first-seen and last-seen times |
| Identity graph | Local and namespaced IDs, current membership, validated signals, weak clues, review decisions, and durable membership events |
| Observations | Every record with its full JSON |
| Evidence | Request and response bytes, in their own table |
| Observation sources | Exact immutable JSON containers and SHA-256 mappings, including exchange provenance, parser version, claim status and completeness |
| Packet index | Links from flows to pcapng packet IDs |

Writes are batched per transaction. `--open` changes only what is printed; the
database always stores closed and filtered results too.

## Networks

A scan name identifies a network. Private address ranges repeat across sites,
so `192.168.1.10` in the office and at home must not share one asset record.

```sh
nyxr scan --name office-lan 192.168.1.0/24   # stored in ~/.nyxr/office-lan.db
nyxr scan --name home-lan 192.168.1.0/24     # stored in ~/.nyxr/home-lan.db
nyxr scan --name office-lan 192.168.1.0/24   # a new scan record in office-lan.db
nyxr history --networks                      # the registry
nyxr history --network office-lan --assets   # read one network
nyxr history --diff office-lan               # what changed on it since the previous scan
nyxr serve                                   # web UI: pick a network from the dropdown
nyxr serve --network office-lan              # web UI opening on one network
```

- A new name creates a database file next to the default one and a row in the
  `networks` table of the default database. Scanning with a known name adds a
  scan record to that network's file. Assets, identities and history are
  separate per network.
- The file is named after the network. Characters other than letters,
  digits, `-`, `_` and `.` become `-`; a name whose file is already taken gets
  a `net-…` file with a digest suffix. A registered name never moves.
- `nyxr history --networks` shows each network's scan count, last scan, file
  and a `FILE` state. After every scan nyxr stores the SHA-256 of the closed
  database file: `unchanged` means the file still has that digest, `changed`
  means something wrote to it since (a prune, an import, an identity review,
  a scan started from `nyxr serve`, or an outside edit), `missing` means it is
  gone. Reading with `nyxr history` does not change the file.
- Without `--name` a scan gets a generated two-word label such as
  `quiet-heron` and is stored in the default database, as before. Imports are
  labelled the same way.
- `--db FILE` overrides all of this: the scan goes to that file with its name
  as a plain label, and the registry is not touched.
- In the web UI a **Network** dropdown in the header switches between the
  default database and every registered network. After every server
  start a browser first sees the dropdown in the middle of the page, next to
  **Create new scan**. A scan started from the form with a new name registers that
  network and stores into its file; the registry row and file digest are
  refreshed when the scan ends. See
  [Web UI and API](web-ui-and-api.md#networks).

## Query with `nyxr history`

```sh
nyxr history                                       # scans, newest first
nyxr history --scan <scan-id>                      # observations and packet evidence of one scan
nyxr history --assets                              # latest state and service per port
nyxr history --identities --json                   # correlated assets, addresses and source signals
nyxr history --identity-events --address 192.0.2.10 # membership audit for one address
nyxr history --diff office-lan                     # what changed on a network since its previous scan
nyxr history --diff <before-id>,<after-id>         # what changed between two scans
nyxr history --topology --json                     # LLDP neighbors from imported captures
nyxr history --import-pcap capture.pcapng --capture-interface en0
nyxr history --import-identifiers inventory.json  # scoped Kubernetes/cloud IDs
nyxr history --kube-api https://api.example:6443 --kube-token-file ./token --kube-cluster-scope cluster-a # Kubernetes nodes
nyxr history --cloud-provider gcp --cloud-scope my-project --cloud-credentials-file ./gcp.token  # cloud VM inventory
nyxr history --assets --open --scope 192.0.2.0/24  # current open ports in a subnet
nyxr history --scan <scan-id> --address 192.0.2.10 # one host within a scan
nyxr history --unknown --json                      # unrecognized responses, for signature work
```

| Flag | Effect |
| --- | --- |
| `--scan ID` | Show one scan |
| `--assets` | Show the asset inventory |
| `--identities` | Group addresses by strong device identity signals |
| `--identity-events` | Show membership changes; optionally filter by `--address` |
| `--networks` | List named networks, their database files and whether each file changed since its last scan |
| `--network NAME` | Read that network's database instead of the default |
| `--diff NAME` | Explain what changed on a network: compare the last two finished scans with this name, read from the network's database when it has one |
| `--diff BEFORE,AFTER` | Explain what changed between two scan IDs; see [Compare two scans](#compare-two-scans) |
| `--topology` | Show imported LLDP neighbors and their current identity links |
| `--import-pcap FILE` | Import passive IP and LLDP observations |
| `--import-identifiers FILE` | Import scoped Kubernetes/cloud inventory IDs |
| `--kube-api URL` | Collect Kubernetes node UIDs and IP addresses; requires `--kube-token-file` and `--kube-cluster-scope`, with optional `--kube-ca-file` |
| `--cloud-provider aws\|azure\|gcp` | Collect read-only VM addresses for one account/subscription/project; requires `--cloud-scope` and `--cloud-credentials-file` (and `--cloud-region` for AWS). See [asset identity](asset-identity.md#cloud-inventory) |
| `--open` | Only ports whose latest state is open |
| `--scope LIST` | With `--assets`, restrict addresses; with `--identities`, select identities having a matching address |
| `--address IP` | With `--scan`, `--unknown`, or `--identity-events`, restrict to one address |
| `--unknown` | List unknown fingerprints |
| `--limit N` | Maximum rows (default 50) |
| `--json` | JSON output, including evidence |

Stored open ports can be rescanned directly with
[`nyxr scan --known-open`](scanning.md#rescan-stored-open-ports).

## Compare two scans

```sh
nyxr scan --name office-lan 192.168.1.0/24   # run again later with the same name
nyxr history --diff office-lan               # previous scan of that network vs the latest
nyxr history --diff 20261112T133605Z-5507b8b66183,20261112T133608Z-06c69b9715ba   # any two scans, older first
```

```text
nyxr-scan-diff/v1  20261112T133605Z-5507b8b66183 (office-lan, tcp-basic, completed) -> 20261112T133608Z-06c69b9715ba (office-lan, tcp-basic, completed)
- 127.0.0.1 tcp/18080    service              removed  "open http SimpleHTTP" -> "closed"
+ 127.0.0.1 tcp/18081    service              added  "closed" -> "open http SimpleHTTP"
```

The first ID is the older scan. Lines start with `+` added, `-` removed,
`~` changed or `?` not observed. `--json` prints one versioned `ScanDiff`
object (see [output records](../reference/output-records.md#scan-diff)); the
same result is served by `GET /api/v1/scans/diff` and shown by **Scans →
Compare** in the web UI, where a scan's name links to the diff of its network.
A name needs two finished scans; running scans are skipped. Output order is stable: address, transport, port.

A diff only claims what both scans can support. Every change has a `status`:

| Status | Meaning |
| --- | --- |
| `observed` | Both scans hold an answer that supports the change |
| `unverified` | The change cannot be proven; `reason` says why |

| Reason | Why nothing is proven |
| --- | --- |
| `not_tested` | The other scan completed and its stored scope does not include this address or port |
| `scan_incomplete` | The other scan failed, was canceled, is still running, or exceeds 200000 observations |
| `silent` | The endpoint was in the other scan's scope, or was probed, and did not answer (`filtered`, `open\|filtered`, timeout, no stored result) |
| `truncated_evidence` | The compared field came from an exchange whose retained bytes were cut short |

Coverage comes from the scope each scan stores: its targets and its port
list per transport. A scan without a stored scope (an import, a known-open
rescan whose ports differ per target, or a scan from before scope was
recorded) falls back to its results: no stored result then means `not_tested`.
An address that first answers in the later scan is `added` and `observed`
when the earlier scan had it in scope, and `unverified` otherwise. The header
shows both scan names. Comparing scans with different names is allowed and
adds a limitation, because they may be different networks.

So a service is `removed` only when the later scan received a `closed` answer
for that port. A host is never reported as removed: silence is reported as
`asset_presence not_observed`, and its ports are not listed one by one.

Change kinds:

| Kind | Compared |
| --- | --- |
| `asset_presence` | An address that answered in one scan only |
| `service` | Open endpoints added or removed, and service, product or version changes |
| `tls_certificate`, `tls_configuration` | Leaf certificate; negotiated version, cipher and ALPN; the `nyxr-tls-server/v1` fingerprint. Only compared between handshakes with the same ClientHello profile and server name |
| `ssh_host_key`, `ssh_configuration` | Host key SHA-256; the `nyxr-ssh-kexinit/v1` fingerprint |
| `http_title`, `snmp_identity` | `http.title`; `snmp.engine_id` |
| `os`, `firmware`, `device_class` | `smb.os_version`, `nmap.os`, `device.os_family`; `s7.firmware`, `bacnet.firmware`; `device.class` |
| `address_membership` | One asset answered on one old and one new address. Its endpoints are compared across the move, not reported as removed and added |
| `address_reassignment` | A strong identity signal changed, so a different device now answers at the address |
| `identity_manual` | A manual join or separation was recorded between the scans |
| `identity_correlation` | Automatic correlation or retention changed the asset ID |

The identity kinds are bookkeeping, not exposure changes. `asset` is the
persistent asset ID and `before_observation`/`after_observation` resolve with
`nyxr evidence show`. Fields are compared only when both scans recorded a
value; a title or key that one scan did not collect is not a change.
`limitations` lists what weakens the whole comparison: an incomplete scan,
different profiles, capture drops, and open endpoints identified by only one
scan. The diff does not apply HORIZON profile expiry or confidence decay.

## Retention

```sh
nyxr history --prune-older-than 720h   # delete scans older than 30 days
nyxr history --keep 20                 # keep only the newest 20 scans
```

Pruning deletes scans with their observations, evidence and packet index, then
removes assets and identity graph nodes that no longer have any records. pcapng files on disk are left
in place.

See [Asset identity graph](asset-identity.md) for correlation rules and limits.

## Source migration and cancellation

Migration 7 adds immutable observation sources and capture artifact IDs without
changing existing address/identity IDs, database lineage, reviews or membership
history. It reconstructs each historical observation from the released record and
evidence columns in batches of 256. Historical parser versions are `unknown`,
missing bytes stay missing, and old captures receive no guessed hash. Existing
probe-update ranges and unknown responses retain their order. Reopening the
upgraded database preserves its references. Back up the database before upgrading;
older binaries refuse the newer schema. A migration failure rolls back its changes.

A canceled scan drains in-flight discovery results and records its partial failed
summary. Store batches remain bounded at 256 records and finish pending writes
with cancellation removed and a 30-second write deadline. Packet RX never performs
source serialization, hashing or database writes. Ordinary capture hashing runs on
the recorder's existing writer; capture download checks container size/hash.

Pruning cascades to observation sources along with exchanges. A previously saved
reference remains useful provenance, but resolving it returns `unavailable` with a
reason after its container is removed. pcapng files remain operator-managed;
rewriting a capture does not silently change its saved artifact identity.
See [Output records](../reference/output-records.md#source-references) for the
source resolver and CLI/JSON compatibility changes.

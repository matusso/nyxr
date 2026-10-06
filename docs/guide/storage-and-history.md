# Storage and history

Every scan is stored in a local SQLite database, so results accumulate into an
asset inventory you can query, rescan and prune.

## Database location

| Setting | Effect |
| --- | --- |
| Default | `~/.nyxr/nyxr.db`, created on first use. Under `sudo`, the directory belongs to the invoking user |
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
| Scans | ID, profile, timing, status and counters |
| Assets | Each address with first-seen and last-seen times |
| Identity graph | Local and namespaced IDs, current membership, validated signals, weak clues, review decisions, and durable membership events |
| Observations | Every record with its full JSON |
| Evidence | Request and response bytes, in their own table |
| Packet index | Links from flows to pcapng packet IDs |

Writes are batched per transaction. `--open` changes only what is printed; the
database always stores closed and filtered results too.

## Query with `nyxr history`

```sh
nyxr history                                       # scans, newest first
nyxr history --scan <scan-id>                      # observations and packet evidence of one scan
nyxr history --assets                              # latest state and service per port
nyxr history --identities --json                   # correlated assets, addresses and source signals
nyxr history --identity-events --address 192.0.2.10 # membership audit for one address
nyxr history --topology --json                     # LLDP neighbors from imported captures
nyxr history --import-pcap capture.pcapng --capture-interface en0
nyxr history --import-identifiers inventory.json  # scoped Kubernetes/cloud IDs
nyxr history --kube-api https://api.example:6443 --kube-token-file ./token --kube-cluster-scope cluster-a # Kubernetes nodes
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
| `--topology` | Show imported LLDP neighbors and their current identity links |
| `--import-pcap FILE` | Import passive IP and LLDP observations |
| `--import-identifiers FILE` | Import scoped Kubernetes/cloud inventory IDs |
| `--kube-api URL` | Collect Kubernetes node UIDs and IP addresses; requires `--kube-token-file` and `--kube-cluster-scope`, with optional `--kube-ca-file` |
| `--open` | Only ports whose latest state is open |
| `--scope LIST` | With `--assets`, restrict addresses; with `--identities`, select identities having a matching address |
| `--address IP` | With `--scan`, `--unknown`, or `--identity-events`, restrict to one address |
| `--unknown` | List unknown fingerprints |
| `--limit N` | Maximum rows (default 50) |
| `--json` | JSON output, including evidence |

Stored open ports can be rescanned directly with
[`nyxr scan --known-open`](scanning.md#rescan-stored-open-ports).

## Retention

```sh
nyxr history --prune-older-than 720h   # delete scans older than 30 days
nyxr history --keep 20                 # keep only the newest 20 scans
```

Pruning deletes scans with their observations, evidence and packet index, then
removes assets and identity graph nodes that no longer have any records. pcapng files on disk are left
in place.

See [Asset identity graph](asset-identity.md) for correlation rules and limits.

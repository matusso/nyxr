# Central storage and cross-lineage reconciliation

A scanner or fleet controller keeps its results in its own SQLite database.
`nyxr central` consolidates many of those databases into one controller store
on **SQLite** (single host) or **PostgreSQL** (shared). It also keeps large
evidence artifacts such as pcapng captures and HORIZON reports in **object
storage** (a directory, or S3 and S3-compatible stores), and reconciles asset
identities across databases.

Each source database is a **lineage**, named by its random identity
namespace (the `<namespace>` in `urn:nyxr:<namespace>:NYXR-…`). Lineages keep
their own stores and resolvers. Standalone `nyxr scan` and `nyxr serve` work
exactly as before.

```text
 scanner.db ──┐                        ┌── PostgreSQL / SQLite (central)
 site-b.db ───┼── nyxr central push ──►│     lineages, observations, scans,
 controller ──┘   (or serve --central) │     signals, clues, entities, audit
   │                                   └── object storage (sha256/aa/<hash>)
   └─ agents: nyxr central upload-dir --dir <evidence-dir>
```

## Quick start

```bash
# A PostgreSQL controller store with captures in S3. Keep the password out of argv.
echo 'postgres://nyxr:…@db.internal/nyxr?sslmode=verify-full' > ~/.nyxr/central.dsn
chmod 600 ~/.nyxr/central.dsn
export NYXR_CENTRAL_OBJECTS='s3://evidence/nyxr?region=eu-west-1'

nyxr central migrate --central-dsn-file ~/.nyxr/central.dsn
nyxr central push    --central-dsn-file ~/.nyxr/central.dsn --db ~/.nyxr/nyxr.db --label hq
nyxr central entities --central-dsn-file ~/.nyxr/central.dsn
```

Or let a server push continuously:

```bash
nyxr serve --db /var/lib/nyxr/controller.db --fleet-listen :9443 … \
  --central-dsn-file /etc/nyxr/central.dsn --central-objects /var/lib/nyxr/objects \
  --central-sync 1m --central-capture-retention 720h
```

A server with `--fleet-listen` pushes as a `controller` lineage; otherwise as a
`standalone` one.

## Ingestion

A push reads the source database from its lineage **cursor** (the highest
observation row already applied). It sends batches of sealed `nyxr/v1`
observation sources, the scan summaries, capture references and the current
local identity membership.

Ingestion is idempotent and order-independent:

| Record | Key | Duplicate | Out of order |
|---|---|---|---|
| Observation | SHA-256 of its sealed source | ignored, counted as duplicate | commutes |
| Same observation ID, different bytes | `(lineage, observation_id)` | **conflict**: kept in `ingest_conflicts`, never overwrites | — |
| Scan summary | `(lineage, scan_id)` | — | `running` never replaces a finished summary |
| Membership snapshot | lineage revision | older or equal snapshots are ignored | newest wins |
| Signal or clue | `(lineage, address, kind, value)` | first/last seen and count merge | commutes |
| Cursor | lineage | — | only moves forward |

Each observation keeps its **provenance**: lineage, scan, and for fleet results
the agent, job, lease and attempt. It also keeps its **time quality**:

| `time_quality` | Meaning |
|---|---|
| `local_clock` | The scanner's own clock. Nothing measured its sync. |
| `agent_offset_corrected` | Agent time corrected by the offset the controller measured at lease time, within 5 s. |
| `agent_skewed` | Corrected too, but the measured offset exceeded 5 s. Ordering against other agents is doubtful. |

`reported_at` is the original timestamp. `observed_at` is in the controller's
timebase.

## Artifacts

Artifacts are content-addressed (`sha256:<hex>`) and stored under
`sha256/<aa>/<hex>`. Uploads are spooled to a private temporary file while
hashed, are bounded (4 GiB by default), and are rejected if they don't match
the expected hash or size. Reads are verified again: a reader fails at EOF if
the object no longer matches its hash.

| State | Meaning |
|---|---|
| `pending` | Referenced (for example a capture recorded on a fleet agent), bytes not uploaded yet |
| `available` | Stored and verified |
| `missing` | Registered, but the object vanished from storage; detected on read, fixed by re-uploading |
| `expired` | Bytes deleted by retention; metadata kept, so references explain the absence |

**Access policy.** `restricted` (the default, and always used for pcapng
captures, which contain payloads) requires `nyxr central get
--allow-restricted`. `internal` is readable by any reader of the central store.

**Retention.** `--retain` / `--central-capture-retention` set when bytes may
be deleted. A later explicit retention extends it. A reference without one
never removes it. `nyxr central prune` deletes expired bytes; run it from cron.

**Fleet captures.** pcapng files stay on each agent's `--evidence-dir`. The
controller's push registers them as `pending` with the agent ID. On the agent
host, run:

```bash
nyxr central upload-dir --central-dsn-file … --objects … --dir /var/lib/nyxr/evidence
```

It hashes the files and uploads only those the central store references.
Unrelated files are never uploaded.

**HORIZON artifacts.** Store them as they are, without re-deriving anything:
`nyxr central put --kind horizon-report --access restricted report.json`.

## Reconciliation

The unit central reconciliation moves is a **node**: one local identity of
one lineage (`urn:nyxr:<lineage>:NYXR-…`), as that lineage's own resolver
decided. Until a lineage reports membership for an address, the address is its
own provisional node (`urn:nyxr:<lineage>:address:<ip>`). When it is replaced,
it is retired with an audit event and its entity ID passes on.

Nodes are joined into **entities** (`NYXC-…`, globally
`urn:nyxr:central:<namespace>:NYXC-…`) conservatively:

- **Scoped identifiers join across lineages.** These are cloud instance IDs
  qualified by account, subscription or project, and Kubernetes node UIDs
  qualified by cluster: the same values the local resolver reports as portable
  IDs. Only an address's latest value of each kind counts, so a replaced
  instance behind a reused address doesn't conflict with itself.
- **Device-scoped values are relations, not merge keys, across lineages.**
  SSH host keys, SMB server GUIDs, SNMP engine IDs and MACs are strong inside
  their own lineage, where the local resolver already applied them. Images
  clone keys and MACs are link-local, so across lineages they appear in
  `nyxr central relations` as `device` leads.
- **Weak clues never change membership.** Hostnames, certificate fingerprints
  and DNS names, UPnP UUIDs, OUIs, VLANs and LLDP IDs appear as `weak`
  relations.
- **Conflicts are refused and kept.** A join that would put two different
  values of one scoped kind into one entity is not made, and is listed in
  `nyxr central conflicts` as `scoped_value_conflict`.

The partition is a deterministic function of the stored evidence and
decisions. Manual joins apply first, in decision order, then scoped signal
edges in `(kind, value, node)` order. Delivering the same data in another
order, or twice, gives the same entities. An entity keeps its ID when it holds
the most nodes of the new component (lowest ID on a tie); a split-off part gets
a new ID. Entity `link` says why its nodes are together: `single`,
`scoped_signal`, `manual` or `scoped_signal+manual`. All of these are
inferred, never observed directly.

### Manual review

```bash
nyxr central entities                     # note the entity revision
nyxr central review --separate --node-a urn:nyxr:… --node-b urn:nyxr:… \
  --note "instance ID reused after restore" --expect NYXC-000000000001@3
nyxr central revert --decision 1 --note "separation was a mistake"
nyxr central history --node urn:nyxr:…
```

- `--separate` blocks automatic joins between the two nodes' components. The
  refused signal edge stays visible as a `separated_by_decision_N` conflict.
- `--join` links two nodes regardless of signals. A join that another active
  separation still blocks, or a separation that another join still bridges, is
  refused and nothing changes.
- The latest decision on a pair supersedes earlier ones. `revert` makes the
  previous decision on that pair effective again. Every decision, including
  reverted ones, stays in `nyxr central decisions`.
- `--expect ENTITY@REVISION` gives optimistic concurrency: if anyone changed
  the entity since you read it, the decision fails with "entity revision
  changed". Every write serializes on one row lock, on both dialects.
- `nyxr central history` is the membership audit: every node move with its
  cause (`ingest:<lineage>:new_node`, `decision:separate`, `revert:N`,
  `…:node_retired`), decision and store revision.

## Migrations, export and restore

The central schema is versioned (`central_schema`) and migrates on open. On
PostgreSQL an advisory lock keeps two controllers from migrating at once. A
store newer than the binary is refused.

`nyxr central export` writes a consistent snapshot (`nyxr-central-export/v1`
JSON lines: a header, typed rows, and a trailer with the row count).
`nyxr central restore` loads it into an **empty** store in one transaction,
keeping the central namespace and the entity, decision and event IDs. Use it
for backups and to move between SQLite and PostgreSQL:

```bash
nyxr central export --central ./central.db --out central.jsonl
nyxr central restore --central-dsn-file ~/.nyxr/central.dsn --in central.jsonl
```

Object bytes aren't in the export. Copy the object store separately; an object
that didn't come along is marked `missing` on first read.

## Bounds

| Limit | Value |
|---|---|
| Sealed observation | 1 MiB |
| Records per batch | 10,000 (pushes use 500) |
| Artifact | 4 GiB (`DB.MaxArtifact`) |
| `upload-dir` files examined | 10,000 (`--max-files`) |
| Decision note | 1–500 characters |

## Limits

- Reconciliation recomputes the whole partition on each change, from compact
  tables (addresses, signals and decisions, not observations). That suits
  hundreds of thousands of addresses. Larger fleets need incremental,
  component-scoped recompute.
- The web UI and REST API don't show central entities yet; use the CLI and
  `--json`.
- Agents don't stream capture bytes to the controller over gRPC. Captures
  reach object storage through `upload-dir` on the agent host, which needs
  central store and object storage credentials.
- HORIZON experiment provenance and inference stay with HORIZON (#71). The
  central store only keeps and references HORIZON artifacts.
- Validated with the unit and integration suites on SQLite and PostgreSQL 17
  (`NYXR_TEST_POSTGRES_DSN`), and an S3 signing test against a local fake.
  Not yet validated against AWS S3 or MinIO, or at production scale.

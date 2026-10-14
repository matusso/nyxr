# Asset identity graph

Nyxr stores address history and a correlated asset graph. Each identity has a
short database-local `NYXR-…` ID and a database-namespaced `global_id`. The
global ID distinguishes independently created databases; copying a database
copies its namespace. Scoped imported inventory IDs also produce
`portable_ids`, which match across databases when the same scoped source ID is
imported. Other devices still need controller-level reconciliation.

```sh
nyxr history --identities --json
nyxr history --identity-events --address 192.0.2.10 --json
```

The web UI's **Identities** view and `GET /api/v1/assets/identities` show
current address membership, per-address ports, source signals, weak clues,
candidate relationships, and device profile claims. `GET /api/v1/assets`
still returns one record per address with an `identity_id`.

## Automatic links

Nyxr automatically joins addresses only on validated device-scoped values:

| Signal | Source |
| --- | --- |
| Full MAC address | Successful local ARP or IPv6 neighbor solicitation |
| SNMP engine ID | Matched SNMPv3 response |
| SMB server GUID | Validated SMB2 negotiate response |
| SSH host key | Signature-verified SSH key exchange; no authentication attempted |
| Scoped Kubernetes node or cloud instance ID | Kubernetes API node collection or operator-supplied inventory import with an explicit cluster, account, subscription, or project scope |

Malformed, zero, multicast, and missing values are ignored. A changed
device-scoped value retires the address's old merge signals and can split its
current identity. A changed MAC does not split an address that has a stable
SNMP, SMB, SSH, or scoped inventory ID. Conflicting stable IDs prevent a new
automatic join. A manual separation also blocks a later automatic join.

Shared certificates, hostnames, MAC OUIs, HTTP headers, and software banners
never merge assets automatically. Shared TCP signatures also never join
addresses. [Stack fingerprints](tcp-stack-fingerprinting.md) contribute
`os_family` claims at their own confidence; one consistent family supplies the
profile OS only when no application OS claim exists. Conflicting families
remain in the claims list. The graph stores safe hostname and leaf
certificate clues, plus UPnP UUIDs extracted from SSDP, and reports shared
clues as relationships. Clues shared by more than 16 identities are omitted
from candidate generation because they are too broad. Candidate scores are
conservative heuristics, not calibrated probabilities. Certificate fingerprint
and DNS name clues from the same certificate, and a potentially related
hostname, contribute at most one score increment. UPnP and LLDP clues are
counted separately. The current identity rule version is `nyxr-identity/v2`.
`link_confidence` scores the current multi-address
link; zero means no link was needed or established. A `blocked` hypothesis
has conflicting strong evidence or a manual separation.

## History and review

`GET /api/v1/assets/identity-events` returns the durable membership audit;
add `?address=IP` to filter it. Events record the old and new IDs, cause,
observation time, recording time, and scan ID when available. They survive
scan retention. Existing databases receive a migration baseline, so earlier
split and merge decisions cannot be reconstructed.

The **Identities** page can record a reviewed `join`, `separate`, or `clear`
decision for two addresses with a reason. The same workflow is available at
`POST /api/v1/assets/identity-reviews`; `GET` returns its audit log. A join is
an explicit edge while both addresses remain in inventory, even if its signal
evidence is pruned. A separation blocks the pair
from rejoining automatically. Clear removes the active decision; later
observations can correlate the pair again. Reviewed changes and resulting
membership changes are both retained in their logs.

## Passive and inventory input

```sh
nyxr history --import-pcap capture.pcapng --capture-interface en0
nyxr history --topology --json
nyxr history --topology-timeline --limit 100 --json
nyxr history --topology-timeline --at 2026-10-14T10:00:00Z --json
nyxr history --topology-review reviewed-assignment.json --json
nyxr history --import-identifiers inventory.json
nyxr history --kube-api https://api.example:6443 --kube-token-file ./token \
  --kube-ca-file ./cluster-ca.pem --kube-cluster-scope cluster-a
```

The pcap/pcapng import stores passive IP source sightings and LLDP chassis,
port, management-address, capture-interface, VLAN, and advertised TTL
observations. `--topology-timeline` returns `nyxr/topology/v1alpha1` address
to MAC-interface claims and LLDP adjacencies. Each address claim points to a
retained, hash-verified observation source. A tagged source packet also records
the VLAN seen on that packet. ARP/NDP replies can supply the same interface
claim. Several addresses or MAC interfaces may appear under one asset; a
passive MAC, VLAN, topology proximity, or LLDP chassis never causes a merge.

An address claim is valid **at the observation instant only**. LLDP adjacency
is bounded by its advertised TTL; missing TTL in older imports is valid only
at the observed instant. A row's `identity_id` is resolved from the membership
audit at that observation time, so a later join or separation does not rewrite
the old link. Before the first retained evidence, ownership is `unknown`.
Equal-time claims that place one address on different interfaces are flagged
as conflicts and left separate. An operator can add a finite, reviewed
`join` or `separate` interval for an observed interface. Reviewed intervals
are labeled separately from observed packets. Overlapping contradictory
reviews and packets are surfaced as conflicts or reviewed separations rather
than silently replacing evidence. Manual asset join/separate reviews remain in
the **Review membership** form and do not turn topology clues into merge keys.

A topology review is one JSON object with `address`, `interface_id`,
`decision` (`join` or `separate`), `valid_from`, `valid_until`, `note`,
and optional `vlan_id` (0 means unspecified). Times are RFC3339; the valid
interval is `[valid_from, valid_until)`, at most ten years. The interface ID
must already have a retained observation. For example:

```json
{
  "address": "192.0.2.5",
  "interface_id": "NYXR-000000000001/mac:02:01:02:03:04:05",
  "decision": "join",
  "valid_from": "2026-10-14T10:00:00Z",
  "valid_until": "2026-10-15T10:00:00Z",
  "vlan_id": 100,
  "note": "reviewed switch inventory"
}
```

The timeline returns reviewed intervals with their immutable review source.
The web **Identities** view offers the same review form, and
`POST /api/v1/assets/topology/reviews` accepts the JSON body. A reviewed
interface assignment does not merge asset identities.

The timeline is available at `GET /api/v1/assets/topology/timeline`; optional
`at=RFC3339` filters to claims valid at one instant and `limit=1..1000`
bounds each category in the response. The web **Identities** view shows the
newest 100 rows per category.
`GET /api/v1/assets/topology` keeps the existing LLDP list shape. New LLDP
rows retain the scan ID, frame index, frame hash and, for frames up to 2 KiB,
an immutable JSON source artifact containing the exact frame bytes. The
existing `POST /api/v1/evidence/resolve` accepts the row's `source`
reference. Retained LLDP bytes are limited to 16 MiB per import; later or
oversize frames report `hash_only`. Rows imported before the migration report
`legacy_unavailable` and receive an unknown-TTL point baseline. The migration
backfills address claims only from retained observations with source artifacts.
Pruning a scan removes its claims, adjacencies and frame sources; it cannot
reconstruct lost history.

LLDP neighbors without a management address remain visible without an asset
identity. Import is bounded to one million frames. Live `sniff` output is not
yet ingested into this graph.

The identifier file is a JSON array of objects with `address`, `kind`,
`scope`, and `value`. Supported kinds are `kubernetes.node_uid`,
`cloud.aws.instance_id`, `cloud.azure.vm_id`, and `cloud.gcp.instance_id`.
Use an owning cluster ID or cloud account/project in `scope`; Nyxr will not
join equal values from different scopes. For example:

```json
[
  {"address":"192.0.2.10","kind":"kubernetes.node_uid","scope":"cluster-a","value":"node-123"}
]
```

The Kubernetes command lists nodes through the HTTPS API, collects each node's
UID and advertised internal/external IP addresses, and records them as a
`kubernetes-api` scan. Give `--kube-cluster-scope` a stable unique ID for the
cluster so equal node UIDs in different clusters stay separate. The bearer
token needs permission to **list nodes**; the CA file is optional when the
server certificate is already trusted by the system. TLS verification is
required. Nyxr rejects conflicting node UIDs for one address, and repeated
imports retain the same scoped identity evidence.

The graph synthesizes a device class from device or Nmap observations, a
model from validated Modbus/EtherNet/IP identity, and OS from SMB or Nmap
evidence. Every claim keeps its address, scan, probe, timestamp, and confidence.
If current claims disagree, the summary field stays empty and the claims
remain visible. Direct cloud collection and live passive ingestion remain
future work. The topology timeline does not infer continuous address ownership
from isolated packets.

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
never merge assets automatically. The graph stores safe hostname and leaf
certificate clues, plus UPnP UUIDs extracted from SSDP, and reports shared
clues as relationships. Clues shared by more than 16 identities are omitted
from candidate generation because they are too broad. Candidate scores are
conservative heuristics, not calibrated probabilities. `link_confidence` scores the current multi-address
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
nyxr history --import-identifiers inventory.json
nyxr history --kube-api https://api.example:6443 --kube-token-file ./token \
  --kube-ca-file ./cluster-ca.pem --kube-cluster-scope cluster-a
```

The pcap/pcapng import stores passive IP source sightings and LLDP chassis,
port, management-address, capture-interface, and VLAN observations. It does
not treat a passive source MAC or an LLDP chassis ID as an automatic merge key.
LLDP neighbors without a management address remain visible in the topology
list, without an asset identity. The import is bounded to one million frames.
Live `sniff` output is not yet ingested into this graph.

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
remain visible. Direct cloud collection, live passive ingestion, and a
complete interface ownership model remain future work.

# Asset identity graph

Nyxr keeps scan history by address and builds a second, correlated view of
assets. Each identity has a persistent `NYXR-…` ID within its SQLite database.
The ID survives rescans and joins; it is not a globally portable identifier.

```sh
nyxr history --identities
nyxr history --identities --json
```

The web UI has an **Identities** view. API clients can read
`GET /api/v1/assets/identities` or `GET /api/v1/assets/identities/{id}`. Each
identity contains its member addresses, their separate port histories, and
signal observations with scan IDs and timestamps. `GET /api/v1/assets` and
`nyxr history --assets` still show one record per address, now with an
`identity_id` field.

## Correlation

Nyxr joins addresses only on these validated device-scoped values:

| Signal | Source |
| --- | --- |
| Full MAC address | A successful local ARP or IPv6 neighbor solicitation |
| SNMP engine ID | A matched SNMPv3 response |
| SMB server GUID | A validated SMB2 negotiate response |

Zero, multicast, malformed, and missing values are ignored. A newly observed
SNMP engine ID or SMB GUID at an address retires that address's previous merge
signals and assigns a fresh identity. A changed MAC does the same when no
stable SNMP engine ID or SMB GUID is already known for that address. The old observations remain in history
and appear in graph evidence with `active: false`. Conflicting device-scoped
values prevent a new cross-address join.

Certificates, DNS names, MAC OUIs, HTTP headers, software banners, and similar
shared values do not automatically join assets. This avoids grouping unrelated
hosts behind a proxy, load balancer, or common certificate. An address with no
strong signal still has its own persistent ID.

The graph shows current address membership. It does not yet provide a complete
timeline of address ownership, manual overrides, identity confidence, or
interface and topology relationships. See the
[next-generation roadmap](../NYXR_NEXT_GEN_ROADMAP.md#3-asset-identity-graph)
for the remaining work.

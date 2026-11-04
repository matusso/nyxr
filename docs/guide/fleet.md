# Fleet: distributed scans with remote agents

A fleet splits one scan across several vantage points. `nyxr serve` acts as
the **controller**; `nyxr agent` runs on each vantage. Agents dial the
controller over gRPC (protocol `nyxr-fleet/v1`), so they work from behind NAT
and need no listening port. The controller pushes work down that connection,
and agents stream results back into the controller's database. Results show
up in history, the asset graph and the web UI like any other scan.

```text
                 nyxr serve --fleet-listen
                         │  gRPC (TLS)
            ┌────────────┼────────────┐
            │            │            │
       nyxr agent   nyxr agent   nyxr agent
         eu-1          us-1         lan-1
```

Agents run each lease through the same `config.Request` resolution and scan
pipeline as the CLI and API. The fleet adds scheduling, budgets and transport,
not another scanner. It distributes ordinary scans only. HORIZON experiments
keep their own admission gates and are never dispatched to agents.

## Quick start

On the controller:

```sh
openssl rand -hex 16 > api.token        # REST API token (required for the fleet)
openssl rand -hex 16 > enroll.token     # shared with agents once, for enrollment
nyxr serve --listen 0.0.0.0:8484 --token-file api.token \
  --fleet-listen 0.0.0.0:8485 \
  --fleet-tls-cert controller.crt --fleet-tls-key controller.key \
  --fleet-enroll-token-file enroll.token
```

On each agent:

```sh
nyxr agent --controller controller.example:8485 --ca ca.crt \
  --name lan-1 --allow-targets 10.20.0.0/16 \
  --enroll-token-file enroll.token
```

The first run enrolls the agent and saves its credential to
`~/.nyxr/agent.json` (mode 0600). Later runs only need `--identity`, and the
enrollment token file can be removed from the agent.

Submit a distributed scan through the REST API:

```sh
curl -H "Authorization: Bearer $(cat api.token)" -H 'Content-Type: application/json' \
  -d '{"request": {"targets": ["10.20.0.0/16"], "ports": "top100", "profile": "tcp-common"},
       "unit_size": 256, "max_parallel": 8}' \
  https://controller.example:8484/api/v1/fleet/scans
```

`request` is the same scan document as `POST /api/v1/scans` and the YAML
`--config` file.

## How a scan is distributed

1. **Validate.** The controller resolves the request exactly as an agent
   would. Fields tied to one machine (`interface`, `source_ip`, `source_mac`,
   `next_hop_mac`, `xdp_pin_dir`) are refused; each agent configures its own.
   `known_open` and the research profile are not distributed.
2. **Partition.** Targets are cut into units of at most `unit_size` addresses
   (default 256). Units are packed from whole IPv4 /24s and IPv6 /64s, so a
   per-subnet rate budget is never shared by two agents. A subnet larger than
   `unit_size` is split, and its `subnet_rate` is divided among the pieces.
3. **Match.** A unit is leased only to a connected agent that fits:

   | The request needs | The agent must advertise |
   | --- | --- |
   | `tcp_mode: syn`, ARP, NDP | raw packet I/O (`--packetd` or `--allow-privileged`) |
   | ICMP echo | a privileged agent |
   | `pcapng` | raw I/O and `--evidence-dir` |
   | `ot-safe` profile | `--allow-ot` |
   | IPv6 targets | a global IPv6 address |
   | ARP / NDP | the targets on a directly attached subnet |
   | any target | the target inside the agent's `--allow-targets` |

   A unit that no agent can run stays pending, and the job detail says why
   (`waiting`).
4. **Lease.** The least-loaded eligible agent gets the unit with a lease TTL
   (`--fleet-lease-ttl`, default 30s). Heartbeats renew it. TTLs are relative,
   so agent and controller clocks never need to agree.
5. **Stream.** The agent runs the scan and streams its `nyxr/v1` records in
   numbered batches. The controller stores each batch and advances the lease
   checkpoint in one database transaction, then acknowledges it. The agent
   keeps at most one unacknowledged batch per lease. When the queue is full,
   the scan waits (backpressure) instead of growing memory.

## Budgets

| Budget | Where it is enforced |
| --- | --- |
| Global `rate` and `service_rate` | divided by `max_parallel` (default 4) for each lease |
| Per agent | `--max-rate` / `--max-service-rate`, divided by `--max-leases`; the agent clamps any lease above it |
| Per host | `host_rate` applies unchanged: each address belongs to one unit |
| Per subnet | `subnet_rate` applies per unit, divided when a subnet is split |
| Per interface | `interface_rate` applies on the agent's raw interface, divided by `--max-leases` because concurrent leases share it |

The sum of concurrent leases never exceeds the request's global rate or any
agent's own budget.

## Failure behavior

| Situation | What happens |
| --- | --- |
| Agent goes offline mid-unit | No heartbeat: the lease expires after the TTL. The unit is retried, possibly on another agent, with backoff, up to `max_attempts` (default 3). |
| Agent cut off from the controller | After one lease TTL without contact, the agent abandons its leases, since the controller may already have re-leased them. Two vantages never knowingly scan the same unit, and global budgets hold. |
| Agent reconnects while its lease is still valid | It reports the lease in `Hello`, resends its unacknowledged batch, and continues. Nothing is lost or stored twice. |
| Agent restarts and loses its lease | The controller ends the lease at reconnect and retries the unit. |
| Controller restarts | Open leases get one TTL of grace. Agents reconnect and resume. |
| Duplicate batch (lost acknowledgement) | Acknowledged again without changes: batches are applied once by `(lease, seq)`. |
| Results about addresses outside the unit, or a sequence gap | The lease fails and is canceled on the agent. Nothing from that batch is stored. |
| Controller storage error | The batch is not acknowledged. The stream drops, and the agent resends after reconnecting. |
| Agent rejects a lease (scope, missing capability) | The unit is retried elsewhere and not offered to that agent again. |
| Job canceled | Pending units are canceled, and running leases are canceled on their agents. |

**No double counting.** A retried unit runs as a new scan. The partial scan
of an expired attempt is kept, marked `failed`, like a partial CLI scan. Job
totals (`observations`, `services`) count only the attempt that completed
each unit. The attempt history (`attempts` in the job detail) records which
agent ran what, when, and why each attempt ended.

**Clocks.** The controller records each agent's clock offset at `Hello` and
on every heartbeat. Lease expiry uses only the controller clock. Observation
timestamps are the agent's own; the offset is stored with each attempt.
Agents more than 5s off are reported with health `clock-skew`.

## Security model

- **Transport.** TLS 1.3 is required. `--fleet-insecure` (controller) and
  `--insecure` (agent) are refused unless the address is loopback.
- **Enrollment.** New agents present the enrollment token
  (`--fleet-enroll-token-file`, at least 16 characters). They receive a
  random per-agent secret, of which the controller stores only a SHA-256
  hash. Omit the token file to stop new enrollments; enrolled agents keep
  working.
- **Mutual TLS** (optional): `--fleet-client-ca` on the controller,
  `--tls-cert`/`--tls-key` on agents.
- **Revocation.** `POST /api/v1/fleet/agents/{id}/revoke` disables the
  credential and disconnects the agent. Its leases expire and are retried
  elsewhere.
- **Authorized vantage.** An agent requires `--allow-targets` and re-checks
  every lease against it. A compromised or misconfigured controller cannot
  make it scan anything else. The controller also checks every streamed record
  against the leased unit, so an agent cannot write observations about
  addresses it was not asked to scan.
- **Privilege.** Like `serve`, `nyxr agent` refuses to run with root or raw
  socket capabilities unless `--allow-privileged` is given. Prefer
  `--packetd` for raw SYN, ARP/NDP and capture.
- **API.** The fleet REST API requires an API token. `--fleet-listen` refuses
  to start without one.

## REST API

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/v1/fleet` | Protocol version and agent counts |
| GET | `/api/v1/fleet/agents` | Enrolled agents: capabilities, health, clock offset, active leases |
| POST | `/api/v1/fleet/agents/{id}/revoke` | Revoke an agent credential |
| GET | `/api/v1/fleet/scans` | Recent distributed scans with unit status counts |
| POST | `/api/v1/fleet/scans` | Submit `{"request": {...}, "unit_size", "max_parallel", "max_attempts"}` |
| GET | `/api/v1/fleet/scans/{id}` | Job, units (with `waiting` reasons and scan IDs) and attempt history |
| POST | `/api/v1/fleet/scans/{id}/cancel` | Cancel a running distributed scan |

Each unit's `scan_id` is an ordinary scan. Its observations, evidence and live
data are available through the normal `/api/v1/scans/{id}/…` endpoints.

## Agent capabilities

Agents advertise on every connection: raw socket, AF_XDP, IPv6, OT
permission, packet capture, ICMP, privilege level (`root`,
`raw-capabilities`, `packetd`, `unprivileged`), interfaces with their
attached prefixes, authorized targets, throughput budgets, maximum leases, OS,
architecture and version. `GET /api/v1/fleet/agents` shows the latest
advertisement.

## Limits

- Lease state on the agent is in memory. An agent restart loses its running
  leases, which are then retried.
- pcapng files stay on the agent's `--evidence-dir`. Packet evidence indexes
  are streamed, but the capture files are not sent over gRPC. A controller
  started with `--central` registers them as pending artifacts, and
  `nyxr central upload-dir` on the agent host uploads them to object storage.
  See [Central storage](central.md).
- Hostname targets are resolved on the controller, and units carry addresses.
  TLS SNI names from hostnames are not forwarded yet.
- Link-local IPv6 targets with a zone are not distributed with their zone.
- The fleet is controller-scheduled. There is no `nyxr scan --distributed`
  CLI client yet; submit through the REST API.

## Regenerating the protocol

The wire definition is `internal/fleet/fleetpb/fleet.proto`. Run `make proto`
(needs `buf`, `protoc-gen-go` and `protoc-gen-go-grpc` on `PATH`) and commit
the generated files.

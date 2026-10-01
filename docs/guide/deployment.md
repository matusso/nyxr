# Deployment

This guide covers running nyxr as a shared service: keeping raw packet
privileges out of the API process, exposing the server on a network, and
running in a container.

- [Privilege separation with nyxr-packetd](#privilege-separation-with-nyxr-packetd)
- [Exposing the server](#exposing-the-server)
- [Containers](#containers)

## Privilege separation with nyxr-packetd

`nyxr serve` refuses to start as root, or on Linux with `CAP_NET_RAW` or
`CAP_NET_ADMIN`, unless given `--allow-privileged`. Raw packet I/O goes through
`nyxr-packetd`, a separate small binary, so capabilities never reach the API,
UI, parsing or database code.

```text
 browser / curl ──HTTP──▶ nyxr serve ──Unix socket──▶ nyxr-packetd ──▶ eth0
                         (unprivileged:              (CAP_NET_RAW,
                          API, UI, scan logic,        CAP_NET_ADMIN:
                          parsing, storage)           Ethernet frames only)
```

```sh
sudo setcap cap_net_raw,cap_net_admin+ep ./nyxr-packetd
./nyxr-packetd --socket /run/nyxr/packetd.sock --interface eth0 &
nyxr serve --db nyxr.db --packetd /run/nyxr/packetd.sock --evidence-dir ./evidence
```

The CLI can use the same relay instead of running as root:

```sh
nyxr scan --packetd /run/nyxr/packetd.sock --tcp-mode syn --interface eth0 192.0.2.10
```

### What packetd allows

packetd relays Ethernet frames and nothing else:

| Control | Behavior |
| --- | --- |
| Socket | Unix socket, mode `0660` by default (`--socket-mode`); world access is refused |
| Interfaces | Only those listed in `--interface` |
| Transmit check | Frames shorter than an Ethernet header, or with a source MAC other than the interface's, are dropped |
| Frame size | At most 9216 bytes |
| Sessions | `--max-clients` (default 4) |
| Transmit rate | `--max-pps` frames per second per session (default unlimited) |

Raw SYN, ARP/NDP, API pcapng capture and the live packets page use packetd; the
API refuses them when started without `--packetd`.

### Limits

- ICMP echo still needs a raw IP socket in the scanning process, so the API
  refuses ICMP requests.
- The `research` profile is CLI-only.
- packetd has been exercised end to end on macOS, where it behaves like the
  local BPF backend. It has not yet been run on privileged Linux or Windows.

### Running packetd under systemd

A minimal unit grants the capabilities to packetd only:

```ini
[Unit]
Description=nyxr packet relay
After=network-online.target

[Service]
ExecStart=/usr/local/bin/nyxr-packetd --socket /run/nyxr/packetd.sock --interface eth0 --max-pps 1000
User=nyxr
Group=nyxr
RuntimeDirectory=nyxr
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

Run `nyxr serve` as a user in the `nyxr` group, without any capabilities.

## Exposing the server

The server listens on loopback by default. To expose it:

1. Create a token of at least 16 characters and store it in a file readable
   only by the service user.
2. Start the server with `--listen` and `--token-file`:

   ```sh
   openssl rand -hex 32 > /etc/nyxr/token && chmod 600 /etc/nyxr/token
   nyxr serve --listen 0.0.0.0:8484 --token-file /etc/nyxr/token
   ```

3. Put a TLS-terminating reverse proxy in front of it. The server speaks plain
   HTTP, and the token is a bearer credential.

See the [security model](web-ui-and-api.md#security-model) for what the server
enforces.

## Containers

The image is built `FROM scratch`. It contains `/nyxr` (the entrypoint),
`/nyxr-packetd` and a CA bundle, and nothing else.

```sh
docker run --rm ghcr.io/matusso/nyxr:latest scan --ports 80,443 example.com

# Linux, raw features on the host network
docker run --rm --network host --cap-add NET_RAW \
  ghcr.io/matusso/nyxr:latest scan --tcp-mode syn --interface eth0 192.0.2.10
```

The container runs as root unless told otherwise, and `nyxr serve` refuses to
run as root. Run the web UI as an ordinary user, with a host directory for the
database:

```sh
mkdir -p nyxr-data
docker run --rm -p 8484:8484 --user "$(id -u):$(id -g)" -v "$PWD/nyxr-data:/data" \
  -e NYXR_API_TOKEN="$(openssl rand -hex 16)" \
  ghcr.io/matusso/nyxr:latest serve --listen 0.0.0.0:8484 --db /data/nyxr.db
```

`--db` is required here because the image has no home directory for the
default `~/.nyxr/nyxr.db`.

Network behavior depends on Docker networking. Bridge networking hides the host
network from the scanner; use `--network host` on Linux when scans need direct
access to it.

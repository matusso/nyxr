# Getting started

This guide installs nyxr, runs a first scan, and points to the guides for each
feature.

- [Requirements](#requirements)
- [Install](#install)
- [First scan](#first-scan)
- [Open the web UI](#open-the-web-ui)
- [Shell completion](#shell-completion)
- [Privileges at a glance](#privileges-at-a-glance)
- [Next steps](#next-steps)

## Requirements

| Component | Requirement |
| --- | --- |
| Operating system | Linux, macOS or Windows on `amd64` or `arm64` |
| Building from source | Go 1.27.1 or newer; no cgo toolchain needed |
| Raw packet features (optional) | Linux: root or `CAP_NET_RAW`. macOS: access to `/dev/bpf*`. Windows: [Npcap](https://npcap.com/) |

The default TCP connect scan, UDP socket scan, service identification, storage,
API and web UI all work without elevated privileges.

## Install

### Release archive

Each [GitHub release](https://github.com/matusso/nyxr/releases) contains
`.tar.gz` (Linux, macOS) and `.zip` (Windows) archives for `amd64` and `arm64`,
plus a `SHA256SUMS` file. Each archive holds the `nyxr` and `nyxr-packetd`
binaries, the README and the license. Replace `v0.6.0` below with the
release you downloaded.

```sh
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf nyxr-v0.6.0-linux-amd64.tar.gz
sudo install -m 0755 nyxr-v0.6.0-linux-amd64/nyxr nyxr-v0.6.0-linux-amd64/nyxr-packetd /usr/local/bin/
nyxr version
```

### Container image

Linux `amd64` and `arm64` images are published to the GitHub Container
Registry. Stable releases also update the `latest` tag.

```sh
docker run --rm ghcr.io/matusso/nyxr:latest version
docker run --rm ghcr.io/matusso/nyxr:latest scan --ports 80,443 example.com
```

Results depend on Docker networking. On Linux, add `--network host` when a
scan needs direct access to the host network, and `--cap-add NET_RAW` for ICMP,
raw SYN and packet capture.

### From source

```sh
git clone https://github.com/matusso/nyxr.git
cd nyxr
make build              # ./nyxr and ./nyxr-packetd for this platform
sudo make install       # copies both into /usr/local/bin (PREFIX and DESTDIR are honored)
```

See [Building and releasing](development/building-and-releasing.md) for
cross-builds, packaging and container builds.

## First scan

Scan a host you are authorized to test. The default `discovery` profile is an
unprivileged TCP connect scan of common ports:

```sh
nyxr scan 192.0.2.10
```

Preview what a scan would do without sending a packet:

```sh
nyxr scan --profile service --dry-run 192.0.2.0/28
```

Identify the services behind open ports:

```sh
nyxr scan --profile service 192.0.2.10
```

```text
192.0.2.10:22    tcp   open           100% TCP connection established
192.0.2.10:80    tcp   open           100% TCP connection established
192.0.2.10:443   tcp   open           100% TCP connection established
192.0.2.10:22    tcp   svc ssh        100% OpenSSH 9.6p1 | SSH identification string
192.0.2.10:80    tcp   svc http       100% nginx 1.27.2 | title "Intranet" | HTTP/1.x response to GET /; product from Server header
192.0.2.10:443   tcp   svc https      100% nginx 1.27.2 | TLS 1.3 cert intranet.example | title "Intranet" | ...
scan 20261001T195109Z-c3b4a07e3884 completed: 6 observations, 3 services identified
```

Every scan is stored in `~/.nyxr/nyxr.db`. Review what you have found so far:

```sh
nyxr history                 # scans, newest first
nyxr history --assets --open # current open ports and services per host
```

Add `--json` to any scan for newline-delimited JSON records, or `--open` to
hide closed and filtered results.

## Open the web UI

```sh
nyxr serve
```

Open <http://127.0.0.1:8484>. The UI reads the same database as the CLI, so
scans started from either side appear in both. See
[Web UI and REST API](guide/web-ui-and-api.md).

## Shell completion

`nyxr completion <shell>` prints a completion script for subcommands, flags,
profile names, port sets, protocols and network interfaces.

```sh
source <(nyxr completion bash)                                  # bash, current shell
nyxr completion bash > ~/.local/share/bash-completion/completions/nyxr
nyxr completion zsh > "${fpath[1]}/_nyxr"                      # zsh, then restart the shell
nyxr completion fish > ~/.config/fish/completions/nyxr.fish     # fish
nyxr completion powershell | Out-String | Invoke-Expression     # PowerShell; add to $PROFILE
```

## Privileges at a glance

| Feature | Privilege needed |
| --- | --- |
| TCP connect, UDP, service identification, storage, `decode`, `serve` | None |
| ICMP echo (`--protocols icmp`) | Raw IP socket (root, `CAP_NET_RAW`, or Administrator) |
| Raw TCP SYN, ARP, NDP, `sniff`, `--pcapng` capture, `research` profile | Raw Ethernet access on the interface |
| Exact ICMP correlation for UDP results | Raw ICMP socket (falls back to socket errors without it) |

When a privilege is missing, nyxr reports it in the result instead of silently
switching to a different scan method. To keep the API and web UI unprivileged
while still using raw features, run them through
[`nyxr-packetd`](guide/deployment.md#privilege-separation-with-nyxr-packetd).

## Next steps

- [Scanning](guide/scanning.md): targets, ports, output, rate limits and configuration files.
- [Scan profiles](guide/profiles.md): choose the right profile for the job.
- [Service identification](guide/service-identification.md): what each probe does and how evidence is kept.
- [CLI reference](reference/cli.md): every command and flag.

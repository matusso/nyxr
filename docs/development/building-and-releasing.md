# Building and releasing

## Build from source

Go 1.27.1 or newer is required. nyxr builds with `CGO_ENABLED=0`, so no C
toolchain or libpcap headers are needed, and every target can be cross-built
from any host.

| Target | Effect |
| --- | --- |
| `make build` | Build `./nyxr` and `./nyxr-packetd` for the host platform |
| `make install` | Copy both into `$(PREFIX)/bin` (default `/usr/local/bin`); `DESTDIR` is honored |
| `make uninstall` | Remove the installed binaries |
| `make check` | `go test ./...` and `go vet ./...` |
| `make fuzz` | Short fuzz campaigns for the decoder, pcap reader, probe definitions, service parsers and Nmap database parser |
| `make benchmark` | Fixed-workload measurements and CPU profile; see [Performance](performance.md) |
| `make cross` | Binaries for every supported platform into `dist/` |
| `make linux-packages` | `.deb` and `.rpm` packages for Linux `amd64`/`arm64` in `dist/` |
| `make package` | Release archives, Linux packages and `SHA256SUMS` in `dist/` |
| `make clean` | Remove build output |
| `make help` | List all targets |

`VERSION` defaults to `git describe --tags --always --dirty` and is embedded in
both binaries. Override it with `make package VERSION=v0.1.0`.

## Supported platforms

| OS | Architectures | Archive |
| --- | --- | --- |
| Linux | `amd64`, `arm64` | `nyxr-<version>-linux-<arch>.tar.gz` |
| macOS | `amd64`, `arm64` | `nyxr-<version>-darwin-<arch>.tar.gz` |
| Windows | `amd64`, `arm64` | `nyxr-<version>-windows-<arch>.zip` |

Each archive contains `nyxr`, `nyxr-packetd`, `README.md` and `LICENSE` in a
directory named after the archive.

## Linux packages

`make linux-packages` builds `nyxr_<version>-1_<arch>.deb` and
`nyxr-<version>-1.<arch>.rpm` with [nFPM](https://nfpm.goreleaser.com/), run
through `go run` so nothing else needs installing. The config is
`packaging/nfpm.yaml`; the systemd unit, `/etc/nyxr/packetd.env`, sysusers
entry and maintainer scripts live in `packaging/linux/`.

Packages need a semantic version: the leading `v` is dropped, and an untagged
`VERSION` becomes `0.0.0-dev`. A pre-release tag such as `v0.7.0-rc1` becomes
`0.7.0~rc1`, which sorts before `0.7.0` in both dpkg and rpm.

The postinstall script creates the `nyxr` system user and group and reloads
systemd, but does not enable `nyxr-packetd.service` or set file capabilities.
Removal stops and disables the unit and keeps the account.

A successful cross-build proves that a binary compiles, not that live packet
capture or raw sockets work on that platform. Runtime validation is tracked in
[Runtime gates](runtime-gates.md).

## Container image

```sh
docker build -t nyxr:local .
docker run --rm nyxr:local version
docker run --rm nyxr:local scan --ports 80,443 example.com
```

The multi-stage `Dockerfile` builds both binaries in `golang:1.27.1-alpine`
and copies them, with a CA bundle, into a `scratch` image whose entrypoint is
`/nyxr`. Runtime options are covered in
[Deployment](../guide/deployment.md#containers).

## Continuous integration

Every push and pull request runs the `build` workflow:

1. `make check`
2. `make fuzz`
3. `make package`
4. Install, run and remove the `amd64` `.deb` in Debian and `.rpm` in Fedora
5. Build the Docker image and smoke-test `nyxr version` inside it
6. Upload the archives and packages as a workflow artifact

## Releases

Pushing a semantic version tag runs the `release` workflow:

```sh
git tag v0.7.0
git push origin v0.7.0
```

The workflow:

1. Validates the tag (`vMAJOR.MINOR.PATCH`, with an optional `-suffix`).
2. Runs `make check` and `make package VERSION=<tag>`.
3. Creates a GitHub release with the `.tar.gz` and `.zip` archives, the
   `.deb` and `.rpm` packages and `SHA256SUMS`.
4. Pushes a Linux `amd64`/`arm64` image to `ghcr.io/matusso/nyxr:<tag>`.

Stable releases also update `:latest`. Tags containing `-`, such as
`v0.7.0-rc1`, are marked as pre-releases and do not update `:latest`. The
workflow can also be started manually for an existing tag.

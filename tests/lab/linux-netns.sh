#!/usr/bin/env bash
# Privileged AF_PACKET classification and NIC-counter gate, isolated in two namespaces.
set -euo pipefail
for tool in ip python3 go; do command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 2; }; done
if [[ $(id -u) -ne 0 ]]; then echo "run as root (CAP_NET_ADMIN and CAP_NET_RAW are required)" >&2; exit 2; fi
cd "$(dirname "$0")/../.."
out=${1:-tests/performance/latest-linux}
mkdir -p "$out"
out=$(cd "$out" && pwd)
{
  date -u '+UTC %Y-%m-%dT%H:%M:%SZ'
  go version
  go env GOOS GOARCH GOMAXPROCS CGO_ENABLED
  uname -a
  sed -n '/model name/{p;q;}' /proc/cpuinfo
  ip -Version
} >"$out/environment.txt"
printf 'sudo bash tests/lab/linux-netns.sh %q\n' "$out" >"$out/command.txt"
tmp=$(mktemp -d)
src="nyxr-src-$$"
dst="nyxr-dst-$$"
cleanup() {
  [[ -n ${server_pid:-} ]] && kill "$server_pid" 2>/dev/null || true
  [[ -n ${udp_pid:-} ]] && kill "$udp_pid" 2>/dev/null || true
  if [[ -n ${xdp_pin_dir:-} ]]; then
    ip -n "$src" link set dev nxsrc xdp off 2>/dev/null || true
    rm -f "$xdp_pin_dir/program" "$xdp_pin_dir/xsks" "$xdp_pin_dir/filter" 2>/dev/null || true
    rmdir "$xdp_pin_dir" 2>/dev/null || true
  fi
  ip netns del "$src" 2>/dev/null || true
  ip netns del "$dst" 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT
CGO_ENABLED=0 go build -o "$tmp/nyxr" ./cmd/nyxr
ip netns add "$src"
ip netns add "$dst"
ip link add nxsrc type veth peer name nxdst
ip link set nxsrc netns "$src"
ip link set nxdst netns "$dst"
ip -n "$src" link set lo up
ip -n "$dst" link set lo up
ip -n "$src" link set nxsrc address 02:00:00:00:00:01
ip -n "$dst" link set nxdst address 02:00:00:00:00:02
ip -n "$src" addr add 10.77.0.1/24 dev nxsrc
ip -n "$dst" addr add 10.77.0.2/24 dev nxdst
# Skip duplicate address detection so ULA and link-local addresses are usable
# as soon as the links are up.
ip netns exec "$src" sysctl -qw net.ipv6.conf.nxsrc.accept_dad=0
ip netns exec "$dst" sysctl -qw net.ipv6.conf.nxdst.accept_dad=0
ip -n "$src" -6 addr add fd77::1/64 dev nxsrc nodad
ip -n "$dst" -6 addr add fd77::2/64 dev nxdst nodad
ip -n "$src" link set nxsrc up
ip -n "$dst" link set nxdst up
ip netns exec "$dst" python3 -u -c 'import socket
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.bind(("10.77.0.2",8080)); s.listen(128)
while True:
 conn,peer=s.accept(); conn.close()' >"$tmp/server.log" 2>&1 &
server_pid=$!
# One IPv6 listener serves both fd77::2 and the EUI-64 link-local address.
ip netns exec "$dst" python3 -u -c 'import socket
s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM); s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1); s.bind(("::",8080)); s.listen(128)
while True:
 conn,peer=s.accept(); conn.close()' >"$tmp/server6.log" 2>&1 &
server6_pid=$!
ip netns exec "$dst" python3 -u -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("10.77.0.2",53001));
while True:
 data,peer=s.recvfrom(4096); s.sendto(data,peer)' >"$tmp/udp.log" 2>&1 &
udp_pid=$!
ready=0
for _ in {1..50}; do
  if ip netns exec "$dst" python3 -c 'import socket; s=socket.create_connection(("10.77.0.2",8080),.05); s.close()' 2>/dev/null; then ready=1; break; fi
  sleep .02
done
if [[ $ready != 1 ]] || ! kill -0 "$server_pid" 2>/dev/null; then cat "$tmp/server.log" >&2; exit 1; fi
if ! kill -0 "$server6_pid" 2>/dev/null; then cat "$tmp/server6.log" >&2; exit 1; fi
if ! kill -0 "$udp_pid" 2>/dev/null; then cat "$tmp/udp.log" >&2; exit 1; fi
ports=8080,8081
if command -v iptables >/dev/null; then
  ip netns exec "$dst" iptables -A INPUT -p tcp --dport 8082 -j DROP
  ports+=,8082
else
  echo "iptables unavailable: filtered-port gate skipped" >&2
fi
ports6=8080,8081
if command -v ip6tables >/dev/null && ip netns exec "$dst" ip6tables -A INPUT -p tcp --dport 8082 -j DROP 2>/dev/null; then
  ports6+=,8082
else
  echo "ip6tables unavailable: IPv6 filtered-port gate skipped" >&2
fi
udp_ports=53001,53002
if command -v iptables >/dev/null; then
  ip netns exec "$dst" iptables -A INPUT -p udp --dport 53003 -j DROP
  udp_ports+=,53003
fi
ip netns exec "$src" "$tmp/nyxr" scan --no-db --no-last-pcapng --profile custom --protocols udp --ports "$udp_ports" --send-hex 010203 --workers 1 --timeout 300ms --json 10.77.0.2 >"$tmp/udp-results.jsonl"
python3 - "$tmp/udp-results.jsonl" "$udp_ports" <<'PY'
import json, sys
rows = [r for r in map(json.loads, open(sys.argv[1])) if r.get('kind') != 'scan']
got = {int(row['port']): row['state'] for row in rows}
expected = {53001: 'open', 53002: 'closed'}
if '53003' in sys.argv[2]: expected[53003] = 'open|filtered'
assert got == expected, (got, expected, rows)
assert all('raw ICMP unavailable' not in row['reason'] for row in rows), rows
print('UDP classification:', got)
PY
ip netns exec "$src" "$tmp/nyxr" scan --no-db --no-last-pcapng --tcp-mode syn --interface nxsrc --protocols tcp --ports "$ports" --workers 1 --timeout 250ms --json 10.77.0.2 >"$tmp/results.jsonl"
python3 - "$tmp/results.jsonl" "$ports" <<'PY'
import json, sys
rows = [r for r in map(json.loads, open(sys.argv[1])) if r.get('kind') != 'scan']
got = {int(row['port']): row['state'] for row in rows}
expected = {8080: 'open', 8081: 'closed'}
if '8082' in sys.argv[2]: expected[8082] = 'filtered'
assert got == expected, (got, expected, rows)
assert all(row['packets_tx'] == 1 for row in rows), rows
print('AF_PACKET classification:', got)
PY
ip netns exec "$src" "$tmp/nyxr" scan --no-db --no-last-pcapng --profile custom --protocols arp --interface nxsrc --timeout 300ms --json 10.77.0.2 >"$tmp/arp.jsonl"
if [[ ${NYXR_LAB_SKIP_NDP:-0} != 1 ]]; then
  ip netns exec "$src" "$tmp/nyxr" scan --no-db --no-last-pcapng --profile custom --protocols ndp --interface nxsrc --timeout 300ms --json fd77::2 >"$tmp/ndp.jsonl"
fi
python3 - "$tmp/arp.jsonl" "$tmp/ndp.jsonl" "${NYXR_LAB_SKIP_NDP:-0}" <<'PY'
import json, sys
paths = sys.argv[1:2] if sys.argv[3] == '1' else sys.argv[1:3]
for path, proto in zip(paths, ('arp', 'ndp')):
    rows = [r for r in map(json.loads, open(path)) if r.get('kind') != 'scan']
    assert len(rows) == 1 and rows[0]['transport'] == proto and rows[0]['state'] == 'responsive' and rows[0]['mac'] == '02:00:00:00:00:02', rows
    print(proto.upper(), 'discovery:', rows[0]['mac'])
PY
# IPv6 raw SYN: no --next-hop-mac, so the ULA target resolves through the
# route table and NDP, and the zoned link-local target stays scoped.
if [[ ${NYXR_LAB_SKIP_NDP:-0} != 1 ]]; then
  ip netns exec "$src" "$tmp/nyxr" scan --no-db --no-last-pcapng --tcp-mode syn --interface nxsrc --protocols tcp --ports "$ports6" --workers 1 --timeout 250ms --fingerprint --json fd77::2 fe80::ff:fe00:2%nxsrc >"$tmp/syn6.jsonl"
  python3 - "$tmp/syn6.jsonl" "$ports6" <<'PY'
import json, sys
rows = [r for r in map(json.loads, open(sys.argv[1])) if r.get('kind') != 'scan']
ports = [r for r in rows if r.get('kind') == 'port']
for target in ('fd77::2', 'fe80::ff:fe00:2%nxsrc'):
    got = {int(r['port']): r['state'] for r in ports if r['target'] == target}
    expected = {8080: 'open', 8081: 'closed'}
    if '8082' in sys.argv[2]: expected[8082] = 'filtered'
    assert got == expected, (target, got, expected, rows)
    for r in ports:
        if r['target'] != target or r['state'] not in ('open', 'closed'):
            continue
        assert r['packets_tx'] == 1, r
        stack = r['tcp_stack']
        assert stack['probe_profile'] == 'nyxr-syn6-v1' and stack['signature'].startswith('nx_tcp6_v1_'), stack
        assert stack['ip_id_behavior'] == 'not-applicable', stack
        assert all(s['ip_version'] == 6 and 'df' not in s and 'ip_id' not in s for s in stack['samples']), stack
    print('IPv6 SYN classification', target + ':', got)
PY
fi
ip -n "$src" -j -s link show nxsrc >"$out/nic-before.json"
start_ns=$(python3 -c 'import time; print(time.monotonic_ns())')
ip netns exec "$src" "$tmp/nyxr" scan --no-db --no-last-pcapng --tcp-mode syn --interface nxsrc --next-hop-mac 02:00:00:00:00:02 --protocols tcp --ports 21000-21099 --workers 4 --timeout 100ms --json 10.77.0.2 >"$tmp/load.jsonl"
end_ns=$(python3 -c 'import time; print(time.monotonic_ns())')
ip -n "$src" -j -s link show nxsrc >"$out/nic-after.json"
cp "$tmp/load.jsonl" "$out/load.jsonl"
python3 - "$out/load.jsonl" "$out/nic-before.json" "$out/nic-after.json" "$start_ns" "$end_ns" <<'PY' | tee "$out/summary.txt"
import json, sys
rows = [r for r in map(json.loads, open(sys.argv[1])) if r.get('kind') != 'scan']
assert len(rows) == 100 and all(row['state'] == 'closed' and row['packets_tx'] == 1 for row in rows), rows
before, after = [json.load(open(path))[0] for path in sys.argv[2:4]]
def counts(x, direction):
    stats = x.get('stats64', x.get('stats'))
    return stats[direction]['packets'], stats[direction]['dropped']
rx0, rxd0 = counts(before, 'rx'); tx0, txd0 = counts(before, 'tx')
rx1, rxd1 = counts(after, 'rx'); tx1, txd1 = counts(after, 'tx')
seconds = (int(sys.argv[5]) - int(sys.argv[4])) / 1e9
print(f'Fixed workload: 100 closed-port SYN probes, 4 workers, 100 ms timeout, one packet per probe')
print(f'Elapsed: {seconds:.3f}s; throughput: {100/seconds:.0f} probes/s; observed reply loss: 0/100 (0%)')
print(f'veth nxsrc counters: TX {tx1-tx0}, RX {rx1-rx0}, TX drops {txd1-txd0}, RX drops {rxd1-rxd0}')
PY
echo "Saved Linux lab environment, workload, results, and veth counters in $out"

if [[ ${NYXR_LAB_XDP:-0} == 1 ]]; then
  for tool in clang bpftool gcc; do command -v "$tool" >/dev/null || { echo "missing $tool for AF_XDP gate" >&2; exit 2; }; done
  xdp_pin_dir="${NYXR_LAB_BPFFS:-/sys/fs/bpf}/nyxr-lab-$$"
  ip netns exec "$src" bash tools/xdp/setup.sh nxsrc "$xdp_pin_dir"
  ip netns exec "$src" bpftool map show pinned "$xdp_pin_dir/xsks" >"$out/xdp-map.txt"
  ip netns exec "$src" "$tmp/nyxr" scan --no-db --no-last-pcapng --tcp-mode syn --interface nxsrc --xdp-pin-dir "$xdp_pin_dir" --protocols tcp --ports "$ports" --workers 1 --timeout 250ms --json 10.77.0.2 >"$out/xdp-results.jsonl"
  python3 - "$out/xdp-results.jsonl" "$ports" <<'PY'
import json, sys
rows = [r for r in map(json.loads, open(sys.argv[1])) if r.get('kind') != 'scan']
got = {int(row['port']): row['state'] for row in rows}
expected = {8080: 'open', 8081: 'closed'}
if '8082' in sys.argv[2]: expected[8082] = 'filtered'
assert got == expected, (got, expected, rows)
assert all(row['packets_tx'] == 1 for row in rows), rows
print('AF_XDP classification:', got)
PY
  ip -n "$src" -j -s link show nxsrc >"$out/xdp-nic-before.json"
  start_ns=$(python3 -c 'import time; print(time.monotonic_ns())')
  ip netns exec "$src" "$tmp/nyxr" scan --no-db --no-last-pcapng --tcp-mode syn --interface nxsrc --xdp-pin-dir "$xdp_pin_dir" --next-hop-mac 02:00:00:00:00:02 --protocols tcp --ports 21000-21099 --workers 4 --timeout 100ms --json 10.77.0.2 >"$out/xdp-load.jsonl"
  end_ns=$(python3 -c 'import time; print(time.monotonic_ns())')
  ip -n "$src" -j -s link show nxsrc >"$out/xdp-nic-after.json"
  python3 - "$out/xdp-load.jsonl" "$out/xdp-nic-before.json" "$out/xdp-nic-after.json" "$start_ns" "$end_ns" <<'PY' | tee "$out/xdp-summary.txt"
import json, sys
rows = [r for r in map(json.loads, open(sys.argv[1])) if r.get('kind') != 'scan']
assert len(rows) == 100 and all(row['state'] == 'closed' and row['packets_tx'] == 1 for row in rows), rows
before, after = [json.load(open(path))[0] for path in sys.argv[2:4]]
def counts(x, direction):
    stats = x.get('stats64', x.get('stats'))
    return stats[direction]['packets'], stats[direction]['dropped']
rx0, rxd0 = counts(before, 'rx'); tx0, txd0 = counts(before, 'tx')
rx1, rxd1 = counts(after, 'rx'); tx1, txd1 = counts(after, 'tx')
seconds = (int(sys.argv[5]) - int(sys.argv[4])) / 1e9
print(f'AF_XDP fixed workload: 100 closed-port SYN probes, 4 workers, 100 ms timeout')
print(f'Elapsed: {seconds:.3f}s; throughput: {100/seconds:.0f} probes/s; observed reply loss: 0/100 (0%)')
print(f'veth nxsrc counters: TX {tx1-tx0}, RX {rx1-rx0}, TX drops {txd1-txd0}, RX drops {rxd1-rxd0}')
PY
fi

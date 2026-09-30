#!/usr/bin/env bash
# Privileged AF_PACKET classification and NIC-counter gate, isolated in two namespaces.
set -euo pipefail
for tool in ip python3 go; do command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 2; }; done
if [[ $(id -u) -ne 0 ]]; then echo "run as root (CAP_NET_ADMIN and CAP_NET_RAW are required)" >&2; exit 2; fi
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
src="nyxr-src-$$"
dst="nyxr-dst-$$"
cleanup() {
  [[ -n ${server_pid:-} ]] && kill "$server_pid" 2>/dev/null || true
  [[ -n ${udp_pid:-} ]] && kill "$udp_pid" 2>/dev/null || true
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
ip -n "$src" -6 addr add fd77::1/64 dev nxsrc
ip -n "$dst" -6 addr add fd77::2/64 dev nxdst
ip -n "$src" link set nxsrc up
ip -n "$dst" link set nxdst up
ip netns exec "$dst" python3 -m http.server 8080 --bind 10.77.0.2 >"$tmp/server.log" 2>&1 &
server_pid=$!
ip netns exec "$dst" python3 -u -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("10.77.0.2",53001));
while True:
 data,peer=s.recvfrom(4096); s.sendto(data,peer)' >"$tmp/udp.log" 2>&1 &
udp_pid=$!
for _ in {1..50}; do
  if ip netns exec "$dst" python3 -c 'import socket; s=socket.create_connection(("10.77.0.2",8080),.05); s.close()' 2>/dev/null; then break; fi
  sleep .02
done
if ! kill -0 "$server_pid" 2>/dev/null; then cat "$tmp/server.log" >&2; exit 1; fi
if ! kill -0 "$udp_pid" 2>/dev/null; then cat "$tmp/udp.log" >&2; exit 1; fi
ports=8080,8081
if command -v iptables >/dev/null; then
  ip netns exec "$dst" iptables -A INPUT -p tcp --dport 8082 -j DROP
  ports+=,8082
else
  echo "iptables unavailable: filtered-port gate skipped" >&2
fi
udp_ports=53001,53002
if command -v iptables >/dev/null; then
  ip netns exec "$dst" iptables -A INPUT -p udp --dport 53003 -j DROP
  udp_ports+=,53003
fi
ip netns exec "$src" "$tmp/nyxr" scan --profile custom --protocols udp --ports "$udp_ports" --send-hex 010203 --workers 1 --timeout 300ms --json 10.77.0.2 >"$tmp/udp-results.jsonl"
python3 - "$tmp/udp-results.jsonl" "$udp_ports" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1])]
got = {int(row['port']): row['state'] for row in rows}
expected = {53001: 'open', 53002: 'closed'}
if '53003' in sys.argv[2]: expected[53003] = 'open|filtered'
assert got == expected, (got, expected, rows)
assert all('raw ICMP unavailable' not in row['reason'] for row in rows), rows
print('UDP classification:', got)
PY
ip -n "$src" -j -s link show nxsrc >"$tmp/nic-before.json"
ip netns exec "$src" "$tmp/nyxr" scan --tcp-mode syn --interface nxsrc --protocols tcp --ports "$ports" --workers 1 --timeout 250ms --json 10.77.0.2 >"$tmp/results.jsonl"
python3 - "$tmp/results.jsonl" "$ports" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1])]
got = {int(row['port']): row['state'] for row in rows}
expected = {8080: 'open', 8081: 'closed'}
if '8082' in sys.argv[2]: expected[8082] = 'filtered'
assert got == expected, (got, expected, rows)
assert all(row['packets_tx'] == 1 for row in rows), rows
print('AF_PACKET classification:', got)
PY
ip netns exec "$src" "$tmp/nyxr" scan --profile custom --protocols arp --interface nxsrc --timeout 300ms --json 10.77.0.2 >"$tmp/arp.jsonl"
ip netns exec "$src" "$tmp/nyxr" scan --profile custom --protocols ndp --interface nxsrc --timeout 300ms --json fd77::2 >"$tmp/ndp.jsonl"
python3 - "$tmp/arp.jsonl" "$tmp/ndp.jsonl" <<'PY'
import json, sys
for path, proto in zip(sys.argv[1:], ('arp', 'ndp')):
    rows = [json.loads(line) for line in open(path)]
    assert len(rows) == 1 and rows[0]['transport'] == proto and rows[0]['state'] == 'responsive' and rows[0]['mac'] == '02:00:00:00:00:02', rows
    print(proto.upper(), 'discovery:', rows[0]['mac'])
PY
start_ns=$(date +%s%N)
ip netns exec "$src" "$tmp/nyxr" scan --tcp-mode syn --interface nxsrc --next-hop-mac 02:00:00:00:00:02 --protocols tcp --ports 21000-21099 --workers 4 --timeout 100ms --json 10.77.0.2 >"$tmp/load.jsonl"
end_ns=$(date +%s%N)
ip -n "$src" -j -s link show nxsrc >"$tmp/nic-after.json"
python3 - "$tmp/load.jsonl" "$tmp/nic-before.json" "$tmp/nic-after.json" "$start_ns" "$end_ns" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1])]
assert len(rows) == 100 and all(row['state'] == 'closed' for row in rows), rows
before, after = [json.load(open(path))[0] for path in sys.argv[2:4]]
def counts(x, direction):
    stats = x.get('stats64', x.get('stats'))
    return stats[direction]['packets'], stats[direction]['dropped']
rx0, rxd0 = counts(before, 'rx'); tx0, txd0 = counts(before, 'tx')
rx1, rxd1 = counts(after, 'rx'); tx1, txd1 = counts(after, 'tx')
seconds = (int(sys.argv[5]) - int(sys.argv[4])) / 1e9
print(f'Fixed workload: 3 classification probes plus 100 closed-port probes; 100-probe scan in {seconds:.3f}s ({100/seconds:.0f} probes/s)')
print(f'NIC counters delta: TX {tx1-tx0}, RX {rx1-rx0}, TX drops {txd1-txd0}, RX drops {rxd1-rxd0}')
PY

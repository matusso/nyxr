// simulate turns stored or streamed observations into the packet exchanges a
// scan puts on the wire, so the map and the packet explainer can show what
// happened under the hood. These frames are reconstructions: the
// observation records the target, port, verdict, timing and any retained
// application bytes, but not the scanner's MAC, source port or sequence
// numbers. Those header values are illustrative and listed in each frame's
// `eg` ranges so the explainer badges them "E.G.". Captured frames (packet
// watch, evidence pcapng) never pass through this file.

import { b64bytes } from "./core.js";

const EG_MAC_SCANNER = [0x02, 0x00, 0x5e, 0x00, 0x53, 0x0a];
const EG_MAC_TARGET = [0x02, 0x00, 0x5e, 0x00, 0x53, 0x01];
const BROADCAST = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
export const EG_SCANNER_V4 = "192.0.2.10";
export const EG_SCANNER_V6 = "2001:db8::a";

function hash(s) {
  let x = 2166136261;
  for (const c of String(s)) x = Math.imul(x ^ c.charCodeAt(0), 16777619) >>> 0;
  return x;
}

function ip4bytes(a) { return a.split(".").map(Number); }
function ip6bytes(a) {
  const [head, tail] = a.includes("::") ? a.split("::") : [a, ""];
  const hp = head ? head.split(":") : [], tp = tail ? tail.split(":") : [];
  const groups = [...hp, ...Array(8 - hp.length - tp.length).fill("0"), ...tp];
  return groups.flatMap(g => { const n = parseInt(g || "0", 16); return [n >> 8, n & 255]; });
}
function macBytes(m) { return m ? m.split(/[:-]/).map(x => parseInt(x, 16)) : null; }

function sum16(bytes, start = 0) {
  let s = start;
  for (let i = 0; i < bytes.length; i += 2) s += (bytes[i] << 8) | (bytes[i + 1] || 0);
  while (s >> 16) s = (s & 0xffff) + (s >> 16);
  return s;
}
const csum = (bytes, start) => (~sum16(bytes, start)) & 0xffff;
const be16 = n => [(n >> 8) & 255, n & 255];
const be32 = n => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];

// frame builds Ethernet + IP + transport bytes. `eg` collects the byte
// ranges whose values are illustrative.
// egIP names which address ("src" or "dst") is the scanner's illustrative one.
function frame({ v6, srcIP, dstIP, srcMAC, dstMAC, proto, l4, ttl = 64, egIP, egSrcMAC, egDstMAC }) {
  const eg = [];
  const eth = [...dstMAC, ...srcMAC, ...(v6 ? [0x86, 0xdd] : [0x08, 0x00])];
  if (egDstMAC) eg.push([0, 6]);
  if (egSrcMAC) eg.push([6, 6]);
  const src = v6 ? ip6bytes(srcIP) : ip4bytes(srcIP), dst = v6 ? ip6bytes(dstIP) : ip4bytes(dstIP);
  let ip;
  const l4bytes = l4.bytes;
  if (!v6) {
    ip = [0x45, 0, ...be16(20 + l4bytes.length), ...be16(l4.id & 0xffff), 0x40, 0, ttl, proto, 0, 0, ...src, ...dst];
    const c = csum(ip);
    ip[10] = c >> 8; ip[11] = c & 255;
    eg.push([14 + 4, 2], [14 + 8, 1], [14 + 10, 2]);
    if (egIP === "src") eg.push([14 + 12, 4]);
    if (egIP === "dst") eg.push([14 + 16, 4]);
  } else {
    ip = [0x60, 0, 0, 0, ...be16(l4bytes.length), proto, ttl, ...src, ...dst];
    eg.push([14 + 7, 1]);
    if (egIP === "src") eg.push([14 + 8, 16]);
    if (egIP === "dst") eg.push([14 + 24, 16]);
  }
  // Transport checksum over the pseudo-header.
  if (l4.ck !== undefined) {
    const pseudo = v6 ? [...src, ...dst, ...be32(l4bytes.length), 0, 0, 0, proto] : [...src, ...dst, 0, proto, ...be16(l4bytes.length)];
    l4bytes[l4.ck] = 0; l4bytes[l4.ck + 1] = 0;
    const c = csum(l4bytes, sum16(pseudo));
    l4bytes[l4.ck] = c >> 8; l4bytes[l4.ck + 1] = c & 255;
  }
  const at = 14 + ip.length;
  for (const [o, n] of l4.eg || []) eg.push([at + o, n]);
  return { bytes: Uint8Array.from([...eth, ...ip, ...l4bytes]), eg };
}

function tcp(sp, dp, seq, ack, flags, payload = [], syn = false) {
  const opts = syn ? [2, 4, 0x05, 0xb4, 4, 2, 1, 3, 3, 7] : [];
  while (opts.length % 4) opts.push(0);
  const hl = 20 + opts.length;
  const b = [...be16(sp), ...be16(dp), ...be32(seq), ...be32(ack), (hl / 4) << 4, flags, ...be16(syn ? 64240 : 502), 0, 0, 0, 0, ...opts, ...payload];
  // Ephemeral port, sequence/ack numbers, window, options and checksum are examples.
  return { bytes: b, ck: 16, id: seq, eg: [[4, 8], [14, 2], [16, 2], ...(opts.length ? [[20, opts.length]] : [])] };
}
function udp(sp, dp, payload = []) {
  return { bytes: [...be16(sp), ...be16(dp), ...be16(8 + payload.length), 0, 0, ...payload], ck: 6, id: sp, eg: [[6, 2]] };
}
function icmp(v6, type, code, rest = []) {
  const b = [type, code, 0, 0, ...rest];
  if (!v6) { const c = csum(b); b[2] = c >> 8; b[3] = c & 255; }
  return { bytes: b, ck: v6 ? 2 : undefined, id: type * 256 + code, eg: [[2, 2]] };
}

const F = { FIN: 1, SYN: 2, RST: 4, PSH: 8, ACK: 16 };

// exchange returns the packets one observation implies. Each packet has a
// direction relative to the agent: "out" (agent → target) or "in".
export function exchange(o, agent) {
  const target = String(o.target || "");
  if (!target) return [];
  const v6 = target.includes(":");
  const loop = target === "127.0.0.1" || target === "::1";
  const scanIP = loop ? target : agent?.address && agent.address.includes(":") === v6 ? agent.address : v6 ? EG_SCANNER_V6 : EG_SCANNER_V4;
  const egScanner = !(loop || agent?.address);
  const tmac = macBytes(o.mac) || EG_MAC_TARGET;
  const base = { v6, srcMAC: EG_MAC_SCANNER, dstMAC: tmac, egSrcMAC: true, egDstMAC: !o.mac };
  const back = { v6, srcMAC: tmac, dstMAC: EG_MAC_SCANNER, egSrcMAC: !o.mac, egDstMAC: true };
  const seed = hash(o.observation_id || target + o.port + o.timestamp);
  const sp = 32768 + (seed % 28000), isn = Math.imul(seed, 2654435761) >>> 0, risn = Math.imul(seed ^ 0x5bd1e995, 40503) >>> 0;
  // The scanner's ephemeral port is an example: the source port going out,
  // the destination port coming back.
  const eph = (l4, proto, at) => { if (proto === 6 || proto === 17) l4.eg.push([at, 2]); return l4; };
  const out = (l4, proto, info, extra = {}) => ({ dir: "out", ...frame({ ...base, srcIP: scanIP, dstIP: target, proto, l4: eph(l4, proto, 0), egIP: egScanner ? "src" : false }), info, ...extra });
  const inn = (l4, proto, info, extra = {}) => ({ dir: "in", ...frame({ ...back, srcIP: target, dstIP: scanIP, proto, l4: eph(l4, proto, 2), ttl: 64, egIP: egScanner ? "dst" : false }), info, ...extra });
  const p = o.port, st = o.state;
  const pk = [];
  const transport = o.transport;

  if (o.kind === "service" || o.kind === "script") {
    let seq = isn + 1, rseq = risn + 1;
    const ev = (o.evidence || []).filter(e => e.request || e.response).slice(0, 6);
    if (!ev.length) return [];
    for (const e of ev) {
      const req = b64bytes(e.request), resp = b64bytes(e.response);
      const layerName = e.layer === "tls" ? "TLS" : (e.probe || "probe");
      if (transport === "udp") {
        if (req.length) pk.push(out(udp(sp, p, [...req]), 17, `${layerName} probe · ${req.length} B`, { kind: "request" }));
        if (resp.length) pk.push(inn(udp(p, sp, [...resp]), 17, `${layerName} reply · ${resp.length} B`, { kind: "response" }));
        continue;
      }
      if (req.length) {
        pk.push(out(tcp(sp, p, seq, rseq, F.PSH | F.ACK, [...req.slice(0, 1400)]), 6, `${layerName} probe · ${req.length} B`, { kind: "request" }));
        seq += Math.min(req.length, 1400);
      }
      if (resp.length) {
        pk.push(inn(tcp(p, sp, rseq, seq, F.PSH | F.ACK, [...resp.slice(0, 1400)]), 6, `${layerName} reply · ${resp.length} B`, { kind: "response" }));
        rseq += Math.min(resp.length, 1400);
      }
    }
    return pk;
  }
  if (o.kind && o.kind !== "port" && o.kind !== "host") return [];

  if (transport === "arp" && !v6) {
    const tip = ip4bytes(target), sip = ip4bytes(loop ? target : scanIP);
    const req = [0, 1, 8, 0, 6, 4, 0, 1, ...EG_MAC_SCANNER, ...sip, 0, 0, 0, 0, 0, 0, ...tip];
    const rep = [0, 1, 8, 0, 6, 4, 0, 2, ...tmac, ...tip, ...EG_MAC_SCANNER, ...sip];
    const egs = egScanner ? [[14 + 14, 4]] : [];
    pk.push({ dir: "out", bytes: Uint8Array.from([...BROADCAST, ...EG_MAC_SCANNER, 8, 6, ...req]), eg: [[6, 6], [14 + 8, 6], ...egs], info: `Who has ${target}?`, kind: "probe" });
    if (st === "up" || st === "open") pk.push({ dir: "in", bytes: Uint8Array.from([...EG_MAC_SCANNER, ...tmac, 8, 6, ...rep]),
      eg: [[0, 6], [14 + 18, 6], ...(o.mac ? [] : [[6, 6], [14 + 8, 6]]), ...(egScanner ? [[14 + 24, 4]] : [])], info: `${target} is at ${o.mac || "its MAC"}`, kind: "reply" });
    else pk.push({ lost: true });
    return finish(pk, o);
  }
  if (transport === "ndp" || (transport === "arp" && v6)) {
    const t = ip6bytes(target);
    pk.push(out(icmp(true, 135, 0, [0, 0, 0, 0, ...t]), 58, `Who has ${target}?`, { kind: "probe" }));
    if (st === "up" || st === "open") pk.push(inn(icmp(true, 136, 0, [0x60, 0, 0, 0, ...t]), 58, `${target} is here`, { kind: "reply" }));
    else pk.push({ lost: true });
    return finish(pk, o);
  }
  if (transport === "icmp") {
    pk.push(out(icmp(v6, v6 ? 128 : 8, 0, [...be16(seed & 0xffff), 0, 1]), v6 ? 58 : 1, "Echo request", { kind: "probe" }));
    if (st === "up" || st === "open") pk.push(inn(icmp(v6, v6 ? 129 : 0, 0, [...be16(seed & 0xffff), 0, 1]), v6 ? 58 : 1, "Echo reply", { kind: "reply" }));
    else pk.push({ lost: true });
    return finish(pk, o);
  }
  if (transport === "udp") {
    // The probe payload is protocol specific and not retained in a port observation.
    const probe = out(udp(sp, p, []), 17, `UDP probe → ${p}`, { kind: "probe" });
    pk.push(probe);
    if (st === "open") {
      const resp = o.response_hex ? (o.response_hex.match(/../g) || []).map(x => parseInt(x, 16)) : [];
      pk.push(inn(udp(p, sp, resp), 17, `UDP reply from ${p}`, { kind: "reply" }));
    } else if (st === "closed") {
      const quoted = Array.from(probe.bytes.slice(14, 14 + (v6 ? 48 : 28)));
      pk.push(inn(icmp(v6, v6 ? 1 : 3, v6 ? 4 : 3, [0, 0, 0, 0, ...quoted]), v6 ? 58 : 1, "Port unreachable", { kind: "reply" }));
    } else pk.push({ lost: true });
    return finish(pk, o);
  }
  if (transport === "tcp") {
    const connect = /connect/.test(o.probe || "");
    pk.push(out(tcp(sp, p, isn, 0, F.SYN, [], true), 6, `${sp} → ${p} [SYN]`, { kind: "probe" }));
    if (st === "open") {
      pk.push(inn(tcp(p, sp, risn, isn + 1, F.SYN | F.ACK, [], true), 6, `${p} → ${sp} [SYN, ACK]`, { kind: "reply" }));
      if (connect) pk.push(out(tcp(sp, p, isn + 1, risn + 1, F.ACK), 6, `${sp} → ${p} [ACK]`, { kind: "probe" }));
      else pk.push(out(tcp(sp, p, isn + 1, 0, F.RST), 6, `${sp} → ${p} [RST]`, { kind: "probe" }));
    } else if (st === "closed") {
      pk.push(inn(tcp(p, sp, 0, isn + 1, F.RST | F.ACK), 6, `${p} → ${sp} [RST, ACK]`, { kind: "reply" }));
    } else if (/icmp|unreachable|prohibited/i.test(o.reason || "")) {
      const quoted = Array.from(pk[0].bytes.slice(14, 14 + (v6 ? 48 : 28)));
      pk.push(inn(icmp(v6, v6 ? 1 : 3, v6 ? 1 : 13, [0, 0, 0, 0, ...quoted]), v6 ? 58 : 1, "Administratively prohibited", { kind: "reply" }));
    } else {
      pk.push({ lost: true });
      pk.push(out(tcp(sp, p, isn, 0, F.SYN, [], true), 6, `${sp} → ${p} [SYN] retransmission`, { kind: "probe" }));
      pk.push({ lost: true });
    }
    return finish(pk, o);
  }
  return [];
}

// finish attaches the verdict to the last real packet and turns "lost"
// markers into a flag on the probe before them (drawn fading out mid-path).
function finish(pk, o) {
  const res = [];
  for (const p of pk) {
    if (p.lost) { if (res.length) res[res.length - 1].lost = true; continue; }
    res.push(p);
  }
  if (res.length) res[res.length - 1].verdict = o.state;
  return res;
}

export function protoOf(p) {
  const b = p.bytes;
  if (b[12] === 8 && b[13] === 6) return "ARP";
  const v6 = b[12] === 0x86;
  const proto = v6 ? b[20] : b[23];
  return { 6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6" }[proto] || "IP";
}

// tone classifies a packet for color: probe (outbound), open (positive
// reply), closed (negative reply), filtered (lost), data (service bytes).
export function tone(p) {
  if (p.kind === "request") return "request";
  if (p.kind === "response") return "response";
  if (p.dir === "out") return p.lost ? "lost" : "probe";
  if (/RST|unreachable|prohibited/i.test(p.info)) return "closed";
  return "open";
}

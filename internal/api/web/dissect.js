// Frame dissector for the packet explainer. Every field keeps its byte
// offset and size so the parsed tree and the hex dump select each other,
// and carries a short explanation written for someone reading a scan.
//
// opts.eg lists [offset, size] byte ranges whose values are illustrative
// rather than captured (reconstructed frames); fields overlapping them are
// flagged so the view can badge them "E.G.".

const WELL_KNOWN = {
  20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP server", 68: "DHCP client",
  69: "TFTP", 80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPC portmapper", 123: "NTP", 135: "MS RPC", 137: "NetBIOS name",
  139: "NetBIOS session", 143: "IMAP", 161: "SNMP", 162: "SNMP trap", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
  500: "IKE", 502: "Modbus", 514: "Syslog", 587: "SMTP submission", 623: "IPMI", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
  1080: "SOCKS", 1433: "MS SQL", 1521: "Oracle", 1883: "MQTT", 1900: "SSDP", 2049: "NFS", 3306: "MySQL", 3389: "RDP",
  4840: "OPC UA", 5353: "mDNS", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP alternate", 8443: "HTTPS alternate",
  9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB", 44818: "EtherNet/IP", 47808: "BACnet",
};
export function serviceName(port) { return WELL_KNOWN[port] || ""; }

const ETHER_TYPES = { 0x0800: "IPv4", 0x0806: "ARP", 0x86dd: "IPv6", 0x8100: "802.1Q VLAN", 0x88a8: "802.1ad VLAN", 0x88cc: "LLDP" };
const IP_PROTOCOLS = { 1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6 in IPv4", 47: "GRE", 50: "ESP", 58: "ICMPv6", 132: "SCTP" };

export const LAYER_COLORS = { link: "var(--l-link)", vlan: "var(--l-link)", arp: "var(--l-arp)", net: "var(--l-net)",
  transport: "var(--l-transport)", icmp: "var(--l-icmp)", app: "var(--l-app)", data: "var(--l-data)" };

const hex2 = n => "0x" + n.toString(16).padStart(2, "0");
const hex4 = n => "0x" + n.toString(16).padStart(4, "0");

export function tcpFlagNames(f) {
  // Wireshark's order, so a reply reads [SYN, ACK] or [RST, ACK].
  return [[0x01, "FIN"], [0x02, "SYN"], [0x04, "RST"], [0x08, "PSH"], [0x10, "ACK"], [0x20, "URG"], [0x40, "ECE"], [0x80, "CWR"], [0x100, "NS"]]
    .filter(([bit]) => f & bit).map(([, n]) => n);
}

function tcpFlagMeaning(f) {
  const syn = f & 2, ack = f & 0x10, rst = f & 4, fin = f & 1, psh = f & 8;
  if (syn && ack) return "SYN+ACK: the port is listening. The target agrees to open the connection, so the port is open.";
  if (syn) return "SYN alone asks to open a connection. In a SYN scan the scanner never completes it; the reply alone tells open from closed.";
  if (rst && ack) return "RST+ACK: nothing listens on this port. The target refuses the connection, so the port is closed.";
  if (rst) return "RST alone tears the half-open connection down so the target does not keep waiting for the final ACK.";
  if (fin) return "FIN closes this side of the connection politely.";
  if (psh && ack) return "PSH+ACK carries application data: a service probe or the service's reply.";
  if (ack) return "ACK confirms bytes received; the third packet of the handshake when it carries no data.";
  return "No common flag combination.";
}

function icmpMeaning(v6, type, code) {
  if (!v6) {
    if (type === 0) return ["Echo reply", "The host answered a ping: it is up."];
    if (type === 8) return ["Echo request", "A ping: asks the host to echo the packet back."];
    if (type === 11) return ["Time exceeded", "A router dropped the packet when its TTL reached zero; traceroute relies on this."];
    if (type === 3) {
      const why = { 0: "Network unreachable", 1: "Host unreachable", 3: "Port unreachable", 9: "Network administratively prohibited",
        10: "Host administratively prohibited", 13: "Communication administratively prohibited" }[code] || `Destination unreachable (code ${code})`;
      if (code === 3) return [why, "The host itself says nothing listens on this UDP port, so the port is closed."];
      if ([9, 10, 13].includes(code)) return [why, "A firewall rejected the probe, so the port counts as filtered."];
      return [why, "The packet could not be delivered; the port state stays unknown or filtered."];
    }
    return [`Type ${type}`, ""];
  }
  if (type === 1) return [code === 4 ? "Port unreachable" : `Destination unreachable (code ${code})`,
    code === 4 ? "Nothing listens on this UDP port, so the port is closed." : "A router or firewall could not deliver the packet."];
  if (type === 128) return ["Echo request", "An IPv6 ping."];
  if (type === 129) return ["Echo reply", "The host answered an IPv6 ping: it is up."];
  if (type === 135) return ["Neighbor solicitation", "IPv6's ARP: asks which link-layer address owns the target address."];
  if (type === 136) return ["Neighbor advertisement", "The owner answers with its link-layer address, proving the host is on the link."];
  if (type === 133) return ["Router solicitation", "Asks routers on the link to announce themselves."];
  if (type === 134) return ["Router advertisement", "A router announces itself and the prefixes of the link."];
  return [`Type ${type}`, ""];
}

export function dissect(input, opts = {}) {
  const bytes = input instanceof Uint8Array ? input : Uint8Array.from(input);
  const eg = opts.eg || [];
  const layers = [];
  const isEg = (at, size) => eg.some(([s, n]) => at < s + n && s < at + size);
  let cur = null;
  const layer = (name, kind, at) => { cur = { name, kind, at, size: 0, summary: "", fields: [] }; layers.push(cur); return cur; };
  const put = (name, at, size, value, explain = "") => {
    if (at + size > bytes.length || size <= 0) return;
    cur.fields.push({ name, at, size, value: String(value), explain, eg: isEg(at, size) });
  };
  const close = end => { cur.size = Math.max(0, Math.min(end, bytes.length) - cur.at); };
  const u16 = at => (bytes[at] << 8) | bytes[at + 1];
  const u32 = at => ((bytes[at] * 0x1000000) + (bytes[at + 1] << 16) + (bytes[at + 2] << 8) + bytes[at + 3]) >>> 0;
  const mac = at => Array.from(bytes.slice(at, at + 6), b => b.toString(16).padStart(2, "0")).join(":");
  const ip4 = at => Array.from(bytes.slice(at, at + 4)).join(".");
  const ip6 = at => compress6(Array.from({ length: 8 }, (_, i) => u16(at + i * 2).toString(16)));
  const out = { bytes, layers, src: "", dst: "", protocol: "", info: "", sport: 0, dport: 0, flags: 0 };
  if (!bytes.length) return out;

  // Link layer.
  layer("Ethernet II", "link", 0);
  if (bytes.length < 14) { put("Incomplete frame", 0, bytes.length, `${bytes.length} bytes`, "Too short for an Ethernet header."); close(bytes.length); return out; }
  const dmac = mac(0);
  put("Destination", 0, 6, dmac, dmac === "ff:ff:ff:ff:ff:ff" ? "Broadcast: every device on the segment receives this frame."
    : bytes[0] & 1 ? "A multicast group address." : "The next hop's network card: the target itself on a local segment, otherwise the gateway.");
  put("Source", 6, 6, mac(6), "The sending network card.");
  let kind = u16(12), at = 14;
  put("Type", 12, 2, `${hex4(kind)} (${ETHER_TYPES[kind] || "unknown"})`, "What the frame carries.");
  cur.summary = `${mac(6)} → ${dmac}`;
  close(14);
  for (let i = 0; i < 2 && (kind === 0x8100 || kind === 0x88a8) && bytes.length >= at + 4; i++) {
    layer("802.1Q VLAN", "vlan", at);
    const tci = u16(at);
    put("Priority / VLAN ID", at, 2, `PCP ${tci >> 13} · VLAN ${tci & 0xfff}`, "A switch tag: the frame belongs to this virtual LAN.");
    kind = u16(at + 2);
    put("Inner type", at + 2, 2, `${hex4(kind)} (${ETHER_TYPES[kind] || "unknown"})`, "What follows the tag.");
    cur.summary = `VLAN ${tci & 0xfff}`;
    at += 4; close(at);
  }

  let protocol = -1, v6 = false;
  if (kind === 0x0806 && bytes.length >= at + 28) {
    layer("ARP", "arp", at);
    const op = u16(at + 6);
    put("Hardware / protocol type", at, 4, `Ethernet / IPv4`, "ARP maps IPv4 addresses to Ethernet addresses.");
    put("Sizes", at + 4, 2, `${bytes[at + 4]} / ${bytes[at + 5]} bytes`, "Lengths of a MAC and an IPv4 address.");
    put("Operation", at + 6, 2, op === 1 ? "1 (request)" : op === 2 ? "2 (reply)" : op,
      op === 1 ? "Who has this IPv4 address? Any reply proves a live host, even one whose firewall drops every port probe."
        : "This address is at this MAC: the host is present on the local segment.");
    put("Sender MAC", at + 8, 6, mac(at + 8), "Who asks or answers.");
    put("Sender IP", at + 14, 4, ip4(at + 14), "");
    put("Target MAC", at + 18, 6, mac(at + 18), op === 1 ? "Unknown yet, so all zeros." : "");
    put("Target IP", at + 24, 4, ip4(at + 24), op === 1 ? "The address being looked up." : "");
    out.src = ip4(at + 14); out.dst = ip4(at + 24); out.protocol = "ARP";
    out.info = op === 1 ? `Who has ${ip4(at + 24)}? Tell ${ip4(at + 14)}` : `${ip4(at + 14)} is at ${mac(at + 8)}`;
    cur.summary = out.info;
    at += 28; close(at);
  } else if (kind === 0x0800 && bytes.length >= at + 20 && bytes[at] >> 4 === 4) {
    const size = (bytes[at] & 15) * 4;
    if (size >= 20 && bytes.length >= at + size) {
      layer("IPv4", "net", at);
      const ttl = bytes[at + 8], flags = u16(at + 6);
      protocol = bytes[at + 9];
      put("Version, header length", at, 1, `4, ${size} bytes`, size === 20 ? "IPv4 with no options." : "IPv4 with options.");
      put("DSCP, ECN", at + 1, 1, `${bytes[at + 1] >> 2}, ${bytes[at + 1] & 3}`, "Priority and congestion marks; 0 means ordinary traffic.");
      put("Total length", at + 2, 2, `${u16(at + 2)} bytes`, "This header and everything inside it.");
      put("Identification", at + 4, 2, hex4(u16(at + 4)), "Lets the receiver reassemble fragments of one packet.");
      put("Flags", at + 6, 2, [flags & 0x4000 ? "DF" : "", flags & 0x2000 ? "MF" : ""].filter(Boolean).join(" ") || "none",
        flags & 0x4000 ? "Don't fragment: routers must drop rather than split it." : "Routers may split it if a link is too small.");
      put("Time to live", at + 8, 1, ttl, "Each router subtracts one. Replies start near 64 (Linux, macOS), 128 (Windows) or 255 (network gear), which hints at the responding stack.");
      put("Protocol", at + 9, 1, `${protocol} (${IP_PROTOCOLS[protocol] || "other"})`, "The transport inside.");
      put("Header checksum", at + 10, 2, hex4(u16(at + 10)), "Detects corruption of this header in transit.");
      put("Source address", at + 12, 4, ip4(at + 12), "");
      put("Destination address", at + 16, 4, ip4(at + 16), "");
      if (size > 20) put("Options", at + 20, size - 20, `${size - 20} bytes`, "");
      out.src = ip4(at + 12); out.dst = ip4(at + 16);
      cur.summary = `${out.src} → ${out.dst}`;
      at += size; close(at);
      if (flags & 0x1fff) protocol = -1; // later fragments carry no transport header
    }
  } else if (kind === 0x86dd && bytes.length >= at + 40 && bytes[at] >> 4 === 6) {
    v6 = true;
    layer("IPv6", "net", at);
    protocol = bytes[at + 6];
    put("Version, class, flow", at, 4, hex4(u32(at) >>> 16) + "…", "Version 6, traffic class and flow label.");
    put("Payload length", at + 4, 2, `${u16(at + 4)} bytes`, "Everything after this 40-byte header.");
    put("Next header", at + 6, 1, `${protocol} (${IP_PROTOCOLS[protocol] || "other"})`, "The transport inside.");
    put("Hop limit", at + 7, 1, bytes[at + 7], "IPv6's TTL: each router subtracts one.");
    put("Source address", at + 8, 16, ip6(at + 8), "");
    put("Destination address", at + 24, 16, ip6(at + 24), "");
    out.src = ip6(at + 8); out.dst = ip6(at + 24);
    cur.summary = `${out.src} → ${out.dst}`;
    at += 40; close(at);
  }

  if (protocol === 6 && bytes.length >= at + 20) {
    layer("TCP", "transport", at);
    const size = (bytes[at + 12] >> 4) * 4, flags = u16(at + 12) & 0x1ff;
    const sp = u16(at), dp = u16(at + 2), names = tcpFlagNames(flags);
    put("Source port", at, 2, sp + (serviceName(sp) ? ` (${serviceName(sp)})` : ""), serviceName(sp) ? "The service answering." : "A temporary port the sender picked for this exchange.");
    put("Destination port", at + 2, 2, dp + (serviceName(dp) ? ` (${serviceName(dp)})` : ""), serviceName(dp) ? "The port being probed." : "The port this segment is addressed to.");
    put("Sequence number", at + 4, 4, u32(at + 4), "The sender's byte counter, started at a random value for each connection.");
    put("Acknowledgment", at + 8, 4, u32(at + 8), flags & 0x10 ? "The next byte the sender expects from the other side." : "Unused until the ACK flag is set.");
    put("Header length", at + 12, 1, `${size} bytes`, size > 20 ? "TCP header with options." : "TCP header without options.");
    put("Flags", at + 12, 2, names.join(", ") || "none", tcpFlagMeaning(flags));
    put("Window", at + 14, 2, u16(at + 14), "How many bytes the sender can accept before the other side must wait.");
    put("Checksum", at + 16, 2, hex4(u16(at + 16)), "Covers the segment and the addresses.");
    put("Urgent pointer", at + 18, 2, u16(at + 18), "Unused unless URG is set.");
    if (size > 20 && at + size <= bytes.length) put("Options", at + 20, size - 20, tcpOptions(bytes.slice(at + 20, at + size)),
      "Window scale, MSS, SACK and timestamps. Their order and values differ between operating systems, which helps fingerprint the stack.");
    out.protocol = "TCP"; out.sport = sp; out.dport = dp; out.flags = flags;
    out.info = `${sp} → ${dp} [${names.join(", ")}] Seq=${u32(at + 4)}` + (flags & 0x10 ? ` Ack=${u32(at + 8)}` : "");
    cur.summary = `${sp} → ${dp} · ${names.join(" ")}`;
    at += size >= 20 && at + size <= bytes.length ? size : bytes.length - at;
    close(at);
  } else if (protocol === 17 && bytes.length >= at + 8) {
    layer("UDP", "transport", at);
    const sp = u16(at), dp = u16(at + 2);
    put("Source port", at, 2, sp + (serviceName(sp) ? ` (${serviceName(sp)})` : ""), "");
    put("Destination port", at + 2, 2, dp + (serviceName(dp) ? ` (${serviceName(dp)})` : ""),
      "UDP has no handshake: an open port answers only if the payload makes sense to the service.");
    put("Length", at + 4, 2, `${u16(at + 4)} bytes`, "This header and the payload.");
    put("Checksum", at + 6, 2, hex4(u16(at + 6)), "");
    out.protocol = "UDP"; out.sport = sp; out.dport = dp;
    out.info = `${sp} → ${dp} Len=${Math.max(0, u16(at + 4) - 8)}`;
    cur.summary = `${sp} → ${dp}`;
    at += 8; close(at);
  } else if ((protocol === 1 || protocol === 58) && bytes.length >= at + 4) {
    layer(v6 ? "ICMPv6" : "ICMP", "icmp", at);
    const [title, meaning] = icmpMeaning(v6, bytes[at], bytes[at + 1]);
    put("Type", at, 1, `${bytes[at]} (${title})`, meaning);
    put("Code", at + 1, 1, bytes[at + 1], "Refines the type.");
    put("Checksum", at + 2, 2, hex4(u16(at + 2)), "");
    out.protocol = v6 ? "ICMPv6" : "ICMP"; out.info = title;
    cur.summary = title;
    if (v6 && (bytes[at] === 135 || bytes[at] === 136) && bytes.length >= at + 24) {
      put("Target address", at + 8, 16, ip6(at + 8), "The address being resolved.");
      out.info += ` for ${ip6(at + 8)}`;
      at += 24;
    } else if (!v6 && bytes[at] === 3 && bytes.length >= at + 8) {
      put("Unused", at + 4, 4, "", "");
      at += 8;
      if (bytes.length >= at + 20) put("Original packet", at, bytes.length - at, `${bytes.length - at} bytes`,
        "The start of the packet that triggered this error, quoted so the sender can match it to its probe.");
      at = bytes.length;
    } else at += 4;
    close(at);
  }

  if (at < bytes.length) appLayer(bytes, at, out, put, layer, close);
  if (!out.protocol) out.protocol = ETHER_TYPES[kind] || hex4(kind);
  if (!out.info) out.info = layers[layers.length - 1].summary;
  return out;
}

function appLayer(bytes, at, out, put, layer, close) {
  const rest = bytes.slice(at);
  const text = String.fromCharCode(...rest.slice(0, 2048));
  const port = Math.min(out.sport || 65536, out.dport || 65536);
  const ports = [out.sport, out.dport];
  const firstLine = text.split("\r\n")[0].split("\n")[0];
  if (/^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT) \S+ HTTP\/\d/.test(firstLine) || /^HTTP\/\d(\.\d)? \d{3}/.test(firstLine)) {
    const l = layer("HTTP", "app", at);
    const request = !firstLine.startsWith("HTTP/");
    let off = at;
    const lines = text.split("\r\n");
    for (let i = 0; i < lines.length && i < 24; i++) {
      const line = lines[i];
      if (line === "") { off += 2; break; }
      if (i === 0) put(request ? "Request line" : "Status line", off, line.length, line,
        request ? "The probe: method, path and protocol version." : "The service's answer. The Server header below usually names the product.");
      else {
        const c = line.indexOf(":");
        const name = c > 0 ? line.slice(0, c) : "Header";
        put(name, off, line.length, c > 0 ? line.slice(c + 1).trim() : line,
          /^server$/i.test(name) ? "Names the web server software; nyxr uses it for product and version." : "");
      }
      off += line.length + 2;
    }
    if (off < bytes.length) put("Body", off, bytes.length - off, `${bytes.length - off} bytes`, "");
    out.protocol = "HTTP"; out.info = firstLine.slice(0, 120); l.summary = firstLine.slice(0, 80);
    close(bytes.length);
    return;
  }
  if (rest.length >= 5 && rest[0] >= 0x14 && rest[0] <= 0x17 && rest[1] === 3 && rest[2] <= 4) {
    const l = layer("TLS", "app", at);
    const type = { 0x14: "change cipher spec", 0x15: "alert", 0x16: "handshake", 0x17: "application data" }[rest[0]];
    const ver = { 0: "SSL 3.0", 1: "TLS 1.0", 2: "TLS 1.1", 3: "TLS 1.2", 4: "TLS 1.3" }[rest[2]];
    put("Content type", at, 1, `${rest[0]} (${type})`, "TLS wraps everything in records.");
    put("Record version", at + 1, 2, ver, "Legacy field; TLS 1.3 still says TLS 1.2 here.");
    put("Length", at + 3, 2, (rest[3] << 8) | rest[4], "");
    let hs = "";
    if (rest[0] === 0x16 && rest.length > 5) {
      hs = { 1: "ClientHello", 2: "ServerHello", 11: "Certificate", 12: "ServerKeyExchange", 14: "ServerHelloDone" }[rest[5]] || `type ${rest[5]}`;
      put("Handshake", at + 5, 1, hs, rest[5] === 1 ? "The scanner offers ciphers and names the server it wants (SNI)."
        : rest[5] === 2 ? "The server picks the version and cipher; its certificate follows." : "");
      if (rest.length > 9) put("Handshake body", at + 9, rest.length - 9, `${rest.length - 9} bytes`, "Encrypted or binary; the field-by-field view stops here.");
    }
    out.protocol = "TLS"; out.info = hs || type; l.summary = out.info;
    close(bytes.length);
    return;
  }
  if (ports.includes(53) && out.protocol === "UDP" && rest.length >= 12) {
    const l = layer("DNS", "app", at);
    const u = i => (rest[i] << 8) | rest[i + 1];
    const response = !!(rest[2] & 0x80);
    put("Transaction ID", at, 2, "0x" + u(0).toString(16).padStart(4, "0"), "Matches an answer to its question.");
    put("Flags", at + 2, 2, response ? "response" : "query", "");
    put("Questions / answers", at + 4, 4, `${u(4)} / ${u(6)}`, "");
    let i = 12, name = [];
    while (i < rest.length && rest[i] && rest[i] < 64 && name.length < 20) {
      name.push(String.fromCharCode(...rest.slice(i + 1, i + 1 + rest[i])));
      i += rest[i] + 1;
    }
    if (name.length) put("Query name", at + 12, i - 12 + 1, name.join("."), "");
    if (at + 12 + (i - 12 + 1) < bytes.length) put("Rest", at + i + 1, bytes.length - (at + i + 1), `${bytes.length - (at + i + 1)} bytes`, "");
    out.protocol = "DNS"; out.info = `${response ? "Response" : "Query"} ${name.join(".")}`; l.summary = out.info;
    close(bytes.length);
    return;
  }
  if (/^SSH-\d\.\d-/.test(text)) {
    const l = layer("SSH", "app", at);
    const line = firstLine.replace(/\r$/, "");
    put("Version banner", at, line.length, line, "SSH servers announce protocol and software version before any key exchange.");
    out.protocol = "SSH"; out.info = line; l.summary = line;
    close(bytes.length);
    return;
  }
  const printableShare = rest.length ? rest.filter(b => (b >= 0x20 && b < 0x7f) || b === 10 || b === 13).length / rest.length : 0;
  const l = layer("Payload", "data", at);
  put("Data", at, rest.length, printableShare > 0.85 ? JSON.stringify(text.slice(0, 80)) : `${rest.length} bytes`,
    port < 65536 && serviceName(port) ? `Application bytes, likely ${serviceName(port)}.` : "Application bytes.");
  l.summary = `${rest.length} bytes`;
  if (out.protocol && serviceName(port) && out.protocol !== "ICMP") out.info += ` · ${rest.length} B data`;
  close(bytes.length);
}

function tcpOptions(o) {
  const out = [];
  for (let i = 0; i < o.length;) {
    const k = o[i];
    if (k === 0) break;
    if (k === 1) { out.push("NOP"); i++; continue; }
    const len = o[i + 1] || 2;
    if (k === 2) out.push(`MSS ${(o[i + 2] << 8) | o[i + 3]}`);
    else if (k === 3) out.push(`WS ${o[i + 2]}`);
    else if (k === 4) out.push("SACK_PERM");
    else if (k === 8) out.push("TS");
    else out.push(`opt ${k}`);
    i += len;
  }
  return out.filter(x => x !== "NOP").join(", ") || "padding";
}

function compress6(parts) {
  let best = -1, bestLen = 0;
  for (let i = 0; i < 8;) {
    if (parts[i] !== "0") { i++; continue; }
    let j = i;
    while (j < 8 && parts[j] === "0") j++;
    if (j - i > bestLen && j - i > 1) { best = i; bestLen = j - i; }
    i = j;
  }
  if (best < 0) return parts.join(":");
  return parts.slice(0, best).join(":") + "::" + parts.slice(best + bestLen).join(":");
}

export function parseHex(text) {
  const clean = String(text || "").replace(/\s/g, "");
  if (/[^0-9a-f]/i.test(clean)) throw new Error("Frame contains non-hex characters.");
  if (clean.length % 2) throw new Error("Frame has an incomplete hex byte.");
  return Uint8Array.from(clean.match(/../g) || [], pair => parseInt(pair, 16));
}

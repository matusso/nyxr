// nyxr web UI. Every value from the API may be attacker-influenced (banners,
// titles, certificates), so the DOM is built with textContent only.
"use strict";

const main = document.getElementById("main");
let pageAbort = null; // aborts streams and requests of the previous page

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "value") el.value = v;
    else if (k === "checked") el.checked = !!v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat()) {
    if (c === undefined || c === null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

function token() {
  try { return sessionStorage.getItem("nyxr-token") || ""; } catch { return ""; }
}
function setToken(t) {
  try { sessionStorage.setItem("nyxr-token", t); } catch { /* private mode */ }
}

class AuthError extends Error {}

async function api(path, opts = {}) {
  const headers = Object.assign({}, opts.headers || {});
  const t = token();
  if (t) headers.Authorization = "Bearer " + t;
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch("/api/v1" + path, {
    method: opts.method || (opts.body !== undefined ? "POST" : "GET"),
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    signal: opts.signal || (pageAbort && pageAbort.signal),
  });
  if (res.status === 401) throw new AuthError("token required");
  if (opts.raw) return res;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

// stream reads Server-Sent Events with fetch so the bearer token can be sent
// (EventSource cannot set headers). It reconnects with Last-Event-ID.
async function stream(path, onEvent, signal) {
  let last = "";
  for (let attempt = 0; attempt < 20 && !signal.aborted; attempt++) {
    const headers = {};
    if (last) headers["Last-Event-ID"] = last;
    let res;
    try {
      res = await api(path, { raw: true, headers, signal });
    } catch (e) {
      if (signal.aborted || e instanceof AuthError) return;
      await new Promise(r => setTimeout(r, 1000));
      continue;
    }
    if (!res.ok) return;
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = "";
    let finished = false;
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        let i;
        while ((i = buf.indexOf("\n\n")) >= 0) {
          const block = buf.slice(0, i);
          buf = buf.slice(i + 2);
          let type = "message", data = "", id = "";
          for (const line of block.split("\n")) {
            if (line.startsWith("event: ")) type = line.slice(7);
            else if (line.startsWith("data: ")) data += line.slice(6);
            else if (line.startsWith("id: ")) id = line.slice(4);
          }
          if (id) last = id;
          if (!data) continue;
          const payload = JSON.parse(data);
          onEvent(type, payload);
          if (type === "scan" && payload.status !== "running") finished = true;
        }
      }
    } catch (e) {
      if (signal.aborted) return;
    }
    if (finished) return;
  }
}

function fmtTime(s) {
  if (!s || s.startsWith("0001")) return "-";
  const d = new Date(s);
  return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}
function fmtRTT(ns) { return ns ? (ns / 1e6).toFixed(2) + " ms" : ""; }
function state(s) { return h("span", { class: "s-" + String(s || "").replace(/\s/g, "") }, s); }
function table(headers, rows) {
  return h("div", { class: "scroll" }, h("table", {},
    h("thead", {}, h("tr", {}, headers.map(x => h("th", {}, x)))),
    h("tbody", {}, rows)));
}
function kv(pairs) {
  return h("dl", { class: "kv" }, pairs.filter(p => p[1] !== undefined && p[1] !== "" && p[1] !== null)
    .flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
}
function port(o) { return o.port ? `${o.port}/${o.transport}` : o.transport; }

// Packet fields retain byte offsets so selecting a parsed value selects its
// source bytes in the editable hex pane, as in a packet analyzer.
function parseFrame(hex) {
  const clean = hex.replace(/\s/g, "");
  if (/[^0-9a-f]/i.test(clean)) throw new Error("Frame contains non-hex characters.");
  if (clean.length % 2) throw new Error("Frame has an incomplete hex byte.");
  const bytes = Uint8Array.from(clean.match(/../g) || [], pair => parseInt(pair, 16));
  if (!bytes.length) return { bytes, groups: [] };
  const groups = [];
  const group = name => { const fields = []; groups.push({ name, fields }); return fields; };
  const put = (fields, name, at, size, value) => {
    if (at + size <= bytes.length) fields.push({ name, at, size, value: String(value) });
  };
  const u16 = at => (bytes[at] << 8) | bytes[at + 1];
  const u32 = at => ((bytes[at] * 0x1000000) + (bytes[at + 1] << 16) + (bytes[at + 2] << 8) + bytes[at + 3]) >>> 0;
  const mac = at => Array.from(bytes.slice(at, at + 6), b => b.toString(16).padStart(2, "0")).join(":");
  const ip4 = at => Array.from(bytes.slice(at, at + 4)).join(".");
  const ip6 = at => Array.from({ length: 8 }, (_, i) => u16(at + i * 2).toString(16)).join(":");
  const eth = group("Ethernet II");
  if (bytes.length < 14) { put(eth, "Incomplete frame", 0, bytes.length, `${bytes.length} bytes`); return { bytes, groups }; }
  put(eth, "Destination", 0, 6, mac(0));
  put(eth, "Source", 6, 6, mac(6));
  let kind = u16(12), at = 14;
  put(eth, "Type", 12, 2, `0x${kind.toString(16).padStart(4, "0")}`);
  for (let i = 0; i < 2 && (kind === 0x8100 || kind === 0x88a8) && bytes.length >= at + 4; i++) {
    const vlan = group("802.1Q VLAN");
    put(vlan, "Tag control", at, 2, `VLAN ${u16(at) & 0xfff}`);
    kind = u16(at + 2);
    put(vlan, "Inner type", at + 2, 2, `0x${kind.toString(16).padStart(4, "0")}`);
    at += 4;
  }
  let protocol = -1;
  if (kind === 0x0800 && bytes.length >= at + 20 && bytes[at] >> 4 === 4) {
    const start = at, size = (bytes[at] & 15) * 4;
    if (size >= 20 && bytes.length >= at + size) {
      const ip = group("Internet Protocol v4");
      put(ip, "Version / header length", at, 1, `IPv4 · ${size} bytes`);
      put(ip, "Total length", at + 2, 2, u16(at + 2));
      put(ip, "Identification", at + 4, 2, `0x${u16(at + 4).toString(16)}`);
      put(ip, "Flags / fragment offset", at + 6, 2, `0x${u16(at + 6).toString(16)}`);
      put(ip, "Time to live", at + 8, 1, bytes[at + 8]);
      protocol = bytes[at + 9];
      put(ip, "Protocol", at + 9, 1, protocol);
      put(ip, "Header checksum", at + 10, 2, `0x${u16(at + 10).toString(16)}`);
      put(ip, "Source address", at + 12, 4, ip4(at + 12));
      put(ip, "Destination address", at + 16, 4, ip4(at + 16));
      if (size > 20) put(ip, "Options", at + 20, size - 20, `${size - 20} bytes`);
      at += size;
      if (u16(start + 6) & 0x1fff) protocol = -1; // later fragments have no transport header
    }
  } else if (kind === 0x86dd && bytes.length >= at + 40 && bytes[at] >> 4 === 6) {
    const ip = group("Internet Protocol v6");
    put(ip, "Version / traffic class / flow", at, 4, `0x${u32(at).toString(16)}`);
    put(ip, "Payload length", at + 4, 2, u16(at + 4));
    protocol = bytes[at + 6];
    put(ip, "Next header", at + 6, 1, protocol);
    put(ip, "Hop limit", at + 7, 1, bytes[at + 7]);
    put(ip, "Source address", at + 8, 16, ip6(at + 8));
    put(ip, "Destination address", at + 24, 16, ip6(at + 24));
    at += 40;
  }
  if (protocol === 6 && bytes.length >= at + 20) {
    const tcp = group("Transmission Control Protocol");
    const size = (bytes[at + 12] >> 4) * 4;
    put(tcp, "Source port", at, 2, u16(at));
    put(tcp, "Destination port", at + 2, 2, u16(at + 2));
    put(tcp, "Sequence number", at + 4, 4, u32(at + 4));
    put(tcp, "Acknowledgment number", at + 8, 4, u32(at + 8));
    put(tcp, "Header length / flags", at + 12, 2, `${size} bytes · 0x${u16(at + 12).toString(16)}`);
    put(tcp, "Window", at + 14, 2, u16(at + 14));
    put(tcp, "Checksum", at + 16, 2, `0x${u16(at + 16).toString(16)}`);
    put(tcp, "Urgent pointer", at + 18, 2, u16(at + 18));
    if (size >= 20 && at + size <= bytes.length) {
      if (size > 20) put(tcp, "Options", at + 20, size - 20, `${size - 20} bytes`);
      at += size;
    } else at = bytes.length;
  } else if (protocol === 17 && bytes.length >= at + 8) {
    const udp = group("User Datagram Protocol");
    put(udp, "Source port", at, 2, u16(at));
    put(udp, "Destination port", at + 2, 2, u16(at + 2));
    put(udp, "Length", at + 4, 2, u16(at + 4));
    put(udp, "Checksum", at + 6, 2, `0x${u16(at + 6).toString(16)}`);
    at += 8;
  } else if ((protocol === 1 || protocol === 58) && bytes.length >= at + 4) {
    const icmp = group(protocol === 1 ? "ICMP" : "ICMPv6");
    put(icmp, "Type", at, 1, bytes[at]);
    put(icmp, "Code", at + 1, 1, bytes[at + 1]);
    put(icmp, "Checksum", at + 2, 2, `0x${u16(at + 2).toString(16)}`);
    at += 4;
  }
  if (at < bytes.length) put(group("Payload / remaining bytes"), "Data", at, bytes.length - at, `${bytes.length - at} bytes`);
  return { bytes, groups };
}
function detail(o) {
  const parts = [];
  const product = [o.product, o.version].filter(Boolean).join(" ");
  if (product) parts.push(product);
  if (o.tls) {
    let t = o.tls.version + (o.tls.alpn ? " " + o.tls.alpn : "");
    const leaf = (o.tls.certificates || [])[0];
    if (leaf) t += " cert " + ((leaf.dns_names || [])[0] || leaf.subject);
    parts.push(t);
  }
  const attrs = o.attributes || {};
  if (attrs["http.title"]) parts.push(`title "${attrs["http.title"]}"`);
  if (o.kind === "script" && o.nse) parts.push((o.nse.output || "").split("\n")[0].slice(0, 160));
  if (o.kind === "device") parts.push(`${attrs["device.class"] || ""} (${(o.signals || []).length} signals)`);
  if (o.mac) parts.push("MAC " + o.mac);
  parts.push(o.reason);
  return parts.filter(Boolean).join(" | ");
}

function obsRow(o, fresh) {
  const label = o.kind === "service" ? "svc " + (o.service || "unknown") : o.kind === "script" ? "nse " + (o.nse?.id || "script") : o.kind === "device" ? "device" : o.state;
  return h("tr", { class: fresh ? "new" : "" },
    h("td", {}, o.target), h("td", {}, port(o)), h("td", {}, state(label)),
    h("td", {}, o.confidence + "%"), h("td", {}, fmtRTT(o.rtt_ns)),
    h("td", { class: "wrap" }, detail(o),
      o.nse ? h("details", {}, h("summary", {}, "NSE output"),
        h("pre", {}, o.nse.output || ""),
        (o.nse.fields && o.nse.fields.length) ? h("pre", {}, JSON.stringify(o.nse.fields, null, 2)) : null) : null,
      (o.evidence && o.evidence.length) ? h("details", {}, h("summary", {}, `${o.evidence.length} exchanges`),
        o.evidence.map(e => h("pre", {}, `${e.probe} [${e.layer}] ${e.matched || "unmatched"}${e.error ? " error: " + e.error : ""}\n` +
          (e.request ? "> " + printable(e.request) + "\n" : "") + (e.response ? "< " + printable(e.response) : "")))) : null));
}
function printable(b64) {
  let s;
  try { s = atob(b64); } catch { return b64; }
  return s.replace(/[^\x20-\x7e\n]/g, c => "\\x" + c.charCodeAt(0).toString(16).padStart(2, "0")).slice(0, 2048);
}
const obsHeaders = ["target", "port", "state", "conf", "rtt", "detail"];

function scanRow(s) {
  return h("tr", {},
    h("td", {}, h("a", { href: "#/scans/" + encodeURIComponent(s.scan_id) }, s.scan_id)),
    h("td", {}, s.profile), h("td", {}, state(s.status)), h("td", {}, fmtTime(s.started)),
    h("td", {}, s.targets), h("td", {}, s.observations), h("td", {}, s.services),
    h("td", { class: "wrap error" }, s.error || ""));
}
const scanHeaders = ["scan", "profile", "status", "started", "targets", "observations", "services", ""];

// ---- pages ----

async function dashboard() {
  const signal = pageAbort.signal;
  const metrics = [
    ["scans", "Total scans", "Across all stored history"],
    ["running", "Active scans", "Currently in progress"],
    ["hosts", "Discovered hosts", "Stored in this workspace"],
    ["open_ports", "Open ports", "Latest known state"],
    ["services", "Services", "Identified on open ports"],
  ];
  const values = Object.fromEntries(metrics.map(([key]) => [key, h("div", { class: "n" }, "—")]));
  const recent = h("div", {});
  const updated = h("span", { class: "muted" }, "Updating…");
  const refresh = async () => {
    const [stats, scans] = await Promise.all([api("/stats", { signal }), api("/scans?limit=8", { signal })]);
    if (signal.aborted) return;
    for (const [key] of metrics) {
      values[key].textContent = Number(stats[key] || 0).toLocaleString();
      values[key].classList.toggle("live-number", key === "running" && stats.running > 0);
    }
    recent.replaceChildren(scans.length ? table(scanHeaders, scans.map(scanRow)) :
      h("p", { class: "muted" }, "No scans yet. ", h("a", { href: "#/new" }, "Start one.")));
    updated.textContent = "Updated " + new Date().toLocaleTimeString();
  };
  await refresh();
  const interval = setInterval(() => refresh().catch(() => { updated.textContent = "Live update unavailable"; }), 5000);
  signal.addEventListener("abort", () => clearInterval(interval), { once: true });
  return [
    h("section", { class: "hero" },
      h("div", { class: "hero-content" }, h("span", { class: "eyebrow" }, "// COMMAND CENTER"),
        h("h1", {}, "See Beyond the Surface."),
        h("p", {}, "Discover hosts, map exposed ports, and identify services from one local network workspace."),
        h("div", { class: "hero-actions" }, h("a", { class: "button-link", href: "#/new" }, "＋ Launch scan"),
          h("a", { class: "button-link secondary", href: "#/assets" }, "Explore assets →"))),
      h("div", { class: "hero-meta" }, h("span", { class: "system-dot" }), "SYSTEM ONLINE")),
    h("div", { class: "tiles" }, metrics.map(([key, label, hint]) =>
      h("div", { class: "tile" }, values[key], h("div", { class: "l" }, label), h("div", { class: "hint" }, hint)))),
    h("div", { class: "bar section-bar" }, h("h2", {}, "Recent scans"), updated),
    recent,
  ];
}

async function scansPage() {
  const signal = pageAbort.signal;
  const list = h("div", {});
  const refresh = async () => {
    const scans = await api("/scans?limit=200", { signal });
    if (!signal.aborted) list.replaceChildren(table(scanHeaders, scans.map(scanRow)));
  };
  await refresh();
  const interval = setInterval(() => refresh().catch(() => {}), 5000);
  signal.addEventListener("abort", () => clearInterval(interval), { once: true });
  return [h("div", { class: "bar" }, h("h1", {}, "Scans"), h("a", { href: "#/new" }, "+ new scan")),
    h("p", { class: "page-intro" }, "Scan history and live activity update automatically."), list];
}

async function newScan(knownScope = null) {
  const profiles = (await api("/profiles")).filter(p => p.Availability === "available" && p.Name !== "research");
  const f = {};
  const input = (name, attrs = {}) => (f[name] = h("input", Object.assign({ type: "text", name }, attrs)));
  const out = h("div", {});
  f.targets = h("textarea", { name: "targets", placeholder: "10.0.0.0/24, 192.168.1.10, host.example" });
  f.knownOpen = h("input", { type: "checkbox", checked: knownScope !== null });
  if (knownScope) f.targets.value = knownScope;
  const targetHelp = h("span", { class: "muted field-help" });
  f.profile = h("select", { name: "profile" }, profiles.map(p => h("option", { value: p.Name }, `${p.Name} — ${p.Description}`)));
  f.portsMode = h("select", {}, ["profile default", "top100", "top1000", "top2000", "top5000", "top8387", "all", "custom"].map(v => h("option", { value: v }, v)));
  const protos = ["tcp", "udp", "arp", "ndp"].map(p => ({ p, el: h("input", { type: "checkbox", value: p }) }));
  f.service = h("select", {}, ["profile default", "on", "off"].map(v => h("option", { value: v }, v)));
  f.tcpMode = h("select", {}, ["", "connect", "syn"].map(v => h("option", { value: v }, v || "profile default")));
  f.fingerprint = h("input", { type: "checkbox" });
  const syncKnownOpen = () => {
    const known = f.knownOpen.checked;
    f.portsMode.disabled = f.ports.disabled = known;
    protos.forEach(x => { x.el.disabled = known; });
    f.service.disabled = known;
    if (known) {
      f.service.value = "on";
      if (profiles.some(p => p.Name === "service")) f.profile.value = "service";
      f.targets.placeholder = "Optional: IP, CIDR or range; blank uses all known open ports";
      targetHelp.textContent = "Uses only ports whose latest stored state is open. Leave blank for every stored host.";
    } else {
      f.targets.placeholder = "10.0.0.0/24, 192.168.1.10, host.example";
      targetHelp.textContent = "IP addresses, hostnames, CIDRs or ranges.";
    }
  };
  f.knownOpen.addEventListener("change", syncKnownOpen);

  const request = () => {
    const r = {};
    const targets = f.targets.value.split(/[\s,]+/).filter(Boolean);
    if (targets.length) r.targets = targets;
    r.profile = f.profile.value;
    const pm = f.portsMode.value;
    if (!f.knownOpen.checked && pm !== "profile default" && pm !== "custom") r.ports = pm;
    if (!f.knownOpen.checked && pm === "custom" && f.ports.value.trim()) r.ports = f.ports.value.trim();
    const chosen = protos.filter(x => x.el.checked).map(x => x.p);
    if (!f.knownOpen.checked && chosen.length) r.protocols = chosen.join(",");
    if (f.knownOpen.checked) r.known_open = true;
    for (const k of ["timeout", "interface", "source_ip", "source_mac", "next_hop_mac", "service_probes", "service_timeout", "send_hex", "pcapng"]) {
      const v = f[k].value.trim();
      if (v) r[k] = v;
    }
    for (const k of ["rate", "host_rate", "subnet_rate", "workers", "udp_retries", "service_rate", "service_workers"]) {
      const v = f[k].value.trim();
      if (v !== "") r[k] = Number(v);
    }
    const allow = f.allow_targets.value.split(/[\s,]+/).filter(Boolean);
    if (allow.length) r.allow_targets = allow;
    if (f.tcpMode.value) r.tcp_mode = f.tcpMode.value;
    if (f.knownOpen.checked) r.service = true;
    else if (f.service.value !== "profile default") r.service = f.service.value === "on";
    if (f.fingerprint.checked) r.fingerprint = true;
    return r;
  };
  const show = (title, obj) => out.replaceChildren(h("h2", {}, title), h("pre", {}, JSON.stringify(obj, null, 2)));
  const fail = e => out.replaceChildren(h("p", { class: "error" }, e.message));
  const planBtn = h("button", { type: "button", class: "secondary", onclick: async () => {
    try { show("plan", await api("/plan", { body: request() })); } catch (e) { fail(e); }
  } }, "plan (dry run)");
  const reqBtn = h("button", { type: "button", class: "secondary", onclick: () =>
    show("request (same document as nyxr scan --config, in JSON)", request()) }, "show request");
  const form = h("form", { class: "grid", onsubmit: async ev => {
    ev.preventDefault();
    try {
      const sc = await api("/scans", { body: request() });
      location.hash = "#/scans/" + encodeURIComponent(sc.scan_id);
    } catch (e) { fail(e); }
  } },
  h("label", {}, "scan source"), h("label", { class: "choice" }, f.knownOpen, " Service scan on stored open ports"),
  h("label", {}, "targets / scope"), h("div", {}, f.targets, targetHelp),
  h("label", {}, "profile"), f.profile,
  h("label", {}, "ports"), h("div", { class: "checks" }, f.portsMode, input("ports", { placeholder: "22,80,443,8000-8100" })),
  h("label", {}, "protocols"), h("div", { class: "checks" }, protos.map(x => h("label", {}, x.el, " " + x.p)),
    h("span", { class: "muted" }, "none = profile default")),
  h("label", {}, "tcp mode"), f.tcpMode,
  h("label", {}, "rate / host / subnet"), h("div", { class: "checks" },
    input("rate", { type: "number", min: 0, placeholder: "probes/s" }), input("host_rate", { type: "number", min: 0, placeholder: "per host" }),
    input("subnet_rate", { type: "number", min: 0, placeholder: "per /24" })),
  h("label", {}, "workers / timeout"), h("div", { class: "checks" },
    input("workers", { type: "number", min: 1, placeholder: "workers" }), input("timeout", { placeholder: "e.g. 1s" }), input("udp_retries", { type: "number", min: 0, max: 5, placeholder: "udp retries" })),
  h("label", {}, "allow targets"), input("allow_targets", { placeholder: "required for ot-safe: 10.1.2.0/24" }),
  h("label", {}, "interface (raw)"), h("div", { class: "checks" }, input("interface", { placeholder: "eth0" }),
    input("source_ip", { placeholder: "source ip" }), input("source_mac", { placeholder: "source mac" }), input("next_hop_mac", { placeholder: "next-hop mac" })),
  h("label", {}, "udp payload hex"), input("send_hex"),
  h("label", {}, "service probes"), h("div", { class: "checks" }, f.service,
    input("service_probes", { placeholder: "banner,ssh,tls,http" }), input("service_timeout", { placeholder: "timeout" }),
    input("service_workers", { type: "number", min: 1, placeholder: "workers" }), input("service_rate", { type: "number", min: 0, placeholder: "conn/s" })),
  h("label", {}, "fingerprint devices"), h("div", {}, f.fingerprint),
  h("label", {}, "capture"), input("pcapng", { placeholder: "evidence.pcapng (needs packetd and --evidence-dir)" }),
  h("div", { class: "actions" }, h("button", { type: "submit" }, "start scan"), planBtn, reqBtn));
  syncKnownOpen();
  return [h("h1", {}, knownScope !== null ? "Service scan" : "New scan"), form, out];
}

async function scanPage(id) {
  const summary = h("div", {});
  const status = h("span", {});
  const tbody = h("tbody", {});
  const evidence = h("div", {});
  const actions = h("span", {});
  const progressTitle = h("span", { class: "scan-progress-title" });
  const progressNote = h("span", { class: "scan-progress-note" });
  const progressTrack = h("div", { class: "scan-progress-track", role: "progressbar", "aria-label": "Scan progress",
    "aria-valuemin": "0", "aria-valuemax": "100" },
    h("div", { class: "scan-progress-fill" }));
  const elapsedValue = h("strong", {}, "0s");
  const targetValue = h("strong", {}, "0");
  const observationValue = h("strong", {}, "0");
  const serviceValue = h("strong", {}, "0");
  const progress = h("section", { class: "scan-progress", "aria-live": "polite" },
    h("div", { class: "scan-progress-top" }, progressTitle, progressNote), progressTrack,
    h("div", { class: "scan-progress-metrics" },
      h("span", {}, "ELAPSED ", elapsedValue), h("span", {}, "TARGETS SEEN ", targetValue),
      h("span", {}, "OBSERVATIONS ", observationValue), h("span", {}, "SERVICES ", serviceValue)));
  const signal = pageAbort.signal;
  let current = await api("/scans/" + encodeURIComponent(id));
  const seen = new Set();
  const seenTargets = new Set();
  let servicesSeen = 0, pending = false;
  const key = o => [o.kind, o.target, o.transport, o.port, o.probe, o.timestamp].join("|");
  const addObs = (o, fresh) => {
    const k = key(o);
    if (seen.has(k)) return;
    seen.add(k);
    seenTargets.add(o.target);
    if (o.kind === "service" && o.fingerprint === "matched") servicesSeen++;
    tbody.append(obsRow(o, fresh));
    if (fresh && !pending) {
      // Counters follow streamed rows until the final summary arrives.
      pending = true;
      requestAnimationFrame(() => {
        pending = false;
        if (current.status === "running") {
          renderSummary(Object.assign({}, current, {
            observations: Math.max(current.observations, seen.size), services: Math.max(current.services, servicesSeen) }));
        }
      });
    }
  };
  const renderSummary = s => {
    current = s;
    progress.classList.toggle("done", s.status === "completed");
    progress.classList.toggle("failed", s.status === "failed");
    progressTitle.textContent = s.status === "running" ? "Scan in progress" :
      s.status === "completed" ? "Scan complete" : "Scan " + s.status;
    progressNote.textContent = s.status === "running" ? "Live results · total completion is unavailable" :
      s.status === "completed" ? "All scan stages finished" : "Partial results remain available";
    progressTrack.setAttribute("aria-valuetext", progressTitle.textContent);
    if (s.status === "completed") progressTrack.setAttribute("aria-valuenow", "100");
    else progressTrack.removeAttribute("aria-valuenow");
    targetValue.textContent = `${seenTargets.size} / ${s.targets}`;
    observationValue.textContent = Math.max(s.observations, seen.size).toLocaleString();
    serviceValue.textContent = Math.max(s.services, servicesSeen).toLocaleString();
    updateElapsed();
    summary.replaceChildren(kv([["profile", s.profile], ["status", state(s.status)], ["started", fmtTime(s.started)],
      ["finished", fmtTime(s.finished)], ["targets", s.targets], ["observations", s.observations], ["services", s.services],
      ["error", s.error], ["capture", s.capture ? `${s.capture.written} packets, ${s.capture.bytes} bytes in ${s.capture.path}` +
        (s.capture.dropped_queue || s.capture.dropped_limit || s.capture.backend_drops ? " (drops recorded)" : "") : undefined]]));
    status.replaceChildren(s.status === "running" ? h("span", { class: "live" }, "live") : "");
    actions.replaceChildren(
      s.status === "running" ? h("button", { class: "secondary", onclick: async () => {
        try { await api(`/scans/${encodeURIComponent(id)}/cancel`, { body: {} }); } catch (e) { alert(e.message); }
      } }, "cancel") : "",
      s.capture && s.status !== "running" ? h("button", { class: "secondary", onclick: () => download(id, s.capture.path) }, "download pcapng") : "");
  };
  const updateElapsed = () => {
    const started = Date.parse(current.started);
    if (!Number.isFinite(started)) return;
    const end = current.status === "running" ? Date.now() : Date.parse(current.finished);
    const seconds = Math.max(0, Math.floor(((Number.isFinite(end) ? end : Date.now()) - started) / 1000));
    elapsedValue.textContent = seconds >= 3600 ? `${Math.floor(seconds / 3600)}h ${Math.floor(seconds % 3600 / 60)}m` :
      seconds >= 60 ? `${Math.floor(seconds / 60)}m ${seconds % 60}s` : `${seconds}s`;
  };
  const loadStored = async () => {
    const [obs, ev] = await Promise.all([
      api(`/scans/${encodeURIComponent(id)}/observations?limit=10000`),
      api(`/scans/${encodeURIComponent(id)}/evidence`)]);
    for (const o of obs) addObs(o, false);
    evidence.replaceChildren(ev.length ? table(["target", "port", "packets", "capture"], ev.map(p =>
      h("tr", {}, h("td", {}, p.target), h("td", {}, port(p)),
        h("td", { class: "wrap" }, p.packets.map(x => `#${x.id} ${x.direction} ${x.summary}`).join("\n")), h("td", {}, p.capture))))
      : h("p", { class: "muted" }, "no packet evidence"));
  };
  renderSummary(current);
  await loadStored();
  renderSummary(current);
  const clock = setInterval(updateElapsed, 1000);
  signal.addEventListener("abort", () => clearInterval(clock), { once: true });
  if (current.status === "running") {
    stream(`/scans/${encodeURIComponent(id)}/events`, (type, data) => {
      if (type === "observation") addObs(data, true);
      else if (type === "scan") {
        renderSummary(data);
        if (data.status !== "running") loadStored().catch(() => {});
      }
    }, signal);
    const poll = setInterval(async () => {
      try {
        const latest = await api("/scans/" + encodeURIComponent(id), { signal });
        if (signal.aborted) return;
        const wasRunning = current.status === "running";
        renderSummary(latest);
        if (wasRunning && latest.status !== "running") loadStored().catch(() => {});
        if (latest.status !== "running") clearInterval(poll);
      } catch { /* the event stream and existing results remain usable */ }
    }, 5000);
    signal.addEventListener("abort", () => clearInterval(poll), { once: true });
  }
  return [h("div", { class: "bar" }, h("h1", {}, "Scan " + id), status, actions), summary,
    progress,
    h("h2", {}, "observations"), h("div", { class: "scroll" }, h("table", {},
      h("thead", {}, h("tr", {}, obsHeaders.map(x => h("th", {}, x)))), tbody)),
    h("h2", {}, "packet evidence"), evidence];
}

async function download(id, name) {
  try {
    const res = await api(`/scans/${encodeURIComponent(id)}/pcapng`, { raw: true });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || res.statusText);
    const url = URL.createObjectURL(await res.blob());
    const a = h("a", { href: url, download: name || "capture.pcapng" });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  } catch (e) { alert(e.message); }
}

async function assetsPage() {
  const assets = await api("/assets?open=true");
  const search = h("input", { type: "search", placeholder: "Address, CIDR, range, port or service", autocomplete: "off", list: "asset-suggestions", "aria-label": "Search assets" });
  const suggestions = h("datalist", { id: "asset-suggestions" });
  const count = h("span", { class: "muted" });
  const results = h("div", {});
  const values = [...new Set(assets.flatMap(a => [a.address, ...(a.ports || []).flatMap(p =>
    [`${p.port}/${p.transport}`, p.service, p.product])]).filter(Boolean))];
  let serial = 0, timer;
  const render = shown => {
    count.textContent = `${shown.length} of ${assets.length} hosts`;
    const rows = [];
    for (const a of shown) {
      (a.ports || []).forEach((p, i) => rows.push(h("tr", {},
        h("td", {}, i === 0 ? h("strong", {}, a.address) : ""),
        h("td", {}, `${p.port}/${p.transport}`), h("td", {}, state(p.state)),
        h("td", {}, p.service || ""), h("td", { class: "wrap" }, [p.product, p.version].filter(Boolean).join(" ")),
        h("td", {}, h("a", { href: "#/scans/" + encodeURIComponent(p.scan_id) }, fmtTime(p.observed_at))),
        h("td", {}, i === 0 ? h("a", { href: "#/new/known-open/" + encodeURIComponent(a.address) }, "scan open ports") : ""))));
    }
    results.replaceChildren(rows.length ? table(["address", "port", "state", "service", "product", "last seen", ""], rows)
      : h("p", { class: "muted" }, "No open ports match this search."));
  };
  const update = () => {
    const query = search.value.trim().toLowerCase();
    const mySerial = ++serial;
    clearTimeout(timer);
    suggestions.replaceChildren(...values.filter(v => v.toLowerCase().includes(query)).sort((a, b) =>
      Number(!a.toLowerCase().startsWith(query)) - Number(!b.toLowerCase().startsWith(query))).slice(0, 12)
      .map(v => h("option", { value: v })));
    if (!query) { render(assets); return; }
    if (/^[0-9a-f:.]+\/\d{1,3}$/i.test(query) || /^[0-9a-f:.]+-[0-9a-f:.]+$/i.test(query)) {
      timer = setTimeout(async () => {
        try {
          const scoped = await api("/assets?open=true&scope=" + encodeURIComponent(query));
          if (serial === mySerial) render(scoped);
        } catch (e) { if (serial === mySerial) results.replaceChildren(h("p", { class: "error" }, e.message)); }
      }, 180);
      return;
    }
    render(assets.filter(a => [a.address, ...(a.ports || []).flatMap(p =>
      [`${p.port}/${p.transport}`, p.port, p.service, p.product, p.version])].some(v => String(v || "").toLowerCase().includes(query))));
  };
  search.addEventListener("input", update);
  render(assets);
  return [h("div", { class: "bar" }, h("h1", {}, "Assets"),
    h("a", { href: "#/new/known-open" }, "+ service scan on open ports")),
    h("div", { class: "asset-search" }, search, suggestions, count), results];
}

async function servicesPage() {
  const obs = await api("/observations?kind=service&limit=2000");
  return [h("h1", {}, `Services (${obs.length} observations)`), table(obsHeaders, obs.map(o => obsRow(o, false)))];
}

async function profilesPage() {
  const profiles = await api("/profiles");
  return [h("h1", {}, "Profiles"), table(["profile", "status", "protocols", "ports", "rate", "description"],
    profiles.map(p => h("tr", {}, h("td", {}, p.Name), h("td", {}, state(p.Availability === "available" ? "open" : "planned")),
      h("td", {}, p.Protocols || "-"), h("td", {}, p.Ports || "-"), h("td", {}, p.Rate || "unlimited"),
      h("td", { class: "wrap" }, p.Availability === "planned" ? "planned: needs " + p.Requires : p.Description))))];
}

function packetsPage() {
  const interfaceInput = h("input", { type: "text", placeholder: "eth0, en0…", autocomplete: "off" });
  const status = h("span", { class: "muted" }, "idle");
  const count = h("span", { class: "muted" }, "0 packets");
  const rows = h("tbody", {});
  const hexInput = h("textarea", { class: "packet-hex", spellcheck: "false", placeholder: "Ethernet frame as hex bytes" });
  const editorInfo = h("span", { class: "muted" }, "Select a packet to clone it into the editor.");
  const fields = h("div", { class: "packet-fields" });
  const selectedValue = h("div", { class: "packet-selected muted" }, "Select a field to highlight its bytes.");
  const sendStatus = h("span", {});
  let watch = null, total = 0, selected = null;

  const setHex = (value, label) => {
    hexInput.value = (value.match(/.{1,2}/g) || []).join(" ");
    selected = label;
    updateEditor();
    hexInput.focus();
  };
  const updateEditor = () => {
    try {
      const parsed = parseFrame(hexInput.value);
      editorInfo.textContent = `${selected || "New frame"} · ${parsed.bytes.length} bytes`;
      const selectField = field => {
        const pairs = [...hexInput.value.matchAll(/[0-9a-f]{2}/gi)];
        const first = pairs[field.at], last = pairs[field.at + field.size - 1];
        if (first && last) {
          hexInput.focus();
          hexInput.setSelectionRange(first.index, last.index + 2);
        }
        selectedValue.textContent = `${field.name}: ${field.value} · bytes ${field.at}–${field.at + field.size - 1}`;
      };
      fields.replaceChildren(...parsed.groups.map(g => h("details", { open: true },
        h("summary", {}, g.name),
        h("div", { class: "packet-field-list" }, g.fields.map(f => h("button", {
          type: "button", class: "packet-field", onclick: () => selectField(f),
          title: `Select bytes ${f.at}–${f.at + f.size - 1}`
        }, h("span", { class: "packet-field-name" }, f.name), h("span", { class: "packet-field-value" }, f.value)))))));
      if (!parsed.groups.length) fields.replaceChildren(h("p", { class: "muted" }, "Paste or clone a frame to inspect its fields."));
    } catch (e) {
      editorInfo.textContent = e.message;
      fields.replaceChildren(h("p", { class: "error" }, e.message));
    }
    selectedValue.textContent = "Select a field to highlight its bytes.";
  };
  hexInput.addEventListener("input", updateEditor);
  updateEditor();
  const submit = async (value, device = interfaceInput.value.trim()) => {
    sendStatus.replaceChildren("");
    try {
      const result = await api("/packets/send", { body: { interface: device, hex: value } });
      sendStatus.replaceChildren(h("span", { class: "live" }, `${result.status}: ${result.bytes} bytes`));
    } catch (e) { sendStatus.replaceChildren(h("span", { class: "error" }, e.message)); }
  };
  const addPacket = (p, device) => {
    total++;
    count.textContent = `${total} packets · latest 500 shown`;
    const label = `#${total} ${p.summary}`;
    const clone = h("button", { type: "button", class: "secondary", onclick: () => setHex(p.hex, label) }, "clone");
    const resend = h("button", { type: "button", class: "secondary", onclick: () => submit(p.hex, device) }, "resend");
    const row = h("tr", { class: "new" }, h("td", {}, total), h("td", {}, fmtTime(p.timestamp)),
      h("td", { class: "wrap" }, p.summary), h("td", {}, p.length),
      h("td", {}, h("div", { class: "packet-actions" }, clone, resend)));
    rows.prepend(row);
    while (rows.children.length > 500) rows.lastChild.remove();
  };
  const stopWatch = () => {
    if (watch) watch.abort();
    watch = null;
    status.replaceChildren("stopped");
    start.disabled = false;
    stop.disabled = true;
  };
  const start = h("button", { type: "button", onclick: async () => {
    const device = interfaceInput.value.trim();
    if (!device) { status.replaceChildren(h("span", { class: "error" }, "Enter an interface.")); return; }
    const controller = new AbortController();
    watch = controller;
    pageAbort.signal.addEventListener("abort", stopWatch, { once: true });
    start.disabled = true;
    stop.disabled = false;
    status.replaceChildren(h("span", { class: "live" }, "connecting"));
    try {
      const res = await api("/packets/watch?interface=" + encodeURIComponent(device), { raw: true, signal: controller.signal });
      if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || res.statusText);
      status.replaceChildren(h("span", { class: "live" }, "watching " + device));
      const reader = res.body.getReader(), decoder = new TextDecoder();
      let buffer = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let end;
        while ((end = buffer.indexOf("\n\n")) >= 0) {
          const block = buffer.slice(0, end);
          buffer = buffer.slice(end + 2);
          const type = block.match(/^event: (.+)$/m)?.[1];
          const data = block.match(/^data: (.+)$/m)?.[1];
          if (!type || !data) continue;
          const item = JSON.parse(data);
          if (type === "packet") addPacket(item, device);
          else if (type === "sampled") status.replaceChildren(h("span", { class: "live" }, `watching ${device} · ${item.skipped} skipped at display cap`));
          else if (type === "error") throw new Error(item.error);
        }
      }
      if (!controller.signal.aborted) status.replaceChildren(h("span", { class: "error" }, "watch ended"));
    } catch (e) {
      if (e.name !== "AbortError" && !controller.signal.aborted) status.replaceChildren(h("span", { class: "error" }, e.message));
    } finally {
      if (watch === controller) {
        watch = null;
        start.disabled = false;
        stop.disabled = true;
      }
    }
  } }, "start watching");
  const stop = h("button", { type: "button", class: "secondary", disabled: true, onclick: stopWatch }, "stop");
  const clear = h("button", { type: "button", class: "secondary", onclick: () => { rows.replaceChildren(); total = 0; count.textContent = "0 packets"; } }, "clear");
  const sendEdited = h("button", { type: "button", onclick: () => submit(hexInput.value) }, "send edited frame");
  return [h("h1", {}, "Packets"), h("p", { class: "muted" }, "Watch live Ethernet frames, clone one into the hex editor, then send or resend one frame. Watching needs packetd; sending also needs --allow-packet-send."),
    h("div", { class: "bar packet-toolbar" }, h("label", {}, "interface ", interfaceInput), start, stop, clear, status, count),
    h("div", { class: "scroll packet-list" }, h("table", {}, h("thead", {}, h("tr", {}, ["#", "time", "packet", "bytes", ""].map(x => h("th", {}, x)))), rows)),
    h("h2", {}, "packet editor"), editorInfo,
    h("div", { class: "packet-split" },
      h("section", { class: "packet-pane" }, h("h3", {}, "headers and parsed values"), fields),
      h("section", { class: "packet-pane" }, h("h3", {}, "frame bytes · editable hex"), hexInput, selectedValue)),
    h("div", { class: "bar" }, sendEdited, sendStatus)];
}

function login(retry) {
  const t = h("input", { type: "password", placeholder: "API token", autocomplete: "current-password" });
  main.replaceChildren(h("h1", {}, "Token required"),
    h("form", { class: "grid", onsubmit: ev => { ev.preventDefault(); setToken(t.value.trim()); retry(); } },
      h("label", {}, "token"), t, h("div", { class: "actions" }, h("button", { type: "submit" }, "continue"))));
  t.focus();
}

async function route() {
  if (pageAbort) pageAbort.abort();
  pageAbort = new AbortController();
  const hash = location.hash.replace(/^#/, "") || "/";
  document.querySelectorAll("nav a").forEach(a => a.classList.toggle("active", a.getAttribute("href") === "#" + hash));
  const section = hash.startsWith("/scans/") ? "Scans" : hash.startsWith("/new") ? "New scan" :
    ({ "/": "Overview", "/scans": "Scans", "/assets": "Assets", "/services": "Services",
      "/packets": "Packets", "/profiles": "Profiles" })[hash] || "Workspace";
  document.getElementById("current-page").textContent = section;
  if (hash.startsWith("/scans/")) document.querySelector('nav a[href="#/scans"]').classList.add("active");
  if (hash.startsWith("/new/")) document.querySelector('nav a[href="#/new"]').classList.add("active");
  let page;
  if (hash === "/") page = dashboard();
  else if (hash === "/scans") page = scansPage();
  else if (hash === "/new") page = newScan();
  else if (hash === "/new/known-open") page = newScan("");
  else if (hash.startsWith("/new/known-open/")) page = newScan(decodeURIComponent(hash.slice(16)));
  else if (hash.startsWith("/scans/")) page = scanPage(decodeURIComponent(hash.slice(7)));
  else if (hash === "/assets") page = assetsPage();
  else if (hash === "/services") page = servicesPage();
  else if (hash === "/profiles") page = profilesPage();
  else if (hash === "/packets") page = packetsPage();
  else page = Promise.resolve([h("p", { class: "error" }, "no such page")]);
  const mine = pageAbort;
  try {
    const nodes = await page;
    if (mine === pageAbort) main.replaceChildren(...[nodes].flat());
  } catch (e) {
    if (e instanceof AuthError) return login(route);
    if (e.name === "AbortError") return;
    if (mine === pageAbort) main.replaceChildren(h("p", { class: "error" }, e.message));
  }
  if (document.getElementById("version").textContent === "Connecting…") {
    api("/version").then(v => { document.getElementById("version").textContent = "v " + v.version + " · " + v.schema; }).catch(() => {});
  }
}

window.addEventListener("hashchange", route);
route();

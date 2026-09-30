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
  if (o.kind === "device") parts.push(`${attrs["device.class"] || ""} (${(o.signals || []).length} signals)`);
  if (o.mac) parts.push("MAC " + o.mac);
  parts.push(o.reason);
  return parts.filter(Boolean).join(" | ");
}

function obsRow(o, fresh) {
  const label = o.kind === "service" ? "svc " + (o.service || "unknown") : o.kind === "device" ? "device" : o.state;
  return h("tr", { class: fresh ? "new" : "" },
    h("td", {}, o.target), h("td", {}, port(o)), h("td", {}, state(label)),
    h("td", {}, o.confidence + "%"), h("td", {}, fmtRTT(o.rtt_ns)),
    h("td", { class: "wrap" }, detail(o),
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
  const [scans, assets] = await Promise.all([api("/scans?limit=20"), api("/assets")]);
  let open = 0, services = 0;
  for (const a of assets) for (const p of a.ports || []) {
    if (p.state === "open") open++;
    if (p.service) services++;
  }
  const running = scans.filter(s => s.status === "running").length;
  return [
    h("h1", {}, "dashboard"),
    h("div", { class: "tiles" },
      [["scans", scans.length + (scans.length === 20 ? "+" : "")], ["running", running], ["hosts", assets.length],
        ["open ports", open], ["identified services", services]]
        .map(([l, n]) => h("div", { class: "tile" }, h("div", { class: "n" }, n), h("div", { class: "l" }, l)))),
    h("h2", {}, "recent scans"),
    scans.length ? table(scanHeaders, scans.map(scanRow)) : h("p", { class: "muted" }, "No scans yet. ", h("a", { href: "#/new" }, "Start one.")),
  ];
}

async function scansPage() {
  const scans = await api("/scans?limit=200");
  return [h("div", { class: "bar" }, h("h1", {}, "scans"), h("a", { href: "#/new" }, "+ new scan")),
    table(scanHeaders, scans.map(scanRow))];
}

async function newScan() {
  const profiles = (await api("/profiles")).filter(p => p.Availability === "available" && p.Name !== "research");
  const f = {};
  const input = (name, attrs = {}) => (f[name] = h("input", Object.assign({ type: "text", name }, attrs)));
  const out = h("div", {});
  f.targets = h("textarea", { name: "targets", placeholder: "10.0.0.0/24, 192.168.1.10, host.example" });
  f.profile = h("select", { name: "profile" }, profiles.map(p => h("option", { value: p.Name }, `${p.Name} — ${p.Description}`)));
  f.portsMode = h("select", {}, ["profile default", "top100", "all", "custom"].map(v => h("option", { value: v }, v)));
  const protos = ["tcp", "udp", "arp", "ndp"].map(p => ({ p, el: h("input", { type: "checkbox", value: p }) }));
  f.service = h("select", {}, ["profile default", "on", "off"].map(v => h("option", { value: v }, v)));
  f.tcpMode = h("select", {}, ["", "connect", "syn"].map(v => h("option", { value: v }, v || "profile default")));
  f.fingerprint = h("input", { type: "checkbox" });

  const request = () => {
    const r = {};
    const targets = f.targets.value.split(/[\s,]+/).filter(Boolean);
    if (targets.length) r.targets = targets;
    r.profile = f.profile.value;
    const pm = f.portsMode.value;
    if (pm === "top100" || pm === "all") r.ports = pm;
    if (pm === "custom" && f.ports.value.trim()) r.ports = f.ports.value.trim();
    const chosen = protos.filter(x => x.el.checked).map(x => x.p);
    if (chosen.length) r.protocols = chosen.join(",");
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
    if (f.service.value !== "profile default") r.service = f.service.value === "on";
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
  h("label", {}, "targets"), f.targets,
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
  return [h("h1", {}, "new scan"), form, out];
}

async function scanPage(id) {
  const summary = h("div", {});
  const status = h("span", {});
  const tbody = h("tbody", {});
  const evidence = h("div", {});
  const actions = h("span", {});
  const signal = pageAbort.signal;
  let current = await api("/scans/" + encodeURIComponent(id));
  const seen = new Set();
  let servicesSeen = 0, pending = false;
  const key = o => [o.kind, o.target, o.transport, o.port, o.probe, o.timestamp].join("|");
  const addObs = (o, fresh) => {
    const k = key(o);
    if (seen.has(k)) return;
    seen.add(k);
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
  if (current.status === "running") {
    stream(`/scans/${encodeURIComponent(id)}/events`, (type, data) => {
      if (type === "observation") addObs(data, true);
      else if (type === "scan") {
        renderSummary(data);
        if (data.status !== "running") loadStored().catch(() => {});
      }
    }, signal);
  }
  return [h("div", { class: "bar" }, h("h1", {}, "scan " + id), status, actions), summary,
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
  const assets = await api("/assets");
  const rows = [];
  for (const a of assets) {
    const ports = a.ports && a.ports.length ? a.ports : [null];
    ports.forEach((p, i) => rows.push(h("tr", {},
      h("td", {}, i === 0 ? a.address : ""),
      h("td", {}, p ? `${p.port}/${p.transport}` : "-"), h("td", {}, p ? state(p.state) : "-"),
      h("td", {}, p ? p.service || "" : ""), h("td", { class: "wrap" }, p ? [p.product, p.version].filter(Boolean).join(" ") : ""),
      h("td", {}, p ? h("a", { href: "#/scans/" + encodeURIComponent(p.scan_id) }, fmtTime(p.observed_at)) : fmtTime(a.last_seen)))));
  }
  return [h("h1", {}, `assets (${assets.length} hosts)`),
    table(["address", "port", "state", "service", "product", "last seen"], rows)];
}

async function servicesPage() {
  const obs = await api("/observations?kind=service&limit=2000");
  return [h("h1", {}, `services (${obs.length} observations)`), table(obsHeaders, obs.map(o => obsRow(o, false)))];
}

async function profilesPage() {
  const profiles = await api("/profiles");
  return [h("h1", {}, "profiles"), table(["profile", "status", "protocols", "ports", "rate", "description"],
    profiles.map(p => h("tr", {}, h("td", {}, p.Name), h("td", {}, state(p.Availability === "available" ? "open" : "planned")),
      h("td", {}, p.Protocols || "-"), h("td", {}, p.Ports || "-"), h("td", {}, p.Rate || "unlimited"),
      h("td", { class: "wrap" }, p.Availability === "planned" ? "planned: needs " + p.Requires : p.Description))))];
}

function login(retry) {
  const t = h("input", { type: "password", placeholder: "API token", autocomplete: "current-password" });
  main.replaceChildren(h("h1", {}, "token required"),
    h("form", { class: "grid", onsubmit: ev => { ev.preventDefault(); setToken(t.value.trim()); retry(); } },
      h("label", {}, "token"), t, h("div", { class: "actions" }, h("button", { type: "submit" }, "continue"))));
  t.focus();
}

async function route() {
  if (pageAbort) pageAbort.abort();
  pageAbort = new AbortController();
  const hash = location.hash.replace(/^#/, "") || "/";
  document.querySelectorAll("nav a").forEach(a => a.classList.toggle("active", a.getAttribute("href") === "#" + hash));
  let page;
  if (hash === "/") page = dashboard();
  else if (hash === "/scans") page = scansPage();
  else if (hash === "/new") page = newScan();
  else if (hash.startsWith("/scans/")) page = scanPage(decodeURIComponent(hash.slice(7)));
  else if (hash === "/assets") page = assetsPage();
  else if (hash === "/services") page = servicesPage();
  else if (hash === "/profiles") page = profilesPage();
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
  if (!document.getElementById("version").textContent) {
    api("/version").then(v => { document.getElementById("version").textContent = "v " + v.version + " · " + v.schema; }).catch(() => {});
  }
}

window.addEventListener("hashchange", route);
route();

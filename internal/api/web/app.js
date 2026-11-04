// nyxr web UI. Every value from the API may be attacker-influenced (banners,
// titles, certificates), so the DOM is built with textContent only.

import { h, svg, api, stream, page, AuthError, setToken, pref, mark, fmtTime, fmtAgo, fmtRTT, state, table, kv, port, printable, panel, download } from "./core.js";
import { createTheater } from "./theater.js";
import { createSearch, invalidateSearch, preloadSearch } from "./search.js";
import { packetView } from "./packetview.js";
import { dissect, parseHex } from "./dissect.js";
import { cmpIP } from "./map.js";

const main = document.getElementById("main");

// ---- agents ----
// nyxr runs one local agent today. Observations that name another agent
// (an `agent` field) add it to the map and this list as a remote agent, so
// multi-agent scans need no UI changes.
let agentCache = null;
async function agents() {
  if (agentCache) return agentCache;
  const local = { id: "local", name: "nyxr", status: "online", remote: false, version: "" };
  try {
    const v = await api("/version", { signal: null });
    local.version = v.version;
  } catch (e) { if (e instanceof AuthError) throw e; }
  agentCache = [local];
  renderAgentBadge(agentCache);
  return agentCache;
}
function renderAgentBadge(list) {
  const online = list.filter(a => a.status === "online").length;
  document.getElementById("agent-count").textContent = `${online} AGENT${online === 1 ? "" : "S"} ONLINE`;
  const local = list.find(a => a.id === "local");
  const v = local?.version || "";
  document.getElementById("version").textContent = v ? (/^v/i.test(v) ? v : "v" + v) : "—";
}

function agentsPanel(list, scans) {
  const running = scans.filter(s => s.status === "running");
  return panel("AGENTS", h("ul", { class: "agent-list" }, list.map(a => h("li", { class: "agent-item" + (a.status !== "online" ? " offline" : "") },
    h("span", { class: "agent-dot", "aria-hidden": "true" }),
    h("div", {}, h("strong", {}, a.name), h("small", {}, [a.remote ? "remote" : "local", a.address, a.version && (/^v/i.test(a.version) ? a.version : "v" + a.version)].filter(Boolean).join(" · "))),
    h("span", { class: "agent-state" }, a.id === "local" && running.length ? `${running.length} scan${running.length > 1 ? "s" : ""} running` : a.status)))),
  { sub: `${list.length} connected` });
}

// ---- shared renderers ----

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
  if (attrs["device.os_family"]) parts.push(`${attrs["device.os_family"]}-like stack (heuristic score ${attrs["device.os_confidence"]}/100)`);
  if (attrs["device.os_conflict"]) parts.push(attrs["device.os_conflict"]);
  if (o.tcp_stack) parts.push((o.tcp_stack.candidates || []).map(c => `${c.family}-like stack (heuristic score ${c.confidence}/100)`).join(", ") || "unknown TCP stack");
  if (o.mac) parts.push("MAC " + o.mac);
  parts.push(o.reason);
  return parts.filter(Boolean).join(" | ");
}

function obsLabel(o) {
  return o.kind === "service" ? "svc " + (o.service || "unknown") : o.kind === "script" ? "nse " + (o.nse?.id || "script") : o.kind === "device" ? "device" : o.state;
}

function obsRow(o, fresh, showTarget = true) {
  return h("tr", { class: fresh ? "new" : "" },
    showTarget ? h("td", {}, o.target) : null, h("td", { class: "mono" }, port(o)), h("td", {}, state(obsLabel(o))),
    h("td", { title: `${o.confidence_method || "heuristic"}: ${o.confidence_model || "legacy rule"}` }, `${o.confidence}/100 ${o.confidence_method || "heuristic"}`), h("td", {}, fmtRTT(o.rtt_ns)),
    h("td", { class: "wrap" }, detail(o),
      o.tcp_stack ? h("details", {}, h("summary", {}, "TCP/IP stack evidence"),
        h("p", { class: "muted" }, "OS families are heuristic claims about the responding stack; intermediaries can change headers."),
        h("pre", {}, JSON.stringify(o.tcp_stack, null, 2))) : null,
      o.nse ? h("details", {}, h("summary", {}, "NSE output"),
        h("pre", {}, o.nse.output || ""),
        (o.nse.fields && o.nse.fields.length) ? h("pre", {}, JSON.stringify(o.nse.fields, null, 2)) : null) : null,
      o.probe_updates?.length ? h("details", {}, h("summary", {}, "Detection path"),
        h("p", { class: "muted" }, o.probe_stop_reason || ""),
        table(["probe", "response", "leading hypothesis", "evidence"], o.probe_updates.map(u => {
          const leading = u.after?.[0];
          return h("tr", {}, [u.probe, u.outcome + (u.signal ? " (" + u.signal + ")" : ""),
            leading ? `${leading.family} ${(100 * leading.probability).toFixed(1)}% (${leading.method || "heuristic"})` : "",
            `${u.evidence_start + 1}–${u.evidence_end}`].map(value => h("td", {}, value)));
        })),
        h("p", { class: "muted" }, "Hypotheses guide probe selection; their scores are estimates."),
        o.probe_decisions?.length ? h("details", {}, h("summary", {}, "Probe selection"),
          table(["probe", "expected gain (bits)", "gain per cost"], o.probe_decisions.map(d =>
            h("tr", {}, [d.probe, Number(d.information_gain).toFixed(4), Number(d.score).toFixed(4)]
              .map(value => h("td", {}, value)))))) : null) : null,
      (o.evidence && o.evidence.length) ? h("details", {}, h("summary", {}, `${o.evidence.length} exchange${o.evidence.length === 1 ? "" : "s"}`),
        o.evidence.map(e => h("pre", {}, `${e.probe} [${e.layer}] ${e.matched || "unmatched"}${e.error ? " error: " + e.error : ""}\n` +
          (e.request ? "> " + printable(e.request) + "\n" : "") + (e.response ? "< " + printable(e.response) : "")))) : null,
      o.observation_id && o.evidence?.length ?
        h("div", {}, h("a", { href: "#/evidence/" + encodeURIComponent(o.observation_id) }, "Trace evidence · packets · clone probe →")) : null));
}
const obsHeaders = ["target", "port", "state", "evidence score", "rtt", "detail"];

function scanRow(s) {
  return h("tr", {},
    h("td", {}, h("a", { class: "mono", href: "#/scans/" + encodeURIComponent(s.scan_id) }, s.scan_id)),
    h("td", {}, s.profile), h("td", {}, state(s.status)), h("td", {}, fmtTime(s.started)),
    h("td", { class: "num" }, s.targets), h("td", { class: "num" }, s.observations), h("td", { class: "num" }, s.services),
    h("td", { class: "wrap error" }, s.error || ""));
}
const scanHeaders = ["scan", "profile", "status", "started", "targets", "observations", "services", ""];

// hostGroup renders one collapsible target: a summary row that opens to its
// ports. Used by the assets page and the scan page.
function hostGroup({ address, sub, chips = [], preview = "", when = "", actions = null, body, open = false, query = "" }) {
  const content = h("div", { class: "host-body" });
  let built = false;
  const toggle = h("button", { type: "button", class: "host-toggle", "aria-expanded": String(open) },
    h("span", { class: "chev", "aria-hidden": "true" }),
    h("span", { class: "host-addr" }, mark(address, query), sub ? h("small", {}, sub) : null),
    h("span", { class: "host-chips" }, chips),
    h("span", { class: "host-preview" }, mark(preview, query)),
    h("span", { class: "host-when" }, when));
  const el = h("div", { class: "host" + (open ? " open" : ""), "data-address": address }, h("div", { class: "host-row" }, toggle, actions), content);
  const set = v => {
    if (v && !built) { content.append(body()); built = true; }
    el.classList.toggle("open", v);
    toggle.setAttribute("aria-expanded", String(v));
  };
  toggle.addEventListener("click", () => set(!el.classList.contains("open")));
  if (open) set(true);
  return { el, set, content, rebuild() { if (built) content.replaceChildren(body()); } };
}

function chip(text, cls = "") { return h("span", { class: "chip " + cls }, text); }

function pageHead(title, intro, tools) {
  return h("div", { class: "page-head" }, h("div", {}, h("h1", {}, title), intro ? h("p", {}, intro) : null), tools ? h("div", { class: "page-tools" }, tools) : null);
}

// ---- pages ----

async function dashboard() {
  const signal = page.abort.signal;
  const [list, stats, scans, assets] = await Promise.all([agents(), api("/stats"), api("/scans?limit=8"), api("/assets?open=true").catch(() => [])]);
  const byIP = new Map(assets.map(a => [String(a.address), a]));
  const inspector = h("div", { class: "inspector" });
  let selectedHost = null;
  const theater = createTheater({ agents: list, title: "NETWORK MAP", height: 430, onSelect: sel => showSelection(sel),
    onAgents: l => { renderAgentBadge(l); if (!selectedHost) inspector.replaceChildren(...defaultInspector()); } });
  signal.addEventListener("abort", () => theater.destroy(), { once: true });

  const readout = (label, value, hint, live) => h("div", { class: "readout" + (live ? " live-number" : "") },
    h("span", { class: "r-label" }, label), h("strong", {}, Number(value || 0).toLocaleString()), h("small", {}, hint));
  const stripEl = h("div", { class: "readouts" });
  const renderStats = s => stripEl.replaceChildren(
    readout("SCANS", s.scans, "stored history"), readout("ACTIVE", s.running, s.running ? "running now" : "idle", s.running > 0),
    readout("HOSTS", s.hosts, "discovered"), readout("OPEN PORTS", s.open_ports, "latest state"), readout("SERVICES", s.services, "identified"));
  renderStats(stats);

  const recentPanel = () => panel("RECENT SCANS", scans.length ? h("ul", { class: "scan-list" }, scans.map(s => h("li", {},
    h("a", { href: "#/scans/" + encodeURIComponent(s.scan_id) }, h("span", { class: "mono" }, s.scan_id), h("small", {}, `${s.profile} · ${s.observations} obs · ${fmtAgo(s.started)}`)),
    state(s.status)))) : h("p", { class: "muted pad" }, "No scans yet. ", h("a", { href: "#/new" }, "Start one.")),
  { tools: h("a", { class: "tool", href: "#/scans" }, "ALL →") });

  const running = scans.find(s => s.status === "running");
  let shownScan = running || scans.find(s => s.observations > 0) || null;
  const defaultInspector = () => [
    agentsPanel(list, scans),
    shownScan ? panel("ON THE MAP", kv([["scan", h("a", { class: "mono", href: "#/scans/" + encodeURIComponent(shownScan.scan_id) }, shownScan.scan_id)],
      ["status", state(shownScan.status)], ["profile", shownScan.profile], ["started", fmtTime(shownScan.started)], ["targets", shownScan.targets],
      ["observations", shownScan.observations], ["services", shownScan.services]]), { sub: "click a host for details" }) : null,
    recentPanel()].filter(Boolean);

  function showSelection(sel) {
    selectedHost = sel.type === "host" ? sel.ip : null;
    if (sel.type !== "host") { inspector.replaceChildren(...defaultInspector()); return; }
    const a = byIP.get(sel.ip);
    const ports = (a?.ports || []).slice().sort((x, y) => (y.state === "open") - (x.state === "open") || x.port - y.port);
    inspector.replaceChildren(panel("HOST", [
      h("div", { class: "host-hero" }, h("strong", { class: "mono" }, sel.ip), a ? h("small", {}, a.identity_id) : null),
      a ? kv([["first seen", fmtTime(a.first_seen)], ["last seen", fmtTime(a.last_seen)],
        ["open ports", ports.filter(p => p.state === "open").length]]) : h("p", { class: "muted pad" }, "Not yet stored as an asset."),
      ports.length ? h("ul", { class: "port-list" }, ports.map(p => h("li", {},
        h("span", { class: "mono" }, `${p.transport}/${p.port}`), state(p.state), h("span", {}, [p.service, p.product, p.version].filter(Boolean).join(" "))))) : null,
      h("div", { class: "pad actions-row" },
        h("a", { class: "button-link secondary", href: "#/assets?host=" + encodeURIComponent(sel.ip) }, "Open in assets"),
        h("a", { class: "button-link secondary", href: "#/new/known-open/" + encodeURIComponent(sel.ip) }, "Service scan"))],
    { tools: h("button", { type: "button", class: "tool", "aria-label": "Close host details", onclick: () => { theater.map.select(null); showSelection({ type: "none" }); } }, "✕") }));
  }

  // A running scan streams live; otherwise replay the latest scan with
  // observations.
  inspector.replaceChildren(...defaultInspector());
  const openOf = ip => (byIP.get(ip)?.ports || []).filter(p => p.state === "open").length;
  if (shownScan) {
    const obs = await api(`/scans/${encodeURIComponent(shownScan.scan_id)}/observations?limit=3000`);
    const agentOf = new Map(obs.map(o => [String(o.target), o.agent || "local"]));
    theater.map.setHosts([...agentOf.keys()].map(ip => ({ ip, open: openOf(ip), agent: agentOf.get(ip) })));
    if (running) {
      theater.setLive(true);
      theater.ingest(obs, { backfill: true });
      const seen = new Set(obs.map(o => o.observation_id || o.timestamp + o.target + o.port));
      stream(`/scans/${encodeURIComponent(running.scan_id)}/events`, (type, data) => {
        if (type === "observation") {
          const k = data.observation_id || data.timestamp + data.target + data.port;
          if (seen.has(k)) return;
          seen.add(k);
          theater.ingest([data]);
          if (data.state === "open" && data.kind === "port") theater.map.addHost(String(data.target), { openPort: `${data.transport}/${data.port}` });
        } else if (type === "scan") {
          shownScan = data;
          if (data.status !== "running") {
            theater.setLive(false);
            invalidateSearch();
            api("/stats", { signal }).then(renderStats).catch(() => {});
            api("/scans?limit=8", { signal }).then(list => { scans.splice(0, scans.length, ...list); if (!selectedHost) inspector.replaceChildren(...defaultInspector()); }).catch(() => {});
          }
        }
      }, signal);
    } else {
      theater.setLive(false);
      theater.ingest(obs);
    }
  } else {
    theater.setLive(false);
    theater.map.setHosts(assets.slice(0, 64).map(a => ({ ip: String(a.address), open: openOf(String(a.address)) })));
  }

  const refresh = setInterval(async () => {
    try { renderStats(await api("/stats", { signal })); } catch { /* keep last values */ }
  }, 5000);
  signal.addEventListener("abort", () => clearInterval(refresh), { once: true });

  return h("div", { class: "overview" }, stripEl,
    h("div", { class: "overview-grid" }, h("div", { class: "stack" }, theater.mapPanel, theater.flowPanel), inspector));
}

async function scansPage() {
  const signal = page.abort.signal;
  const list = h("div", {});
  const refresh = async () => {
    const scans = await api("/scans?limit=200", { signal });
    if (!signal.aborted) list.replaceChildren(scans.length ? table(scanHeaders, scans.map(scanRow)) : h("p", { class: "muted pad" }, "No scans yet."));
  };
  await refresh();
  const interval = setInterval(() => refresh().catch(() => {}), 5000);
  signal.addEventListener("abort", () => clearInterval(interval), { once: true });
  return [pageHead("Scans", "Scan history and live activity update automatically.", h("a", { class: "button-link", href: "#/new" }, "＋ New scan")),
    panel("HISTORY", list, { flush: true })];
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
  f.portsMode = h("select", {}, ["profile default", "top100", "top1000", "top2000", "top5000", "top8387", "all", "web", "udp", "database", "custom"].map(v => h("option", { value: v }, v)));
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
      if (profiles.some(p => p.Name === "tcp-common")) f.profile.value = "tcp-common";
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
  const show = (title, obj) => out.replaceChildren(panel(title.toUpperCase(), h("pre", { class: "bare" }, JSON.stringify(obj, null, 2)), { flush: true }));
  const fail = e => out.replaceChildren(h("p", { class: "error" }, e.message));
  const planBtn = h("button", { type: "button", class: "secondary", onclick: async () => {
    try { show("plan", await api("/plan", { body: request() })); } catch (e) { fail(e); }
  } }, "Plan (dry run)");
  const reqBtn = h("button", { type: "button", class: "secondary", onclick: () =>
    show("request · same document as nyxr scan --config", request()) }, "Show request");
  const form = h("form", { class: "grid", onsubmit: async ev => {
    ev.preventDefault();
    try {
      const sc = await api("/scans", { body: request() });
      invalidateSearch();
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
  h("div", { class: "actions" }, h("button", { type: "submit" }, "▶ Start scan"), planBtn, reqBtn));
  syncKnownOpen();
  return [pageHead(knownScope !== null ? "Service scan" : "New scan", knownScope !== null ? "Probe services on ports whose latest stored state is open." : "Define targets, ports and pacing. Plan first to see what will be sent."),
    panel("PARAMETERS", form), out];
}

async function scanPage(id) {
  const signal = page.abort.signal;
  const list = await agents();
  const summary = h("div", {});
  const status = h("span", {});
  const actions = h("span", { class: "page-tools" });
  const progressTitle = h("span", { class: "scan-progress-title" });
  const progressNote = h("span", { class: "scan-progress-note" });
  const progressTrack = h("div", { class: "scan-progress-track", role: "progressbar", "aria-label": "Scan progress",
    "aria-valuemin": "0", "aria-valuemax": "100" }, h("div", { class: "scan-progress-fill" }));
  const elapsedValue = h("strong", {}, "0s");
  const targetValue = h("strong", {}, "0");
  const observationValue = h("strong", {}, "0");
  const serviceValue = h("strong", {}, "0");
  const progress = h("section", { class: "scan-progress", "aria-live": "polite" },
    h("div", { class: "scan-progress-top" }, progressTitle, progressNote), progressTrack,
    h("div", { class: "scan-progress-metrics" },
      h("span", {}, "ELAPSED ", elapsedValue), h("span", {}, "TARGETS SEEN ", targetValue),
      h("span", {}, "OBSERVATIONS ", observationValue), h("span", {}, "SERVICES ", serviceValue)));
  let current = await api("/scans/" + encodeURIComponent(id));
  const theater = createTheater({ agents: list, title: "SCAN TRAFFIC", height: 360, onAgents: renderAgentBadge,
    onSelect: sel => { if (sel.type === "host") openTarget(sel.ip); } });
  signal.addEventListener("abort", () => theater.destroy(), { once: true });

  // Observations grouped per target, ports behind a dropdown.
  const targetsBox = h("div", { class: "hosts" });
  const groups = new Map();
  const filter = h("input", { type: "search", placeholder: "Filter targets, ports, services…", "aria-label": "Filter targets" });
  const seen = new Set();
  let servicesSeen = 0, pending = false;
  const key = o => [o.kind, o.target, o.transport, o.port, o.probe, o.timestamp].join("|");
  const groupFor = ip => {
    let g = groups.get(ip);
    if (g) return g;
    g = { ip, obs: [], counts: {}, agent: "local" };
    g.ui = hostGroup({ address: ip, body: () => table(obsHeaders.slice(1), g.obs.map(o => obsRow(o, false, false)), "inner"),
      actions: h("a", { class: "tool", href: "#/assets?host=" + encodeURIComponent(ip) }, "ASSET →") });
    groups.set(ip, g);
    const order = [...groups.keys()].sort(cmpIP);
    const next = groups.get(order[order.indexOf(ip) + 1]);
    if (next && next.ui.el.isConnected) targetsBox.insertBefore(g.ui.el, next.ui.el);
    else targetsBox.append(g.ui.el);
    return g;
  };
  const refreshGroup = (g, fresh) => {
    const c = g.counts;
    const chips = [];
    if (c.open) chips.push(chip(`${c.open} open`, "open"));
    if (c.closed) chips.push(chip(`${c.closed} closed`, "closed"));
    if (c.filtered) chips.push(chip(`${c.filtered} filtered`, "filtered"));
    if (c.service) chips.push(chip(`${c.service} svc`, "svc"));
    g.ui.el.querySelector(".host-chips").replaceChildren(...chips);
    const services = [...new Set(g.obs.filter(o => o.kind === "service").map(o => `${o.port}/${o.service || "?"}${o.product ? " " + o.product : ""}`))];
    g.ui.el.querySelector(".host-preview").textContent = services.slice(0, 4).join(" · ");
    g.ui.rebuild();
    if (fresh) { g.ui.el.classList.remove("flash"); void g.ui.el.offsetWidth; g.ui.el.classList.add("flash"); }
  };
  const addObs = (o, fresh) => {
    const k = key(o);
    if (seen.has(k)) return false;
    seen.add(k);
    if (o.kind === "service" && o.fingerprint === "matched") servicesSeen++;
    const g = groupFor(String(o.target));
    g.obs.push(o);
    if (o.agent) g.agent = String(o.agent);
    const bucket = o.kind === "service" ? "service" : o.state === "open" ? "open" : o.state === "closed" ? "closed" : /filtered/.test(o.state) ? "filtered" : "other";
    g.counts[bucket] = (g.counts[bucket] || 0) + 1;
    refreshGroup(g, fresh);
    if (fresh && !pending) {
      pending = true;
      requestAnimationFrame(() => {
        pending = false;
        if (current.status === "running") renderSummary(Object.assign({}, current, {
          observations: Math.max(current.observations, seen.size), services: Math.max(current.services, servicesSeen) }));
      });
    }
    return true;
  };
  filter.addEventListener("input", () => {
    const q = filter.value.trim().toLowerCase();
    for (const g of groups.values()) {
      g.ui.el.hidden = !(!q || g.ip.includes(q) || g.obs.some(o => [port(o), o.service, o.product, o.state].some(v => String(v || "").toLowerCase().includes(q))));
      const addr = g.ui.el.querySelector(".host-addr");
      addr.replaceChildren(mark(g.ip, q));
    }
  });
  function openTarget(ip) {
    const g = groups.get(ip);
    if (!g) return;
    g.ui.set(true);
    g.ui.el.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  const renderSummary = s => {
    current = s;
    progress.classList.toggle("done", s.status === "completed");
    progress.classList.toggle("failed", s.status === "failed");
    progressTitle.textContent = s.status === "running" ? "Scan in progress" : s.status === "completed" ? "Scan complete" : "Scan " + s.status;
    progressNote.textContent = s.status === "running" ? "Live results · total completion is unavailable" :
      s.status === "completed" ? "All scan stages finished" : "Partial results remain available";
    progressTrack.setAttribute("aria-valuetext", progressTitle.textContent);
    if (s.status === "completed") progressTrack.setAttribute("aria-valuenow", "100");
    else progressTrack.removeAttribute("aria-valuenow");
    targetValue.textContent = `${groups.size} / ${s.targets}`;
    observationValue.textContent = Math.max(s.observations, seen.size).toLocaleString();
    serviceValue.textContent = Math.max(s.services, servicesSeen).toLocaleString();
    updateElapsed();
    summary.replaceChildren(kv([["profile", s.profile], ["status", state(s.status)], ["started", fmtTime(s.started)],
      ["finished", fmtTime(s.finished)], ["targets", s.targets], ["observations", s.observations], ["services", s.services],
      ["error", s.error], ["capture", s.capture ? `${s.capture.written} packets, ${s.capture.bytes} bytes in ${s.capture.path}` +
        (s.capture.dropped_queue || s.capture.dropped_limit || s.capture.backend_drops ? " (drops recorded)" : "") : undefined]]));
    status.replaceChildren(s.status === "running" ? h("span", { class: "badge live" }, "● LIVE") : state(s.status));
    actions.replaceChildren(
      s.status === "running" ? h("button", { class: "secondary", onclick: async () => {
        try { await api(`/scans/${encodeURIComponent(id)}/cancel`, { body: {} }); } catch (e) { alert(e.message); }
      } }, "Cancel scan") : "",
      s.capture && s.status !== "running" ? h("button", { class: "secondary", onclick: () => downloadCapture(id, s.capture.path) }, "Download pcapng") : "");
  };
  const updateElapsed = () => {
    const started = Date.parse(current.started);
    if (!Number.isFinite(started)) return;
    const end = current.status === "running" ? Date.now() : Date.parse(current.finished);
    const seconds = Math.max(0, Math.floor(((Number.isFinite(end) ? end : Date.now()) - started) / 1000));
    elapsedValue.textContent = seconds >= 3600 ? `${Math.floor(seconds / 3600)}h ${Math.floor(seconds % 3600 / 60)}m` :
      seconds >= 60 ? `${Math.floor(seconds / 60)}m ${seconds % 60}s` : `${seconds}s`;
  };
  const evidence = h("div", {});
  const loadStored = async initial => {
    const [obs, ev] = await Promise.all([
      api(`/scans/${encodeURIComponent(id)}/observations?limit=10000`),
      api(`/scans/${encodeURIComponent(id)}/evidence`)]);
    const fresh = obs.filter(o => addObs(o, false));
    if (initial) {
      theater.map.setHosts([...groups.values()].map(g => ({ ip: g.ip, open: g.counts.open || 0, agent: g.agent })));
      theater.ingest(fresh.slice(0, 4000), { backfill: current.status === "running" });
    }
    evidence.replaceChildren(ev.length ? table(["target", "port", "packets", "capture"], ev.map(p =>
      h("tr", {}, h("td", {}, p.target), h("td", { class: "mono" }, port(p)),
        h("td", { class: "wrap" }, p.packets.map(x => `#${x.id} ${x.direction} ${x.summary}`).join("\n")), h("td", {}, p.capture))))
      : h("p", { class: "muted pad" }, "No packet evidence. Start a scan with a pcapng capture to retain frames."));
  };
  renderSummary(current);
  await loadStored(true);
  renderSummary(current);
  theater.setLive(current.status === "running");
  const clock = setInterval(updateElapsed, 1000);
  signal.addEventListener("abort", () => clearInterval(clock), { once: true });
  if (current.status === "running") {
    stream(`/scans/${encodeURIComponent(id)}/events`, (type, data) => {
      if (type === "observation") {
        if (addObs(data, true)) {
          theater.ingest([data]);
          if (data.kind === "port" && data.state === "open") theater.map.addHost(String(data.target), { openPort: `${data.transport}/${data.port}` });
        }
      } else if (type === "scan") {
        renderSummary(data);
        if (data.status !== "running") { theater.setLive(false); invalidateSearch(); loadStored(false).catch(() => {}); }
      }
    }, signal);
    const poll = setInterval(async () => {
      try {
        const latest = await api("/scans/" + encodeURIComponent(id), { signal });
        if (signal.aborted) return;
        const wasRunning = current.status === "running";
        renderSummary(latest);
        if (wasRunning && latest.status !== "running") { theater.setLive(false); loadStored(false).catch(() => {}); }
        if (latest.status !== "running") clearInterval(poll);
      } catch { /* the event stream and existing results remain usable */ }
    }, 5000);
    signal.addEventListener("abort", () => clearInterval(poll), { once: true });
  }
  return [pageHead(h("span", {}, "Scan ", h("span", { class: "mono" }, id), " ", status), null, actions),
    progress,
    h("div", { class: "overview-grid" }, h("div", { class: "stack" }, theater.mapPanel, theater.flowPanel), h("div", { class: "inspector" }, panel("SUMMARY", summary))),
    panel("TARGETS", [h("div", { class: "panel-filter" }, filter), targetsBox], { sub: "open a target to see its ports", flush: true }),
    panel("PACKET EVIDENCE", evidence, { flush: true })];
}

async function downloadCapture(id, name) {
  try {
    const res = await api(`/scans/${encodeURIComponent(id)}/pcapng`, { raw: true });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || res.statusText);
    download(name || "capture.pcapng", await res.blob());
  } catch (e) { alert(e.message); }
}

async function assetsPage(params) {
  // Only hosts with open ports: the full inventory includes every closed
  // port ever scanned and can reach hundreds of MB.
  const all = await api("/assets?open=true");
  const search = h("input", { type: "search", placeholder: "Address, CIDR, range, port (tcp/80) or service", autocomplete: "off", "aria-label": "Filter assets" });
  const count = h("span", { class: "muted" });
  const results = h("div", { class: "hosts" });
  let rendered = [], serial = 0, timer;
  const expandAll = h("button", { type: "button", class: "tool", onclick: () => rendered.forEach(r => r.set(true)) }, "EXPAND ALL");
  const collapseAll = h("button", { type: "button", class: "tool", onclick: () => rendered.forEach(r => r.set(false)) }, "COLLAPSE");
  const focusHost = params.get("host"), focusPort = params.get("port");
  search.value = params.get("q") || focusHost || focusPort || "";

  // An exact port query (tcp/80) matches that port only, not tcp/8080.
  const exactPort = q => /^(tcp|udp|sctp)\/\d+$/.test(q);
  const portMatches = (p, q) => !!q && (exactPort(q) ? `${p.transport}/${p.port}` === q
    : [`${p.transport}/${p.port}`, p.service, p.product, p.version].some(v => String(v || "").toLowerCase().includes(q)));
  const markPort = (key, q) => exactPort(q) ? (key === q ? h("mark", {}, key) : key) : mark(key, q);

  const render = (shown, q) => {
    const list = shown;
    count.textContent = `${list.length} of ${all.length} hosts`;
    rendered = [];
    const nodes = list.slice().sort((a, b) => cmpIP(String(a.address), String(b.address))).slice(0, 1000).map(a => {
      const ip = String(a.address);
      const ports = (a.ports || []).filter(p => p.state === "open")
        .sort((x, y) => x.transport.localeCompare(y.transport) || x.port - y.port);
      const open = (a.ports || []).filter(p => p.state === "open");
      const tcp = open.filter(p => p.transport === "tcp").length, udp = open.filter(p => p.transport === "udp").length;
      const matchedPorts = ports.filter(p => portMatches(p, q));
      const expand = ip === focusHost || (matchedPorts.length > 0 && !ip.includes(q) && list.length <= 30);
      const services = [...new Set(open.map(p => p.service).filter(Boolean))];
      const g = hostGroup({
        address: ip, sub: a.identity_id, query: exactPort(q) ? "" : q, open: expand,
        chips: [open.length ? chip(`${open.length} open`, "open") : chip("no open ports", "closed"), tcp ? chip(`tcp ${tcp}`) : null, udp ? chip(`udp ${udp}`) : null],
        preview: services.slice(0, 5).join(" · "), when: fmtAgo(a.last_seen),
        actions: h("a", { class: "tool", href: "#/new/known-open/" + encodeURIComponent(ip), title: "Service scan on this host's open ports" }, "SCAN →"),
        body: () => ports.length ? table(["port", "state", "service", "product", "last seen"], ports.map(p => h("tr", { class: portMatches(p, q) ? "match" : "" },
          h("td", { class: "mono" }, markPort(`${p.transport}/${p.port}`, q)), h("td", {}, state(p.state)),
          h("td", {}, exactPort(q) ? p.service || "" : mark(p.service || "", q)), h("td", { class: "wrap" }, exactPort(q) ? [p.product, p.version].filter(Boolean).join(" ") : mark([p.product, p.version].filter(Boolean).join(" "), q)),
          h("td", {}, h("a", { href: "#/scans/" + encodeURIComponent(p.scan_id), title: p.scan_id }, fmtTime(p.observed_at))))), "inner")
          : h("p", { class: "muted pad" }, "No ports recorded."),
      });
      rendered.push(g);
      return g.el;
    });
    results.replaceChildren(...(nodes.length ? nodes : [h("p", { class: "muted pad" }, "No hosts match this filter.")]));
    if (list.length > 1000) results.append(h("p", { class: "muted pad" }, `Showing the first 1000 of ${list.length} hosts. Narrow the filter.`));
    if (focusHost) requestAnimationFrame(() => results.querySelector(`[data-address="${CSS.escape(focusHost)}"]`)?.scrollIntoView({ block: "center" }));
  };
  const update = () => {
    const q = search.value.trim().toLowerCase();
    const mySerial = ++serial;
    clearTimeout(timer);
    if (!q) { render(all, ""); return; }
    if (/^[0-9a-f:.]+\/\d{1,3}$/i.test(q) || /^[0-9a-f:.]+-[0-9a-f:.]+$/i.test(q)) {
      timer = setTimeout(async () => {
        try {
          const scoped = await api("/assets?open=true&scope=" + encodeURIComponent(q));
          if (serial === mySerial) render(scoped, "");
        } catch (e) { if (serial === mySerial) results.replaceChildren(h("p", { class: "error pad" }, e.message)); }
      }, 180);
      return;
    }
    const pm = q.match(/^(tcp|udp|sctp)\/(\d+)$/);
    render(all.filter(a => pm ? (a.ports || []).some(p => p.transport === pm[1] && String(p.port) === pm[2])
      : String(a.address).toLowerCase().includes(q) || (a.ports || []).some(p => portMatches(p, q))), q);
  };
  search.addEventListener("input", update);
  update();
  return [pageHead("Assets", "Every host with an open port. Open a host to see its ports.", h("a", { class: "button-link secondary", href: "#/new/known-open" }, "＋ Service scan on open ports")),
    panel("HOSTS", [h("div", { class: "panel-filter" }, search, count, expandAll, collapseAll), results],
      { flush: true })];
}

async function identitiesPage() {
  const [graph, relations, reviews, events, topology] = await Promise.all([
    api("/assets/identities?ports=none"), api("/assets/identity-relations"),
    api("/assets/identity-reviews"), api("/assets/identity-events"), api("/assets/topology/timeline?limit=100")]);
  const rows = graph.map(asset => h("tr", {},
    h("td", {}, h("strong", { class: "mono" }, asset.id), h("small", { class: "block muted" }, asset.global_id)),
    h("td", {}, asset.addresses.map(a => a.address).join(", ")),
    h("td", {}, [asset.profile.class, asset.profile.model, asset.profile.os].filter(Boolean).join(" · ") || "-"),
    h("td", {}, [...new Set(asset.clues.filter(c => c.kind === "capture_interface" || c.kind === "vlan_id")
      .map(c => `${c.kind}: ${c.value}`))].join(" · ") || "-"),
    h("td", {}, asset.signals.some(s => s.active) ? [...new Set(asset.signals.filter(s => s.active).map(s => `${s.kind}: ${s.value}`))].join(" · ") : "No strong signal yet"),
    h("td", {}, asset.link_confidence ? `${asset.link_confidence}/100 ${asset.link_confidence_method || "heuristic"}` : "No link"),
    h("td", {}, (asset.hypotheses || []).map(x => `${x.other_id}: ${x.blocked ? "blocked" : x.confidence + "/100 heuristic"}`).join(" · ") || "-"),
    h("td", {}, fmtTime(asset.last_seen))));
  const addresses = [...new Set(graph.flatMap(asset => asset.addresses.map(a => a.address)))].sort();
  const addressSelect = () => h("select", {}, addresses.map(a => h("option", { value: a }, a)));
  const a = addressSelect(), b = addressSelect();
  const decision = h("select", {}, ["join", "separate", "clear"].map(v => h("option", { value: v }, v)));
  const note = h("input", { type: "text", maxlength: "500", placeholder: "Reason for this review", required: true });
  const message = h("span", { class: "muted" });
  const form = h("form", { class: "grid", onsubmit: async ev => {
    ev.preventDefault();
    message.textContent = "Saving…";
    try {
      await api("/assets/identity-reviews", { body: { address_a: a.value, address_b: b.value, decision: decision.value, note: note.value } });
      await route();
    } catch (error) { message.textContent = error.message; }
  } }, h("label", {}, "First address"), a, h("label", {}, "Second address"), b,
  h("label", {}, "Decision"), decision, h("label", {}, "Reason"), note,
  h("div", { class: "actions" }, h("button", { type: "submit", disabled: addresses.length < 2 }, "Record review"), message));
  const interfaceIDs = [...new Set(topology.claims.map(c => c.interface_id))].sort();
  const topologyAddress = addressSelect();
  const topologyInterface = h("select", {}, interfaceIDs.map(id => h("option", { value: id }, id)));
  const topologyDecision = h("select", {}, ["join", "separate"].map(v => h("option", { value: v }, v)));
  const topologyVLAN = h("input", { type: "number", min: "0", max: "4094", value: "0" });
  const localStamp = date => new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  const topologyFrom = h("input", { type: "datetime-local", value: localStamp(new Date()), required: true });
  const topologyUntil = h("input", { type: "datetime-local", value: localStamp(new Date(Date.now() + 3600000)), required: true });
  const topologyNote = h("input", { type: "text", maxlength: "500", placeholder: "Evidence and reason", required: true });
  const topologyMessage = h("span", { class: "muted" });
  const topologyForm = h("form", { class: "grid", onsubmit: async ev => {
    ev.preventDefault();
    topologyMessage.textContent = "Saving…";
    try {
      await api("/assets/topology/reviews", { body: {
        address: topologyAddress.value, interface_id: topologyInterface.value,
        decision: topologyDecision.value, vlan_id: Number(topologyVLAN.value),
        valid_from: new Date(topologyFrom.value).toISOString(),
        valid_until: new Date(topologyUntil.value).toISOString(), note: topologyNote.value,
      } });
      await route();
    } catch (error) { topologyMessage.textContent = error.message; }
  } }, h("label", {}, "Address"), topologyAddress, h("label", {}, "Observed interface"), topologyInterface,
  h("label", {}, "Decision"), topologyDecision, h("label", {}, "VLAN (0 if unspecified)"), topologyVLAN,
  h("label", {}, "Valid from"), topologyFrom, h("label", {}, "Valid until"), topologyUntil,
  h("label", {}, "Evidence and reason"), topologyNote,
  h("div", { class: "actions" }, h("button", { type: "submit", disabled: !interfaceIDs.length }, "Record topology review"), topologyMessage));
  const none = text => h("p", { class: "muted pad" }, text);
  return [pageHead(`Asset identities (${graph.length})`, "Addresses join only when a device-scoped signal matches. Link and candidate scores are rule heuristics, not calibrated probabilities; shared certificate and name clues count once and conflicting strong evidence blocks a candidate."),
    panel("IDENTITIES", rows.length ? table(["asset ID", "addresses", "device profile", "observed network", "identity evidence", "link confidence", "competing candidates", "last seen"], rows)
      : none("No assets recorded yet."), { flush: true }),
    panel("REVIEW MEMBERSHIP", [form, h("p", { class: "muted" }, "A manual join keeps the addresses together; a separation blocks automatic rejoining. Clear removes the decision.")]),
    panel("SHARED CLUES", relations.length ? table(["identity", "related identity", "clue", "value"],
      relations.map(r => h("tr", {}, h("td", {}, r.left_id), h("td", {}, r.right_id), h("td", {}, r.kind), h("td", {}, r.value))))
      : none("No shared identity clues."), { flush: true }),
    panel("TEMPORAL TOPOLOGY", [none("Address and VLAN sightings are proven at the packet time only. LLDP links expire at their advertised TTL. Earlier unobserved ownership is unknown; conflicting claims stay separate."),
      topology.claims.length ? table(["observed", "interface", "address", "VLAN", "identity then", "evidence", "status"],
        topology.claims.map(claim => h("tr", {}, h("td", {}, fmtTime(claim.valid_from)),
          h("td", {}, claim.interface_id), h("td", {}, claim.address), h("td", {}, claim.vlan_id || "-"),
          h("td", {}, claim.identity_id || "unknown"), h("td", {}, claim.source.artifactID),
          h("td", {}, claim.overridden ? "reviewed separation" : claim.conflict ? "conflict" : claim.validity))))
        : none("No address/interface sightings retained."),
      topology.truncated ? none("Showing the newest 100 sightings. Use the API or CLI to inspect more.") : null], { flush: true }),
    panel("REVIEW INTERFACE MEMBERSHIP", [topologyForm, h("p", { class: "muted" }, "A reviewed join or separation has a finite valid interval. It does not merge device identities or erase packet evidence."),
      topology.reviews.length ? table(["valid from", "valid until", "address", "interface", "VLAN", "decision", "reason", "status"],
        topology.reviews.map(r => h("tr", {}, h("td", {}, fmtTime(r.valid_from)), h("td", {}, fmtTime(r.valid_until)),
          h("td", {}, r.address), h("td", {}, r.interface_id), h("td", {}, r.vlan_id || "-"),
          h("td", {}, r.decision), h("td", {}, r.note), h("td", {}, r.conflict ? "conflict" : "reviewed"))))
        : h("p", { class: "muted" }, "No interface membership reviews yet.")]),
    panel("LLDP NEIGHBORS", topology.adjacencies.length ? table(["observed", "valid until", "capture interface", "VLAN", "chassis", "port", "management address", "identity then", "evidence"],
      topology.adjacencies.map(link => h("tr", {}, h("td", {}, fmtTime(link.observed_at)),
        h("td", {}, fmtTime(link.valid_until)), h("td", {}, link.local_interface || "unknown"),
        h("td", {}, link.vlan_id || "-"), h("td", {}, link.chassis_id), h("td", {}, link.port_id),
        h("td", {}, link.management_address || "-"), h("td", {}, link.identity_id || "unknown"),
        h("td", {}, link.conflict ? "conflict · " + link.evidence_status : link.evidence_status))))
      : none("No LLDP neighbors retained."), { flush: true }),
    panel("MEMBERSHIP CHANGES", events.length ? table(["address", "from", "to", "cause", "time"],
      events.slice(-50).reverse().map(e => h("tr", {}, h("td", {}, e.address), h("td", {}, e.from_identity || "-"),
        h("td", {}, e.to_identity || "-"), h("td", {}, e.cause), h("td", {}, fmtTime(e.recorded_at)))))
      : none("No membership changes yet."), { flush: true }),
    panel("REVIEW LOG", reviews.length ? table(["addresses", "decision", "reason", "time"],
      reviews.slice(-50).reverse().map(r => h("tr", {}, h("td", {}, `${r.address_a} ↔ ${r.address_b}`),
        h("td", {}, r.decision), h("td", {}, r.note), h("td", {}, fmtTime(r.decided_at)))))
      : none("No manual reviews yet."), { flush: true })];
}

async function servicesPage() {
  const obs = await api("/observations?kind=service&limit=2000");
  return [pageHead("Services", "Evidence scores and planner percentages are engineering estimates. Open Detection path to see which exchanges changed a protocol hypothesis; product and version claims have no separate calibrated probability."),
    panel("SERVICE OBSERVATIONS", table(obsHeaders, obs.map(o => obsRow(o, false))), { sub: `${obs.length} observations`, flush: true })];
}

async function profilesPage() {
  const profiles = await api("/profiles");
  return [pageHead("Profiles", "Scan presets. Planned profiles list what they still need."),
    panel("PROFILES", table(["profile", "status", "protocols", "ports", "rate", "description"],
      profiles.map(p => h("tr", {}, h("td", { class: "mono" }, p.Name), h("td", {}, state(p.Availability === "available" ? "available" : "planned")),
        h("td", {}, p.Protocols || "-"), h("td", {}, p.Ports || "-"), h("td", {}, p.Rate || "unlimited"),
        h("td", { class: "wrap" }, p.Availability === "planned" ? "planned: needs " + p.Requires : p.Description)))), { flush: true })];
}

// pendingFrame carries one evidence frame into the packet workbench.
let pendingFrame = null;

function packetsPage() {
  const interfaceInput = h("input", { type: "text", placeholder: "eth0, en0…", autocomplete: "off", "aria-label": "Interface" });
  const status = h("span", { class: "muted" }, "idle");
  const count = h("span", { class: "flow-count" }, "0 packets");
  const rows = h("tbody", {}, h("tr", { class: "empty" }, h("td", { colspan: 7 }, "Start watching an interface to capture frames.")));
  const captured = [];
  const viewer = h("div", { class: "map-detail" }, h("p", { class: "muted pad" }, "Select a captured packet to explain it, or paste a frame into the editor."));
  const hexInput = h("textarea", { class: "packet-hex", spellcheck: "false", placeholder: "Ethernet frame as hex bytes", "aria-label": "Frame bytes as hex" });
  const editorInfo = h("span", { class: "muted" }, "Clone a packet or paste hex.");
  const sendStatus = h("span", {});
  let watch = null, total = 0, selected = null, current = -1;

  const show = (bytes, meta, idx = -1) => {
    current = idx;
    for (const r of rows.querySelectorAll("tr.sel")) r.classList.remove("sel");
    if (idx >= 0) captured[idx]?.row.classList.add("sel");
    viewer.replaceChildren(packetView({ no: meta.no, time: meta.time, bytes, origin: meta.origin, eg: [] }, {
      prev: idx > 0 ? () => openCaptured(idx - 1) : null,
      next: idx >= 0 && idx < captured.length - 1 ? () => openCaptured(idx + 1) : null,
    }));
  };
  const openCaptured = idx => {
    const p = captured[idx];
    if (!p) return;
    try { show(parseHex(p.hex), { no: p.no, time: fmtTime(p.timestamp), origin: `Captured on ${p.device}. Every value was on the wire.` }, idx); }
    catch (e) { viewer.replaceChildren(h("p", { class: "error pad" }, e.message)); }
  };
  const setHex = (value, label) => {
    hexInput.value = (value.match(/.{1,2}/g) || []).join(" ");
    selected = label;
    updateEditor();
  };
  let editTimer;
  const updateEditor = () => {
    clearTimeout(editTimer);
    editTimer = setTimeout(() => {
      try {
        const bytes = parseHex(hexInput.value);
        editorInfo.textContent = `${selected || "New frame"} · ${bytes.length} bytes`;
        if (bytes.length) show(bytes, { no: "✎", origin: `${selected || "Edited frame"}. The explainer follows your edits.` });
      } catch (e) { editorInfo.textContent = e.message; }
    }, 120);
  };
  hexInput.addEventListener("input", () => {
    if (selected && !selected.endsWith("(edited)")) selected += " (edited)";
    updateEditor();
  });
  if (pendingFrame) {
    const frame = pendingFrame;
    pendingFrame = null;
    setHex(frame.hex, frame.label);
  }
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
    rows.querySelector("tr.empty")?.remove();
    const idx = captured.length;
    let d = null;
    try { d = dissect(parseHex(p.hex)); } catch { /* the server summary remains */ }
    const entry = Object.assign({}, p, { no: total, device });
    captured.push(entry);
    const label = `#${total} ${p.summary}`;
    const clone = h("button", { type: "button", class: "tool", onclick: e => { e.stopPropagation(); setHex(p.hex, label); hexInput.scrollIntoView({ block: "center" }); } }, "CLONE");
    const resend = h("button", { type: "button", class: "tool", onclick: e => { e.stopPropagation(); submit(p.hex, device); } }, "RESEND");
    const row = h("tr", { class: "new", tabindex: 0, onclick: () => openCaptured(idx), onkeydown: e => { if (e.key === "Enter") openCaptured(idx); } },
      h("td", {}, h("span", { class: "no" }, total)), h("td", {}, fmtTime(p.timestamp)),
      h("td", { class: "mono" }, d && d.src ? `${d.src} → ${d.dst}` : ""), h("td", {}, d ? d.protocol : ""),
      h("td", { class: "wrap" }, d ? d.info : p.summary), h("td", {}, p.length),
      h("td", {}, h("div", { class: "packet-actions" }, clone, resend)));
    entry.row = row;
    rows.append(row);
    while (rows.children.length > 500) rows.firstChild.remove();
    const scroller = rows.closest(".flow-scroll");
    if (scroller && scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight < 80) scroller.scrollTop = scroller.scrollHeight;
    if (current < 0 && !hexInput.value) openCaptured(idx);
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
    page.abort.signal.addEventListener("abort", stopWatch, { once: true });
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
  } }, "▶ Watch");
  const stop = h("button", { type: "button", class: "secondary", disabled: true, onclick: stopWatch }, "Stop");
  const clear = h("button", { type: "button", class: "secondary", onclick: () => {
    rows.replaceChildren(h("tr", { class: "empty" }, h("td", { colspan: 7 }, "Cleared.")));
    captured.length = 0; total = 0; current = -1; count.textContent = "0 packets";
  } }, "Clear");
  const sendEdited = h("button", { type: "button", onclick: () => submit(hexInput.value) }, "Send edited frame");
  return [pageHead("Packets", "Watch live Ethernet frames and click one to explain it. Clone a frame into the editor to change and send it. Watching needs packetd; sending also needs --allow-packet-send.",
    h("div", { class: "packet-toolbar" }, h("label", {}, "interface ", interfaceInput), start, stop, clear, status)),
  panel("PACKET EXPLAINER", viewer, { class: "map-panel showing-packet", flush: true }),
  panel("CAPTURE", h("div", { class: "scroll flow-scroll" }, h("table", { class: "flow" },
    h("thead", {}, h("tr", {}, ["No.", "Time", "Source → destination", "Protocol", "Info", "Bytes", ""].map(x => h("th", {}, x)))), rows)),
  { class: "flow-panel", flush: true, tools: count }),
  panel("FRAME EDITOR", [h("div", { class: "pad" }, editorInfo), hexInput, h("div", { class: "pad actions-row" }, sendEdited, sendStatus)], { flush: true })];
}

// evidencePage follows one stored claim to its retained exchanges, the
// planner decisions that cite them and the exact indexed capture packets.
// Missing or incomplete packet evidence is stated, never hidden.
const cloneLayers = new Set(["tcp", "udp", "tls"]);
async function evidencePage(id) {
  const t = await api("/evidence/trace?observation=" + encodeURIComponent(id));
  const o = t.observation, c = t.capture;
  const viewer = h("div", {});
  const showFrame = async pid => {
    try {
      const res = await api(`/scans/${encodeURIComponent(o.scan_id)}/frames?ids=${pid}`);
      if (!res.frames.length) throw new Error(`packet #${pid} is not in the capture`);
      const fr = res.frames[0];
      viewer.replaceChildren(panel("PACKET EXPLAINER", packetView({ no: "#" + pid, bytes: parseHex(fr.hex), eg: [],
        origin: h("span", {}, `Evidence packet #${pid} (${fr.direction}) from ${c.capture || "the scan capture"}. `,
          h("button", { type: "button", class: "tool", onclick: () => { pendingFrame = { hex: fr.hex, label: `evidence packet #${pid} (${fr.direction})` }; location.hash = "#/packets"; } }, "OPEN IN EDITOR →")) },
      { close: () => viewer.replaceChildren() }), { class: "map-panel showing-packet", flush: true }));
      viewer.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (e) { alert(e.message); }
  };
  const runsBox = h("div", {});
  const renderRuns = runs => runsBox.replaceChildren(runs.length ? table(["run", "mode", "status", "protocol", "exchange", "request as retained", "new scan"],
    runs.map(r => h("tr", {}, h("td", {}, r.run_id), h("td", {}, r.mode), h("td", {}, state(r.status)), h("td", {}, r.protocol),
      h("td", {}, r.source.pointer), h("td", {}, r.request_matches_evidence ? "yes" : "no (edited)"),
      h("td", {}, r.scan_id ? h("a", { href: "#/scans/" + encodeURIComponent(r.scan_id) }, r.scan_id) : "none (offline)")))) :
    h("p", { class: "muted pad" }, "No replays of this claim yet."));
  renderRuns(t.runs);
  const workbench = h("div", {});
  const clone = async index => {
    let draft;
    try { draft = await api("/evidence/clone", { body: { observation_id: o.observation_id, exchange: index } }); }
    catch (e) { workbench.replaceChildren(h("p", { class: "error" }, e.message)); return; }
    const editor = h("textarea", { class: "packet-hex", spellcheck: "false", "aria-label": "Protocol DSL definition" });
    editor.value = draft.definition;
    const target = h("input", { type: "text", placeholder: o.target, autocomplete: "off" });
    const result = h("div", {});
    const run = async (mode, dryRun) => {
      result.replaceChildren(h("span", { class: "muted" }, "working…"));
      const body = { observation_id: o.observation_id, exchange: index, definition: editor.value, mode, dry_run: dryRun };
      if (mode === "live") body.target = target.value.trim();
      try {
        const r = await api("/probes/replay", { body });
        if (dryRun) {
          result.replaceChildren(kv([["mode", r.mode], ["protocol", `${r.protocol} (${r.schema})`], ["target", `${r.target} ${r.transport}/${r.port}`],
            ["traffic", r.connections ? `${r.connections} connection` : "none: retained response served from memory"],
            ["timeout", `${r.timeout_ns / 1e6} ms`], ["max send", `${r.max_send_bytes} bytes`], ["max receive", `${r.max_receive_bytes} bytes`]]));
          return;
        }
        const ev = r.result.evidence?.[0];
        result.replaceChildren(kv([["run", r.run_id], ["status", state(r.status)], ["error", r.error],
          ["request", r.request_matches_evidence ? "same bytes as retained" : "differs from the retained request"],
          ["reason", r.result.reason], ["new scan", r.scan_id]]),
        ev ? h("pre", {}, (ev.request ? "> " + printable(ev.request) + "\n" : "") + (ev.response ? "< " + printable(ev.response) : "")) : null);
        renderRuns((await api("/evidence/trace?observation=" + encodeURIComponent(id))).runs);
      } catch (e) { result.replaceChildren(h("p", { class: "error" }, e.message)); }
    };
    const live = h("button", { type: "button", class: "secondary", onclick: () => {
      if (confirm(`Send the edited probe to ${o.target} ${o.transport}/${o.port}? This contacts the target.`)) run("live", false);
    } }, "Live resend");
    workbench.replaceChildren(panel(`PROBE WORKBENCH · EXCHANGE ${index + 1}`, [
      h("p", { class: "muted pad" }, "Offline replay feeds the retained response to the edited parser and sends nothing. A live resend opens one connection to the original target only; it needs an API token and serve --allow-packet-send, and is stored as a new scan. The original evidence never changes."),
      editor,
      h("div", { class: "pad actions-row" },
        h("button", { type: "button", class: "secondary", onclick: () => run("offline", true) }, "Dry run"),
        h("button", { type: "button", onclick: () => run("offline", false) }, "Offline replay"),
        h("label", {}, "original target ", target), live),
      result], { flush: true }));
    workbench.scrollIntoView({ behavior: "smooth" });
  };
  const exchanges = t.exchanges.map(x => h("tr", {},
    h("td", {}, x.index + 1), h("td", {}, x.probe), h("td", {}, x.layer),
    h("td", {}, state(x.matched ? "matched" : "unmatched"), x.error ? h("div", { class: "error" }, x.error) : null),
    h("td", {}, x.completeness, x.truncated ? " · truncated" : ""), h("td", {}, `${x.request_bytes} / ${x.response_bytes}`),
    h("td", {}, (x.decisions || []).map(d => "#" + (d + 1)).join(" ")),
    h("td", {}, h("div", { class: "packet-actions" }, (x.packets || []).map(pid =>
      h("button", { type: "button", class: "tool", title: "Explain this packet", onclick: () => showFrame(pid) }, "#" + pid)))),
    h("td", {}, cloneLayers.has(x.layer) ? h("button", { type: "button", class: "tool", onclick: () => clone(x.index) }, "CLONE PROBE") : "")));
  const decisions = (o.probe_updates || []).map((u, i) => h("tr", {}, h("td", {}, "#" + (i + 1)), h("td", {}, u.probe),
    h("td", {}, u.outcome + (u.signal ? ` (${u.signal})` : "")),
    h("td", {}, u.after?.[0] ? `${u.after[0].family} ${(100 * u.after[0].probability).toFixed(1)}%` : ""),
    h("td", {}, `${u.evidence_start + 1}–${u.evidence_end}`)));
  return [pageHead("Evidence trace", null, h("a", { class: "button-link secondary", href: "#/scans/" + encodeURIComponent(o.scan_id) }, "← scan " + o.scan_id)),
    panel("CLAIM", kv([["claim", `${o.kind} ${o.service || ""}`.trim()], ["target", `${o.target} ${port(o)}`], ["claim status", state(o.claim_status)],
      ["evidence score", `${o.confidence}/100 ${o.confidence_method || "heuristic"}`], ["reason", o.reason],
      ["source", o.source ? o.source.artifactID : "not sealed"]])),
    decisions.length ? panel("DECISIONS", table(["step", "probe", "response", "leading hypothesis", "exchanges"], decisions), { flush: true }) : null,
    panel("EXCHANGES", t.exchanges.length ? table(["#", "probe", "layer", "outcome", "completeness", "bytes req / resp", "decisions", "packets (by time)", ""], exchanges)
      : h("p", { class: "muted pad" }, "No exchanges were retained."), { flush: true }),
    panel(h("span", {}, "PACKETS ", state(c.status)), [
      (c.reasons || []).map(r => h("p", { class: "error pad" }, r)),
      c.capture ? h("p", { class: "muted pad" }, `${c.capture} · ${c.capture_artifact_id || "no artifact ID"}`) : null,
      (c.packets || []).length ? table(["id", "time", "direction", "bytes", "summary", ""], c.packets.map(p => h("tr", {},
        h("td", {}, "#" + p.id), h("td", {}, fmtTime(p.timestamp)), h("td", {}, p.direction), h("td", {}, p.length),
        h("td", { class: "wrap" }, p.summary),
        h("td", {}, h("button", { type: "button", class: "tool", onclick: () => showFrame(p.id) }, "EXPLAIN"))))) : null,
      h("p", { class: "muted pad" }, "Packet IDs are exact pcapng epb_packetid values. Their association with an exchange uses capture time and is an inference.")], { flush: true }),
    viewer,
    panel("REPLAYS", runsBox, { flush: true }), workbench];
}

// HORIZON: opt-in experiment runs. Run IDs and every report field come from
// the API and are rendered as text only.
const horizonHeaders = ["run", "mode", "state", "experiment", "target", "ports", "created", "packets", "conclusion", ""];

function horizonRow(r, refresh) {
  const cancel = r.state === "running" ? h("button", { class: "tool", type: "button", onclick: async () => {
    try { await api(`/horizon/runs/${encodeURIComponent(r.id)}/cancel`, { body: {} }); } catch (e) { alert(e.message); }
    refresh();
  } }, "CANCEL") : null;
  return h("tr", {}, h("td", {}, h("a", { class: "mono", href: "#/horizon/" + encodeURIComponent(r.id) }, r.id.slice(0, 12))), h("td", {}, r.mode),
    h("td", {}, state(r.state)), h("td", {}, r.experiment), h("td", {}, r.target), h("td", {}, (r.ports || []).join(", ")),
    h("td", {}, fmtTime(r.createdAt)), h("td", {}, r.packetsTx), h("td", {}, r.comparison ? r.comparison.conclusion : (r.error || "")), h("td", {}, cancel));
}

async function horizonPage() {
  const signal = page.abort.signal;
  let caps;
  try { caps = await api("/horizon", { signal }); } catch (e) {
    if (e instanceof AuthError) throw e;
    return [pageHead("HORIZON", e.message)];
  }
  const list = h("div", {}, h("p", { class: "muted pad" }, "Loading runs…"));
  const metrics = h("pre", { class: "bare" });
  const refresh = async () => {
    const [{ runs }, text] = await Promise.all([api("/horizon/runs", { signal }), api("/horizon/metrics", { signal, raw: true }).then(r => r.text())]);
    if (signal.aborted) return;
    list.replaceChildren(runs.length ? h("div", { class: "scroll" }, h("table", {}, h("thead", {}, h("tr", {}, horizonHeaders.map(x => h("th", {}, x)))),
      h("tbody", {}, runs.map(r => horizonRow(r, refresh))))) : h("p", { class: "muted pad" }, "No retained runs. Create runs with POST /api/v1/horizon/runs."));
    metrics.textContent = text.split("\n").filter(l => l && !l.startsWith("#")).join("\n");
    if (runs.some(r => r.state === "running")) setTimeout(() => { if (!signal.aborted) refresh().catch(() => {}); }, 2000);
  };
  await refresh();
  const kill = h("button", { class: "danger", type: "button", onclick: async () => {
    if (!confirm("Engage the HORIZON kill switch? All runs stop and the API refuses new runs until the server restarts.")) return;
    try { await api("/horizon/stop", { body: {} }); } catch (e) { alert(e.message); }
    refresh();
  } }, "Kill switch");
  return [pageHead("HORIZON", `Enabled modes: ${caps.modes.join(", ")}. Statements are observed, inferred or unresolved; nothing here is a topology claim.`, kill),
    panel("RUNS", list, { flush: true }), panel("METRICS", metrics, { flush: true })];
}

// horizonTimeline plots every trial by send time and arm, colored by response.
function horizonTimeline(report) {
  const trials = (report.trials || []).filter(t => t.sentAt && !t.sentAt.startsWith("0001"));
  if (!trials.length) return h("p", { class: "muted pad" }, "No transmitted trials.");
  const t0 = Date.parse(trials[0].sentAt), span = Math.max(1, Date.parse(trials[trials.length - 1].sentAt) - t0);
  const arms = ["control", "treatment", "reference"], width = 760, left = 90, row = 34;
  const tones = { "syn-ack": "open", "rst-ack": "closed", "icmp-error": "lost", "no-response": "muted" };
  const chart = svg("svg", { viewBox: `0 0 ${width} ${arms.length * row + 40}`, role: "img", "aria-label": "trial timeline", class: "timeline" });
  arms.forEach((arm, i) => chart.append(svg("text", { x: 4, y: 24 + i * row, class: "tl-label" }, arm)));
  for (const t of trials) {
    const x = left + (Date.parse(t.sentAt) - t0) / span * (width - left - 10), y = 20 + arms.indexOf(t.arm) * row;
    const c = svg("circle", { cx: x.toFixed(1), cy: y, r: t.probe ? 3 : 5, class: "tl-dot t-" + (tones[t.features.responseClass] || "probe") });
    c.append(svg("title", {}, `pair ${t.pair} ${t.arm} probe ${t.probe || 0}: ${t.features.responseClass}${(t.qualityFlags || []).length ? " [" + t.qualityFlags.join(", ") + "]" : ""}`));
    chart.append(c);
  }
  chart.append(svg("text", { x: left, y: arms.length * row + 32, class: "tl-label" }, `0 … ${(span / 1000).toFixed(1)} s · ${Object.keys(tones).join(" / ")}`));
  return chart;
}

async function horizonRunPage(id) {
  const signal = page.abort.signal;
  const path = "/horizon/runs/" + encodeURIComponent(id);
  const run = await api(path, { signal });
  const out = [pageHead(h("span", {}, "HORIZON run ", h("span", { class: "mono" }, run.id.slice(0, 12)))),
    panel("RUN", kv([["mode", run.mode], ["state", state(run.state)], ["experiment", run.experiment],
      ["experiment hash", run.experimentHash], ["target", run.target], ["ports", (run.ports || []).join(", ")], ["created", fmtTime(run.createdAt)],
      ["finished", run.finishedAt ? fmtTime(run.finishedAt) : ""], ["packets", run.packetsTx], ["trials", run.trials], ["stop", run.stopReason || ""],
      ["curtailment", run.curtailment ? `${run.curtailment.decision} after ${run.curtailment.pairs} pairs` : ""], ["error", run.error || ""], ["report SHA-256", run.reportSha256 || ""]]))];
  if (run.state === "running") {
    setTimeout(() => { if (!signal.aborted) route(); }, 2000);
    return out.concat(h("p", { class: "muted" }, "Running; this page refreshes."));
  }
  if (!run.reportSha256) return out;
  const [env, graph] = await Promise.all([api(path + "/report", { signal }), api(path + "/evidence-graph", { signal }).catch(e => ({ error: e.message }))]);
  const c = env.report.comparison;
  const save = h("button", { class: "secondary", type: "button", onclick: () =>
    download(`horizon-${run.id}.json`, new Blob([JSON.stringify(env, null, 2)], { type: "application/json" })) }, "Download sealed report");
  out.push(h("div", { class: "actions-row" }, save), panel("TIMELINE", horizonTimeline(env.report)),
    panel("CONTROL / TREATMENT COMPARISON", kv([["status", state(c.status)], ["conclusion", c.conclusion], ["metric", c.metric || "SACK permission"],
      ["complete pairs", c.completePairs], ["discordant pairs", c.discordantPairs], ["exact paired p-value", c.pValue]])));
  if (graph.error) out.push(h("p", { class: "error" }, graph.error));
  else out.push(panel("EVIDENCE GRAPH", [graph.hypotheses.length ? table(["hypothesis", "family", "subject", "status", "statement", "observation grade", "support", "against"],
    graph.hypotheses.map(x => h("tr", {}, [x.id, x.family, x.subject, state(x.status), x.statement, x.observationGrade, x.support.length, x.against.length].map(v => h("td", {}, v)))))
    : h("p", { class: "muted pad" }, "This run supports no hypothesis on its own."),
  h("p", { class: "muted pad" }, `Not evaluated: ${graph.notEvaluated.join(", ") || "none"}. Probabilities stay null until calibrated.`)], { flush: true }));
  out.push(panel("LIMITATIONS", h("ul", {}, env.report.limitations.map(l => h("li", {}, l)))));
  return out;
}

function login(retry) {
  const t = h("input", { type: "password", placeholder: "API token", autocomplete: "current-password" });
  main.replaceChildren(pageHead("Token required", "This server requires a bearer token. It stays in this browser tab only."),
    panel("SIGN IN", h("form", { class: "grid", onsubmit: ev => { ev.preventDefault(); setToken(t.value.trim()); agentCache = null; retry(); } },
      h("label", {}, "token"), t, h("div", { class: "actions" }, h("button", { type: "submit" }, "Continue")))));
  t.focus();
}

// ---- shell ----

const SECTIONS = { "/": "Overview", "/scans": "Scans", "/new": "New scan", "/assets": "Assets", "/identities": "Identities",
  "/services": "Services", "/packets": "Packets", "/profiles": "Profiles", "/horizon": "HORIZON", "/evidence": "Evidence" };

async function route() {
  if (page.abort) page.abort.abort();
  page.abort = new AbortController();
  const full = location.hash.replace(/^#/, "") || "/";
  const [hash, qs] = full.split("?");
  const params = new URLSearchParams(qs || "");
  const top = "/" + (hash.split("/")[1] || "");
  document.querySelectorAll(".rail a").forEach(a => {
    const on = a.getAttribute("href").slice(1) === top;
    a.classList.toggle("active", on);
    if (on) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  });
  const section = SECTIONS[top] || "Workspace";
  document.getElementById("current-page").textContent = section;
  document.title = section === "Overview" ? "nyxr" : `${section} · nyxr`;
  let pageP;
  if (hash === "/") pageP = dashboard();
  else if (hash === "/scans") pageP = scansPage();
  else if (hash === "/new") pageP = newScan();
  else if (hash === "/new/known-open") pageP = newScan("");
  else if (hash.startsWith("/new/known-open/")) pageP = newScan(decodeURIComponent(hash.slice(16)));
  else if (hash.startsWith("/scans/")) pageP = scanPage(decodeURIComponent(hash.slice(7)));
  else if (hash === "/assets") pageP = assetsPage(params);
  else if (hash === "/identities") pageP = identitiesPage();
  else if (hash === "/services") pageP = servicesPage();
  else if (hash === "/profiles") pageP = profilesPage();
  else if (hash === "/packets") pageP = packetsPage();
  else if (hash.startsWith("/evidence/")) pageP = evidencePage(decodeURIComponent(hash.slice(10)));
  else if (hash === "/horizon") pageP = horizonPage();
  else if (hash.startsWith("/horizon/")) pageP = horizonRunPage(decodeURIComponent(hash.slice(9)));
  else pageP = Promise.resolve([h("p", { class: "error" }, "No such page.")]);
  const mine = page.abort;
  main.setAttribute("aria-busy", "true");
  // Large stores can take a while; say so instead of showing the old page.
  const slow = setTimeout(() => { if (mine === page.abort) main.replaceChildren(h("div", { class: "loading" }, h("span", { class: "loading-bar" }), `Loading ${section.toLowerCase()}…`)); }, 150);
  try {
    const nodes = await pageP;
    if (mine === page.abort) { main.replaceChildren(...[nodes].flat(Infinity).filter(Boolean)); window.scrollTo(0, 0); }
  } catch (e) {
    if (e instanceof AuthError) return login(route);
    if (e.name === "AbortError") return;
    if (mine === page.abort) main.replaceChildren(h("p", { class: "error" }, e.message));
  } finally {
    clearTimeout(slow);
    if (mine === page.abort) main.removeAttribute("aria-busy");
  }
  if (!agentCache) agents().catch(() => {});
  if (!searchPreloaded) { searchPreloaded = true; preloadSearch(); }
}
let searchPreloaded = false;

function initTheme() {
  const buttons = document.querySelectorAll("[data-set-theme]");
  const dark = matchMedia("(prefers-color-scheme: dark)");
  const apply = t => {
    if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
    else delete document.documentElement.dataset.theme;
    const effective = t === "light" || t === "dark" ? t : dark.matches ? "dark" : "light";
    buttons.forEach(b => b.setAttribute("aria-pressed", String(b.dataset.setTheme === effective)));
  };
  apply(pref("theme"));
  buttons.forEach(b => b.addEventListener("click", () => { pref("theme", b.dataset.setTheme); apply(b.dataset.setTheme); }));
  dark.addEventListener("change", () => apply(pref("theme")));
}

document.getElementById("search-slot").replaceWith(createSearch().el);
initTheme();
window.addEventListener("hashchange", route);
route();

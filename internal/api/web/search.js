// Global search with autocompletion over hosts, ports, services, products,
// scans and pages. Every occurrence of the query is marked, so "80" colors
// tcp/80, 80.1.2.3, 10.80.1.2 and 10.1.180.2 alike.

import { h, api, mark, AuthError } from "./core.js";
import { cmpIP } from "./map.js";

const PAGES = [
  ["Overview", "#/", "network map, live traffic"], ["Scans", "#/scans", "scan history"], ["New scan", "#/new", "launch a scan"],
  ["Assets", "#/assets", "hosts and ports"], ["Identities", "#/identities", "asset identity graph"], ["Services", "#/services", "service observations"],
  ["Packets", "#/packets", "live capture and packet editor"], ["Profiles", "#/profiles", "scan profiles"], ["HORIZON", "#/horizon", "experiment runs"],
];

let index = null, loading = null, loadedAt = 0;

async function load() {
  if (index && Date.now() - loadedAt < 30000) return index;
  if (loading) return loading;
  loading = (async () => {
    const [assets, scans] = await Promise.all([api("/assets?open=true", { signal: null }), api("/scans?limit=200", { signal: null }).catch(() => [])]);
    const ports = new Map(), services = new Map(), products = new Map();
    for (const a of assets) {
      for (const p of a.ports || []) {
        const key = `${p.transport}/${p.port}`;
        const e = ports.get(key) || { key, transport: p.transport, port: p.port, open: 0, seen: 0 };
        e.seen++;
        if (p.state === "open") e.open++;
        ports.set(key, e);
        if (p.service) services.set(p.service, (services.get(p.service) || 0) + 1);
        const prod = [p.product, p.version].filter(Boolean).join(" ");
        if (prod) products.set(prod, (products.get(prod) || 0) + 1);
      }
    }
    index = {
      hosts: assets.map(a => ({ ip: String(a.address), open: (a.ports || []).filter(p => p.state === "open").length, id: a.identity_id })),
      ports: [...ports.values()], services: [...services], products: [...products], scans,
    };
    loadedAt = Date.now();
    return index;
  })().finally(() => { loading = null; });
  return loading;
}

export function invalidateSearch() { loadedAt = 0; }
export function preloadSearch() { load().catch(() => {}); }

function suggestions(ix, raw) {
  const q = raw.trim().toLowerCase();
  if (!q) return [];
  const out = [];
  const num = /^\d{1,5}$/.test(q) ? Number(q) : null;
  const pm = q.match(/^(tcp|udp|sctp)\s*\/\s*(\d{1,5})$/) || q.match(/^(\d{1,5})\s*\/\s*(tcp|udp|sctp)$/);
  const exact = pm ? (isNaN(pm[1]) ? `${pm[1]}/${pm[2]}` : `${pm[2]}/${pm[1]}`) : null;

  // Ranking: an exact port (tcp/80, udp/80) leads, then hosts, then other
  // ports containing the query. Closed-only ports are noise (a scan stores
  // thousands), so they appear only for an exact port query. A query with a
  // dot or colon reads as an address, so hosts come first.
  const portItem = (p, group) => ({ group, label: p.key, q: exact || q,
    meta: p.open ? `${p.open} host${p.open > 1 ? "s" : ""} open` : `seen on ${p.seen}, none open`, href: "#/assets?port=" + encodeURIComponent(p.key), icon: "⊡" });
  const byPort = (a, b) => (b.open > 0) - (a.open > 0) || a.port - b.port || a.transport.localeCompare(b.transport);
  const exactPorts = ix.ports.filter(p => p.key === exact || (num !== null && p.port === num)).sort(byPort);
  const typedKey = q.replace(/\s+/g, "");
  const otherPorts = ix.ports.filter(p => p.open && !exactPorts.includes(p) &&
    (num !== null ? String(p.port).includes(q) : /^[a-z]+\/?\d*$/.test(typedKey) && p.key.startsWith(typedKey))).sort(byPort);

  const hosts = ix.hosts.filter(x => x.ip.toLowerCase().includes(q))
    .sort((a, b) => (b.ip.startsWith(q) - a.ip.startsWith(q)) || (b.open > 0) - (a.open > 0) || cmpIP(a.ip, b.ip));
  const hostItems = hosts.slice(0, 8).map(x => ({ group: "Hosts", label: x.ip, q, meta: x.open ? `${x.open} open port${x.open > 1 ? "s" : ""}` : "no open ports",
    href: "#/assets?host=" + encodeURIComponent(x.ip), icon: "▣" }));
  if (hosts.length > 8) hostItems.push({ group: "Hosts", label: `All ${hosts.length} hosts matching “${raw.trim()}”`, q: "", meta: "", href: "#/assets?q=" + encodeURIComponent(raw.trim()), icon: "…", noComplete: true });

  // Exact ports (tcp/80, udp/80) stay together. They lead unless none is
  // open anywhere and a host address starts with the query ("127" means
  // 127.0.0.1, not a closed tcp/127), or the query reads as an address.
  const portItems = exactPorts.slice(0, 4).map(p => portItem(p, "Ports"));
  const morePorts = otherPorts.slice(0, 5).map(p => portItem(p, portItems.length ? "More ports" : "Ports"));
  const hostsFirst = /[.:]/.test(q) || (!exactPorts.some(p => p.open) && hosts.some(x => x.ip.startsWith(q)));
  if (hostsFirst) out.push(...hostItems, ...portItems, ...morePorts);
  else out.push(...portItems, ...hostItems, ...morePorts);

  for (const [name, n] of ix.services.filter(([s]) => s.toLowerCase().includes(q)).slice(0, 4))
    out.push({ group: "Services", label: name, q, meta: `${n} port${n > 1 ? "s" : ""}`, href: "#/assets?q=" + encodeURIComponent(name), icon: "≋" });
  for (const [name, n] of ix.products.filter(([s]) => s.toLowerCase().includes(q)).slice(0, 4))
    out.push({ group: "Products", label: name, q, meta: `${n} port${n > 1 ? "s" : ""}`, href: "#/assets?q=" + encodeURIComponent(name), icon: "◈" });
  for (const s of ix.scans.filter(s => s.scan_id.toLowerCase().includes(q) || (s.profile || "").toLowerCase().includes(q)).slice(0, 4))
    out.push({ group: "Scans", label: s.scan_id, q, meta: `${s.profile} · ${s.status}`, href: "#/scans/" + encodeURIComponent(s.scan_id), icon: "⌁" });
  for (const [name, href, hint] of PAGES.filter(([n, , hint]) => n.toLowerCase().includes(q) || hint.includes(q)).slice(0, 3))
    out.push({ group: "Pages", label: name, q, meta: hint, href, icon: "→" });
  return out;
}

export function createSearch() {
  const input = h("input", { type: "search", class: "gsearch-input", placeholder: "Search hosts, ports, services, scans…", autocomplete: "off",
    spellcheck: "false", role: "combobox", "aria-expanded": "false", "aria-controls": "gsearch-list", "aria-autocomplete": "list", "aria-label": "Search" });
  const list = h("div", { class: "gsearch-list", id: "gsearch-list", role: "listbox", hidden: true });
  const kbd = h("kbd", { class: "gsearch-kbd" }, "/");
  const wrap = h("div", { class: "gsearch" }, h("div", { class: "gsearch-box" },
    h("span", { class: "gsearch-icon", "aria-hidden": "true" }, "⌕"), input, kbd, list));
  let items = [], active = -1, serial = 0;

  const close = () => { list.hidden = true; input.setAttribute("aria-expanded", "false"); active = -1; };
  // Navigating clears the box so the next search starts fresh.
  const go = href => {
    close();
    input.value = "";
    input.blur();
    if (location.hash === href) window.dispatchEvent(new HashChangeEvent("hashchange")); else location.hash = href;
  };
  const setActive = i => {
    active = i;
    [...list.querySelectorAll(".gs-item")].forEach((el, j) => {
      el.classList.toggle("active", j === i);
      el.setAttribute("aria-selected", j === i ? "true" : "false");
      if (j === i) { el.scrollIntoView({ block: "nearest" }); input.setAttribute("aria-activedescendant", el.id); }
    });
  };

  const render = async () => {
    const mine = ++serial, raw = input.value;
    if (!raw.trim()) { close(); return; }
    let ix;
    if (!index) {
      list.replaceChildren(h("div", { class: "gs-empty" }, h("span", { class: "loading-bar" }), "Loading search index… large inventories take a moment."));
      list.hidden = false;
    }
    try { ix = await load(); } catch (e) {
      if (mine !== serial) return;
      list.replaceChildren(h("div", { class: "gs-empty" }, e instanceof AuthError ? "Sign in to search." : "Search unavailable: " + e.message));
      list.hidden = false;
      return;
    }
    if (mine !== serial) return;
    items = suggestions(ix, raw);
    const groups = [];
    let last = null, n = 0;
    for (const it of items) {
      if (it.group !== last) { groups.push(h("div", { class: "gs-group" }, it.group)); last = it.group; }
      const i = n++;
      groups.push(h("a", { class: "gs-item", id: "gs-" + i, role: "option", href: it.href,
        onmousedown: e => e.preventDefault(), onclick: e => { e.preventDefault(); go(it.href); }, onmousemove: () => active !== i && setActive(i) },
      h("span", { class: "gs-icon", "aria-hidden": "true" }, it.icon), h("span", { class: "gs-label" }, mark(it.label, it.q)), h("span", { class: "gs-meta" }, it.meta)));
    }
    if (!items.length) groups.push(h("div", { class: "gs-empty" }, `Nothing matches “${raw.trim()}”. Press Enter to search assets.`));
    list.replaceChildren(...groups);
    list.hidden = false;
    input.setAttribute("aria-expanded", "true");
    setActive(items.length ? 0 : -1);
  };

  input.addEventListener("input", render);
  input.addEventListener("focus", () => { load().catch(() => {}); if (input.value.trim()) render(); });
  input.addEventListener("blur", () => setTimeout(close, 120));
  input.addEventListener("keydown", e => {
    if (e.key === "ArrowDown") { e.preventDefault(); if (list.hidden) render(); else setActive(Math.min(items.length - 1, active + 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive(Math.max(0, active - 1)); }
    else if (e.key === "Tab" && !e.shiftKey && !list.hidden && items[active] && !items[active].noComplete && input.value !== items[active].label) {
      // Tab accepts the highlighted suggestion into the box.
      e.preventDefault();
      input.value = items[active].label;
      render();
    }
    else if (e.key === "Enter") {
      e.preventDefault();
      if (active >= 0 && items[active]) go(items[active].href);
      else if (input.value.trim()) go("#/assets?q=" + encodeURIComponent(input.value.trim()));
    } else if (e.key === "Escape") { if (!list.hidden) close(); else input.blur(); }
  });
  document.addEventListener("keydown", e => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName) || document.activeElement?.isContentEditable;
    if ((e.key === "/" && !typing) || (e.key.toLowerCase() === "k" && (e.metaKey || e.ctrlKey))) { e.preventDefault(); input.focus(); input.select(); }
  });
  return { el: wrap, input };
}

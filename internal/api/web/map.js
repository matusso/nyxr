// Network map: agents on the left, targets grouped by subnet on the right,
// and animated packets between them. The map draws what it is told; the
// theater (theater.js) decides when packets fly. A subnet frame is only a
// grouping by address prefix: it does not claim a router exists there.

import { svg } from "./core.js";

const COS = Math.cos(Math.PI / 6), SIN = 0.5;
const CELL_W = 104, CELL_H = 92, PAD = 16, HEAD = 26, GAP = 26, MIN_FRAME_W = 236;
export const MAX_HOSTS = 64;

export function subnetOf(ip) {
  if (ip.includes(":")) {
    const parts = ip.split("::")[0].split(":").slice(0, 4);
    while (parts.length < 4) parts.push("0");
    return parts.join(":") + "::/64";
  }
  const p = ip.split(".");
  return `${p[0]}.${p[1]}.${p[2]}.0/24`;
}

// iso draws an isometric box; (x, y) is the bottom-front corner.
function isoBox(g, x, y, w, d, ht, cls = "") {
  const P = (a, b, c) => [x + (a - b) * COS, y + (a + b) * SIN * -1 + 0 - c].map(v => v.toFixed(1));
  // a runs right-back, b runs left-back.
  const pts = arr => arr.map(p => P(...p).join(",")).join(" ");
  g.append(
    svg("polygon", { class: "face-l " + cls, points: pts([[0, 0, 0], [0, d, 0], [0, d, ht], [0, 0, ht]]) }),
    svg("polygon", { class: "face-r " + cls, points: pts([[0, 0, 0], [w, 0, 0], [w, 0, ht], [0, 0, ht]]) }),
    svg("polygon", { class: "face-t " + cls, points: pts([[0, 0, ht], [w, 0, ht], [w, d, ht], [0, d, ht]]) }));
  return P;
}

function agentGlyph(remote) {
  const g = svg("g", { class: "glyph agent-glyph" });
  g.append(svg("ellipse", { class: "shadow", cx: 0, cy: 4, rx: 46, ry: 14 }));
  const P = isoBox(g, 0, 0, 40, 28, 16);
  // Front panel slots and LEDs.
  for (let i = 0; i < 4; i++) {
    const [x1, y1] = P(6 + i * 7, 0, 5), [x2, y2] = P(10 + i * 7, 0, 5);
    g.append(svg("line", { class: "detail", x1, y1, x2, y2 }));
  }
  const [lx, ly] = P(4, 0, 11);
  g.append(svg("circle", { class: "led", cx: lx, cy: ly, r: 2 }));
  // Antenna (remote agents) or sensor dome (local agent).
  const [ax, ay] = P(30, 18, 16);
  if (remote) {
    g.append(svg("line", { class: "detail", x1: ax, y1: ay, x2: ax, y2: +ay - 22 }), svg("circle", { class: "led", cx: ax, cy: +ay - 24, r: 2.5 }));
  } else {
    const [cx, cy] = P(20, 14, 16);
    g.append(svg("path", { class: "dome", d: `M${+cx - 10},${cy} a10,6 0 0 1 20,0 z` }));
  }
  return g;
}

function hostGlyph() {
  const g = svg("g", { class: "glyph host-glyph" });
  g.append(svg("ellipse", { class: "shadow", cx: 0, cy: 3, rx: 22, ry: 7 }));
  const P = isoBox(g, 0, 0, 16, 16, 30);
  for (let i = 0; i < 3; i++) {
    const [x1, y1] = P(3, 0, 8 + i * 7), [x2, y2] = P(13, 0, 8 + i * 7);
    g.append(svg("line", { class: "detail", x1, y1, x2, y2 }));
  }
  const [lx, ly] = P(0, 4, 24);
  g.append(svg("circle", { class: "led host-led", cx: lx, cy: ly, r: 1.6 }));
  return g;
}

export function createMap({ onSelect } = {}) {
  const root = svg("svg", { class: "netmap", role: "img", "aria-label": "Network map of agents and scanned targets" });
  const defs = svg("defs");
  const grid = svg("pattern", { id: "map-grid", width: 24, height: 24, patternUnits: "userSpaceOnUse" });
  grid.append(svg("path", { d: "M24 0H0V24", class: "grid-line" }));
  defs.append(grid);
  const gBg = svg("rect", { class: "grid-bg", x: -5000, y: -5000, width: 10000, height: 10000, fill: "url(#map-grid)" });
  const gFrames = svg("g"), gEdges = svg("g"), gNodes = svg("g"), gPackets = svg("g", { class: "packets" });
  root.append(defs, gBg, gFrames, gEdges, gNodes, gPackets);

  const agents = new Map();  // id -> {id, name, address, remote, el, x, y}
  const hosts = new Map();   // ip -> {ip, open, el, x, y, group, last}
  const hidden = new Map();  // subnet -> count of hosts beyond MAX_HOSTS
  const links = new Map();   // subnet -> Set of agent ids that probed it
  const flights = [];
  let W = 900, H = 460, selected = null, query = "", raf = 0, paused = false, last = 0, speed = 1;
  let layoutPending = false;

  const ro = new ResizeObserver(entries => {
    const r = entries[0].contentRect;
    if (r.width > 10) { W = r.width; H = Math.max(320, r.height); scheduleLayout(); }
  });

  function scheduleLayout() {
    if (layoutPending) return;
    layoutPending = true;
    requestAnimationFrame(() => { layoutPending = false; layout(); });
  }

  function setAgents(list) {
    for (const a of list) {
      if (agents.has(a.id)) Object.assign(agents.get(a.id), a);
      else agents.set(a.id, { ...a });
    }
    scheduleLayout();
  }

  function addHost(ip, info = {}) {
    let n = hosts.get(ip);
    if (!n) {
      if (hosts.size >= MAX_HOSTS) {
        // Evict the idlest host without open ports, else count it as hidden.
        let victim = null;
        for (const x of hosts.values()) if (!x.open && x !== selected && (!victim || x.last < victim.last)) victim = x;
        if (!victim) { const s = subnetOf(ip); hidden.set(s, (hidden.get(s) || 0) + 1); scheduleLayout(); return null; }
        hosts.delete(victim.ip);
        const s = victim.group; hidden.set(s, (hidden.get(s) || 0) + 1);
      }
      n = { ip, open: 0, last: 0, group: subnetOf(ip) };
      hosts.set(ip, n);
      scheduleLayout();
    }
    link(n.group, info.agent);
    if (info.open !== undefined && info.open !== n.open) { n.open = info.open; scheduleLayout(); }
    // Streamed open ports are counted once each, on top of the stored count.
    if (info.openPort && !(n.openSet ||= new Set()).has(info.openPort)) {
      n.openSet.add(info.openPort);
      if (n.openSet.size > n.open) { n.open = n.openSet.size; scheduleLayout(); }
    }
    if (info.label !== undefined) n.label = info.label;
    return n;
  }

  function link(group, agent) {
    const id = agent || [...agents.keys()][0] || "local";
    if (!links.has(group)) links.set(group, new Set());
    if (!links.get(group).has(id)) { links.get(group).add(id); scheduleLayout(); }
  }

  function setHosts(list) {
    hosts.clear(); hidden.clear(); links.clear();
    const sorted = [...list].sort((a, b) => (b.open || 0) - (a.open || 0));
    for (const x of sorted) addHost(x.ip, x);
    scheduleLayout();
  }

  function layout() {
    gFrames.replaceChildren(); gEdges.replaceChildren(); gNodes.replaceChildren();
    const al = [...agents.values()];
    // Wide: agents in a column on the left with ports to their right.
    // Narrow (phones): agents in a row on top with ports beneath them.
    const narrow = W < 640;
    al.forEach((a, i) => {
      a.i = i;
      if (narrow) { a.x = 64 + i * 120; a.y = 80; a.port = { x: a.x, y: a.y + 60 }; }
      else a.x = 96;
    });
    // Subnet frames, packed in shelves right of the agents' backbone.
    const groups = new Map();
    for (const n of hosts.values()) {
      if (!groups.has(n.group)) groups.set(n.group, []);
      groups.get(n.group).push(n);
    }
    for (const s of hidden.keys()) if (!groups.has(s)) groups.set(s, []);
    const left = narrow ? 26 + al.length * 6 : 250 + al.length * 8, right = W - (narrow ? 12 : 24);
    const avail = Math.max(MIN_FRAME_W, right - left);
    const frames = [...groups.entries()].sort((a, b) => cmpIP(a[0].split("/")[0], b[0].split("/")[0])).map(([name, list]) => {
      list.sort((a, b) => cmpIP(a.ip, b.ip));
      const count = list.length + (hidden.get(name) ? 1 : 0);
      const cols = Math.max(1, Math.min(count, Math.floor((avail - PAD * 2) / CELL_W), Math.ceil(Math.sqrt(count * 1.6))));
      const rows = Math.ceil(count / cols) || 1;
      return { name, list, cols, rows, w: Math.max(MIN_FRAME_W, cols * CELL_W + PAD * 2), h: rows * CELL_H + PAD + HEAD };
    });
    let x = left, y = narrow ? 172 : 30, shelf = 0, row = [];
    const center = () => {
      const used = row.length ? row[row.length - 1].x + row[row.length - 1].w - left : 0;
      const off = Math.max(0, (avail - used) / 2);
      for (const f of row) f.x += off;
      row = [];
    };
    for (const f of frames) {
      if (x + f.w > right && x > left) { center(); x = left; y += shelf + GAP; shelf = 0; }
      f.x = x; f.y = y; x += f.w + GAP; shelf = Math.max(shelf, f.h);
      row.push(f);
    }
    center();
    const contentH = Math.max(H, y + shelf + 30);
    const shift = contentH === H && !narrow ? Math.max(0, (H - (y + shelf) - 30) / 2) : 0;
    root.setAttribute("viewBox", `0 0 ${W} ${contentH}`);
    root.style.height = (contentH === H ? H : Math.min(contentH, H * (narrow ? 4 : 1.8))) + "px";
    if (!narrow) al.forEach((a, i) => { a.y = contentH / 2 + (i - (al.length - 1) / 2) * 150; a.port = { x: a.x + 50, y: a.y - 8 }; });

    for (const f of frames) {
      f.y += shift;
      f.hub = { x: f.x, y: f.y + HEAD / 2 };
      const total = f.list.length + (hidden.get(f.name) || 0);
      gFrames.append(
        svg("rect", { class: "subnet-frame", x: f.x, y: f.y, width: f.w, height: f.h }),
        svg("rect", { class: "subnet-head", x: f.x, y: f.y, width: f.w, height: HEAD }),
        svg("text", { class: "subnet-label", x: f.x + 14, y: f.y + 17 }, f.name),
        svg("text", { class: "subnet-count", x: f.x + f.w - 10, y: f.y + 17, "text-anchor": "end" }, `${total} HOST${total === 1 ? "" : "S"}`));
      // Inside the frame: a spine down the left edge and one rail per row.
      const spineX = f.x + 8;
      const railY = r => f.y + HEAD + r * CELL_H + 6;
      const rowEnd = new Map();
      f.list.forEach((n, i) => {
        const r = Math.floor(i / f.cols);
        n.x = f.x + PAD + (i % f.cols) * CELL_W + CELL_W / 2;
        n.y = f.y + HEAD + r * CELL_H + 62;
        n.frame = f;
        n.inside = [{ x: spineX, y: f.hub.y }, { x: spineX, y: railY(r) }, { x: n.x, y: railY(r) }, { x: n.x, y: n.y - 40 }];
        rowEnd.set(r, Math.max(rowEnd.get(r) || 0, n.x));
        gEdges.append(svg("line", { class: "spoke", x1: n.x, y1: railY(r), x2: n.x, y2: n.y - 44 }));
      });
      if (rowEnd.size) {
        gEdges.append(svg("line", { class: "spoke", x1: f.hub.x, y1: f.hub.y, x2: spineX, y2: f.hub.y }),
          svg("line", { class: "spoke", x1: spineX, y1: f.hub.y, x2: spineX, y2: railY(Math.max(...rowEnd.keys())) }));
        for (const [r, endX] of rowEnd) gEdges.append(svg("line", { class: "spoke", x1: spineX, y1: railY(r), x2: endX, y2: railY(r) }));
      }
      if (hidden.get(f.name)) {
        const i = f.list.length;
        const hx = f.x + PAD + (i % f.cols) * CELL_W + CELL_W / 2, hy = f.y + HEAD + Math.floor(i / f.cols) * CELL_H + 50;
        gNodes.append(svg("text", { class: "more-label", x: hx, y: hy, "text-anchor": "middle" }, `+${hidden.get(f.name)} more`));
      }
      // Orthogonal trunks: agent → its backbone → the gap above the shelf →
      // down the column gap → the subnet port. Only agents that probed
      // this subnet get a trunk.
      f.routes = new Map();
      for (const a of al) {
        if (!(links.get(f.name) || new Set()).has(a.id)) continue;
        const bx = narrow ? 10 + a.i * 6 : left - 40 - a.i * 8, port = a.port, gy = f.y - GAP / 2 - a.i * 3, cx = f.x - GAP / 2 + a.i * 3;
        const pts = [port, { x: bx, y: port.y }, { x: bx, y: gy }, { x: cx, y: gy }, { x: cx, y: f.hub.y }, { x: f.hub.x, y: f.hub.y }];
        f.routes.set(a.id, pts);
        gEdges.append(svg("path", { class: "trunk", d: "M" + pts.map(p => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join("L") }));
      }
      gEdges.append(svg("rect", { class: "subnet-port", x: f.hub.x - 5, y: f.hub.y - 5, width: 10, height: 10 }));
    }

    for (const a of al) {
      const g = svg("g", { class: "node agent" + (a.status === "offline" ? " offline" : ""), transform: `translate(${a.x},${a.y})`, tabindex: 0,
        role: "button", "aria-label": `Agent ${a.name}`, onclick: () => onSelect && onSelect({ type: "agent", id: a.id }) });
      g.append(agentGlyph(a.remote),
        svg("text", { class: "node-title", x: 0, y: 34, "text-anchor": "middle" }, a.name),
        svg("text", { class: "node-sub", x: 0, y: 48, "text-anchor": "middle" }, a.address || (a.remote ? "remote agent" : "local agent")));
      gEdges.append(svg("circle", { class: "agent-port", cx: a.port.x, cy: a.port.y, r: 3.5 }));
      a.el = g;
      gNodes.append(g);
    }
    for (const n of hosts.values()) {
      if (n.x === undefined) continue;
      const g = svg("g", { class: "node host" + (n.open ? " has-open" : "") + (n === selected ? " selected" : ""), transform: `translate(${n.x},${n.y})`,
        tabindex: 0, role: "button", "aria-label": `Host ${n.ip}`,
        onclick: () => { select(n.ip); onSelect && onSelect({ type: "host", ip: n.ip }); },
        onkeydown: e => { if (e.key === "Enter") { select(n.ip); onSelect && onSelect({ type: "host", ip: n.ip }); } } });
      const ring = svg("ellipse", { class: "ring", cx: 0, cy: -2, rx: 26, ry: 10 });
      g.append(ring, hostGlyph());
      const label = svg("text", { class: "node-title host-ip", x: 0, y: 20, "text-anchor": "middle" });
      labelText(label, n.ip);
      g.append(label);
      if (n.open) g.append(svg("text", { class: "node-sub", x: 0, y: 32, "text-anchor": "middle" }, `${n.open} open`));
      n.el = g; n.ring = ring;
      gNodes.append(g);
    }
  }

  function labelText(el, ip) {
    el.replaceChildren();
    const q = query.toLowerCase();
    if (!q || !ip.includes(q)) { el.textContent = ip; return; }
    let from = 0, at;
    while ((at = ip.indexOf(q, from)) >= 0) {
      if (at > from) el.append(svg("tspan", {}, ip.slice(from, at)));
      el.append(svg("tspan", { class: "hit" }, ip.slice(at, at + q.length)));
      from = at + q.length;
    }
    if (from < ip.length) el.append(svg("tspan", {}, ip.slice(from)));
  }

  function select(ip) {
    if (selected?.el) selected.el.classList.remove("selected");
    selected = ip ? hosts.get(ip) || null : null;
    if (selected?.el) selected.el.classList.add("selected");
  }

  function setQuery(q) {
    query = q || "";
    for (const n of hosts.values()) if (n.el) labelText(n.el.querySelector(".host-ip"), n.ip);
  }

  // fly launches one packet. dir "out": agent → host, "in": host → agent.
  function fly({ agent = "local", target, dir = "out", tone = "probe", lost = false, duration = 900, onArrive }) {
    const a = agents.get(agent) || agents.values().next().value;
    const n = hosts.get(target) || addHost(target, { agent: a?.id });
    if (!a || !n) return;
    n.last = performance.now();
    link(n.group, a.id);
    if (layoutPending || n.x === undefined || !n.frame?.routes?.has(a.id)) { layout(); layoutPending = false; }
    const route = n.frame.routes.get(a.id) || [a.port, n.frame.hub];
    const path = [...route, ...n.inside];
    const pts = dir === "out" ? path : path.slice().reverse();
    const dot = svg("g", { class: "pkt t-" + tone });
    dot.append(svg("rect", { x: -6, y: -4, width: 12, height: 8, rx: 1.5 }));
    gPackets.append(dot);
    flights.push({ pts, len: pathLen(pts), dot, t: 0, dur: duration, lost, dir, n, a, tone, onArrive });
    if (dir === "in") pulse(n, tone);
    start();
  }

  function pulse(n, tone) {
    if (!n.el) return;
    n.el.classList.remove("hit-open", "hit-closed", "hit-probe", "hit-lost", "hit-request", "hit-response");
    void n.el.getBBox?.();
    n.el.classList.add("hit-" + tone);
    clearTimeout(n.pulseTimer);
    n.pulseTimer = setTimeout(() => n.el && n.el.classList.remove("hit-" + tone), 700);
  }

  function frame(now) {
    raf = 0;
    const dt = last ? Math.min(64, now - last) : 16;
    last = now;
    if (!paused) {
      for (let i = flights.length - 1; i >= 0; i--) {
        const f = flights[i];
        f.t += dt * speed / f.dur;
        const stop = f.lost ? 0.62 : 1;
        if (f.t >= stop) {
          if (f.lost) {
            const p = pointAt(f.pts, f.len, stop);
            const x = svg("text", { class: "lost-mark", x: p.x, y: p.y + 4, "text-anchor": "middle" }, "×");
            gPackets.append(x);
            setTimeout(() => x.remove(), 900);
          } else if (f.dir === "out") pulse(f.n, f.tone);
          f.dot.remove();
          flights.splice(i, 1);
          f.onArrive && f.onArrive();
          continue;
        }
        const p = pointAt(f.pts, f.len, ease(f.t));
        f.dot.setAttribute("transform", `translate(${p.x.toFixed(1)},${p.y.toFixed(1)})`);
        if (f.lost) f.dot.style.opacity = String(Math.max(0, 1 - Math.max(0, f.t - 0.35) / 0.27));
      }
    }
    if (flights.length) start(); else last = 0;
  }
  function start() { if (!raf) raf = requestAnimationFrame(frame); }

  return {
    el: root,
    mount(container) { ro.observe(container); },
    destroy() { ro.disconnect(); if (raf) cancelAnimationFrame(raf); flights.length = 0; },
    setAgents, setHosts, addHost, fly, select, setQuery,
    clearFlights() { for (const f of flights) f.dot.remove(); flights.length = 0; },
    setPaused(v) { paused = v; if (!v) { last = 0; start(); } },
    setSpeed(v) { speed = v; },
    get busy() { return flights.length; },
    hosts, agents,
  };
}

function ease(t) { return t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2; }
function pathLen(pts) { let s = 0; for (let i = 1; i < pts.length; i++) s += Math.hypot(pts[i].x - pts[i - 1].x, pts[i].y - pts[i - 1].y); return s; }
function pointAt(pts, len, t) {
  let d = t * len;
  for (let i = 1; i < pts.length; i++) {
    const seg = Math.hypot(pts[i].x - pts[i - 1].x, pts[i].y - pts[i - 1].y);
    if (d <= seg || i === pts.length - 1) {
      const k = seg ? Math.min(1, d / seg) : 1;
      return { x: pts[i - 1].x + (pts[i].x - pts[i - 1].x) * k, y: pts[i - 1].y + (pts[i].y - pts[i - 1].y) * k };
    }
    d -= seg;
  }
  return pts[pts.length - 1];
}
export function cmpIP(a, b) {
  const v4 = s => s.includes(".") && !s.includes(":") ? s.split(".").reduce((n, x) => n * 256 + Number(x), 0) : null;
  const x = v4(a), y = v4(b);
  if (x !== null && y !== null) return x - y;
  if (x !== null) return -1;
  if (y !== null) return 1;
  return a.localeCompare(b);
}

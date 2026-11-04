// Theater: the network map, the packet flow table and the packet explainer
// working together. Replay mode steps through a stored scan; live mode
// animates observations as the scan streams them.

import { h, fmtBytes, panel } from "./core.js";
import { createMap } from "./map.js";
import { exchange, protoOf, tone as toneOf } from "./simulate.js";
import { packetView } from "./packetview.js";

const TONES = [["probe", "Probe"], ["open", "Open / reply"], ["closed", "Closed"], ["lost", "No reply"], ["request", "Service probe"], ["response", "Service reply"]];
const MAX_ROWS = 1500;

export function createTheater({ agents, title = "NETWORK MAP", onSelect, onAgents, height } = {}) {
  const map = createMap({ onSelect: sel => { onSelect && onSelect(sel); } });
  map.setAgents(agents);
  const agentName = id => (agents.find(a => a.id === id) || agents[0] || { name: id }).name;

  const queue = [];     // every packet known, in time order
  let head = 0;         // next packet to emit
  let playing = true, speed = 1, live = false, timer = 0, t0 = null, shown = [], current = -1;
  const rows = h("tbody", {});
  const empty = h("tr", { class: "empty" }, h("td", { colspan: 8 }, "No packets on the wire yet."));
  rows.append(empty);

  const mode = h("span", { class: "badge" }, "REPLAY");
  const stage = h("div", { class: "map-stage" }, map.el);
  if (height) stage.style.minHeight = height + "px";
  const detail = h("div", { class: "map-detail", hidden: true });
  const mapPanel = panel(title, [stage, detail], { class: "map-panel", flush: true,
    tools: [mode, h("span", { class: "legend" }, TONES.map(([k, l]) => h("span", { class: "lg t-" + k }, h("i", {}), l)))] });
  map.mount(stage);

  const speedBtn = h("button", { type: "button", class: "tool", title: "Playback speed", onclick: () => {
    speed = { 1: 2, 2: 4, 4: 8, 8: 0.5, 0.5: 1 }[speed];
    speedBtn.textContent = speed + "×";
    map.setSpeed(speed);
  } }, "1×");
  const playBtn = h("button", { type: "button", class: "tool primary", onclick: () => setPlaying(!playing) }, "❚❚ PAUSE");
  const stepBtn = h("button", { type: "button", class: "tool", title: "Emit the next packet", onclick: () => { setPlaying(false); emit(true); } }, "STEP");
  const resetBtn = h("button", { type: "button", class: "tool", title: "Restart the replay", onclick: () => reset() }, "↻ RESET");
  const note = h("span", { class: "flow-note" }, "Reconstructed from observations");
  const counter = h("span", { class: "flow-count" }, "0 packets");
  const flowPanel = panel("PACKET FLOW", h("div", { class: "scroll flow-scroll" }, h("table", { class: "flow" },
    h("thead", {}, h("tr", {}, ["No.", "Time", "Agent", "Source", "Destination", "Protocol", "Info", "Size"].map(x => h("th", {}, x)))), rows)),
  { class: "flow-panel", flush: true, tools: [note, counter, speedBtn, stepBtn, playBtn, resetBtn] });

  function setPlaying(v) {
    if (v && !live && queue.length && head >= queue.length) { reset(); return; }
    playing = v;
    playBtn.textContent = v ? "❚❚ PAUSE" : "▶ PLAY";
    map.setPaused(!v);
    clearTimeout(timer);
    timer = 0;
    if (v) schedule(0);
  }

  function reset() {
    clearTimeout(timer);
    timer = 0;
    head = 0; shown = []; current = -1;
    rows.replaceChildren(empty);
    map.clearFlights();
    closeDetail();
    counter.textContent = "0 packets";
    setPlaying(true);
  }

  function schedule(delay) {
    clearTimeout(timer);
    if (!playing || head >= queue.length) {
      timer = 0;
      // A replay plays once; RESET plays it again.
      if (!live && head >= queue.length && queue.length && playing) setPlaying(false);
      return;
    }
    timer = setTimeout(() => {
      timer = 0;
      // In live mode a backlog is drained quickly so the table keeps up.
      const backlog = queue.length - head;
      const burst = live && backlog > 40 ? Math.min(backlog - 20, 25) : 0;
      for (let i = 0; i < burst; i++) emit(false, true);
      emit(false);
      const next = queue[head];
      const prev = queue[head - 1];
      const gap = next && prev ? (next.t - prev.t) * 1000 : 0;
      // Replays of large scans speed up so a full pass stays around a minute.
      const pace = Math.max(50, Math.min(420, 60000 / Math.max(1, queue.length)));
      const base = live ? (backlog > 10 ? 60 : 160) : prev && next && prev.ex === next.ex ? pace * 0.6 : pace;
      schedule(Math.max(40, Math.min(1200, Math.max(base, gap)) / speed));
    }, delay);
  }

  function emit(stepping, quiet = false) {
    const p = queue[head];
    if (!p) return;
    head++;
    p.no = head;
    if (!quiet && (stepping || playing)) map.fly({ agent: p.agent, target: p.target, dir: p.dir, tone: p.tone, lost: p.lost, duration: 900 });
    else map.addHost(p.target);
    addRow(p);
  }

  function addRow(p) {
    if (empty.isConnected) empty.remove();
    const idx = shown.length;
    shown.push(p);
    const src = p.dir === "out" ? agentName(p.agent) : p.target, dst = p.dir === "out" ? p.target : agentName(p.agent);
    const tr = h("tr", { class: "t-" + p.tone + " new", tabindex: 0, onclick: () => openDetail(idx),
      onkeydown: e => { if (e.key === "Enter") openDetail(idx); } },
    h("td", {}, h("span", { class: "no" }, p.no)), h("td", {}, p.t.toFixed(3) + "s"), h("td", {}, agentName(p.agent)),
    h("td", {}, src), h("td", {}, dst), h("td", {}, p.protocol),
    h("td", { class: "info" }, p.info, p.lost ? h("span", { class: "s s-filtered" }, " · no reply") : null, p.verdict ? h("span", { class: "verdict s s-" + p.verdict.replace(/[^a-z]/g, "") }, p.verdict) : null),
    h("td", {}, fmtBytes(p.bytes.length)));
    p.row = tr;
    rows.append(tr);
    counter.textContent = `${shown.length.toLocaleString()} packets`;
    while (rows.children.length > MAX_ROWS) rows.firstChild.remove();
    const scroller = rows.closest(".flow-scroll");
    if (scroller && scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight < 80) scroller.scrollTop = scroller.scrollHeight;
  }

  function openDetail(idx) {
    const p = shown[idx];
    if (!p) return;
    current = idx;
    for (const r of rows.querySelectorAll("tr.sel")) r.classList.remove("sel");
    p.row?.classList.add("sel");
    const o = p.obs;
    const origin = h("span", {}, p.captured ? p.captured : [
      "Reconstructed from observation ", h("code", {}, o.observation_id || `${o.target} ${o.transport}/${o.port || ""}`),
      ` (${o.reason || o.state}). Addresses, ports, flags, verdict and payload bytes come from the scan.`,
      o.observation_id && o.evidence?.length ? [" ", h("a", { href: "#/evidence/" + encodeURIComponent(o.observation_id) }, "Trace evidence →")] : null]);
    const view = packetView({ no: p.no, time: p.t.toFixed(3) + "s", bytes: p.bytes, eg: p.eg, origin, tone: p.tone }, {
      prev: idx > 0 ? () => openDetail(idx - 1) : null,
      next: idx < shown.length - 1 ? () => openDetail(idx + 1) : null,
      close: closeDetail,
    });
    detail.replaceChildren(view);
    detail.hidden = false;
    stage.hidden = true;
    mapPanel.classList.add("showing-packet");
    view.focus({ preventScroll: true });
    map.select(p.target);
  }
  function closeDetail() {
    current = -1;
    detail.hidden = true;
    stage.hidden = false;
    mapPanel.classList.remove("showing-packet");
    for (const r of rows.querySelectorAll("tr.sel")) r.classList.remove("sel");
  }

  // ingest converts observations to packets and appends them in time order.
  function ingest(observations, opts = {}) {
    const added = [];
    for (const o of observations) {
      const ts = Date.parse(o.timestamp) / 1000;
      if (!Number.isFinite(ts)) continue;
      const agent = String(o.agent || "local");
      if (!agents.some(a => a.id === agent)) {
        agents.push({ id: agent, name: agent, status: "online", remote: true });
        map.setAgents(agents);
        onAgents && onAgents(agents);
      }
      const pk = exchange(o, agents.find(a => a.id === agent));
      if (!pk.length) continue;
      if (t0 === null) t0 = ts - (o.rtt_ns || 0) / 1e9;
      const rtt = (o.rtt_ns || 0) / 1e9;
      pk.forEach((p, i) => {
        const t = Math.max(0, (i === 0 ? ts - rtt : i === 1 ? ts : ts + i * 0.00005) - t0);
        added.push(Object.assign(p, { t, agent, target: String(o.target), obs: o, ex: o.observation_id || o.timestamp,
          protocol: protoOf(p), tone: toneOf(p) }));
      });
    }
    added.sort((a, b) => a.t - b.t);
    if (opts.backfill) {
      // Already-finished traffic: list it without animation.
      for (const p of added) { queue.push(p); head = queue.length; p.no = head; map.addHost(p.target); addRow(p); }
      return;
    }
    // Keep the queue time-ordered for packets not yet emitted.
    for (const p of added) {
      let i = queue.length;
      while (i > head && queue[i - 1].t > p.t) i--;
      queue.splice(i, 0, p);
    }
    if (playing && !timer) schedule(0);
  }

  return {
    map, mapPanel, flowPanel,
    ingest,
    setLive(v) {
      // When a live scan ends, list the backlog at once instead of animating
      // it packet by packet for minutes after the scan finished.
      if (live && !v) { while (head < queue.length) emit(false, true); setPlaying(false); }
      live = v;
      mode.textContent = v ? "● LIVE" : "REPLAY";
      mode.classList.toggle("live", v);
      resetBtn.disabled = v;
      note.textContent = v ? "Live · reconstructed from streamed observations" : "Replay · reconstructed from stored observations";
    },
    clear() { queue.length = 0; t0 = null; reset(); },
    play() { setPlaying(true); },
    destroy() { clearTimeout(timer); map.destroy(); },
    get count() { return queue.length; },
    get current() { return current; },
  };
}

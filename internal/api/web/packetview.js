// Packet explainer: a header strip, a byte-proportional layer bar, the
// dissected fields with plain-language notes, and a hex dump. Selecting a
// field highlights its bytes and hovering a byte highlights its field.

import { h, fmtBytes } from "./core.js";
import { dissect, LAYER_COLORS, tcpFlagNames } from "./dissect.js";

export function packetTitle(d) {
  const app = d.layers.find(l => l.kind === "app");
  if (app) return app.name + " · " + (d.info || "").slice(0, 60);
  if (d.protocol === "TCP") return "TCP " + tcpFlagNames(d.flags).join("+");
  if (d.protocol === "ARP") return /Who has/.test(d.info) ? "ARP request" : "ARP reply";
  if (d.protocol === "UDP") return d.layers.some(l => l.kind === "data") ? "UDP datagram" : "UDP probe";
  return d.protocol + (d.info && d.info !== d.protocol ? " · " + d.info : "");
}

// view renders one packet. p: { no, time, bytes, eg, origin, tone }.
// nav: { prev, next, close } callbacks (optional).
export function packetView(p, nav = {}) {
  const d = dissect(p.bytes, { eg: p.eg });
  const total = d.bytes.length;
  const byteEls = [];
  const fieldEls = [];
  let pinned = null;

  const highlight = (field, on) => {
    for (let i = field.at; i < field.at + field.size && i < byteEls.length; i++) byteEls[i].classList.toggle("hl", on);
    field.el?.classList.toggle("hl", on);
  };
  const select = field => {
    if (pinned) highlight(pinned, false);
    pinned = pinned === field ? null : field;
    if (pinned) {
      highlight(pinned, true);
      byteEls[pinned.at]?.scrollIntoView({ block: "nearest" });
    }
  };

  const bar = h("div", { class: "layer-bar", role: "img", "aria-label": d.layers.map(l => `${l.name} ${l.size} bytes`).join(", ") },
    d.layers.map(l => {
      const seg = h("div", { class: "layer-seg", title: `${l.name} · ${l.size} bytes` },
        h("i", {}), h("b", {}, l.name), h("span", {}, l.size));
      seg.style.flexGrow = String(Math.max(l.size, total / 14));
      seg.style.setProperty("--c", LAYER_COLORS[l.kind]);
      return seg;
    }));

  const tree = h("div", { class: "pv-tree" }, d.layers.map(l => {
    const sec = h("section", { class: "pv-layer" },
      h("header", {}, h("b", {}, `${l.name} · ${l.size} bytes`), h("span", {}, l.summary)),
      l.fields.map(f => {
        const row = h("button", { type: "button", class: "pv-field", title: `bytes ${f.at}–${f.at + f.size - 1}`,
          onclick: () => select(f), onmouseenter: () => highlight(f, true), onmouseleave: () => { if (pinned !== f) highlight(f, false); } },
        h("span", { class: "pv-name" }, f.name),
        h("span", { class: "pv-value" }, h("span", {}, f.value), f.eg ? h("em", { class: "eg", title: "An example value, not captured" }, "E.G.") : null,
          f.explain ? h("small", {}, f.explain) : null));
        f.el = row;
        fieldEls.push(f);
        return row;
      }));
    sec.style.setProperty("--c", LAYER_COLORS[l.kind]);
    return sec;
  }));

  const kindAt = new Array(total).fill("data");
  for (const l of d.layers) for (let i = l.at; i < l.at + l.size; i++) kindAt[i] = l.kind;
  const fieldAt = i => { let best = null; for (const f of fieldEls) if (i >= f.at && i < f.at + f.size && (!best || f.size < best.size)) best = f; return best; };
  const dump = h("div", { class: "hexdump" });
  for (let row = 0; row < total; row += 16) {
    const hexCells = [], ascii = [];
    for (let i = row; i < Math.min(row + 16, total); i++) {
      const b = d.bytes[i];
      const cell = h("span", { class: "hb k-" + kindAt[i] }, b.toString(16).padStart(2, "0"));
      const idx = i;
      cell.addEventListener("mouseenter", () => { const f = fieldAt(idx); if (f) highlight(f, true); });
      cell.addEventListener("mouseleave", () => { const f = fieldAt(idx); if (f && f !== pinned) highlight(f, false); });
      cell.addEventListener("click", () => { const f = fieldAt(idx); if (f) { select(f); f.el.scrollIntoView({ block: "nearest" }); } });
      byteEls.push(cell);
      hexCells.push(cell);
      ascii.push(b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".");
    }
    dump.append(h("div", { class: "hexrow" }, h("span", { class: "off" }, row.toString(16).padStart(4, "0")),
      h("span", { class: "hx" }, hexCells), h("span", { class: "asc" }, ascii.join(""))));
  }

  const navBtn = (label, fn, text) => fn ? h("button", { type: "button", class: "icon", "aria-label": label, title: label, onclick: fn }, text) : null;
  const egCount = fieldEls.filter(f => f.eg).length;
  const el = h("article", { class: "packet-view tone-" + (p.tone || "none"), tabindex: "-1" },
    h("header", { class: "pv-head" },
      h("span", { class: "pv-no" }, p.no ?? "•"),
      h("div", { class: "pv-title" }, h("strong", {}, p.title || packetTitle(d)),
        h("span", {}, [p.time, `${d.src || "?"} → ${d.dst || "?"}`, d.protocol, fmtBytes(total)].filter(Boolean).join(" · "))),
      h("div", { class: "pv-nav" }, navBtn("Previous packet", nav.prev, "‹"), navBtn("Next packet", nav.next, "›"), navBtn("Close", nav.close, "✕"))),
    p.origin ? h("p", { class: "pv-origin" }, p.origin) : null,
    bar,
    h("div", { class: "pv-body" }, tree,
      h("aside", { class: "pv-bytes" }, h("header", {}, h("b", {}, "BYTES"), h("span", {}, `${total} in this frame`)), dump)),
    h("footer", { class: "pv-foot" },
      h("span", {}, egCount ? [h("em", { class: "eg" }, "E.G."), " an example value: nyxr did not record it, so it differs in every real capture"] : "Every value shown was captured on the wire."),
      h("span", {}, "Click a field to pin its bytes")));
  el.addEventListener("keydown", e => {
    if (e.key === "ArrowLeft" && nav.prev) { e.preventDefault(); nav.prev(); }
    else if (e.key === "ArrowRight" && nav.next) { e.preventDefault(); nav.next(); }
    else if (e.key === "Escape" && nav.close) { e.preventDefault(); nav.close(); }
  });
  return el;
}

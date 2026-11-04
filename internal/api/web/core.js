// Shared DOM, API and formatting helpers. Every value from the API may be
// attacker-influenced (banners, titles, certificates), so the DOM is built
// with textContent only; nothing here ever assigns innerHTML.

export const page = { abort: null }; // aborts streams and requests of the previous page

export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "value") el.value = v;
    else if (k === "checked") el.checked = !!v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat(Infinity)) {
    if (c === undefined || c === null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const svgNS = "http://www.w3.org/2000/svg";
export function svg(tag, attrs, text) {
  const el = document.createElementNS(svgNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, String(v));
  }
  if (text !== undefined) el.textContent = text;
  return el;
}

// mark wraps every case-insensitive occurrence of query in <mark>, so a
// search for "80" colors 80.1.2.3, 10.80.1.2 and 10.1.180.2 alike.
export function mark(text, query) {
  text = String(text ?? "");
  const q = String(query || "").trim().toLowerCase();
  if (!q) return text;
  const lower = text.toLowerCase(), out = [];
  let from = 0, at;
  while ((at = lower.indexOf(q, from)) >= 0) {
    if (at > from) out.push(text.slice(from, at));
    out.push(h("mark", {}, text.slice(at, at + q.length)));
    from = at + q.length;
  }
  if (!out.length) return text;
  if (from < text.length) out.push(text.slice(from));
  return h("span", {}, out);
}

export function token() {
  try { return sessionStorage.getItem("nyxr-token") || ""; } catch { return ""; }
}
export function setToken(t) {
  try { sessionStorage.setItem("nyxr-token", t); } catch { /* private mode */ }
}
// pref reads (one argument) or writes a per-browser convenience setting.
export function pref(key, value) {
  try {
    if (value === undefined) return localStorage.getItem("nyxr-" + key);
    if (value === null) localStorage.removeItem("nyxr-" + key);
    else localStorage.setItem("nyxr-" + key, value);
  } catch { /* storage blocked */ }
  return null;
}

export class AuthError extends Error {}

export async function api(path, opts = {}) {
  const headers = Object.assign({}, opts.headers || {});
  const t = token();
  if (t) headers.Authorization = "Bearer " + t;
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch("/api/v1" + path, {
    method: opts.method || (opts.body !== undefined ? "POST" : "GET"),
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    signal: opts.signal === undefined ? (page.abort && page.abort.signal) : opts.signal,
  });
  if (res.status === 401) throw new AuthError("token required");
  if (opts.raw) return res;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

// stream reads Server-Sent Events with fetch so the bearer token can be sent
// (EventSource cannot set headers). It reconnects with Last-Event-ID.
export async function stream(path, onEvent, signal) {
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
    } catch {
      if (signal.aborted) return;
    }
    if (finished) return;
  }
}

export function fmtTime(s) {
  if (!s || s.startsWith("0001")) return "—";
  const d = new Date(s);
  return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}
export function fmtAgo(s) {
  if (!s || s.startsWith("0001")) return "—";
  const sec = Math.max(0, (Date.now() - Date.parse(s)) / 1000);
  if (sec < 60) return Math.floor(sec) + "s ago";
  if (sec < 3600) return Math.floor(sec / 60) + "m ago";
  if (sec < 86400) return Math.floor(sec / 3600) + "h ago";
  return Math.floor(sec / 86400) + "d ago";
}
export function fmtRTT(ns) { return ns ? (ns / 1e6).toFixed(2) + " ms" : ""; }
export function fmtBytes(n) {
  n = Number(n) || 0;
  return n >= 1048576 ? (n / 1048576).toFixed(1) + " MB" : n >= 1024 ? (n / 1024).toFixed(1) + " KB" : n + " B";
}
export function state(s) { return h("span", { class: "s s-" + String(s || "").replace(/[^a-z]/gi, "") }, s); }
export function table(headers, rows, cls) {
  return h("div", { class: "scroll" + (cls ? " " + cls : "") }, h("table", {},
    h("thead", {}, h("tr", {}, headers.map(x => h("th", {}, x)))),
    h("tbody", {}, rows)));
}
export function kv(pairs) {
  return h("dl", { class: "kv" }, pairs.filter(p => p[1] !== undefined && p[1] !== "" && p[1] !== null)
    .flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
}
export function port(o) { return o.port ? `${o.transport}/${o.port}` : o.transport; }
export function printable(b64) {
  let s;
  try { s = atob(b64); } catch { return b64; }
  return s.replace(/[^\x20-\x7e\n]/g, c => "\\x" + c.charCodeAt(0).toString(16).padStart(2, "0")).slice(0, 2048);
}
export function b64bytes(b64) {
  try { return Uint8Array.from(atob(b64 || ""), c => c.charCodeAt(0)); } catch { return new Uint8Array(); }
}
export function hexOf(bytes) { return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join(""); }

// panel draws the blueprint frame used across the UI: a title bar with an
// optional tool area and a body.
export function panel(title, body, opts = {}) {
  return h("section", { class: "panel" + (opts.class ? " " + opts.class : ""), id: opts.id },
    h("header", { class: "panel-head" },
      h("h2", {}, title, opts.sub ? h("small", {}, opts.sub) : null),
      opts.tools ? h("div", { class: "panel-tools" }, opts.tools) : null),
    h("div", { class: "panel-body" + (opts.flush ? " flush" : "") }, body));
}

export function download(name, blob) {
  const url = URL.createObjectURL(blob);
  const a = h("a", { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

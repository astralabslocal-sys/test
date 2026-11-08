"use strict";
/* Gemeinsame Hilfen für alle Seiten */
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const num = (v, d = 0) => (v == null ? "–" : Number(v).toLocaleString("de-DE", { maximumFractionDigits: d, minimumFractionDigits: d }));
const nowS = () => Math.floor(Date.now() / 1000);
const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* egal */ } },
};

function ago(ts, now = nowS()) {
  if (!ts) return "nie";
  const s = Math.max(0, now - ts);
  if (s < 90) return "gerade eben";
  if (s < 3600) return `vor ${Math.round(s / 60)} Min`;
  if (s < 86400) return `vor ${Math.round(s / 3600)} Std`;
  return `vor ${Math.round(s / 86400)} Tagen`;
}
const when = (ts) => (ts ? new Date(ts * 1000).toLocaleString("de-DE", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" }) : "–");
const isV6 = (ip) => String(ip || "").includes(":");
const famPill = (ip) => (ip ? `<span class="pill ${isV6(ip) ? "v6" : "v4"}">${isV6(ip) ? "IPv6" : "IPv4"}</span>` : "");
const ipCell = (ip) => (ip ? `<span class="mono">${esc(ip)}</span> ${famPill(ip)}` : '<span class="muted">–</span>');

function shortUA(ua = "") {
  const os = /iPhone/.test(ua) ? "iPhone" : /iPad/.test(ua) ? "iPad" : /Android/.test(ua) ? "Android"
    : /Windows/.test(ua) ? "Windows" : /Mac OS X/.test(ua) ? "Mac" : /Linux/.test(ua) ? "Linux" : "";
  const br = /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /Firefox\//.test(ua) ? "Firefox"
    : /SamsungBrowser/.test(ua) ? "Samsung Internet" : /Chrome\//.test(ua) ? "Chrome"
    : /Safari\//.test(ua) ? "Safari" : (ua.split("/")[0] || "unbekannt");
  return os ? `${br} · ${os}` : br;
}

async function api(path, opts = {}) {
  const o = { ...opts, headers: { "X-WiFiMon": "1", ...(opts.headers || {}) } };
  if (o.json !== undefined) {
    o.method = "POST";
    o.body = JSON.stringify(o.json);
    o.headers["Content-Type"] = "application/json";
    delete o.json;
  }
  const r = await fetch(path, o);
  if (r.status === 401) { location.href = "/login"; throw new Error("Bitte anmelden"); }
  let data = null;
  try { data = await r.json(); } catch { /* leer */ }
  if (!r.ok && r.status !== 409) throw new Error((data && data.error) || `HTTP ${r.status}`);
  return data;
}
const post = (path, json = {}) => api(path, { json });

let toastTimer;
function toast(msg) {
  let t = $("#toast");
  if (!t) { t = document.createElement("div"); t.id = "toast"; t.className = "toast"; t.setAttribute("role", "status"); document.body.append(t); }
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 3200);
}

async function copyText(text) {
  try { await navigator.clipboard.writeText(text); toast("Kopiert ✓"); }
  catch { prompt("Zum Kopieren markieren:", text); }
}

/** Kopfzeile mit Navigation. active: "wlan" | "adblock" | "geraete" */
function nav(active) {
  const links = [["wlan", "/", "WLAN"], ["adblock", "/adblock", "Werbeblocker"], ["geraete", "/geraete", "Geräte & Zugriff"]];
  $("#top").innerHTML = `
    <a class="brand" href="/">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><path d="M2 8.5a15 15 0 0 1 20 0M5.5 12a10 10 0 0 1 13 0M9 15.5a5 5 0 0 1 6 0"/><circle cx="12" cy="19" r="1.2" fill="currentColor"/></svg>
      WiFiMon
    </a>
    <nav class="nav">${links.map(([k, href, label]) => `<a href="${href}" class="${k === active ? "on" : ""}">${label}</a>`).join("")}</nav>
    <span class="spacer"></span>
    <span class="meta" id="whoami"></span>
    <button class="btn ghost small" id="logoutBtn" type="button">Abmelden</button>`;
  $("#logoutBtn").addEventListener("click", async () => {
    await post("/api/logout").catch(() => {});
    location.href = "/login";
  });
  api("/api/me").then((me) => {
    $("#whoami").innerHTML = `Du: ${ipCell(me.ip)}`;
    if (!me.auth) $("#logoutBtn").hidden = true;
  }).catch(() => {});
}

/** Klicks auf [data-act] in einem Container an eine Funktion weiterreichen */
function onAction(container, handlers) {
  container.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-act]");
    if (!b || !container.contains(b)) return;
    const fn = handlers[b.dataset.act];
    if (!fn) return;
    b.disabled = true;
    try { await fn(b.dataset, b); } catch (err) { toast(err.message); } finally { b.disabled = false; }
  });
}

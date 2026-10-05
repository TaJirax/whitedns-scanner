"use strict";
// WhiteDNS Scanner UI. Talks to the Go side through Wails bindings:
// window.go.main.App.* (calls) and window.runtime.EventsOn (scan:stats, scan:done).

const api = window.go.main.App;
const rt = window.runtime;
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const DNS_MODES = ["dns", "dns-udptcp", "txt"];
const NUMERIC_KEYS = new Set(["timeoutSecs", "retryCount", "maxConcurrent", "minConcurrent", "streamingThreshold",
  "streamingSizeMb", "dnsMaxPingMs", "dnsRate", "dnsRatePerResolver", "dnsBurst", "dnsJitter"]);

let settings = {};
let stats = { state: "IDLE", counts: {} };
let page = "scan";
const view = { tab: "all", search: "", protocol: "", sortBy: "seq", desc: false, offset: 0, limit: 100 };
let rows = [];
let selectedSeq = 0;

// ---------- helpers ----------
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtNum = (n) => (n || 0).toLocaleString("en-US");
function fmtDur(s) {
  s = Math.max(0, Math.round(s || 0));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  const mm = String(m).padStart(h ? 2 : 1, "0"), ss = String(sec).padStart(2, "0");
  return h ? `${h}:${mm}:${ss}` : `${mm}:${ss}`;
}
const latClass = (ms) => (ms < 200 ? "lat-fast" : ms < 500 ? "lat-mid" : "lat-slow");
const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
const isDNS = () => DNS_MODES.includes(activeMode());
const activeMode = () => (stats.state !== "IDLE" && stats.mode) || settings.mode;

function snack(text, error = false) {
  const el = $("#snack");
  el.textContent = text;
  el.className = "snackbar show" + (error ? " error" : "");
  clearTimeout(snack.t);
  snack.t = setTimeout(() => (el.className = "snackbar"), error ? 6000 : 3500);
}
const errText = (e) => (typeof e === "string" ? e : e?.message || String(e));

// ---------- navigation ----------
function showPage(name) {
  page = name;
  $$(".rail-item").forEach((b) => b.classList.toggle("active", b.dataset.page === name));
  $$(".page").forEach((p) => (p.hidden = p.id !== "page-" + name));
  $("#pageTitle").textContent = { scan: "Scan", results: "Results", settings: "Settings" }[name];
  if (name !== "results") closeDrawer();
  applyMode();
  if (name === "results") loadResults();
}

// ---------- theme ----------
function applyTheme(choice) {
  const resolved = choice === "system" ? (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light") : choice;
  document.documentElement.dataset.theme = resolved;
  try { localStorage.setItem("theme", choice); } catch (_) {}
  $$("#themeSeg button").forEach((b) => b.classList.toggle("active", b.dataset.themeOpt === choice));
}
function setTheme(choice) {
  settings.theme = choice;
  applyTheme(choice);
  saveSoon();
}
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => settings.theme === "system" && applyTheme("system"));

// ---------- settings binding ----------
const saveSoon = debounce(() => api.SaveSettings(settings).catch((e) => snack(errText(e), true)), 400);

function readInput(el) {
  if (el.type === "checkbox") return el.checked;
  if (NUMERIC_KEYS.has(el.dataset.key)) { const v = parseFloat(el.value); return Number.isFinite(v) ? v : 0; }
  return el.value;
}
function writeInput(el, v) {
  if (el.type === "checkbox") el.checked = !!v;
  else if (el !== document.activeElement) el.value = v ?? "";
}
function syncKey(key) {
  $$(`[data-key="${key}"]`).forEach((el) => writeInput(el, settings[key]));
  $$(`[data-out="${key}"]`).forEach((o) => (o.textContent = key === "dnsJitter" ? (settings[key] > 0 ? settings[key].toFixed(2) : "off") : settings[key]));
}
function bindSettings() {
  $$("[data-key]").forEach((el) => {
    const key = el.dataset.key;
    el.addEventListener(el.type === "checkbox" ? "change" : "input", () => {
      settings[key] = readInput(el);
      syncKey(key);
      saveSoon();
    });
  });
  $$('input[name="mode"]').forEach((r) => r.addEventListener("change", () => { settings.mode = r.value; applyMode(); saveSoon(); }));
}
function renderSettings() {
  Object.keys(settings).forEach(syncKey);
  const radio = $(`input[name="mode"][value="${settings.mode}"]`);
  if (radio) radio.checked = true;
  applyTheme(settings.theme || "system");
  applyMode();
}

// Show only the controls that matter for the current mode.
function applyMode() {
  const mode = page === "results" ? activeMode() : settings.mode;
  $$("[data-show]").forEach((el) => (el.hidden = !el.dataset.show.split(",").includes(mode)));
  const dns = DNS_MODES.includes(settings.mode);
  $$(".hint-dns").forEach((e) => (e.hidden = !dns));
  $$(".hint-http").forEach((e) => (e.hidden = dns));
  const okLabel = DNS_MODES.includes(activeMode()) ? "Responding" : "Reachable";
  $("#sOkLabel").textContent = okLabel;
  $("#tabOkLabel").textContent = okLabel;
}

// ---------- scan controls ----------
async function startScan() {
  closeDrawer();
  try {
    await api.StartScan(settings);
    view.offset = 0;
    rows = [];
    snack("Scan started");
  } catch (e) {
    snack(errText(e), true);
  }
}

function renderStats(s) {
  stats = s;
  const running = s.state === "RUNNING", paused = s.state === "PAUSED", active = running || paused;
  const chip = $("#stateChip");
  chip.dataset.state = s.state;
  chip.textContent = { IDLE: "Idle", RUNNING: "Scanning", PAUSED: "Paused", STOPPED: "Finished" }[s.state] || s.state;

  $("#startBtn").disabled = active;
  $("#pauseBtn").disabled = !active;
  $("#stopBtn").disabled = !active;
  $("#pauseBtn span").textContent = paused ? "Resume" : "Pause";
  $("#pauseBtn svg").innerHTML = paused ? '<path d="M8 5v14l11-7z"/>' : '<path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z"/>';
  $$("#page-scan [data-key], #page-scan input[name=mode], #pickInput, #clearInput").forEach((el) => (el.disabled = active));

  const pct = s.total > 0 ? Math.min(100, (s.done / s.total) * 100) : 0;
  const bar = $("#progressBar");
  $(".progress").classList.toggle("indeterminate", running && s.total <= 0);
  bar.style.width = s.total > 0 ? pct + "%" : running ? "" : "0";
  $("#progressText").textContent = s.state === "IDLE" ? "Ready"
    : s.total > 0 ? `${fmtNum(s.done)} of ${fmtNum(s.total)} probes · ${pct.toFixed(1)}%`
    : `${fmtNum(s.done)} probes`;
  $("#etaText").textContent = running && s.etaS > 0 ? `about ${fmtDur(s.etaS)} left` : "";

  const msg = $("#scanMessage");
  msg.hidden = !s.message;
  msg.textContent = s.message || "";
  msg.classList.toggle("error", /^(FATAL|ERROR)/.test(s.message || ""));

  const c = s.counts || {};
  $("#sDone").textContent = fmtNum(s.done);
  $("#sTotal").textContent = "of " + fmtNum(s.total);
  $("#sOk").textContent = fmtNum(c.ok);
  $("#sDead").textContent = fmtNum(c.dead);
  $("#sPoisoned").textContent = fmtNum(c.poisoned);
  $("#sTunnel").textContent = fmtNum(c.tunnel);
  $("#sRate").textContent = fmtNum(Math.round(s.ratePerS || 0));
  $("#sElapsed").textContent = fmtDur(s.elapsedS);
  $$("[data-count]").forEach((b) => (b.textContent = fmtNum(c[b.dataset.count])));
  const badge = $("#railBadge");
  badge.hidden = !c.ok;
  badge.textContent = c.ok > 9999 ? "9k+" : c.ok;

  renderFeed(s.recent || []);
  if (page === "results" && $("#liveRefresh").checked && active) loadResultsThrottled();
}

function renderFeed(list) {
  const feed = $("#feed");
  if (!list.length) {
    if (!feed.querySelector(".empty")) feed.innerHTML = '<li class="empty">Results appear here while scanning.</li>';
    return;
  }
  feed.innerHTML = list.map((r) => {
    const target = isDNS() ? `${r.label} ${r.protocol ? "· " + r.protocol : ""}` : r.url || r.label;
    const right = r.error ? `<span class="badge ${r.category}">${esc(shortErr(r.error))}</span>` : `<span class="${latClass(r.latencyMs)}">${r.latencyMs} ms</span>`;
    return `<li data-seq="${r.seq}"><span class="dot ${r.category}"></span><span class="t">${esc(target)}</span>${r.tunnelReady ? '<span class="badge poisoned">tunnel</span>' : "<span></span>"}${right}</li>`;
  }).join("");
}
const shortErr = (e) => (e.length > 22 ? e.slice(0, 22) + "…" : e);

// ---------- results ----------
const columns = {
  http: [
    { h: "Target", cell: (r) => `<td class="mono" title="${esc(r.url)}">${esc(r.label)}</td>` },
    { h: "IP", cell: (r) => `<td class="mono">${esc(r.ip)}</td>` },
    { h: "Port", cell: (r) => `<td class="num">${r.port || ""}</td>` },
    { h: "Status", cell: (r) => `<td>${r.error ? `<span class="badge dead" title="${esc(r.error)}">${esc(shortErr(r.error))}</span>` : `<span class="badge ok">${r.status}</span>`}</td>` },
    { h: "Latency", cell: (r) => `<td class="num ${r.error ? "" : latClass(r.latencyMs)}">${r.error ? "—" : r.latencyMs + " ms"}</td>` },
  ],
  dns: [
    { h: "Resolver", cell: (r) => `<td class="mono">${esc(r.label)}</td>` },
    { h: "Protocol", cell: (r) => `<td><span class="badge ${esc((r.protocol || "").split("/")[0])}">${esc(r.protocol)}</span></td>` },
    { h: "Answer", cell: (r) => `<td class="mono" title="${esc(r.answer)}">${esc(r.answer)}</td>` },
    { h: "Latency", cell: (r) => `<td class="num ${r.status ? latClass(r.latencyMs) : ""}">${r.status ? r.latencyMs + " ms" : "—"}</td>` },
    { h: "Flags", cell: (r) => `<td>${r.hdrDump ? [r.ra && "RA", r.edns && "EDNS", r.tc && "TC", r.rcode && "RCODE " + r.rcode].filter(Boolean).map((f) => `<span class="badge">${f}</span>`).join(" ") : ""}</td>` },
    { h: "Tunnel", cell: (r) => `<td>${r.tunnelReady ? '<span class="badge ok">ready</span>' : `<span class="muted-cell" title="${esc(r.tunnelReason)}">${esc(shortErr(r.tunnelReason || ""))}</span>`}</td>` },
    { h: "Result", cell: (r) => `<td>${r.poisoned ? '<span class="badge poisoned">poisoned</span>' : r.error ? `<span class="badge dead" title="${esc(r.error)}">${esc(shortErr(r.error))}</span>` : '<span class="badge ok">ok</span>'}</td>` },
  ],
};

async function loadResults() {
  applyMode();
  const q = { ...view, protocol: isDNS() ? view.protocol : "" };
  let res;
  try { res = await api.QueryResults(q); } catch (e) { return snack(errText(e), true); }
  rows = res.rows || [];
  if (view.offset > 0 && !rows.length && res.total > 0) { view.offset = 0; return loadResults(); }

  const cols = isDNS() ? columns.dns : columns.http;
  $("#thead").innerHTML = "<tr>" + cols.map((c) => `<th>${c.h}</th>`).join("") + "</tr>";
  $("#tbody").innerHTML = rows.map((r) => `<tr data-seq="${r.seq}" class="${r.seq === selectedSeq ? "selected" : ""}">${cols.map((c) => c.cell(r)).join("")}</tr>`).join("");
  $("#tableEmpty").hidden = rows.length > 0;
  $("#tableEmpty").textContent = (res.counts?.all || 0) === 0 ? "No results yet. Start a scan." : "Nothing matches this filter.";
  const from = res.total ? view.offset + 1 : 0, to = view.offset + rows.length;
  $("#pageInfo").textContent = `${fmtNum(from)}–${fmtNum(to)} of ${fmtNum(res.total)} rows`;
  $("#prevPage").disabled = view.offset <= 0;
  $("#nextPage").disabled = to >= res.total;
  $$("[data-count]").forEach((b) => (b.textContent = fmtNum(res.counts?.[b.dataset.count])));
}
let lastLoad = 0;
function loadResultsThrottled() {
  const now = Date.now();
  if (now - lastLoad < 1000) return;
  lastLoad = now;
  loadResults();
}

// ---------- details drawer ----------
function openDrawer(r) {
  selectedSeq = r.seq;
  $$("#tbody tr").forEach((tr) => tr.classList.toggle("selected", +tr.dataset.seq === r.seq));
  const fields = isDNS()
    ? [["Resolver", r.label], ["Protocol", r.protocol], ["Port", r.port], ["Answer", r.answer], ["Answer IP", r.ip],
       ["Latency", r.status ? r.latencyMs + " ms" : ""], ["Poisoned", r.poisoned ? "yes" : "no"],
       ["Recursion", r.hdrDump ? (r.ra ? "available" : "no") : ""], ["EDNS0", r.hdrDump ? (r.edns ? "yes" : "no") : ""],
       ["Truncated", r.tc ? "yes" : ""], ["RCODE", r.hdrDump ? r.rcode : ""], ["Tunnel", r.tunnelReady ? "ready" : "not ready"],
       ["Why", r.tunnelReason], ["Header", r.hdrDump], ["Error", r.error]]
    : [["Target", r.label], ["URL", r.url], ["Resolved IP", r.ip], ["Port", r.port], ["HTTP status", r.status || ""],
       ["Latency", r.latencyMs + " ms"], ["Error", r.error]];
  $("#detailList").innerHTML = fields.filter(([, v]) => v !== "" && v !== undefined && v !== null)
    .map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`).join("");
  $("#drawer").hidden = false;
  $("#drawer").dataset.copy = isDNS() ? r.label : r.url || r.label;
}
function closeDrawer() {
  $("#drawer").hidden = true;
  selectedSeq = 0;
  $$("#tbody tr.selected").forEach((tr) => tr.classList.remove("selected"));
}

// ---------- wiring ----------
function wire() {
  $$(".rail-item").forEach((b) => b.addEventListener("click", () => showPage(b.dataset.page)));
  $("#themeToggle").addEventListener("click", () => setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"));
  $$("#themeSeg button").forEach((b) => b.addEventListener("click", () => setTheme(b.dataset.themeOpt)));

  $("#pickInput").addEventListener("click", async () => {
    const p = await api.PickInputFile();
    if (p) { settings.inputFile = p; syncKey("inputFile"); saveSoon(); }
  });
  $("#clearInput").addEventListener("click", () => { settings.inputFile = ""; syncKey("inputFile"); saveSoon(); });
  $("#pickOutput").addEventListener("click", async () => {
    const p = await api.PickOutputDir();
    if (p) { settings.outputDir = p; syncKey("outputDir"); saveSoon(); }
  });
  $("#openDir").addEventListener("click", () => api.OpenOutputDir());
  $("#resetSettings").addEventListener("click", async () => {
    settings = await api.ResetSettings();
    renderSettings();
    snack("Settings reset to defaults");
  });

  $("#startBtn").addEventListener("click", startScan);
  $("#pauseBtn").addEventListener("click", () => (stats.state === "PAUSED" ? api.ResumeScan() : api.PauseScan()));
  $("#stopBtn").addEventListener("click", () => api.StopScan());

  $$(".tab").forEach((t) => t.addEventListener("click", () => {
    $$(".tab").forEach((x) => x.classList.toggle("active", x === t));
    view.tab = t.dataset.tab; view.offset = 0; loadResults();
  }));
  $("#search").addEventListener("input", debounce((e) => { view.search = e.target.value.trim(); view.offset = 0; loadResults(); }, 250));
  $("#protoFilter").addEventListener("change", (e) => { view.protocol = e.target.value; view.offset = 0; loadResults(); });
  $("#sortBy").addEventListener("change", (e) => { view.sortBy = e.target.value; view.desc = e.target.value === "status"; $("#sortDir").classList.toggle("desc", view.desc); loadResults(); });
  $("#sortDir").addEventListener("click", () => { view.desc = !view.desc; $("#sortDir").classList.toggle("desc", view.desc); loadResults(); });
  $("#pageSize").addEventListener("change", (e) => { view.limit = +e.target.value; view.offset = 0; loadResults(); });
  $("#prevPage").addEventListener("click", () => { view.offset = Math.max(0, view.offset - view.limit); loadResults(); });
  $("#nextPage").addEventListener("click", () => { view.offset += view.limit; loadResults(); });
  $("#exportBtn").addEventListener("click", async () => {
    try { const m = await api.ExportResults({ ...view, offset: 0, limit: 0 }); if (m) snack(m); } catch (e) { snack(errText(e), true); }
  });

  $("#tbody").addEventListener("click", (e) => {
    const tr = e.target.closest("tr");
    const r = tr && rows.find((x) => x.seq === +tr.dataset.seq);
    if (r) openDrawer(r);
  });
  $("#feed").addEventListener("click", (e) => {
    const li = e.target.closest("li[data-seq]");
    const r = li && (stats.recent || []).find((x) => x.seq === +li.dataset.seq);
    if (r) { showPage("results"); openDrawer(r); }
  });
  $("#closeDrawer").addEventListener("click", closeDrawer);
  $("#copyDetail").addEventListener("click", () => rt.ClipboardSetText($("#drawer").dataset.copy || "").then(() => snack("Copied")));
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

  rt.EventsOn("scan:stats", renderStats);
  rt.EventsOn("scan:done", (s) => {
    renderStats(s);
    if (page === "results") loadResults();
    if (s.message) snack(s.message, /^(FATAL|ERROR)/.test(s.message));
  });
}

async function init() {
  settings = await api.GetSettings();
  bindSettings();
  renderSettings();
  wire();
  renderStats(await api.GetStats());
}
init().catch((e) => snack("Startup failed: " + errText(e), true));

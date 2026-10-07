"use strict";

// The engine owns probe semantics. This view keeps inputs local to each mode,
// pages results, and only patches live sections rather than rebuilding forms.
(() => {
  const $ = (s, root = document) => root.querySelector(s);
  const $$ = (s, root = document) => [...root.querySelectorAll(s)];
  const api = window.go?.main?.App;
  const rt = window.runtime;
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"}[c]));
  const number = (v) => Number.isFinite(Number(v)) ? Number(v) : 0;
  const fmt = (v) => Math.max(0, number(v)).toLocaleString(undefined, {maximumFractionDigits: 0});
  const duration = (v) => {
    const s = Math.max(0, Math.floor(number(v)));
    return s >= 3600 ? `${Math.floor(s / 3600)}h ${Math.floor(s % 3600 / 60)}m` : s >= 60 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${s}s`;
  };
  const bytes = (v) => number(v) >= 1048576 ? `${(v / 1048576).toFixed(1)} MB` : number(v) >= 1024 ? `${(v / 1024).toFixed(1)} KB` : `${fmt(v)} B`;
  const date = (v) => { const d = new Date(v); return Number.isNaN(d.getTime()) || d.getFullYear() < 1900 ? "Unknown date" : d.toLocaleString(); };
  const paths = {
    globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c-5 5-5 13 0 18 5-5 5-13 0-18z"/>',
    cloud: '<path d="M7 19h11a5 5 0 0 0 1-10 7 7 0 0 0-13-1 6 6 0 0 0 1 11z"/>',
    tune: '<path d="M4 6h16M4 12h16M4 18h16M8 3v6M16 9v6M10 15v6"/>',
    dns: '<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6h1M7 17h1"/>',
    swap: '<path d="M4 7h16l-4-4M20 17H4l4 4"/>',
    txt: '<path d="M4 5h16M12 5v15M8 20h8"/>',
    table: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M9 9v11M3 14h18"/>',
    folder: '<path d="M3 7V5h7l2 3h9v12H3z"/>',
    gear: '<path d="M9 3h6l1 3 3 1 2 5-2 5-3 1-1 3H9l-1-3-3-1-2-5 2-5 3-1z"/><circle cx="12" cy="12" r="3"/>',
    play: '<path d="m8 4 12 8-12 8z"/>',
    pause: '<path d="M8 4v16M16 4v16"/>',
    stop: '<rect x="5" y="5" width="14" height="14" rx="2"/>',
    redo: '<path d="M20 10a8 8 0 1 0-2 8M20 3v7h-7"/>',
    open: '<path d="M14 3h7v7M21 3 10 14M10 3H3v18h18v-7"/>',
    file: '<path d="M14 3H5v18h14V8zM14 3v5h5M8 13h8M8 17h8"/>',
    search: '<circle cx="10" cy="10" r="6"/><path d="m15 15 6 6"/>',
    sort: '<path d="M4 6h16M4 12h11M4 18h6"/>',
    download: '<path d="M12 3v12m-5-5 5 5 5-5M4 17v4h16v-4"/>',
    left: '<path d="m15 5-7 7 7 7"/>',
    right: '<path d="m9 5 7 7-7 7"/>',
    copy: '<rect x="8" y="8" width="13" height="13" rx="2"/><path d="M16 8V3H3v13h5"/>',
    config: '<path d="M4 6h9M4 12h16M4 18h9M16 3l4 3-4 3M16 15l4 3-4 3"/>',
    trash: '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>',
    close: '<path d="M6 6l12 12M18 6 6 18"/>',
  };
  const icon = (name) => `<svg viewBox="0 0 24 24" aria-hidden="true" style="fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round">${paths[name] || paths.file}</svg>`;
  const btn = (label, action, kind = "tonal", glyph = "", extra = "") => `<button type="button" class="btn ${kind}" data-action="${action}" ${extra}>${glyph ? icon(glyph) : ""}${label}</button>`;
  const MODES = [
    {id:"http", group:"Clean IP", title:"Default Ports (443/80 only)", family:"http", icon:"globe", subtitle:"Standard HTTP and HTTPS reachability", desc:"Check domains, IPs and CIDR ranges through DNS, TCP, TLS and HTTP. These clean IP checks use ordinary TLS and keep the original HTTP Host. The scanner's existing fallback and retry rules apply.", chips:[["Default", "HTTPS 443 / HTTP 80"], ["TLS", "ordinary"], ["Priority", "previous passes first"]]},
    {id:"http-all", group:"Clean IP", title:"All Cloudflare Ports (13 ports)", family:"http", icon:"cloud", subtitle:"Reachability across all 13 proxied ports", desc:"Try each target across all 13 Cloudflare HTTP and HTTPS ports. Find reachable endpoints when standard ports are filtered, using ordinary TLS and the target Host header.", chips:[["HTTPS", "6 ports"], ["HTTP", "7 ports"], ["Expansion", "13 probes per host"]]},
    {id:"custom", group:"Clean IP", title:"Custom ports", family:"http", icon:"tune", subtitle:"HTTP and HTTPS on the ports you choose", desc:"Scan each target on a custom port list or range. Ports are tried with ordinary TLS and HTTP; the request Host stays tied to the target.", chips:[["Syntax", "80,443,8000-8010"], ["TLS", "ordinary"]]},
    {id:"dns", group:"DNS scan", title:"DNS Resolver Discovery", family:"dns", icon:"dns", subtitle:"Resolver integrity, headers and tunnel readiness", desc:"Discover resolvers over UDP, TCP, DNS over TLS and DNS over HTTPS. Check answers against the integrity domain and inspect poisoning, hijacking, recursion and tunnel readiness.", chips:[["Protocols", "UDP / TCP / DoT / DoH"], ["Checks", "integrity + tunnel readiness"]]},
    {id:"dns-udptcp", group:"DNS scan", title:"DNS UDP/TCP only", family:"dns", icon:"swap", subtitle:"Focused discovery over UDP and TCP", desc:"Run resolver discovery using UDP and TCP only. Keep the same integrity and tunnel checks without DoT or DoH probes.", chips:[["Protocols", "UDP / TCP"], ["Default port", "53"]]},
    {id:"txt", group:"DNS scan", title:"TXT Resolver Probe", family:"txt", icon:"txt", subtitle:"TXT answers and DNS tunnel readiness", desc:"Query resolvers for TXT records under your base domain. The scanner adds a random label to each query and checks the returned records and tunnel suitability.", chips:[["Query", "random label + your domain"], ["Checks", "TXT + tunnel readiness"]]},
    {id:"sni",group:"SNI scan",title:"SNI scan",family:"http",icon:"globe",subtitle:"Forged SNI verification over HTTPS",desc:"Verify TLS and HTTPS using your forged SNI hostname while keeping the original target as the HTTP Host. This is the only mode that applies SNI spoofing. A failed TLS handshake stays failed instead of falling back to plain HTTP.",chips:[["TLS","forged SNI"],["Default port","443"]]},
    {id:"http-proxy",group:"Proxy scan",title:"HTTP proxy",family:"http",icon:"swap",subtitle:"Verify HTTP forwarding and HTTPS CONNECT",desc:"Fetch your test URL through each HTTP proxy. A listening socket alone does not count as a working proxy: the endpoint must successfully forward the request. HTTPS proxy URLs are supported. SNI spoofing is disabled.",chips:[["Default ports","8080 / 3128 / 80"],["Input","IP:port or proxy URL"]]},
    {id:"socks-proxy",group:"Proxy scan",title:"SOCKS proxy",family:"http",icon:"swap",subtitle:"Verify SOCKS5 forwarding",desc:"Connect through each SOCKS5 proxy and fetch your test URL. Supports IPv4, IPv6, domains and username/password authentication in socks5://user:pass@host:port URLs. SNI spoofing is disabled.",chips:[["Default ports","1080 / 1081 / 9050"],["Protocol","SOCKS5"]]},
  ];
  const modeByID = Object.fromEntries(MODES.map(m => [m.id, m]));
  let edgeProviders=[
    {id:"cloudflare",name:"Cloudflare",modes:["http","http-all","custom"],hint:"Standard HTTP/HTTPS, all 13 Cloudflare ports, or your custom ports."},
    {id:"fastly",name:"Fastly",modes:["http","custom"],hint:"Standard HTTP/HTTPS defaults or your configured ports."},
    {id:"akamai",name:"Akamai",modes:["http","custom"],hint:"Standard HTTP/HTTPS defaults or your configured ports."},
    {id:"custom",name:"Other / custom CDN",modes:["http","custom"],hint:"Your own domain list and port configuration."},
  ];
  const WORKSPACES=[
    {id:"clean-ip",title:"Clean IP finder",icon:"cloud",modes:["http","http-all","custom"],targetType:"ip"},
    {id:"edge-domains",title:"Edge domains",icon:"globe",modes:["http","http-all","custom"],targetType:"domain"},
    {id:"sni",title:"SNI scan",icon:"globe",modes:["sni"]},
    {id:"proxies",title:"Proxy scan",icon:"swap",modes:["http-proxy","socks-proxy"]},
    {id:"dns-scans",title:"DNS scan",icon:"dns",modes:["dns","dns-udptcp","txt"]},
  ];
  const workspaceByID=Object.fromEntries(WORKSPACES.map(w=>[w.id,w]));
  let rememberedModes={}, currentEdgeProvider="";
  try {rememberedModes=JSON.parse(localStorage.getItem("scan-workspaces")||"{}");currentEdgeProvider=localStorage.getItem("edge-provider")||"";} catch(_) {}
  const ORIGINAL_SERVICES=["workers.dev","pages.dev","gemini.google.com","notebooklm.google.com","instagram.com","chatgpt.com","web.telegram.org","reddit.com","claude.ai"];
  function serviceDomains(input,provider){const platform=(input.platformDomainsText||provider?.platformDomains?.join("\n")||"workers.dev\npages.dev").split(/[\s,]+/).filter(Boolean);return [...new Set([...platform,...ORIGINAL_SERVICES.slice(2)])];}
  const CF_PORTS = [443,2053,2083,2087,2096,8443,80,8080,8880,2052,2082,2086,2095];
  const emptyStats = () => ({state:"IDLE", mode:"", targetType:"", edgeProvider:"", done:0, total:0, counts:{}, recent:[], log:[], ratePerS:0, elapsedS:0, etaS:0, runDir:"", viewing:"", message:""});
  let settings, stats = emptyStats(), page = "http", ready = false;
  let busy = false, activeMode = "", actionPending = "", eventVersion = 0, paintPending = false;
  let saveTimer, saveChain = Promise.resolve(), snackTimer, previewTimer;
  let query = {tab:"all", search:"", protocol:"", sortBy:"seq", desc:true, offset:0, limit:100};
  let resultPage = {rows:[], total:0, counts:{}}, live = true, resultMode = "";
  let searching = false;
  let queryVersion = 0, queryPending = false, queryAgain = false, searchTimer, liveTimer;
  let feedView = "log", logSignature = "";
  let feedRows = [], feedSignature = "", runs = [], reportsFilter = "all", reportsVersion = 0;
  const MAX_RESULT_ROWS = 250, rowMetadata = new WeakMap();
  let pendingFeedRows = null, pendingResultPage = null, resultsRefreshDeferred = false, rowsFlushPending = false;
  let speedRow = null, speedRunDir = "", speedRunning = false, speedResult = null;
  let detailRow = null, viewerFile = null, viewerVersion = 0, overlayFocus = null;
  // ASN picker: the mode it adds to, the ranges family, the checked ASNs and the last search.
  const asnState = {mode:"", family:"ipv4", selected:new Set(), info:new Map(), rows:[], version:0};
  let asnTimer;

  function toast(message, error = false) {
    const el = $("#snack");
    el.textContent = String(message?.message || message || "An unexpected error occurred");
    el.classList.toggle("error", error); el.classList.add("show");
    el.setAttribute("role", error ? "alert" : "status");
    clearTimeout(snackTimer); snackTimer = setTimeout(() => el.classList.remove("show"), error ? 7000 : 4000);
  }
  const isCleanMode = id => ["http","http-all","custom"].includes(id);
  const targetTypeLabel = type => type === "ip" ? "Cloudflare clean IP finder" : type === "domain" ? "Edge domains" : "";
  function legacyLineIsIP(line) {
    let value=line.split("|").at(-1).trim().replace(/^['"]|['"]$/g,"");
    try {if(value.includes("://")) value=new URL(value).hostname;} catch(_) {return false;}
    value=value.split("/")[0];
    if(value.startsWith("[")) value=value.slice(1,value.indexOf("]"));
    else if((value.match(/:/g)||[]).length===1) value=value.replace(/:[0-9]+$/,"");
    return /^([0-9]{1,3}\.){3}[0-9]{1,3}$/.test(value) || (value.match(/:/g)||[]).length>=2;
  }
  const providerInfo=id=>edgeProviders.find(p=>p.id===id);
  function targetInput(mode,type="") {
    const t=settings.targets[mode];
    if(!isCleanMode(mode)) return t;
    const kind=type||t.targetType;
    return kind==="domain" && t.edgeInputs ? t.edgeInputs[t.edgeProvider] : t.inputs[kind];
  }
  function syncTargetInput(mode) {
    const t=settings.targets[mode],input=targetInput(mode);
    if(t.targetType==="domain") t.inputs.domain={...input};
    Object.assign(t,input);
  }
  function workspaceFor(mode,type="") {
    if(isCleanMode(mode)) return (type||settings?.targets[mode]?.targetType)==="domain" ? "edge-domains" : "clean-ip";
    return WORKSPACES.find(w=>w.modes.includes(mode))?.id||mode;
  }
  function selectedWorkspace() {return modeByID[page] ? workspaceFor(page) : page;}
  function workspaceKey(id) {return id==="edge-domains" ? id+":"+currentEdgeProvider : id;}
  function modesForWorkspace(id) {return id==="edge-domains" ? providerInfo(currentEdgeProvider)?.modes||["http","custom"] : workspaceByID[id]?.modes||[];}
  function openWorkspace(id) {
    if(!workspaceByID[id]) {navigate(id);return;}
    if(id==="edge-domains" && !providerInfo(currentEdgeProvider)) currentEdgeProvider="cloudflare";
    const allowed=modesForWorkspace(id), saved=rememberedModes[workspaceKey(id)];
    const mode=allowed.includes(saved) ? saved : allowed[0];
    if(isCleanMode(mode)) {
      const t=settings.targets[mode];t.targetType=workspaceByID[id].targetType;
      if(t.targetType==="domain") t.edgeProvider=currentEdgeProvider;
      syncTargetInput(mode);scheduleSave();
    }
    navigate(mode);
  }
  function openScanVariant(mode) {
    const workspace=selectedWorkspace();
    if(!modesForWorkspace(workspace).includes(mode)) return;
    if(isCleanMode(mode)) {
      settings.targets[mode].targetType=workspaceByID[workspace].targetType;
      if(workspace==="edge-domains") settings.targets[mode].edgeProvider=currentEdgeProvider;
      syncTargetInput(mode);scheduleSave();
    }
    navigate(mode);
  }
  function goToActiveScan() {
    const mode=activeMode||stats.mode;
    if(isCleanMode(mode)) {
      settings.targets[mode].targetType=stats.targetType||settings.targets[mode].targetType;
      if(stats.targetType==="domain") {currentEdgeProvider=providerInfo(stats.edgeProvider) ? stats.edgeProvider : "custom";settings.targets[mode].edgeProvider=currentEdgeProvider;}
      syncTargetInput(mode);
    }
    navigate(mode);
  }
  function runLabel(mode, type, provider="") {
    const name=modeByID[mode]?.title || mode || "No scan yet";
    return targetTypeLabel(type) ? name+" · "+targetTypeLabel(type)+(type==="domain"&&providerInfo(provider) ? " / "+providerInfo(provider).name : "") : name;
  }
  function normalizeSettings(s) {
    const out = {accent:"purple",proxyTestUrl:"https://example.com/",speedTestUrl:"https://speed.cloudflare.com/__down?bytes=25000000",speedDurationSecs:10,speedMaxSizeMb:25,...s, targets:{...s.targets}};
    for (const m of MODES) {
      const t={inputFile:"",targetsText:"",customPorts:"",...out.targets[m.id]};
      if(isCleanMode(m.id)) {
        const lines=t.targetsText.split(/\r?\n/);
        const targets=lines.filter(l=>l.trim()&&!l.trim().startsWith("#"));
        if(!["ip","domain"].includes(t.targetType)) t.targetType=targets.length && targets.every(l=>!legacyLineIsIP(l)) ? "domain" : "ip";
        const existing=t.inputs || {};
        t.inputs={...existing};
        for(const type of ["ip","domain"]) {
          const text=lines.filter(l=>!l.trim()||l.trim().startsWith("#")||legacyLineIsIP(l)===(type==="ip")).join("\n");
          t.inputs[type]={inputFile:t.inputFile,targetsText:text,customPorts:t.customPorts,serviceChecks:true,platformDomainsText:"workers.dev\npages.dev",...existing[type]};
        }
        const legacyDomain=t.inputs.domain,existingEdge=t.edgeInputs||{};
        if(!providerInfo(t.edgeProvider)) t.edgeProvider="cloudflare";
        t.edgeInputs={...existingEdge};
        for(const provider of edgeProviders) {
          const preserve=provider.id===t.edgeProvider && !Object.keys(existingEdge).length;
          t.edgeInputs[provider.id]={inputFile:"",targetsText:(provider.hosts||[]).join("\n"),customPorts:"",timeoutSecs:out.timeoutSecs,retryCount:out.retryCount,userAgent:out.userAgent,...(preserve ? legacyDomain : {}),...existingEdge[provider.id]};
          t.edgeInputs[provider.id].serviceChecks=existingEdge[provider.id]?.serviceChecks ?? true;
          t.edgeInputs[provider.id].platformDomainsText=existingEdge[provider.id]?.platformDomainsText ?? (provider.platformDomains||["workers.dev","pages.dev"]).join("\n");
          if(!Number.isFinite(t.edgeInputs[provider.id].retryCount)) t.edgeInputs[provider.id].retryCount=out.retryCount;
        }
        if(t.targetType==="domain") t.inputs.domain={...t.edgeInputs[t.edgeProvider]};
        Object.assign(t,t.inputs[t.targetType]);
      }
      out.targets[m.id]=t;
    }
    if (!["light","dark","system"].includes(out.theme)) out.theme = "system";
    if (!["purple","teal","milk"].includes(out.accent)) out.accent="purple";
    return out;
  }
  const snapshot = () => JSON.parse(JSON.stringify(settings));
  function persistSettings() {
    clearTimeout(saveTimer);
    const saved = snapshot();
    // Serialize writes: an older save must not overwrite a later edit or start.
    const next = saveChain.catch(() => {}).then(() => api.SaveSettings(saved));
    saveChain = next;
    return next;
  }
  function scheduleSave() {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => persistSettings().catch(e => toast(e, true)), 400);
  }
  function applyAccent(accent) {
    document.documentElement.dataset.accent=accent;
    try {localStorage.setItem("accent",accent)} catch(_) {}
  }
  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme === "system" ? (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light") : theme;
    try { localStorage.setItem("theme", theme); } catch (_) { /* storage may be disabled */ }
    $$("[data-theme-opt]").forEach(b => { b.classList.toggle("active", b.dataset.themeOpt === theme); b.setAttribute("aria-pressed", String(b.dataset.themeOpt === theme)); });
  }
  function field(key, label, {type="text", mode="", value, min, max, step, placeholder="", hint="",rows=7} = {}) {
    const id = `field-${mode ? mode + "-" : ""}${key}`;
    const v = value ?? (mode ? targetInput(mode)[key] : settings[key]);
    const attrs = `id="${id}" data-setting="${key}" ${mode ? `data-target-mode="${mode}"` : ""} ${min !== undefined ? `min="${min}"` : ""} ${max !== undefined ? `max="${max}"` : ""} ${step !== undefined ? `step="${step}"` : type === "number" ? 'step="1"' : ""} placeholder="${esc(placeholder)}" aria-describedby="${hint ? `${id}-hint ` : ""}${id}-error"`;
    return `<div class="field"><label for="${id}">${label}</label>${type === "textarea" ? `<textarea ${attrs} rows="${rows}" spellcheck="false">${esc(v)}</textarea>` : `<input type="${type}" ${attrs} value="${esc(v)}" ${type === "text" ? 'spellcheck="false"' : ""}>`}${hint ? `<small class="subtitle" id="${id}-hint">${hint}</small>` : ""}<small class="field-error" id="${id}-error" aria-live="polite" hidden></small></div>`;
  }
  function setFieldError(el, message = "") {
    if (!el) return;
    const error = document.getElementById(`${el.id}-error`);
    if (error) { error.textContent = message; error.hidden = !message; }
    if (message) { el.setAttribute("aria-invalid","true"); el.setAttribute("aria-errormessage",`${el.id}-error`); }
    else { el.removeAttribute("aria-invalid"); el.removeAttribute("aria-errormessage"); }
  }
  function numberFieldError(el) {
    const label = document.querySelector(`label[for="${el.id}"]`)?.textContent || "This value";
    if (!el.value.trim() || !Number.isFinite(el.valueAsNumber)) return `Enter a number for ${label.toLowerCase()}.`;
    if (el.validity.rangeUnderflow) return `${label} must be at least ${el.min}.`;
    if (el.validity.rangeOverflow) return `${label} must be at most ${el.max}.`;
    if (el.validity.stepMismatch) return el.step === "1" ? `${label} must be a whole number.` : `${label} must use increments of ${el.step}.`;
    return el.checkValidity() ? "" : `Check the value for ${label.toLowerCase()}.`;
  }
  function validateVisibleFields() {
    $$("#content input[type=number]:not(:disabled)").forEach(el => setFieldError(el,numberFieldError(el)));
    updateInputPreview(); updateConcurrencyControls();
    const invalid = $("#content [aria-invalid=true]:not(:disabled)");
    if (invalid) {
      invalid.focus();
      throw new Error(document.getElementById(`${invalid.id}-error`)?.textContent || "Correct the highlighted field.");
    }
  }
  const toggle = (key, label, hint = "") => `<label class="switch-row"><span>${label}${hint ? `<small>${hint}</small>` : ""}</span><input type="checkbox" data-setting="${key}" ${settings[key] ? "checked" : ""}><span class="switch" aria-hidden="true"></span></label>`;
  const rateFields = () => `<div class="field-row">${field("dnsRate", "Global queries / second", {type:"number", min:0, step:0.1})}${field("dnsRatePerResolver", "Per resolver / second", {type:"number", min:0, step:0.1})}</div><div class="field-row">${field("dnsBurst", "Burst", {type:"number", min:1})}${field("dnsJitter", "Timing jitter (0-1)", {type:"number", min:0, max:1, step:0.05})}</div><p class="subtitle">A rate of 0 disables that limit. Limits and jitter can improve accuracy on networks that drop rapid DNS queries.</p>`;
  function renderNav() {
    const scans=WORKSPACES.map(w=>'<button type="button" class="nav-item" data-workspace="'+w.id+'">'+icon(w.icon)+'<span>'+w.title+'</span><i class="live" hidden aria-label="Active scan"></i></button>').join("");
    const tools=[["results","Results","table"],["reports","Reports","folder"],["config","Config maker","config"],["speed","Speed test","download"]].map(([id,label,glyph])=>'<button type="button" class="nav-item" data-page="'+id+'">'+icon(glyph)+'<span>'+label+'</span>'+(id==="results" ? '<span class="count" id="navCount">0</span>' : '')+'</button>').join("");
    const options=WORKSPACES.map(w=>'<option value="'+w.id+'">'+w.title+'</option>').join("");
    $("#nav").innerHTML='<div class="nav-links"><div class="nav-group">Scans</div>'+scans+'<div class="nav-group">Workspace</div>'+tools+'<div class="nav-divider"></div><button type="button" class="nav-item" data-page="settings">'+icon("gear")+'<span>Settings</span></button></div><div class="mobile-navigation"><label for="mobileNav">Navigate</label><select id="mobileNav" aria-label="Navigate"><optgroup label="Scans">'+options+'</optgroup><optgroup label="Workspace"><option value="results">Results</option><option value="reports">Reports</option><option value="config">Config maker</option><option value="speed">Speed test</option><option value="settings">Settings</option></optgroup></select></div>';
    updateChrome();
  }
  function setText(selector, value) { const el = $(selector); const text = String(value); if (el && el.textContent !== text) el.textContent = text; }
  function updateChrome() {
    const current=selectedWorkspace(),running=workspaceFor(activeMode,stats.targetType);
    $$("#nav [data-workspace],#nav [data-page]").forEach(b => {
      const route=b.dataset.workspace||b.dataset.page;
      const selected=route===current;
      b.classList.toggle("active", selected);
      if (selected) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current");
      const dot = $(".live", b); if (dot) dot.hidden = !(busy && route===running);
    });
    if($("#mobileNav")) $("#mobileNav").value=current;
    setText("#navCount", fmt(stats.counts?.all));
    const state = busy && stats.state === "STOPPED" ? "SAVING" : stats.viewing ? "SAVED" : stats.state;
    $("#stateChip").dataset.state = state;
    setText("#stateChip span", actionPending === "start" ? "Starting" : state === "SAVING" ? "Saving reports" : state === "SAVED" ? "Loaded run" : ({IDLE:"Idle",RUNNING:"Running",PAUSED:"Paused",STOPPED:"Finished"}[state] || "Idle"));
  }
  function navigate(next) {
    if (!modeByID[next] && !["results","reports","settings","speed","config"].includes(next)) return;
    page = next; queryVersion++; clearTimeout(searchTimer); searching = false; clearTimeout(liveTimer);
    pendingFeedRows = pendingResultPage = null; resultsRefreshDeferred = false;
    $("#drawer").hidden = true; detailRow = null;
    $("#content").scrollTop = 0;
    const m = modeByID[page];
    if(m) {
      const workspace=workspaceFor(page);
      if(workspace==="edge-domains") currentEdgeProvider=settings.targets[page].edgeProvider;
      rememberedModes[workspaceKey(workspace)]=page;
      try {localStorage.setItem("scan-workspaces",JSON.stringify(rememberedModes));if(currentEdgeProvider) localStorage.setItem("edge-provider",currentEdgeProvider);} catch(_) {}
    }
    setText("#pageTitle", m ? workspaceByID[workspaceFor(page)].title : m?.title || ({results:"Results",reports:"Reports",settings:"Settings",speed:"Speed test",config:"Config maker"}[page]));
    setText("#pageSubtitle", m?.subtitle || ({results:"Search, filter and inspect one page at a time",reports:"Saved scans, grouped by mode and date",settings:"Appearance, output and scanner preferences",speed:"Download performance through your selected IP or proxy",config:"Point your proxy configs at the clean IPs you found"}[page]));
    $("#modeBadge").hidden = !m; setText("#modeBadge", m?.id === "sni" ? "SNI / HTTPS" : m?.id?.endsWith("proxy") ? m.title : m?.family === "http" ? "Clean IP" : m?.family === "txt" ? "TXT" : "DNS");
    updateChrome();
    if (m) renderMode(m); else if (page === "results") renderResults(); else if (page === "reports") renderReports(); else if (page === "speed") renderSpeedPage(); else if (page === "config") renderConfigPage(); else renderSettings();
  }
  function concurrencyControls() {
    return '<div class="concurrency-control"><div class="concurrency-title">Concurrency</div><div class="segmented" role="group" aria-label="Concurrency mode">'+[true,false].map(auto=>'<button type="button" data-action="concurrency-mode" data-auto="'+auto+'" class="'+(settings.autoConcurrency===auto?'active':'')+'" aria-pressed="'+(settings.autoConcurrency===auto)+'">'+(auto?'Automatic':'Manual')+'</button>').join('')+'</div><div class="field-row">'+field('maxConcurrent',settings.autoConcurrency?'Maximum workers':'Concurrent workers',{type:'number',min:1,hint:'Your worker limit applies to every scan type.'})+'<div class="automatic-min" '+(settings.autoConcurrency?'':'hidden')+'>'+field('minConcurrent','Minimum workers',{type:'number',min:1})+'</div></div><p class="subtitle">Manual uses your chosen worker limit. Changes apply to the next scan.</p></div>';
  }
  function updateConcurrencyControls() {
    $$("[data-action=concurrency-mode]").forEach(b=>{const chosen=(b.dataset.auto==='true')===settings.autoConcurrency;b.classList.toggle('active',chosen);b.setAttribute('aria-pressed',String(chosen));});
    const min=$(".automatic-min");if(min) min.hidden=!settings.autoConcurrency;
    const label=$("label[for=field-maxConcurrent]");if(label) label.textContent=settings.autoConcurrency?'Maximum workers':'Concurrent workers';
    const minimum=$("#field-minConcurrent");
    if(minimum) {
      minimum.disabled=!settings.autoConcurrency;
      const error = minimum.disabled ? "" : numberFieldError(minimum);
      const maximum = $("#field-maxConcurrent");
      setFieldError(minimum,error || (!minimum.disabled && maximum && !numberFieldError(maximum) && minimum.valueAsNumber > maximum.valueAsNumber ? "Minimum workers must not exceed maximum workers." : ""));
    }
  }
  function metricsFor(m) {
    const base = [["done","Scanned","primary"],["ok",m.family === "http" ? "Reachable" : m.family === "txt" ? "Answered" : "Clean","matcha"]];
    if (m.family === "http") return [...base,["dead","Failed","strawberry"],["alerts","Alerts","taro"],["speed","Speed","honey"],["elapsed","Elapsed","thai"]];
    if (m.family === "txt") return [...base,["dead","Failed","strawberry"],["all","Records","honey"],["tunnel","Tunnel-ready","taro"]];
    return [...base,["poisoned","Poisoned","taro"],["hijacked","Hijacked","honey"],["dead","Failed","strawberry"],["tunnel","Tunnel-ready","matcha"],["speed","Speed","primary"],["elapsed","Elapsed","thai"]];
  }
  function renderMode(m) {
    feedSignature = ""; logSignature = "";
    const clean=isCleanMode(m.id), selectedType=clean ? settings.targets[m.id].targetType : "";
    const selectedName=targetTypeLabel(selectedType);
    const targetLabel=clean ? selectedType==="ip" ? "Paste IPs, IP endpoints or CIDR ranges" : "Paste edge domains or domain URLs" : m.id.endsWith("proxy") ? "Paste proxy IPs, endpoints or URLs" : m.family==="http" ? "Paste domains, IPs, endpoints or CIDR ranges" : "Paste resolver IPs or CIDR ranges";
    const targetPlaceholder=clean ? selectedType==="ip" ? "104.16.0.1\n104.16.0.0/24\n[2606:4700::1111]:443" : "edge.example.com\nhttps://cdn.example.com\ncdn.example.net:8443" : m.id.endsWith("proxy") ? "127.0.0.1:8080\nhttp://user:pass@proxy.example.com:3128" : m.family==="http" ? "example.com\n1.1.1.1:443" : "1.1.1.1\n8.8.8.8";
    const targetHint=clean ? (selectedType==="ip" ? "Only IPs and CIDR ranges. Domains belong in Edge domains." : "Only domain names and domain URLs. IPs and CIDRs belong in Cloudflare clean IP finder.")+" One target per line. Explicit endpoints and URLs keep their ports. Pasted text takes priority over the file." : "One target per line. Supports IPs, domains, CIDRs, [IPv6]:port and URLs. Explicit endpoints and URLs take priority over port lists. Pasted text takes priority over the file.";
    const workspace=workspaceFor(m.id),variants=modesForWorkspace(workspace);
    const provider=selectedType==="domain" ? providerInfo(settings.targets[m.id].edgeProvider) : null;
    const providerPicker=provider ? '<div class="field provider-field"><label for="edgeProvider">CDN provider</label><select id="edgeProvider" aria-label="CDN provider">'+edgeProviders.map(p=>'<option value="'+p.id+'" '+(p.id===provider.id ? 'selected' : '')+'>'+esc(p.name)+'</option>').join("")+'</select></div>' : '';
    const variantPicker=variants.length>1 ? '<div class="variant-picker" role="group" aria-label="Scan option">'+variants.map(id=>'<button type="button" class="scan-variant '+(id===m.id ? 'active' : '')+'" data-action="scan-variant" data-scan-mode="'+id+'" aria-pressed="'+(id===m.id)+'"><b>'+esc(modeByID[id].title)+'</b><small>'+esc(modeByID[id].subtitle)+'</small></button>').join("")+'</div>' : '';
    const setup=providerPicker||variantPicker ? '<section class="glass panel scan-setup">'+(provider ? '<h2>'+esc(provider.name)+' domain options</h2>' : '<h2>Scan options</h2>')+providerPicker+variantPicker+(provider ? '<p class="subtitle">'+esc(provider.hint)+' Targets and request settings are saved independently for this provider and scan option.</p>' : '')+'</section>' : '';
    setText("#pageSubtitle",(provider ? provider.name+" · " : "")+m.title);
    setText("#modeBadge",provider ? provider.name : clean ? "IP finder" : m.family==="txt" ? "TXT" : m.family==="dns" ? "DNS" : m.id==="sni" ? "SNI / HTTPS" : "Proxy");
    let options = "";
    if (m.id === "http-all") options += `<div class="port-chips">${CF_PORTS.map(p => `<span title="${p === 443 || [2053,2083,2087,2096,8443].includes(p) ? "HTTPS" : "HTTP"}">${p}</span>`).join("")}</div>`;
    if (m.id !== "http-all") options += field("customPorts", m.id === "custom" ? "Ports (required)" : "Custom ports (optional)", {mode:m.id, placeholder:"80,443,8000-8010", hint:"Comma separated ports and ranges, from 1 to 65535."}) + '<div class="port-chips" id="portPreview"></div>';
    if (m.id === "sni") options += field("spoofedSni", "Forged SNI", {placeholder:"www.speedtest.net", hint:"Hostname sent in TLS ClientHello. Applies to both preflight and HTTPS requests; HTTP keeps the target Host."});
    else if (m.id.endsWith("proxy")) options += field("proxyTestUrl","Proxy test URL",{placeholder:"https://example.com/",hint:"Each proxy must forward this URL successfully. Use a URL reachable on your network."});
    else if (m.family === "txt") options += field("dnsTxtDomain", "TXT base domain (required)", {placeholder:"tunnel.example.com"});
    else if (m.family === "dns") options += `<div class="field-row">${field("targetDomain", "Integrity domain", {placeholder:"google.com"})}${field("dnsMaxPingMs", "Maximum DNS ping (ms)", {type:"number",min:1})}</div>`;
    if(clean) {
      // Fronting: a clean IP is one the user's own Worker / Pages hostnames answer through.
      const input=targetInput(m.id),domains=serviceDomains(input,provider);
      options+=field("platformDomainsText",provider ? "Fronting domains ("+esc(provider.name)+")" : "Fronting domains",{mode:m.id,type:"textarea",rows:3,placeholder:"my-worker.me.workers.dev",hint:"The Worker / Pages hostnames from your configs, one per line, tested through each IP as both SNI and Host. An IP is clean when any tested domain answers through it."});
      options+='<details class="service-checks"><summary>Service checks ('+domains.length+' domains)</summary><label class="switch-row"><span>Test every fronting domain and the shared services<small>Off: a quicker check through the first fronting domain only.</small></span><input type="checkbox" data-setting="serviceChecks" data-target-mode="'+m.id+'" '+(input.serviceChecks?'checked':'')+'><span class="switch" aria-hidden="true"></span></label><p class="subtitle">These shared services are tested through each IP as well. Any domain that answers makes the IP clean; Results lists which ones passed.</p><div class="service-domain-list">'+ORIGINAL_SERVICES.slice(2).map(domain=>'<span>'+esc(domain)+'</span>').join("")+'</div></details>';
    }
    if(provider) options+='<details class="provider-requests"><summary>'+esc(provider.name)+' request settings</summary><div class="field-row">'+field("timeoutSecs","Timeout (seconds)",{mode:m.id,type:"number",min:1})+field("retryCount","Retries",{mode:m.id,type:"number",min:0})+'</div>'+field("userAgent","User-Agent",{mode:m.id,hint:"Saved only for this provider and scan option."})+'</details>';
    // IP-based targets can come from the ASN list and be limited to one IP version.
    const ipTargets=!(clean && selectedType==="domain"), family=targetInput(m.id).ipFamily||"both";
    const asnButton=btn("ASN list", "pick-asn", "outlined", "dns", ipTargets ? 'title="Add the IP ranges of networks you pick"' : 'title="Add ASN IP ranges to Clean IP finder (edge domains take hostnames)"');
    const familyPicker=ipTargets ? '<div class="field ip-family"><span class="field-label" id="ipFamilyLabel">IP version</span><div class="segmented" role="group" aria-labelledby="ipFamilyLabel">'+[["both","Both"],["ipv4","IPv4"],["ipv6","IPv6"]].map(([v,l])=>'<button type="button" data-action="ip-family" data-family="'+v+'" class="'+(family===v?"active":"")+'" aria-pressed="'+(family===v)+'">'+l+'</button>').join("")+'</div><small class="subtitle">Scans only IPv4 or only IPv6 addresses and ranges from your targets. Hostnames are always kept. IPv6 ranges are sampled (up to 256 addresses each), as on Android.</small></div>' : "";
    $("#content").innerHTML = `${setup}<div class="mode-grid"><div class="col"><article class="glass panel intro"><h2>${icon(m.icon)}${m.title}</h2><p>${clean ? selectedType==="ip" ? "Scan the IPs and ranges you provide for Cloudflare-compatible HTTP/HTTPS reachability on this mode’s ports. You choose the target IPs; domain targets are kept in Edge domains." : "Resolve the edge domains you provide and test their HTTP/HTTPS endpoints on this mode’s ports. Domain targets stay separate from the IP finder." : m.desc}</p><div class="how">${m.chips.map(([k,v]) => `<span><b>${k}</b> ${v}</span>`).join("")}</div></article><section class="glass panel"><h2>${icon("file")}Targets <small>${provider ? esc(provider.name) : clean ? esc(selectedName) : "saved for this mode"}</small></h2><div class="field-row"><div class="grow">${field("inputFile", "Targets file", {mode:m.id,placeholder:"Choose a text file"})}</div>${btn("Browse", "pick-input", "outlined", "folder")}${asnButton}</div>${field("targetsText",targetLabel,{mode:m.id,type:"textarea",placeholder:targetPlaceholder,hint:targetHint})}<div class="asn-chips" id="asnChips"></div><p class="estimate" id="targetEstimate"></p>${familyPicker}</section><section class="glass panel"><h2>${icon("tune")}Scan options</h2>${options}${(clean || m.id.endsWith("proxy")) ? `<div class="anti-dpi-options">${toggle("antiDpi","Anti-DPI: fragment ClientHello","Optional TCP fragmentation; preserves TLS validation and original hostnames. May add handshake time.")}<div class="field-row">${field("dpiFragmentSize","Fragment size (bytes)",{type:"number",min:1,max:1024,value:settings.dpiFragmentSize || 64})}${field("dpiFragmentDelayMs","Delay between fragments (ms)",{type:"number",min:0,max:20,value:settings.dpiFragmentDelayMs ?? 1})}</div></div>` : ""}${btn("More settings", "settings", "text small", "gear")}</section>${m.family !== "http" ? `<details class="glass panel"><summary>DNS rate limit</summary><div class="details-body">${rateFields()}</div></details>` : ""}</div><div class="col"><div class="banner" id="otherScan" hidden><span id="otherScanText"></span>${btn("Go to scan", "go-active", "tonal small")}</div><section class="glass panel"><h2>${icon("play")}Scan control</h2>${concurrencyControls()}<div class="run-head">${btn("Start scan", "start", "filled", "play", 'id="startScan" title="Start this mode (Ctrl+Enter)"')}${btn("Pause", "pause-resume", "tonal", "pause", 'id="pauseScan" title="Pause (P) / resume (R)"')}${btn("Stop &amp; save", "stop", "danger", "stop", 'id="stopScan" title="Stop and save every report (Q)"')}</div><div class="boba-wrap"><span class="boba-bubble" id="progressBubble">0%</span><div class="boba" id="progressBar" role="progressbar" aria-label="Scan progress" aria-valuemin="0" aria-valuemax="100"><div class="boba-fill" id="progressFill"></div></div></div><div class="progress-text"><span id="progressCount"></span><span id="progressEta"></span></div><div class="message" id="scanMessage" role="status"></div><p class="subtitle" id="performanceSummary"></p></section><div class="metrics">${metricsFor(m).map(([key,label,color]) => `<div class="metric glass c-${color}"><span>${label}</span><b data-metric="${key}">0</b>${key === "speed" ? "<small>probes / second</small>" : ""}</div>`).join("")}</div><section class="glass panel"><h2>${icon("table")}Live activity<span class="grow"></span><span class="segmented feed-views" role="group" aria-label="Activity view">${[["log","Scan log"],["hits",m.family === "http" ? "Passed" : "Latest probes"]].map(([v,l]) => `<button type="button" data-action="feed-view" data-view="${v}" class="${feedView===v?"active":""}" aria-pressed="${feedView===v}">${l}</button>`).join("")}</span>${btn("Results", "results", "text small")}</h2><ol class="scan-log" id="scanLog" aria-label="Scan log" tabindex="0" ${feedView==="log"?"":"hidden"}></ol><div id="hitsView" ${feedView==="hits"?"":"hidden"}><ul class="feed" id="activityFeed" aria-label="Recent scan results"></ul><p class="subtitle">Hover or focus a result for quick actions. Select a row for full details.</p><p class="subtitle" id="feedRefreshState" role="status"></p></div></section><section class="glass panel done-panel" id="postScan" hidden><h2>${icon("folder")}<span id="postScanTitle">Reports saved</span></h2><p class="subtitle" id="runFolder"></p><div class="row-gap">${btn("Run again", "start", "filled small", "redo")}${btn("View results", "results", "tonal small", "table")}${btn("Open run folder", "open-run", "outlined small", "open")}${btn("Reports", "reports", "text small", "folder")}</div></section></div></div>`;
    updateInputPreview(); updateConcurrencyControls(); updateMode();
  }
  function parsePorts(text) {
    const seen = new Set();
    for (const part of String(text).split(",").map(p => p.trim()).filter(Boolean)) {
      const match = part.match(/^\+?([0-9]+)(?:\s*-\s*\+?([0-9]+))?$/);
      if (!match) throw new Error(`Invalid port or range: ${part}`);
      let a = Number(match[1]), b = Number(match[2] || match[1]);
      if (a > b) [a,b] = [b,a];
      if (a < 1 || b > 65535) throw new Error(`Port out of range: ${part}`);
      for (let p = a; p <= b; p++) seen.add(p);
    }
    return [...seen];
  }
  function updateInputPreview() {
    const m = modeByID[page]; if (!m) return;
    const t = targetInput(m.id), preview = $("#portPreview");
    if (preview) {
      try { const ports = parsePorts(t.customPorts); preview.innerHTML = ports.length ? ports.slice(0,30).map(p => `<span>${p}</span>`).join("") + (ports.length > 30 ? `<span>+${fmt(ports.length - 30)} more</span>` : "") : '<span>Use mode defaults</span>'; setFieldError($("[data-setting=customPorts]")); }
      catch(e) { preview.innerHTML = '<span class="err">Check the port list</span>'; setFieldError($("[data-setting=customPorts]"),e.message); }
    }
    // Count input lines only; never expand CIDRs in the webview.
    const count = t.targetsText.split(/\r?\n/).filter(l => l.trim() && !l.trim().startsWith("#")).length;
    const picks = t.asns || [], ranges = picks.reduce((n,p) => n + number(p.ranges), 0);
    const asnText = picks.length ? `${fmt(picks.length)} ASN${picks.length === 1 ? "" : "s"} (${fmt(ranges)} ranges, expanded when the scan starts)` : "";
    const source = count ? `${fmt(count)} target lines in pasted list` : t.inputFile.trim() ? "The selected targets file" : "";
    setText("#targetEstimate", source || asnText ? `${[source, asnText].filter(Boolean).join(" + ")}. CIDRs and ports are expanded by the scanner.` : "Choose a file, paste targets or add an ASN to get started.");
    renderASNChips(t);
  }
  function rowsEngaged(root, selector) {
    if (!root) return false;
    const focused = document.activeElement;
    if (root.contains(focused) && focused.closest(selector)) return true;
    const overlayOpen = ["drawer","help","viewer"].some(id => !$("#"+id).hidden);
    if (overlayOpen && overlayFocus && root.contains(overlayFocus)) return true;
    return matchMedia("(hover:hover)").matches && !!root.querySelector(`${selector}:hover`);
  }
  function reconcileRows(root, rows, kind, render) {
    const existing = new Map([...root.children].filter(el => el.dataset.rowKey).map(el => [el.dataset.rowKey,el]));
    const template = document.createElement("template");
    const remember = (node,row,index) => {
      node.dataset.rowKey = String(row.seq);
      rowMetadata.set(node,{signature:JSON.stringify(row),index,actions:[...node.querySelectorAll("[data-index]")]});
    };
    if (!existing.size) {
      template.innerHTML = rows.map(render).join("");
      root.replaceChildren(template.content);
      [...root.children].forEach((node,index) => remember(node,rows[index],index));
      return;
    }
    rows.forEach((row,index) => {
      const key = String(row.seq), signature = JSON.stringify(row);
      let node = existing.get(key), metadata = node && rowMetadata.get(node);
      if (!metadata || metadata.signature !== signature) {
        template.innerHTML = render(row,index);
        const replacement = template.content.firstElementChild;
        if (node) node.replaceWith(replacement);
        node = replacement; remember(node,row,index); metadata = rowMetadata.get(node);
      }
      if (metadata.index !== index) {
        node.dataset[kind] = String(index);
        metadata.actions.forEach(action => action.dataset.index = String(index));
        metadata.index = index;
      }
      if (root.children[index] !== node) root.insertBefore(node,root.children[index] || null);
      existing.delete(key);
      if (kind === "result") node.classList.toggle("selected",detailRow?.seq === row.seq);
    });
    existing.forEach(node => node.remove());
  }
  function renderActivityFeed(rows) {
    const root = $("#activityFeed"); if (!root) return;
    const signature = JSON.stringify(rows);
    if (signature === feedSignature) return;
    if (rowsEngaged(root,"[data-feed]")) {
      pendingFeedRows = rows; setText("#feedRefreshState","Updates wait while you use a result"); return;
    }
    pendingFeedRows = null; feedRows = rows; feedSignature = signature;
    setText("#feedRefreshState","");
    const m = modeByID[page];
    reconcileRows(root,rows,"feed",(r,i) => `<li data-feed="${i}" title="${esc(r.error || r.answer || r.url)}"><button type="button" class="feed-inspect" data-action="inspect-feed" data-index="${i}" aria-label="${esc(`Inspect ${r.label}`)}"><span class="line"><span class="who">${esc(r.label)}</span><span class="grow"></span>${m.family !== "http" ? protocolBadge(r.protocol)+resultBadge(r) : latency(r)}</span><span class="line"><span class="sub">${esc(m.family === "http" ? `${r.url} | ${r.ip}:${r.port}` : r.error || r.answer || r.ip || "No answer")}</span>${m.family !== "http" ? latency(r) : ""}</span></button><span class="quick-actions">${m.family === "http" ? `<button type="button" class="icon-btn" data-action="speed-feed" data-index="${i}" title="Test download speed through this endpoint" aria-label="Test speed">${icon("download")}</button>` : ""}<button type="button" class="icon-btn" data-action="copy-feed" data-index="${i}" title="Copy target" aria-label="Copy target">${icon("copy")}</button></span></li>`);
    if (!rows.length) { const empty = document.createElement("li"); empty.className = "empty"; empty.textContent = "Results will appear here as probes finish."; root.append(empty); }
  }
  // The scan log keeps its place: it follows new lines only while scrolled to the bottom.
  function renderScanLog(lines) {
    const root = $("#scanLog"); if (!root) return;
    const signature = lines.length ? `${lines[0].seq}-${lines[lines.length-1].seq}` : "";
    if (signature === logSignature) return;
    logSignature = signature;
    const follow = root.scrollHeight - root.scrollTop - root.clientHeight < 24;
    root.innerHTML = lines.length ? lines.map(l => `<li class="log-${["ok","fail","error"].includes(l.level) ? l.level : "info"}"><time>${esc(l.at)}</time><span>${esc(l.text)}</span></li>`).join("")
      : '<li class="empty">Scan steps and every probe result appear here.</li>';
    if (follow) root.scrollTop = root.scrollHeight;
  }
  function applyResultPage(data) {
    resultPage = data; pendingResultPage = null; resultsRefreshDeferred = false;
    renderResultRows(); updateTabs(resultPage.counts); updateResultsSource();
  }
  function scheduleRowsFlush() {
    if (rowsFlushPending || (!pendingFeedRows && !resultsRefreshDeferred)) return;
    rowsFlushPending = true;
    requestAnimationFrame(() => {
      rowsFlushPending = false;
      if (pendingFeedRows && !rowsEngaged($("#activityFeed"),"[data-feed]")) renderActivityFeed(pendingFeedRows);
      if (page === "results" && resultsRefreshDeferred && !rowsEngaged($("#resultRows"),"[data-result]")) {
        const pending = pendingResultPage; pendingResultPage = null; resultsRefreshDeferred = false;
        if (pending?.version === queryVersion) applyResultPage(pending.data); else refreshResults();
      }
    });
  }
  document.addEventListener("focusout",scheduleRowsFlush);
  document.addEventListener("pointerout",scheduleRowsFlush);
  function updateMode() {
    const m = modeByID[page]; if (!m || !$("#startScan")) return;
    const sameProfile=!isCleanMode(m.id) || ((!stats.targetType || stats.targetType===settings.targets[m.id].targetType) && (settings.targets[m.id].targetType!=="domain" || !stats.edgeProvider || stats.edgeProvider===settings.targets[m.id].edgeProvider));
    const own = stats.mode === m.id && sameProfile;
    const shown = own ? stats : emptyStats();
    const active = busy && activeMode === m.id && sameProfile;
    $("#startScan").disabled = !ready || busy || !!actionPending;
    $("#pauseScan").disabled = !active || !["RUNNING","PAUSED"].includes(stats.state) || !!actionPending;
    $("#pauseScan").innerHTML = icon(stats.state === "PAUSED" ? "play" : "pause") + (stats.state === "PAUSED" ? "Resume" : "Pause");
    $("#stopScan").disabled = !active || !["RUNNING","PAUSED"].includes(stats.state) || !!actionPending;
    $("#otherScan").hidden = !busy || active;
    setText("#otherScanText", `${modeByID[activeMode]?.title || "Another mode"} is ${stats.state === "STOPPED" ? "saving reports" : "active"}.`);
    const total = number(shown.total), done = number(shown.done), known = total > 0;
    const pct = known ? Math.max(0, Math.min(100, done / total * 100)) : 0;
    $("#progressFill").style.width = `${pct}%`;
    $("#progressBubble").style.left = `${Math.min(96, Math.max(4,pct))}%`;
    setText("#progressBubble", known ? `${pct.toFixed(0)}%` : active ? "..." : "0%");
    $("#progressBar").classList.toggle("running", active && shown.state === "RUNNING");
    $("#progressBar").classList.toggle("indeterminate", active && !known);
    if (known) $("#progressBar").setAttribute("aria-valuenow", String(Math.round(pct))); else $("#progressBar").removeAttribute("aria-valuenow");
    setText("#progressCount", `${fmt(done)} of ${known ? fmt(total) : active ? "unknown total" : "0"}`);
    setText("#progressEta", shown.viewing ? "Loaded run" : shown.state === "PAUSED" ? "Paused" : active && shown.state === "STOPPED" ? "Saving reports..." : shown.etaS > 0 ? `${duration(shown.etaS)} remaining` : active ? "Estimating..." : duration(shown.elapsedS));
    const message = active && shown.state === "STOPPED" ? "Saving reports. Please wait before starting another scan." : shown.message || (active ? "Preparing targets and scanning..." : "Ready when you are.");
    setText("#scanMessage", message); $("#scanMessage").classList.toggle("error", /^(FATAL|ERROR)/.test(shown.message));
    const counts = shown.counts || {};
    $$("[data-metric]").forEach(el => {
      const key = el.dataset.metric;
      const value = key === "done" ? fmt(shown.done) : key === "alerts" ? fmt(number(counts.poisoned) + number(counts.hijacked)) : key === "speed" ? number(shown.ratePerS).toFixed(1) : key === "elapsed" ? duration(shown.elapsedS) : fmt(counts[key]);
      if (el.textContent !== value) el.textContent = value;
    });
    setText("#performanceSummary", `${isCleanMode(m.id) && shown.targetType ? targetTypeLabel(shown.targetType)+". " : ""}${settings.autoConcurrency ? "Automatic" : "Manual"} concurrency, up to ${fmt(settings.maxConcurrent)} workers.${settings.limitedNetwork ? " Limited network mode." : ""} ${settings.streaming ? "Streaming enabled" : settings.streamingAuto ? "Large inputs stream automatically" : "Targets loaded into memory"}.`);
    renderActivityFeed((shown.recent || []).filter(r => m.family !== "http" || r.category === "ok").slice(0,14));
    renderScanLog(shown.log || []);
    $("#postScan").hidden = !(own && shown.state === "STOPPED" && !busy && shown.runDir && !shown.viewing);
    setText("#postScanTitle", /^(FATAL|ERROR)/.test(shown.message) ? "Run needs attention" : "Reports saved");
    setText("#runFolder", shown.runDir);
  }
  function protocolBadge(p) { const family = ["UDP","TCP","DoT","DoH"].find(k => String(p).startsWith(k)) || ""; return `<span class="badge ${family}">${esc(p || "-")}</span>`; }
  function resultBadge(r) { const category = ["ok","dead","poisoned"].includes(r.category) ? r.category : "dead"; return `<span class="badge ${category}" title="${esc(r.error)}">${category === "ok" ? "Clean" : category === "dead" ? "Failed" : "Poisoned"}</span>${r.hijacked ? '<span class="badge hijacked">Hijacked</span>' : ""}`; }
  function latency(r) { return r.error ? '<span class="dim">-</span>' : `<span class="lat lat-${r.latencyMs <= 200 ? "fast" : r.latencyMs <= 1000 ? "mid" : "slow"}">${fmt(r.latencyMs)} ms</span>`; }
  function renderSettings() {
    $("#content").innerHTML = `<div class="settings"><section class="glass panel"><h2>Appearance</h2><div class="segmented" role="group" aria-label="Appearance">${["system","light","dark"].map(t => `<button type="button" data-action="theme" data-theme="${t}" class="${settings.theme === t ? "active" : ""}" aria-pressed="${settings.theme === t}">${t[0].toUpperCase() + t.slice(1)}</button>`).join("")}</div><p class="subtitle">System follows your device appearance.</p><h3 class="palette-heading">Bubble tea palette</h3><div class="segmented palette" role="group" aria-label="Accent palette">${[["purple","Taro purple"],["teal","Teal tea"],["milk","Milk tea"]].map(([key,label])=>`<button type="button" data-action="accent" data-accent="${key}" class="${settings.accent===key ? "active" : ""}" aria-pressed="${settings.accent===key}">${label}</button>`).join("")}</div></section><section class="glass panel"><h2>Output</h2>${field("outputDir","Output folder")}${btn("Browse", "pick-output", "outlined small", "folder")}${btn("Open folder", "open-output", "text small", "open")}${field("cacheFile","Passed-target cache filename", {hint:"Each mode keeps its own cache beside its run folders."})}</section><section class="glass panel"><h2>Requests</h2><div class="field-row">${field("timeoutSecs","Timeout (seconds)",{type:"number",min:1})}${field("retryCount","Retries",{type:"number",min:0})}</div>${toggle("limitedNetwork","Limited network mode","For slow or lossy connections: timeouts are retried and service checks run 3 domains at a time, as in earlier versions. Scans take longer but miss fewer IPs on unreliable networks.")}${field("userAgent","User-Agent")}${field("spoofedSni","Forged SNI",{hint:"Used only by SNI scan. Clean IP, HTTP proxy, SOCKS proxy and DNS modes use ordinary TLS."})}</section><section class="glass panel"><h2>Performance</h2>${concurrencyControls()}${toggle("streaming","Always stream targets","Read targets incrementally to reduce memory use.")}${toggle("streamingAuto","Stream large inputs automatically")}<div class="field-row">${field("streamingThreshold","Target threshold",{type:"number",min:1})}${field("streamingSizeMb","File threshold (MB)",{type:"number",min:1})}</div>${toggle("countTotal","Count total targets","Request an accurate progress total when supported.")}<p class="subtitle">Live results refresh at most once per second. Pause live updates in Results to reduce rendering work further.</p></section><section class="glass panel"><h2>DNS</h2>${field("targetDomain","Integrity domain")}${field("dnsMaxPingMs","Maximum DNS ping (ms)",{type:"number",min:1})}${field("dnsTxtDomain","TXT base domain")}</section><section class="glass panel"><h2>DNS rate limit</h2>${rateFields()}</section><section class="glass panel wide"><h2>About WhiteDNS Scanner</h2><p class="subtitle">Nine independent scan modes with live results, per-mode target lists and saved reports. Changes apply to the next scan.</p><p>Developed by whisper the heaven &amp; ashentajir</p>${btn("Keyboard shortcuts", "help", "tonal small")}</section><div class="settings-actions wide">${btn("Reset to defaults", "reset", "outlined", "redo")}</div></div>`;
    updateConcurrencyControls();
  }

  function selectSpeedRow(row) {
    if (!row || row.category !== "ok" || row.protocol) return;
    if (speedRunning) {toast("Wait for the current speed test or cancel it first.");return;}
    speedRow={...row}; speedRunDir=stats.runDir; speedResult=null; navigate("speed");
  }
  // ---- Config maker (the TUI's): repoint proxy configs at clean IP:port targets ----
  const cm = {mode:"rewrite", configs:"", targets:"", info:null, result:null, busy:false};
  let cmTimer = 0, cmVersion = 0;
  function renderConfigPage() {
    const rewrite = cm.mode === "rewrite";
    $("#content").innerHTML = `<div class="mode-grid config-maker"><div class="col"><section class="glass panel intro"><h2>${icon("config")}Config maker</h2><p>Make one config per clean IP: each IP:port gets a copy of your config with only its address and port replaced, so UUIDs, SNI, Host and paths stay as they are. Or pull the IP:port endpoints out of configs you already have.</p><div class="how"><span><b>Formats</b> vless, vmess, trojan, ss, hysteria2</span><span><b>Also</b> WireGuard, AmneziaWG</span></div><div class="segmented" role="group" aria-label="Config maker action">${[["rewrite","Make configs"],["extract","Extract IP:port"]].map(([v,l]) => `<button type="button" data-action="cm-mode" data-mode="${v}" class="${cm.mode===v?"active":""}" aria-pressed="${cm.mode===v}">${l}</button>`).join("")}</div></section><section class="glass panel"><h2>${icon("file")}Configs</h2><div class="field"><label for="cmConfigs">${rewrite ? "Proxy configs to copy" : "Configs or any text with IP:port"}</label><textarea id="cmConfigs" rows="8" spellcheck="false" placeholder="vless://uuid@host:443?security=tls&amp;sni=my-worker.me.workers.dev#name" aria-describedby="cmConfigsInfo">${esc(cm.configs)}</textarea><small class="subtitle" id="cmConfigsInfo"></small></div>${btn("Load file", "cm-load", "outlined small", "folder", 'data-into="configs"')}</section>${rewrite ? `<section class="glass panel"><h2>${icon("table")}Clean IP targets</h2><div class="field"><label for="cmTargets">IP:port, one per line</label><textarea id="cmTargets" rows="8" spellcheck="false" placeholder="104.16.0.1:443" aria-describedby="cmTargetsInfo">${esc(cm.targets)}</textarea><small class="subtitle" id="cmTargetsInfo"></small></div><div class="row-gap">${btn("Use clean IPs from Results", "cm-use-clean", "tonal small", "table")}${btn("Load file", "cm-load", "outlined small", "folder", 'data-into="targets"')}</div></section>` : ""}</div><div class="col"><section class="glass panel"><h2>${icon("play")}Output</h2><div class="run-head">${btn(rewrite ? "Make configs" : "Extract endpoints", "cm-run", "filled", "play", 'id="cmRun"')}</div><div class="message" id="cmMessage" role="status"></div><div class="field"><label for="cmOutput">${rewrite ? "Configs ready to import" : "IP:port endpoints"}</label><textarea id="cmOutput" rows="16" readonly spellcheck="false"></textarea></div><div class="row-gap">${btn("Copy", "cm-copy", "tonal small", "copy", 'id="cmCopy"')}${btn("Open folder", "cm-open", "outlined small", "folder", 'id="cmOpen"')}</div></section></div></div>`;
    updateConfigPage(); inspectConfigs();
  }
  function updateConfigPage() {
    if (page !== "config") return;
    const r = cm.result, info = cm.info;
    $("#cmOutput").value = r?.text || "";
    $("#cmCopy").disabled = $("#cmOpen").disabled = !r;
    $("#cmRun").disabled = cm.busy || !info?.configs || (cm.mode === "rewrite" && !info?.targets);
    setText("#cmConfigsInfo", !cm.configs.trim() ? "Paste configs or load a file." : cm.mode === "extract" ? "Every IP:port found in this text is extracted." : info?.configs ? `${fmt(info.configs)} config${info.configs === 1 ? "" : "s"}${info.summary ? ": " + info.summary : ""}` : "No configs found yet.");
    if ($("#cmTargetsInfo")) setText("#cmTargetsInfo", info?.targets ? `${fmt(info.targets)} IP:port target${info.targets === 1 ? "" : "s"}. Each gets a config; configs repeat when there are fewer.` : "Paste IP:port lines, or use the clean IPs from your last scan.");
    setText("#cmMessage", r ? `${cm.mode === "rewrite" ? "Made" : "Extracted"} ${fmt(r.count)} ${cm.mode === "rewrite" ? "config" : "endpoint"}${r.count === 1 ? "" : "s"}. Saved to ${r.path}${r.wireguard ? `, with ${fmt(r.wireguard)} WireGuard .conf file${r.wireguard === 1 ? "" : "s"} beside it` : ""}.` : "");
  }
  function inspectConfigs() {
    clearTimeout(cmTimer);
    cmTimer = setTimeout(async () => {
      const version = ++cmVersion;
      try { const info = await api.ConfigMakerInspect(cm.configs, cm.targets); if (version === cmVersion) { cm.info = info; updateConfigPage(); } }
      catch (e) { toast(e, true); }
    }, 200);
  }
  async function runConfigMaker() {
    cm.busy = true; updateConfigPage();
    try { cm.result = cm.mode === "rewrite" ? await api.ConfigMakerRewrite(cm.configs, cm.targets) : await api.ConfigMakerExtract(cm.configs); }
    finally { cm.busy = false; updateConfigPage(); }
    $("#cmOutput")?.focus();
  }
  function setConfigText(key, text) {
    cm[key] = text; cm.result = null;
    const box = $(key === "configs" ? "#cmConfigs" : "#cmTargets"); if (box) box.value = text;
    updateConfigPage(); inspectConfigs();
  }
  function renderSpeedPage() {
    $("#content").innerHTML=`<div class="mode-grid"><div class="col"><section class="glass panel intro"><h2>Test selected IPs and proxies</h2><p>Download a bounded amount of data through a reachable scan result. The selected endpoint carries the traffic; the test never falls back to your normal connection. DNS results cannot be used as HTTP download endpoints.</p><div class="how"><span><b>Measurement</b> download Mbps</span><span><b>Control</b> time and size limits</span></div></section><section class="glass panel"><h2>Selected endpoint</h2><p class="speed-target">${esc(speedRow ? speedRow.label : "Select a successful scan result first")}</p><p class="subtitle">${esc(speedRow ? speedRow.ip+":"+speedRow.port : "Open Results, then use the speed action on a reachable IP or proxy.")}</p>${btn("Select from Results","results","tonal","table")}</section><section class="glass panel"><h2>Download settings</h2>${field("speedTestUrl","Direct download URL",{hint:"Use a URL that returns a file directly. Redirects are rejected. The selected IP must serve this origin; proxies forward it normally."})}<div class="field-row">${field("speedDurationSecs","Time limit (seconds)",{type:"number",min:1,max:60})}${field("speedMaxSizeMb","Download limit (MB)",{type:"number",min:1,max:1024})}</div><div class="row-gap">${btn("Run speed test","start-speed","filled","download",'id="startSpeed"')}${btn("Cancel","cancel-speed","danger","stop",'id="cancelSpeed"')}</div></section></div><div class="col"><section class="glass panel"><h2>Download performance</h2><div class="metrics"><div class="metric glass c-taro"><span>Download</span><b id="speedMbps">-</b><small>Mbps</small></div><div class="metric glass c-matcha"><span>Data received</span><b id="speedBytes">-</b></div><div class="metric glass c-honey"><span>First response</span><b id="speedLatency">-</b><small>milliseconds</small></div></div><div class="message" id="speedMessage" role="status"></div><p class="subtitle" id="speedElapsed"></p></section></div></div>`;
    updateSpeedPage();
  }
  function updateSpeedPage() {
    if (page!=="speed") return;
    $("#startSpeed").disabled=!speedRow || speedRunning;
    $("#cancelSpeed").disabled=!speedRunning;
    setText("#speedMessage",speedRunning ? "Downloading through the selected endpoint..." : speedResult ? "Speed test complete." : "Ready to measure a selected result.");
    setText("#speedMbps",speedResult ? number(speedResult.downloadMbps).toFixed(2) : "-");
    setText("#speedBytes",speedResult ? bytes(speedResult.bytes) : "-");
    setText("#speedLatency",speedResult ? fmt(speedResult.latencyMs) : "-");
    setText("#speedElapsed",speedResult ? "Measured over "+number(speedResult.elapsedS).toFixed(2)+" seconds." : "Results reflect the selected endpoint, download server and current network conditions.");
  }
  async function runSpeedTest() {
    if (!speedRow || speedRunning) return;
    validateVisibleFields();
    speedRunning=true;speedResult=null;$("#speedMessage").classList.remove("error");updateSpeedPage();
    try {
      await persistSettings();
      speedResult=await api.TestSpeed({seq:speedRow.seq,runDir:speedRunDir,downloadUrl:settings.speedTestUrl,durationSecs:settings.speedDurationSecs,maxSizeMb:settings.speedMaxSizeMb});
      toast("Download: "+number(speedResult.downloadMbps).toFixed(2)+" Mbps");
    } catch(e) { if(page==="speed") {setText("#speedMessage",String(e?.message || e));$("#speedMessage").classList.add("error");}throw e; }
    finally {speedRunning=false;if(page==="speed") {$("#startSpeed").disabled=!speedRow;$("#cancelSpeed").disabled=true;if(speedResult) updateSpeedPage();} }
  }

  function resultFamily() { return modeByID[stats.mode]?.family || "http"; }
  function tabsForMode() { return resultFamily() === "dns" ? ["all","ok","poisoned","hijacked","dead","tunnel"] : resultFamily() === "txt" ? ["all","ok","dead","tunnel"] : ["all","ok","dead"]; }
  const tabLabel = (tab) => ({all:"All",ok:resultFamily() === "http" ? "Reachable" : resultFamily() === "txt" ? "Answered" : "Clean",dead:"Failed",poisoned:"Poisoned",hijacked:"Hijacked",tunnel:"Tunnel-ready"}[tab]);
  function renderResults() {
    query.limit = Math.min(MAX_RESULT_ROWS,query.limit);
    pendingResultPage = null; resultsRefreshDeferred = false;
    resultMode = stats.mode;
    if (!tabsForMode().includes(query.tab)) query.tab = "all";
    if (resultFamily() === "http") query.protocol = "";
    resultPage = {rows:[],total:0,counts:stats.counts || {}};
    $("#content").innerHTML = `<div class="results"><div class="source glass"><span class="what" id="resultSource"></span>${resultFamily() === "http" ? btn("Copy clean IPs", "copy-clean", "tonal small", "copy", 'title="Copy every passed IP as ip:port, fastest first, for your configs"') : ""}${btn("Delete shown", "delete-shown", "danger small", "trash", 'id="deleteResults" title="Delete every result matching these filters"')}${btn("Reports", "reports", "text small", "folder")}</div><div class="tabs" role="group" aria-label="Result categories">${tabsForMode().map(t => `<button type="button" aria-pressed="${query.tab === t}" class="tab ${query.tab === t ? "active" : ""}" data-tab="${t}">${tabLabel(t)}<b data-tab-count="${t}">0</b></button>`).join("")}</div><div class="toolbar"><div class="search">${icon("search")}<input type="search" id="resultSearch" aria-label="Search results" placeholder="Search targets, answers or errors" value="${esc(query.search)}"></div>${resultFamily() !== "http" ? `<select id="protocolFilter" aria-label="Protocol"><option value="">All protocols</option>${["UDP","TCP","DoT","DoH"].map(p => `<option ${query.protocol === p ? "selected" : ""}>${p}</option>`).join("")}</select>` : ""}<select id="resultSort" aria-label="Sort results">${[["seq","Scan order"],["latency","Latency"],["target","Target"],["port","Port"],["status","Status"]].map(([value,label]) => `<option value="${value}" ${query.sortBy === value ? "selected" : ""}>${label}</option>`).join("")}</select><button type="button" class="icon-btn dir-btn ${query.desc ? "desc" : ""}" id="sortDirection" data-action="direction" title="${query.desc ? "Descending; switch to ascending" : "Ascending; switch to descending"}" aria-label="Toggle sort direction" aria-pressed="${query.desc}">${icon("sort")}</button><select id="pageSize" aria-label="Rows per page">${[50,100,250].map(n => `<option value="${n}" ${query.limit === n ? "selected" : ""}>${n} rows</option>`).join("")}</select><label class="switch-inline">Live<input type="checkbox" id="liveResults" ${live ? "checked" : ""}><span class="switch" aria-hidden="true"></span></label>${btn("Refresh", "refresh-results", "outlined small", "redo")}${btn("Export CSV", "export", "tonal small", "download", 'id="exportResults" title="Export every result matching these filters"')}</div><div class="table-wrap glass" id="resultsTable" aria-busy="true"><table class="data"><thead><tr>${(resultFamily() === "http" ? ["Target","IP","Port","Status","Latency","Services"] : ["Resolver","Protocol","Answer","Latency","Flags","Tunnel","Result"]).map(c => `<th scope="col">${c}</th>`).join("")}<th scope="col">Actions</th></tr></thead><tbody id="resultRows"></tbody></table><div class="table-empty" id="resultEmpty" role="status">Loading results...</div></div><div class="pager">${btn("Previous", "previous", "outlined small", "left", 'id="previousPage"')}${btn("Next", "next", "outlined small", "right", 'id="nextPage"')}<span id="pagePosition"></span><span class="grow"></span><span id="resultRefreshState" role="status"></span></div></div>`;
    updateResultsSource(); updateTabs(stats.counts || {}); refreshResults();
  }
  function updateResultsSource() {
    if (!$("#resultSource")) return;
    $("#resultSource").innerHTML = `<b>${stats.viewing ? "Loaded run" : "Live scan"}</b> &middot; ${esc(runLabel(stats.mode,stats.targetType,stats.edgeProvider))}${stats.viewing ? `<span class="source-path" title="${esc(stats.viewing)}">${esc(stats.viewing)}</span>` : ""}`;
    setText("#resultRefreshState", resultsRefreshDeferred ? "Updates wait while you use a result" : stats.viewing ? "Saved results" : live && busy ? "Live updates every second" : live ? "Up to date" : "Live updates paused");
  }
  function updateTabs(counts) {
    $$("[data-tab-count]").forEach(el => { const value = fmt(counts[el.dataset.tabCount]); if (el.textContent !== value) el.textContent = value; });
    const del = $("#deleteResults");
    if (del && !del.dataset.confirm) { del.disabled = busy || !resultPage.total; del.title = busy ? "Results can be deleted when the scan finishes" : "Delete every result matching these filters"; }
  }
  // Deleting is permanent, so "Delete shown" asks once more on the button itself.
  let deleteConfirmTimer = 0;
  function resetDeleteConfirm() {
    clearTimeout(deleteConfirmTimer);
    const del = $("#deleteResults"); if (!del) return;
    delete del.dataset.confirm; del.innerHTML = icon("trash") + "Delete shown"; updateTabs(resultPage.counts || {});
  }
  async function deleteResults(seqs) {
    const n = await api.DeleteResults({...query}, seqs);
    if (seqs.length && detailRow && seqs.includes(detailRow.seq)) closePanels();
    toast(`Deleted ${fmt(n)} result${n === 1 ? "" : "s"}${stats.runDir || stats.viewing ? ". The run's results.csv was updated." : "."}`);
    refreshResults();
  }
  function refreshResults() {
    if (page !== "results" || !ready) return;
    if (rowsEngaged($("#resultRows"),"[data-result]")) { resultsRefreshDeferred = true; updateResultsSource(); return; }
    pendingResultPage = null; resultsRefreshDeferred = false;
    clearTimeout(liveTimer); queryVersion++;
    if (queryPending) { queryAgain = true; return; }
    fetchResults();
  }
  async function fetchResults() {
    if (page !== "results" || queryPending) return;
    const version = queryVersion, requested = {...query};
    queryPending = true; queryAgain = false;
    $("#resultsTable")?.setAttribute("aria-busy", "true");
    try {
      const data = await api.QueryResults(requested);
      if (version !== queryVersion || page !== "results") return;
      const nextPage = {rows:data.rows || [],total:number(data.total),counts:data.counts || {}};
      if (query.offset > 0 && query.offset >= nextPage.total) {
        query.offset = Math.max(0, Math.floor((nextPage.total - 1) / query.limit) * query.limit);
        queryVersion++; queryAgain = true; return;
      }
      if (rowsEngaged($("#resultRows"),"[data-result]")) {
        pendingResultPage = {version,data:nextPage}; resultsRefreshDeferred = true; updateResultsSource();
      } else applyResultPage(nextPage);
    } catch(e) {
      if (version === queryVersion && page === "results") {
        setText("#resultEmpty", String(e?.message || e)); $("#resultEmpty").hidden = false;
        toast(e,true);
      }
    } finally {
      queryPending = false;
      if (page === "results") $("#resultsTable")?.setAttribute("aria-busy","false");
      if (queryAgain && page === "results") fetchResults();
    }
  }
  function renderResultRows() {
    const http = resultFamily() === "http";
    reconcileRows($("#resultRows"),resultPage.rows,"result",(r,i) => `<tr data-result="${i}" tabindex="0" aria-label="${esc(`Inspect ${r.label}`)}" class="${detailRow?.seq === r.seq ? "selected" : ""}" title="${esc(r.error || r.answer || r.url)}">${http ? `<td class="mono">${esc(r.label)}</td><td class="mono">${esc(r.ip || "-")}</td><td class="num">${fmt(r.port)}</td><td><span class="badge ${r.category === "ok" ? "ok" : "dead"}">${esc(r.error || r.status || "-")}</span></td><td class="num">${latency(r)}</td><td class="num" title="${esc(r.passedDomains)}">${r.serviceTotal ? fmt(r.servicePassed)+" / "+fmt(r.serviceTotal) : "-"}</td>` : `<td class="mono">${esc(r.label)}</td><td>${protocolBadge(r.protocol)}</td><td class="mono" title="${esc(r.answer || r.error)}">${esc(r.answer || r.error || r.ip || "-")}</td><td class="num">${latency(r)}</td><td class="dim">${r.ra ? "RA " : ""}${r.edns ? "EDNS " : ""}${r.tc ? "TC " : ""}RCODE ${fmt(r.rcode)}</td><td><span class="badge ${r.tunnelReady ? "ok" : "dead"}" title="${esc(r.tunnelReason)}">${r.tunnelReady ? "Ready" : "No"}</span></td><td>${resultBadge(r)}</td>`}<td><div class="quick-actions">${http && r.category === "ok" ? `<button type="button" class="icon-btn" data-action="speed-row" data-index="${i}" title="Test download speed through this endpoint" aria-label="Test speed">${icon("download")}</button>` : ""}<button type="button" class="icon-btn" data-action="inspect-row" data-index="${i}" title="Inspect result" aria-label="Inspect result">${icon("file")}</button><button type="button" class="icon-btn" data-action="copy-row" data-index="${i}" title="Copy target" aria-label="Copy target">${icon("copy")}</button><button type="button" class="icon-btn" data-action="delete-row" data-index="${i}" title="Delete result" aria-label="Delete result">${icon("trash")}</button></div></td></tr>`);
    $("#resultEmpty").hidden = resultPage.rows.length > 0;
    setText("#resultEmpty", query.search || query.tab !== "all" || query.protocol ? "No results match these filters." : busy ? "Waiting for the first results..." : "Start a scan or load a saved run from Reports.");
    const first = resultPage.total ? query.offset + 1 : 0;
    setText("#pagePosition", `${fmt(first)}-${fmt(query.offset + resultPage.rows.length)} of ${fmt(resultPage.total)}`);
    $("#previousPage").disabled = query.offset <= 0;
    $("#nextPage").disabled = query.offset + query.limit >= resultPage.total;
  }
  function changedQuery() {
    query.offset = 0;
    pendingResultPage = null;
    $$("[data-tab]").forEach(b => { const active = b.dataset.tab === query.tab; b.classList.toggle("active", active); b.setAttribute("aria-pressed",String(active)); });
    refreshResults();
  }
  async function renderReports() {
    const version = ++reportsVersion;
    $("#content").innerHTML = `<div class="filters" role="group" aria-label="Filter runs by mode">${[{id:"all",title:"All modes"},...MODES].map(m => `<button type="button" class="tab ${reportsFilter === m.id ? "active" : ""}" data-report-filter="${m.id}" aria-pressed="${reportsFilter === m.id}">${m.title}</button>`).join("")}<span class="grow"></span>${btn("Refresh", "refresh-reports", "outlined small", "redo")}</div><div class="runs" id="runCards"><div class="empty-state">Loading saved runs...</div></div>`;
    try { const loaded = await api.ListRuns(); if (version !== reportsVersion || page !== "reports") return; runs = loaded || []; renderRunCards(); }
    catch(e) { if (version === reportsVersion && page === "reports") { setText("#runCards", String(e?.message || e)); toast(e,true); } }
  }
  function renderRunCards() {
    if (page !== "reports") return;
    $$("[data-report-filter]").forEach(b => { const selected = b.dataset.reportFilter === reportsFilter; b.classList.toggle("active",selected); b.setAttribute("aria-pressed",String(selected)); });
    const visible = runs.map((run,index) => ({run,index})).filter(({run}) => reportsFilter === "all" || run.mode === reportsFilter);
    $("#runCards").innerHTML = visible.length ? visible.map(({run,index}) => {
      const c = run.counts || {}, end = new Date(run.finished), start = new Date(run.started);
      const elapsed = end >= start ? duration((end - start) / 1000) : "In progress";
      const state = ["completed","stopped","failed","running"].includes(run.state) ? run.state : "completed";
      return `<article class="glass panel run-card"><header><div><h2>${esc(runLabel(run.mode,run.targetType,run.edgeProvider))}</h2><div class="when">${esc(date(run.started))} &middot; ${elapsed}</div></div><span class="badge state ${state === "failed" ? "dead" : state === "completed" ? "ok" : "warn"}">${state}</span></header><div class="tallies"><span class="badge">${fmt(run.done)} of ${run.total > 0 ? fmt(run.total) : "unknown"} scanned</span>${[["ok","Passed"],["dead","Failed"],["poisoned","Poisoned"],["hijacked","Hijacked"],["tunnel","Tunnel-ready"]].filter(([key]) => c[key] > 0).map(([key,label]) => `<span class="badge ${key === "tunnel" ? "ok" : key}">${fmt(c[key])} ${label}</span>`).join("")}</div>${run.message ? `<p class="subtitle">${esc(run.message)}</p>` : ""}<p class="subtitle" title="${esc(run.targets)}">Targets: ${esc(run.targets || "Unknown")}</p><div class="files">${(run.files || []).map((f,fi) => `<button type="button" class="file" data-action="read-report" data-run="${index}" data-file="${fi}" title="${esc(f.name)}">${icon("file")}${esc(f.kind || f.name)}<small>${bytes(f.size)} &middot; ${fmt(f.lines)} lines</small></button>`).join("") || '<span class="subtitle">Reports are being written.</span>'}</div><div class="row-gap run-actions">${run.hasResults ? btn("Load in Results", "load-run", "tonal small", "table", `data-run="${index}" ${busy || actionPending ? "disabled" : ""}`) : ""}${btn("Open folder", "open-report-folder", "outlined small", "folder", `data-run="${index}"`)}</div></article>`;
    }).join("") : `<div class="glass panel empty-state">${icon("folder")}<p>No saved runs${reportsFilter === "all" ? " yet" : " for this mode"}.</p><p>Completed and stopped scans appear here once their reports are saved.</p>${btn("Open output folder", "open-output", "tonal small", "folder")}</div>`;
  }
  async function showReport(file) {
    if (!file) return;
    const version = ++viewerVersion;
    viewerFile = file;
    setText("#viewerTitle", file.kind || file.name); setText("#viewerSub", `${file.name} | ${bytes(file.size)} | ${fmt(file.lines)} lines`);
    setText("#viewerBody", "Loading report..."); $("#viewerCopy").disabled = true;
    openOverlay("viewer", "viewerClose");
    try { const text = await api.ReadReport(file.path); if (version !== viewerVersion) return; setText("#viewerBody", text); $("#viewerCopy").disabled = false; }
    catch(e) { if (version === viewerVersion) { setText("#viewerBody", String(e?.message || e)); toast(e,true); } }
  }
  const detailFields = [["servicePassed","Service checks passed"],["serviceTotal","Service checks total"],["passedDomains","Passed domains"],["serviceSummary","Per-domain results"],["kind","Scan type"],["seq","Sequence"],["label","Target"],["url","URL"],["ip","IP"],["answer","Answer"],["port","Port"],["status","Status"],["latencyMs","Latency (ms)"],["error","Error"],["protocol","Protocol"],["category","Category"],["poisoned","Poisoned"],["hijacked","Hijacked"],["ra","Recursion (RA)"],["edns","EDNS"],["tc","Truncated (TC)"],["rcode","RCODE"],["tunnelReady","Tunnel-ready"],["tunnelReason","Tunnel reason"],["hdrDump","DNS header"]];
  function showDetail(row) {
    if (!row) return;
    detailRow = row; overlayFocus = document.activeElement;
    $("#detailList").innerHTML = detailFields.filter(([key]) => row[key] !== "" && row[key] !== undefined && row[key] !== null).map(([key,label]) => `<dt>${label}</dt><dd>${esc(typeof row[key] === "boolean" ? row[key] ? "Yes" : "No" : row[key])}</dd>`).join("");
    $("#drawerSpeed").hidden = !!row.protocol || row.category !== "ok";
    $("#drawer").hidden = false; $("#closeDrawer").focus();
    $$("[data-result]").forEach(tr => tr.classList.toggle("selected", resultPage.rows[Number(tr.dataset.result)]?.seq === row.seq));
  }
  function openOverlay(id, focusID) {
    for (const other of ["help","viewer","asnPicker"]) if (other !== id) $("#" + other).hidden = true;
    overlayFocus = document.activeElement; $("#" + id).hidden = false; $("#" + focusID)?.focus();
  }
  function openASNPicker() {
    asnState.mode=page; asnState.selected.clear();
    const family=targetInput(page).ipFamily; asnState.family=family==="ipv6" ? "ipv6" : "ipv4";
    $("#asnSearch").value="";
    openOverlay("asnPicker","asnSearch");
    return refreshASNs();
  }
  async function refreshASNs() {
    $$("[data-action=asn-family]").forEach(b => { const on=b.dataset.family===asnState.family; b.classList.toggle("active",on); b.setAttribute("aria-pressed",String(on)); });
    const version=++asnState.version;
    const rows=await api.SearchASNs($("#asnSearch").value,asnState.family);
    if(version!==asnState.version) return; // a newer search is on its way
    asnState.rows=rows||[]; renderASNs();
  }
  const ASN_ROWS=300; // enough to browse; search narrows the rest
  function renderASNs() {
    const rows=asnState.rows, shown=rows.slice(0,ASN_ROWS);
    $("#asnList").innerHTML = shown.length ? shown.map(a => `<li><label class="asn-row"><input type="checkbox" data-asn="${esc(a.asn)}" ${asnState.selected.has(a.asn) ? "checked" : ""}><span class="asn-main"><b>${esc(a.name || a.asn)}</b><small>${esc([a.asn,a.country,a.type,a.domain].filter(Boolean).join(" · "))}</small></span><span class="asn-counts">${a.ipv4 ? `<span class="badge">${fmt(a.ipv4)} IPv4</span>` : ""}${a.ipv6 ? `<span class="badge">${fmt(a.ipv6)} IPv6</span>` : ""}</span></label></li>`).join("") + (rows.length>shown.length ? `<li class="more">Showing ${fmt(shown.length)} of ${fmt(rows.length)} ASNs. Search to find the rest.</li>` : "")
      : '<li class="empty">No ASNs match. Try part of a network name or an AS number.</li>';
    updateASNCount();
  }
  function updateASNCount() {
    const n=asnState.selected.size;
    setText("#asnCount", n ? `${fmt(n)} selected` : `${fmt(asnState.rows.length)} ASNs`);
    $("#asnAdd").disabled=!n; $("#asnExport").disabled=!n;
    setText("#asnAdd", n ? `Add ${fmt(n)} ASN${n===1?"":"s"}` : "Add ASNs");
  }
  // Added ASNs stay as entries; the scanner expands their ranges when the scan
  // starts, so Cloudflare's 26,000 ranges never sit in the page as text.
  function addASNRanges() {
    const ids=[...asnState.selected];
    if(!ids.length) return;
    if(asnState.mode!==page) throw new Error("Open the scan page again to add ASNs.");
    const family=asnState.family;
    const picks=ids.map(id => { const a=asnState.info.get(id)||{}; return {asn:id,name:a.name||"",family,ranges:family==="ipv4" ? number(a.ipv4) : family==="ipv6" ? number(a.ipv6) : number(a.ipv4)+number(a.ipv6)}; });
    const toIPFinder=isCleanMode(page) && settings.targets[page].targetType==="domain";
    const input=toIPFinder ? targetInput(page,"ip") : targetInput(page);
    const byASN=new Map((input.asns||[]).map(p => [p.asn,p]));
    picks.forEach(p => byASN.set(p.asn,p));
    input.asns=[...byASN.values()];
    if(isCleanMode(page) && !toIPFinder) syncTargetInput(page);
    scheduleSave(); closePanels();
    const ranges=picks.reduce((n,p) => n+p.ranges,0), what=`${fmt(picks.length)} ASN${picks.length===1?"":"s"} (${fmt(ranges)} ranges)`;
    if(toIPFinder) {
      // Edge domains scan hostnames; IP ranges go to the same variant's Clean IP finder.
      rememberedModes["clean-ip"]=page; openWorkspace("clean-ip");
      toast(`Added ${what} to Clean IP finder. Edge domains takes hostnames.`);
      return;
    }
    updateInputPreview();
    toast(`Added ${what}. Ranges are expanded when the scan starts.`);
  }
  function renderASNChips(t) {
    const root=$("#asnChips"); if(!root) return;
    const picks=t.asns||[], label={ipv4:"IPv4",ipv6:"IPv6",both:"IPv4 + IPv6"};
    const html=picks.map(p => `<span class="asn-chip" title="${esc(p.name || p.asn)}"><b>${esc(p.asn)}</b><span class="name">${esc(p.name)}</span><small>${fmt(p.ranges)} ranges &middot; ${label[p.family] || label.both}</small><button type="button" class="icon-btn" data-action="asn-remove" data-asn="${esc(p.asn)}" aria-label="${esc(`Remove ${p.asn}`)}" title="Remove">${icon("close")}</button></span>`).join("");
    if(root.innerHTML!==html) root.innerHTML=html;
    root.hidden=!picks.length;
  }
  function closePanels() {
    $("#help").hidden = true; $("#viewer").hidden = true; $("#asnPicker").hidden = true; $("#drawer").hidden = true;
    viewerVersion++;
    if (overlayFocus?.isConnected) overlayFocus.focus();
  }
  async function copy(text) {
    if (!rt?.ClipboardSetText) throw new Error("Clipboard is unavailable. Run the desktop app to copy results.");
    const copied = await rt.ClipboardSetText(String(text ?? ""));
    if (copied === false) throw new Error("Could not copy to the clipboard.");
    toast("Copied to clipboard");
  }
  async function startScan() {
    if (busy || actionPending || !ready || !modeByID[page]) return;
    const mode = page;
    validateVisibleFields();
    actionPending = "start"; busy = true; activeMode = mode; updateChrome(); updateMode();
    try {
      await persistSettings();
      // Cancel any edit-save queued while this one was in flight.
      clearTimeout(saveTimer); await saveChain;
      const before = eventVersion;
      query.offset = 0; queryVersion++;
      await api.StartScan(mode, snapshot());
      if (eventVersion === before) {
        acceptStats({...emptyStats(),state:"RUNNING",mode});
        const version = eventVersion;
        try {
          const current = await api.GetStats();
          if (version === eventVersion) acceptStats(current);
        } catch(e) { toast(e,true); }
      }
    } catch(e) { busy = false; activeMode = ""; throw e; }
    finally { actionPending = ""; updateChrome(); if (modeByID[page]) updateMode(); }
  }
  async function controlScan(kind) {
    if (!busy || actionPending || !["RUNNING","PAUSED"].includes(stats.state)) return;
    if (kind === "pause" && stats.state !== "RUNNING" || kind === "resume" && stats.state !== "PAUSED") return;
    actionPending = kind; updateMode();
    try { await api[{pause:"PauseScan",resume:"ResumeScan",stop:"StopScan"}[kind]](); }
    finally { actionPending = ""; updateMode(); }
  }
  function acceptStats(data, done = false) {
    if (!data) return;
    stats = {...emptyStats(),...data,counts:data.counts || {},recent:data.recent || []};
    if (done) { busy = false; activeMode = ""; queryVersion++; }
    else if (!stats.viewing && ["RUNNING","PAUSED"].includes(stats.state)) { busy = true; activeMode = stats.mode; }
    // STOPPED does not unlock the UI: scan:done is the reports-saved barrier.
    if (!paintPending) {
      paintPending = true;
      requestAnimationFrame(() => {
        paintPending = false; updateChrome();
        if (modeByID[page]) updateMode();
        if (page === "results") {
          if (resultMode !== stats.mode) { query.offset = 0; queryVersion++; renderResults(); }
          else { updateResultsSource(); if (live) updateTabs(stats.counts); }
        }
        if (page === "reports") $$("[data-action=load-run]").forEach(b => b.disabled = busy || !!actionPending);
      });
    }
    if (done) {
      if (page === "results" && live) refreshResults();
      if (page === "reports") renderReports();
      toast(stats.message || "Scan finished. Reports saved.", /^(FATAL|ERROR)/.test(stats.message));
    }
  }
  async function action(name, el) {
    if (!ready && name !== "help" && name !== "retry-startup") return;
    switch (name) {
      case "start": return startScan();
      case "pause-resume": return controlScan(stats.state === "PAUSED" ? "resume" : "pause");
      case "stop": return controlScan("stop");
      case "speed": return navigate("speed");
      case "results": case "reports": case "settings": return navigate(name);
      case "go-active": return goToActiveScan();
      case "help": return $("#help").hidden ? openOverlay("help","helpClose") : closePanels();
      case "ip-family": {
        const input=targetInput(page); input.ipFamily = el.dataset.family==="both" ? "" : el.dataset.family;
        if(isCleanMode(page)) syncTargetInput(page);
        scheduleSave();
        $$("[data-action=ip-family]").forEach(b => { const on=b.dataset.family===el.dataset.family; b.classList.toggle("active",on); b.setAttribute("aria-pressed",String(on)); });
        return;
      }
      case "feed-view": {
        feedView = el.dataset.view === "hits" ? "hits" : "log";
        $$("[data-action=feed-view]").forEach(b => { const on=b.dataset.view===feedView; b.classList.toggle("active",on); b.setAttribute("aria-pressed",String(on)); });
        $("#scanLog").hidden = feedView !== "log"; $("#hitsView").hidden = feedView !== "hits";
        if (feedView === "log") $("#scanLog").scrollTop = $("#scanLog").scrollHeight;
        return;
      }
      case "pick-asn": return openASNPicker();
      case "asn-remove": {
        const input=targetInput(page); input.asns=(input.asns||[]).filter(p => p.asn!==el.dataset.asn);
        if(isCleanMode(page)) syncTargetInput(page);
        scheduleSave(); updateInputPreview(); $("[data-action=pick-asn]")?.focus();
        return;
      }
      case "asn-family": asnState.family=el.dataset.family; return refreshASNs();
      case "asn-clear": asnState.selected.clear(); return renderASNs();
      case "asn-add": return addASNRanges();
      case "asn-export": {
        if(!asnState.selected.size) return;
        const message=await api.ExportASNs([...asnState.selected],asnState.family);
        if(message) toast(message);
        return;
      }
      case "theme":
        settings.theme = el.dataset.theme; applyTheme(settings.theme); scheduleSave();
        $$("[data-action=theme]").forEach(b => { b.classList.toggle("active",b.dataset.theme === settings.theme); b.setAttribute("aria-pressed",String(b.dataset.theme === settings.theme)); });
        return;
      case "concurrency-mode":
        settings.autoConcurrency=el.dataset.auto==='true';scheduleSave();updateConcurrencyControls();updateMode();return;
      case "scan-variant": return openScanVariant(el.dataset.scanMode);
      case "target-type": {
        if(!isCleanMode(page)||!["ip","domain"].includes(el.dataset.targetType)) return;
        const t=settings.targets[page]; t.targetType=el.dataset.targetType;
        syncTargetInput(page); scheduleSave();navigate(page);return;
      }
      case "pick-input": {
        const mode=page, owner=targetInput(mode), path=await api.PickInputFile();
        if(path && modeByID[mode]) {
          owner.inputFile=path;
          if(isCleanMode(mode)) syncTargetInput(mode);
          scheduleSave();
          if(page===mode && targetInput(mode)===owner){$("[data-setting=inputFile]").value=path;updateInputPreview();}
        }
        return;
      }
      case "pick-output": {
        const path = await api.PickOutputDir();
        if (path) { settings.outputDir = path; scheduleSave(); const field = $("[data-setting=outputDir]"); if (field) field.value = path; }
        return;
      }
      case "open-output": await persistSettings(); return api.OpenPath("");
      case "open-run": return api.OpenPath(stats.runDir);
      case "open-report-folder": return api.OpenPath(runs[Number(el.dataset.run)]?.dir || "");
      case "refresh-reports": return renderReports();
      case "read-report": return showReport(runs[Number(el.dataset.run)]?.files?.[Number(el.dataset.file)]);
      case "load-run": {
        if (busy || actionPending) return;
        const run = runs[Number(el.dataset.run)]; if (!run?.hasResults) return;
        actionPending = "load"; renderRunCards();
        try { const loaded = await api.LoadRun(run.dir); eventVersion++; acceptStats(loaded); query.offset = 0; navigate("results"); }
        finally { actionPending = ""; if (page === "reports") renderRunCards(); }
        return;
      }
      case "reset":
        await persistSettings();
        settings = normalizeSettings(await api.ResetSettings()); applyTheme(settings.theme); applyAccent(settings.accent);
        if (page === "settings") renderSettings(); toast("Defaults restored. Theme, accent and target lists kept.");
        return;
      case "export": {
        el.disabled = true;
        try { const msg = await api.ExportResults({...query}); if (msg) toast(msg); }
        finally { if (el.isConnected) el.disabled = false; }
        return;
      }
      case "direction":
        query.desc = !query.desc; el.classList.toggle("desc",query.desc); el.setAttribute("aria-pressed",String(query.desc));
        el.title = query.desc ? "Descending; switch to ascending" : "Ascending; switch to descending"; return changedQuery();
      case "previous": query.offset = Math.max(0,query.offset - query.limit); return refreshResults();
      case "next": if (query.offset + query.limit < resultPage.total) query.offset += query.limit; return refreshResults();
      case "refresh-results": return refreshResults();
      case "speed-row": return selectSpeedRow(resultPage.rows[Number(el.dataset.index)]);
      case "speed-feed": return selectSpeedRow(feedRows[Number(el.dataset.index)]);
      case "speed-detail": return selectSpeedRow(detailRow);
      case "start-speed": return runSpeedTest();
      case "cancel-speed": return api.CancelSpeedTest();
      case "accent": settings.accent=el.dataset.accent; applyAccent(settings.accent);scheduleSave();$$("[data-action=accent]").forEach(b=>{b.classList.toggle("active",b.dataset.accent===settings.accent);b.setAttribute("aria-pressed",String(b.dataset.accent===settings.accent));});return;
      case "inspect-row": return showDetail(resultPage.rows[Number(el.dataset.index)]);
      case "inspect-feed": return showDetail(feedRows[Number(el.dataset.index)]);
      case "copy-row": return copy(resultPage.rows[Number(el.dataset.index)]?.label);
      case "cm-mode": cm.mode = el.dataset.mode === "extract" ? "extract" : "rewrite"; cm.result = null; return renderConfigPage();
      case "cm-run": return runConfigMaker();
      case "cm-copy": return copy(cm.result?.text || "");
      case "cm-open": return api.OpenPath(cm.result?.path.replace(/[\\/][^\\/]*$/, "") || "");
      case "cm-use-clean": {
        const ips = await api.CleanIPs();
        if (!ips.trim()) { toast("No clean IPs in Results yet. Run a Clean IP scan or load a past run from Reports."); return; }
        return setConfigText("targets", ips.trim());
      }
      case "cm-load": {
        const path = await api.PickInputFile();
        if (path) setConfigText(el.dataset.into === "targets" ? "targets" : "configs", await api.ReadTextFile(path));
        return;
      }
      case "copy-clean": {
        const ips = await api.CleanIPs();
        if (!ips.trim()) { toast("No clean IPs in these results yet."); return; }
        return copy(ips);
      }
      case "delete-row": { const row = resultPage.rows[Number(el.dataset.index)]; return row ? deleteResults([row.seq]) : undefined; }
      case "delete-shown": {
        if (!el.dataset.confirm) {
          el.dataset.confirm = "1"; el.innerHTML = icon("trash") + `Delete ${fmt(resultPage.total)} result${resultPage.total === 1 ? "" : "s"}?`;
          clearTimeout(deleteConfirmTimer); deleteConfirmTimer = setTimeout(resetDeleteConfirm, 5000);
          return;
        }
        resetDeleteConfirm();
        return deleteResults([]);
      }
      case "copy-feed": return copy(feedRows[Number(el.dataset.index)]?.label);
      case "retry-startup": return initialize();
    }
  }
  function readSetting(el) {
    if (!ready) return;
    const key = el.dataset.setting, target = el.dataset.targetMode;
    let value = el.type === "checkbox" ? el.checked : el.value;
    if (el.type === "number") {
      const error = numberFieldError(el);
      if (error) { setFieldError(el,error); return; }
      value = el.valueAsNumber;
    }
    setFieldError(el);
    if(target) {
      targetInput(target)[key]=value;
      if(isCleanMode(target)) syncTargetInput(target);
    } else settings[key]=value;
    scheduleSave();
    if(["autoConcurrency","maxConcurrent","minConcurrent"].includes(key)) updateConcurrencyControls();
    if (modeByID[page]) {
      clearTimeout(previewTimer); previewTimer = setTimeout(updateInputPreview,150);
      updateMode();
    }
  }
  document.addEventListener("input", e => {
    if (e.target.matches("[data-setting]") && e.target.type !== "checkbox") readSetting(e.target);
    if (e.target.id === "cmConfigs" || e.target.id === "cmTargets") { cm[e.target.id === "cmConfigs" ? "configs" : "targets"] = e.target.value; cm.result = null; updateConfigPage(); inspectConfigs(); }
    if (e.target.id === "asnSearch") { clearTimeout(asnTimer); asnTimer = setTimeout(() => refreshASNs().catch(err => toast(err,true)),150); }
    if (e.target.id === "resultSearch") {
      query.search = e.target.value; searching = true; queryVersion++; clearTimeout(searchTimer);
      searchTimer = setTimeout(() => { searching = false; changedQuery(); },250);
    }
  });
  document.addEventListener("change", e => {
    const el = e.target;
    if (el.dataset.asn && el.type === "checkbox") {
      const id=el.dataset.asn;
      if(el.checked) { asnState.selected.add(id); asnState.info.set(id, asnState.rows.find(a => a.asn===id)); } else asnState.selected.delete(id);
      updateASNCount(); return;
    }
    if (el.matches("[data-setting]") && el.type === "checkbox") readSetting(el);
    if(el.id==="mobileNav") {openWorkspace(el.value);return;}
    if(el.id==="edgeProvider") {
      currentEdgeProvider=el.value;
      if(providerInfo(currentEdgeProvider)) openWorkspace("edge-domains");
      return;
    }
    if (el.id === "protocolFilter") { query.protocol = el.value; changedQuery(); }
    if (el.id === "resultSort") { query.sortBy = el.value; changedQuery(); }
    if (el.id === "pageSize") { query.limit = Math.min(MAX_RESULT_ROWS,Number(el.value)); changedQuery(); }
    if (el.id === "liveResults") { live = el.checked; updateResultsSource(); if (live) refreshResults(); }
  });
  document.addEventListener("click", e => {
    const el = e.target.closest("button,[data-result],[data-feed],.scrim"); if (!el) return;
    if (el.matches(":disabled")) return;
    if(el.dataset.workspace && ready) {openWorkspace(el.dataset.workspace);return;}
    if (el.dataset.page && ready) { navigate(el.dataset.page); return; }
    if (el.dataset.tab) { query.tab = el.dataset.tab; changedQuery(); return; }
    if (el.dataset.reportFilter) { reportsFilter = el.dataset.reportFilter; renderRunCards(); return; }
    if (el.dataset.themeOpt && ready) {
      settings.theme = el.dataset.themeOpt; applyTheme(settings.theme); scheduleSave();
      $$("[data-action=theme]").forEach(b => { b.classList.toggle("active",b.dataset.theme === settings.theme); b.setAttribute("aria-pressed",String(b.dataset.theme === settings.theme)); });
      return;
    }
    if (el.dataset.action) { Promise.resolve().then(() => action(el.dataset.action,el)).catch(e => toast(e,true)); return; }
    if (el.dataset.result !== undefined) { showDetail(resultPage.rows[Number(el.dataset.result)]); return; }
    if (el.dataset.feed !== undefined) { showDetail(feedRows[Number(el.dataset.feed)]); return; }
    if (el.id === "helpBtn") { $("#help").hidden ? openOverlay("help","helpClose") : closePanels(); return; }
    if (["closeDrawer","viewerClose"].includes(el.id) || el.dataset.close === "help" || el.dataset.close === "asn" || el.classList.contains("scrim") && e.target === el) { closePanels(); return; }
    if (el.id === "copyDetail" && detailRow) copy(detailFields.map(([key,label]) => `${label}: ${detailRow[key] ?? ""}`).join("\n")).catch(e => toast(e,true));
    if (el.id === "viewerCopy") copy($("#viewerBody").textContent).catch(e => toast(e,true));
    if (el.id === "viewerOpen" && viewerFile) api.OpenPath(viewerFile.path).catch(e => toast(e,true));
  });
  document.addEventListener("keydown", e => {
    if (e.key === "Escape") { e.preventDefault(); closePanels(); return; }
    const modal = !$("#viewer").hidden ? $("#viewer .modal") : !$("#help").hidden ? $("#help .modal") : !$("#asnPicker").hidden ? $("#asnPicker .modal") : null;
    if (modal && e.key === "Tab") {
      const focusable = $$("button:not(:disabled),input:not(:disabled),[tabindex='0']",modal), first = focusable[0], last = focusable.at(-1);
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last?.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first?.focus(); }
      return;
    }
    const typing = e.target.matches("input,textarea,select,[contenteditable=true]") || e.target.isContentEditable;
    if (!modal && e.ctrlKey && e.key === "Enter" && !e.repeat) { e.preventDefault(); startScan().catch(err => toast(err,true)); return; }
    if (typing || e.ctrlKey || e.altKey || e.metaKey || e.repeat) return;
    if ((e.key === "Enter" || e.key === " ") && e.target.matches("[data-feed],[data-result]")) { e.preventDefault(); e.target.click(); return; }
    const key = e.key.toLowerCase();
    if (key === "h" || key === "؟") { e.preventDefault(); $("#help").hidden ? openOverlay("help","helpClose") : closePanels(); return; }
    if (modal) return;
    const command = ({p:"pause", "ح":"pause", r:"resume", "ق":"resume", q:"stop", "ض":"stop"})[key];
    if (command) { e.preventDefault(); controlScan(command).catch(err => toast(err,true)); }
  });
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => { if (settings?.theme === "system") applyTheme("system"); });
  document.addEventListener("visibilitychange", () => { if (!document.hidden && page === "results" && live) refreshResults(); });
  // Live polling is bounded, never overlaps, and sends only the selected page.
  setInterval(() => {
    if (page === "results" && live && busy && stats.state === "RUNNING" && !document.hidden && !queryPending && !searchTimerActive()) refreshResults();
  },1000);
  function searchTimerActive() { return searching; }

  function enhanceLayout() {
    const style = document.createElement("style");
    style.textContent = `
      button,input,select,textarea { font-family:inherit; }
      button:focus-visible,summary:focus-visible,[tabindex]:focus-visible { outline:2px solid var(--primary); outline-offset:3px; }
      input[aria-invalid=true] { border-color:var(--strawberry); box-shadow:0 0 0 3px var(--strawberry-soft); }
      .switch-row input,.switch-inline input { display:block; position:absolute; width:1px; height:1px; overflow:hidden; clip-path:inset(50%); }
      .switch-row input:focus-visible + .switch,.switch-inline input:focus-visible + .switch { outline:2px solid var(--primary); outline-offset:3px; }
      .field-row > .field { flex:1; } .field small { line-height:1.5; }
      .panel h2 { flex-wrap:wrap; } .panel summary { cursor:pointer; font-weight:650; color:var(--primary); } .details-body { margin-top:16px; }
      .source { min-width:0; } .source .what { min-width:0; } .source-path { display:block; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; font-size:11px; }
      .results { min-height:0; } .table-wrap { min-height:180px; } .data td { user-select:text; } .data td:last-child { width:86px; }
      .quick-actions { display:flex; align-items:center; opacity:0; transition:opacity .15s; }
      .quick-actions .icon-btn { width:30px; height:30px; } .quick-actions svg { width:16px; height:16px; }
      tr:hover .quick-actions,tr:focus-within .quick-actions,.feed li:hover .quick-actions,.feed li:focus-within .quick-actions { opacity:1; }
      .drawer { min-width:0; } .drawer dd { white-space:pre-wrap; } .run-actions { flex-wrap:wrap; } .run-card p { overflow-wrap:anywhere; margin:0; }
      .run-card .files { align-items:flex-start; } .file { text-align:left; white-space:normal; flex-wrap:wrap; }
      .runs { grid-template-columns:repeat(auto-fill,minmax(min(100%,380px),1fr)); }
      .state-chip[data-state=SAVING] { color:var(--honey); } .state-chip[data-state=SAVED] { color:var(--taro); }
      .settings .field-row > .field { min-width:125px; } .progress-text { flex-wrap:wrap; } .runFolder { overflow-wrap:anywhere; }
      #runFolder { overflow-wrap:anywhere; } .feed .who { min-width:0; } .feed .sub { user-select:text; }
      @media (max-width:1180px) { .mode-grid { grid-template-columns:minmax(0,1fr) minmax(0,1.08fr); gap:14px; } .sidebar { width:210px; } .panel { padding:18px; } }
      @media (max-width:1050px) { .mode-grid { grid-template-columns:1fr; } .drawer { position:fixed; right:16px; top:16px; bottom:16px; width:min(380px,calc(100vw - 32px)); z-index:10; background:var(--glass-strong); } }
      @media (max-width:760px) {
        .app { flex-direction:column; gap:10px; padding:10px; } .sidebar { width:100%; padding:10px; border-radius:20px; max-height:185px; }
        .brand { padding:0 4px 8px; } .brand-cup { width:30px; height:30px; } .brand b { font-size:15px; } .brand span { display:none; }
        #nav { display:flex; flex-wrap:wrap; gap:4px; overflow:auto; } .nav-group { display:none; } .nav-item { width:auto; margin:0; padding:8px; font-size:12px; } .nav-item svg { width:16px; height:16px; }
        .sidebar-foot { position:absolute; right:12px; top:10px; border:0; padding:0; flex-direction:row; } .sidebar-foot .credit,.help-btn { display:none; } .theme-switch { min-width:140px; }
        main { min-height:0; } .topbar { padding:2px 4px 8px; gap:8px; } .topbar h1 { font-size:21px; } .subtitle { font-size:12px; } .mode-badge { display:none; }
        .settings { grid-template-columns:1fr; } .toolbar { gap:8px; } .search { flex:1 1 100%; } .toolbar select { flex:1; min-width:100px; }
        .scrim { padding:12px; } .modal header { flex-wrap:wrap; } .modal .row-gap { flex-wrap:wrap; } .pager { flex-wrap:wrap; } .banner { flex-wrap:wrap; } .metrics { grid-template-columns:repeat(3,minmax(0,1fr)); }
        .metric { padding:12px; } .metric b { font-size:21px; } .panel { border-radius:20px; }
      }
      @media (hover:none) { .quick-actions { opacity:1; } .panel:hover { transform:none; } }
      @media (prefers-reduced-motion:reduce) { *,*::before,*::after { animation:none !important; transition:none !important; } .panel:hover { transform:none; } }
    `;
    document.head.append(style);
    $("#nav").setAttribute("aria-label","Scanner navigation");
    $("#content").setAttribute("aria-label","Current page");
    $("#drawer").setAttribute("aria-label","Result details");
    $("#snack").setAttribute("aria-live","polite");
    $("#help [data-close=help]").id = "helpClose";
    for (const id of ["help","viewer"]) {
      const modal = $("#" + id + " .modal"); modal.setAttribute("role","dialog"); modal.setAttribute("aria-modal","true");
      modal.setAttribute("aria-label",id === "help" ? "Keyboard shortcuts" : "Report viewer");
    }
    // Fix keyboard labels independently of the HTML file's text encoding.
    $$("#help kbd.fa").forEach((el,i) => el.textContent = ["ح","ق","ض","؟"][i]);
  }
  async function initialize() {
    if (!api || !rt?.EventsOn) {
      setText("#pageTitle","WhiteDNS Scanner");
      $("#content").innerHTML = '<div class="glass panel empty-state"><p>The desktop bridge is unavailable. Launch WhiteDNS Scanner or use wails dev to connect the scanning engine.</p></div>';
      return;
    }
    ready = false; const before = eventVersion;
    try {
      const [loaded,initial,modes,providers] = await Promise.all([api.GetSettings(),api.GetStats(),api.GetScanModes(),api.GetEdgeProviders()]);
      if(providers?.length) edgeProviders=providers;
      for(const mode of modes || []) {if(modeByID[mode.id]) Object.assign(modeByID[mode.id],{title:mode.name,group:mode.group});}
      settings = normalizeSettings(loaded); applyTheme(settings.theme); applyAccent(settings.accent);
      if(!providerInfo(currentEdgeProvider)) currentEdgeProvider=settings.targets.http.edgeProvider;
      if (before === eventVersion) acceptStats(initial);
      ready = true; renderNav(); navigate(page);
    } catch(e) {
      toast(e,true);
      $("#content").innerHTML = `<div class="glass panel empty-state"><p>${esc(e?.message || e)}</p>${btn("Retry loading", "retry-startup", "filled")}</div>`;
    }
  }
  enhanceLayout();
  if (rt?.EventsOn) {
    rt.EventsOn("scan:stats", data => { eventVersion++; acceptStats(data); });
    rt.EventsOn("scan:done", data => { eventVersion++; acceptStats(data,true); });
  }
  initialize();
})();

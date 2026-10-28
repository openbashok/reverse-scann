"use strict";
// Dashboard reverse-scann. Regla de oro de seguridad: TODO dato capturado se
// inserta en el DOM vía textContent / createElement, nunca como HTML. Así un
// payload XSS guardado (p. ej. "<script>…") se ve como texto y jamás se ejecuta.

const $ = (s) => document.querySelector(s);

function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;        // texto seguro
    else if (k === "data") for (const [dk, dv] of Object.entries(v)) n.dataset[dk] = dv;
    else n.setAttribute(k, v);
  }
  for (const c of kids) if (c != null) n.append(c);
  return n;
}

async function api(path, opts) {
  const r = await fetch(path, opts);
  let data = null;
  try { data = await r.json(); } catch (_) {}
  if (!r.ok) throw new Error((data && data.error) || ("HTTP " + r.status));
  return data;
}

const fmtTime = (iso) => {
  if (!iso) return "";
  const d = new Date(iso);
  const day = d.toLocaleDateString(undefined, { day: "2-digit", month: "2-digit", year: "2-digit" });
  return day + " " + d.toLocaleTimeString();
};
const statusClass = (s) => (s ? "s" + String(s)[0] : "");
const safeMethodClass = (m) => (/^[A-Z]{1,12}$/.test(m || "") ? "m-" + m : "m-OTHER");

// --- Copy as curl ---
const shq = (s) => "'" + String(s).replace(/'/g, "'\\''") + "'";

function buildCurl(r) {
  const scheme = r.scheme || "http";
  const host = r.host || "TARGET";
  const url = scheme + "://" + host + (r.uri || "/");
  const skip = new Set(["content-length", "transfer-encoding"]);
  const seg = ["curl -sk --path-as-is -X " + (r.method || "GET")];
  for (const [k, v] of Object.entries(r.headers || {})) {
    if (skip.has(k.toLowerCase())) continue;
    const val = Array.isArray(v) ? v.join(", ") : v;
    seg.push("-H " + shq(k + ": " + val));
  }
  let prefix = "";
  if (r.body) {
    if (r.body_encoding === "base64") {
      prefix = "printf %s " + shq(r.body) + " | base64 -d | ";
      seg.push("--data-binary @-");
    } else {
      seg.push("--data-binary " + shq(r.body));
    }
  }
  seg.push(shq(url));
  return prefix + seg.join(" \\\n  ");
}

async function copyText(t) {
  try {
    await navigator.clipboard.writeText(t);
    return true;
  } catch (_) {
    const ta = document.createElement("textarea");
    ta.value = t; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.append(ta); ta.focus(); ta.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch (_) {}
    ta.remove();
    return ok;
  }
}

/* ======================= Rango de fecha GLOBAL ======================= */
let panelRange = "24h";       // preset activo
let panelCustom = null;       // {from, to} o null (custom pisa el preset)

function rangeQS() {
  return panelCustom
    ? `from=${encodeURIComponent(panelCustom.from)}&to=${encodeURIComponent(panelCustom.to)}`
    : "range=" + encodeURIComponent(panelRange);
}

function reloadActiveTab() {
  const v = document.querySelector(".tabs button.active")?.dataset.view;
  if (v === "captures") { loadStats(); lastId = null; loadRows(); }
  else if (v === "panel") loadPanel();
  else if (v === "alerts") { loadAlertStats(); loadAlerts(); }
}

/* ======================= Tabs ======================= */
document.querySelectorAll(".tabs button").forEach((b) => {
  b.addEventListener("click", () => {
    document.querySelectorAll(".tabs button").forEach((x) => x.classList.remove("active"));
    document.querySelectorAll(".view").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    const v = b.dataset.view;
    $("#view-" + v).classList.add("active");
    // la barra de rango solo aplica a tabs con datos temporales
    $("#global-range").style.display = (v === "persona" || v === "config") ? "none" : "flex";
    if (v === "persona") loadProfiles();
    if (v === "panel") loadPanel();
    if (v === "alerts") { loadAlertStats(); loadAlerts(); loadHoneytokens(); }
    if (v === "config") { loadWhitelist(); loadWordlists(); updateWlLink(); }
  });
});

/* ======================= Capturas ======================= */
let lastId = null, autoTimer = null;

async function loadStats() {
  const d = await api("/api/stats?" + rangeQS());
  const t = d.totals;
  const stats = $("#stats");
  stats.replaceChildren();

  const numCard = (label, value) =>
    el("div", { class: "card" }, el("div", { class: "k", text: label }),
      el("div", { class: "v", text: String(value ?? 0) }));

  const listCard = (title, rows, keyName) => {
    const body = el("div", { class: "v" });
    if (!rows.length) body.append(el("span", { class: "label", text: "—" }));
    rows.forEach((r) => body.append(
      el("div", { class: "row" },
        el("span", { class: "label", text: String(r[keyName]) }),
        el("span", { class: "hits", text: String(r.hits) }))));
    return el("div", { class: "card list" }, el("div", { class: "k", text: title }), body);
  };

  stats.append(
    numCard("Requests", t.total),
    numCard("IPs distintas", t.ips),
    numCard("Con body", t.con_body),
    listCard("Top métodos", d.methods, "method"),
    listCard("Top IPs", d.top_ips, "remote_addr"),
    listCard("Top paths", d.top_paths, "path"),
    listCard("Top user-agents", d.top_uas, "user_agent"),
  );
}

function filters() {
  const p = new URLSearchParams();
  const q = $("#f-q").value.trim(); if (q) p.set("q", q);
  const ip = $("#f-ip").value.trim(); if (ip) p.set("ip", ip);
  const m = $("#f-method").value; if (m) p.set("method", m);
  if ($("#f-body").checked) p.set("body", "1");
  return p;
}

function rowNode(r) {
  const bodyInfo = r.body_size
    ? `${r.body_size}B ${r.body_encoding || ""}${r.body_truncated ? " ✂" : ""}` : "";
  const uriTd = el("td", { class: "uri" }, document.createTextNode(String(r.uri ?? "")));
  if (r.scheme === "https") uriTd.append(el("span", { class: "badge", text: "TLS" }));
  const tr = el("tr", { data: { id: String(r.id) } },
    el("td", { text: String(r.id) }),
    el("td", { text: fmtTime(r.ts) }),
    el("td", { text: String(r.remote_addr ?? "") }),
    el("td", {}, el("span", { class: "pill " + safeMethodClass(r.method), text: String(r.method ?? "") })),
    el("td", { class: statusClass(r.status), text: r.status != null ? String(r.status) : "" }),
    uriTd,
    el("td", { class: "bodyinfo", text: bodyInfo }));
  return tr;
}

async function loadRows(append = false) {
  const p = filters();
  if (append && lastId) p.set("before", lastId);
  p.set("limit", "100");
  const d = await api("/api/requests?" + rangeQS() + "&" + p);
  const tbody = $("#rows");
  if (!append) tbody.replaceChildren();
  d.rows.forEach((r) => tbody.append(rowNode(r)));
  if (d.rows.length) lastId = d.rows[d.rows.length - 1].id;
  $("#more").style.display = d.rows.length === 100 ? "block" : "none";
  $("#empty").style.display = (!append && d.rows.length === 0) ? "block" : "none";
  $("#count").textContent = `${tbody.children.length} mostradas`;
}

// Barra de clasificación manual dentro del visor de una request.
function renderAlertBar(r) {
  const box = el("div", { class: "alert-box" });
  box.append(el("h3", { text: "Clasificación / alertas" }));

  // Alertas ya asociadas (automáticas y manuales).
  const list = el("div", { class: "alert-assoc" });
  (r.alerts || []).forEach((a) => {
    const row = el("div", { class: "alert-assoc-row" },
      el("span", { class: "sev sev-" + a.severity, text: a.severity }),
      el("span", { class: "badge", text: a.manual ? "manual" : a.rule }),
      el("span", { class: "val", text: a.summary || "" }));
    if (a.manual) {
      const rm = el("button", { class: "ghost small", text: "Quitar" });
      rm.addEventListener("click", async () => {
        rm.disabled = true;
        try { await api("/api/alerts/" + a.id, { method: "DELETE" }); openDetail(r.id); }
        catch (e) { rm.disabled = false; alert(e.message); }
      });
      row.append(rm);
    }
    list.append(row);
  });
  if (!(r.alerts || []).length) {
    list.append(el("span", { class: "hint", text: "Sin alertas para esta request." }));
  }
  box.append(list);

  // Formulario para marcarla a mano.
  const form = el("div", { class: "toolbar", style: "padding:10px 0 0" });
  const sel = el("select", { class: "sev-select" });
  ["critical", "high", "medium", "low", "info"].forEach((s) => {
    const o = el("option", { value: s, text: s });
    if (s === "medium") o.setAttribute("selected", "selected");
    sel.append(o);
  });
  const note = el("input", { type: "text", placeholder: "nota (opcional): qué viste", maxlength: "200", class: "note-input" });
  const btn = el("button", { class: "primary", text: "Marcar como alerta" });
  const msg = el("span", { class: "msg" });
  btn.addEventListener("click", async () => {
    btn.disabled = true; msg.textContent = ""; msg.className = "msg";
    try {
      await api("/api/requests/" + r.id + "/alert", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ severity: sel.value, note: note.value.trim() }),
      });
      openDetail(r.id);  // re-render con la nueva alerta
    } catch (e) {
      btn.disabled = false;
      msg.textContent = e.message; msg.className = "msg err";
    }
  });
  form.append(sel, note, btn, msg);
  box.append(form);
  return box;
}

async function openDetail(id) {
  const r = await api("/api/requests/" + id);
  $("#d-title").textContent = `#${r.id} · ${r.method} ${r.path}`;
  const b = $("#d-body");
  b.replaceChildren();

  // Copy as curl: reproducir el request completo (método, headers, body) con curl
  const curlBar = el("div", { class: "toolbar", style: "padding:0 0 12px" });
  const curlBtn = el("button", { class: "primary", text: "Copy as curl" });
  const curlMsg = el("span", { class: "msg" });
  curlBtn.addEventListener("click", async () => {
    const ok = await copyText(buildCurl(r));
    curlMsg.textContent = ok ? "copiado ✓" : "no se pudo copiar";
    curlMsg.className = "msg " + (ok ? "ok" : "err");
  });
  curlBar.append(curlBtn, curlMsg);
  b.append(curlBar);

  // Clasificación manual: marcar esta request como alerta (complementa al watcher).
  b.append(renderAlertBar(r));

  const kv = el("div", { class: "kv" });
  const addKv = (k, v) => { kv.append(el("span", { class: "k", text: k }), el("span", { class: "val", text: v == null ? "" : String(v) })); };
  addKv("Timestamp", r.ts);
  addKv("Origen", `${r.remote_addr || ""}:${r.remote_port || ""}`);
  addKv("Esquema", `${r.scheme || ""} · HTTP/${r.http_version || ""}`);
  addKv("Host", r.host);
  addKv("Status", `${r.status} · ${r.request_time}s`);
  addKv("User-Agent", r.user_agent);
  b.append(kv);

  const section = (title, textValue) => {
    b.append(el("h3", { text: title }));
    b.append(el("pre", { text: textValue }));
  };
  section("URI", r.uri || "");
  section("Request line + headers (crudo)", r.raw_header || "(no disponible)");

  let headers = "(sin headers)";
  if (r.headers) {
    headers = Object.entries(r.headers)
      .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : v}`).join("\n");
  }
  section("Headers (parseados)", headers);

  b.append(el("h3", { text: "Body" }));
  if (r.body) {
    b.append(el("pre", { text: r.body }));
    const note = (r.body_encoding === "base64" ? " (base64, binario)" : "")
      + (r.body_truncated ? " — TRUNCADO" : "");
    b.append(el("div", { class: "hint", text: `${r.body_size} bytes${note}` }));
  } else {
    b.append(el("span", { class: "hint", text: "(sin body)" }));
  }
  $("#overlay").classList.add("open");
}

$("#rows")?.addEventListener("click", (e) => {
  const tr = e.target.closest("tr[data-id]");
  if (tr) openDetail(tr.dataset.id);
});
$("#d-close")?.addEventListener("click", () => $("#overlay").classList.remove("open"));
$("#overlay")?.addEventListener("click", (e) => { if (e.target.id === "overlay") $("#overlay").classList.remove("open"); });
$("#apply")?.addEventListener("click", () => { lastId = null; loadRows(); });
["f-q", "f-ip"].forEach((id) => $("#" + id).addEventListener("keydown", (e) => {
  if (e.key === "Enter") { lastId = null; loadRows(); }
}));
$("#more-btn")?.addEventListener("click", () => loadRows(true));
$("#auto")?.addEventListener("change", (e) => {
  if (e.target.checked) {
    autoTimer = setInterval(() => {
      const v = document.querySelector(".tabs button.active")?.dataset.view;
      if (v === "captures") { loadStats(); lastId = null; loadRows(); }
      else if (v === "panel") loadPanel();
      else if (v === "alerts") { loadAlertStats(); loadAlerts(); }
    }, 5000);
  } else clearInterval(autoTimer);
});

/* ======================= Personas ======================= */
let editingId = null;   // null = creando nuevo

async function loadProfiles() {
  const d = await api("/api/profiles");
  const list = $("#plist");
  list.replaceChildren();
  d.rows.forEach((p) => {
    const name = el("div", { class: "name" }, document.createTextNode(p.name));
    if (p.is_active) name.append(el("span", { class: "tag-active", text: "ACTIVO" }));

    const acts = el("div", { class: "acts" });
    if (!p.is_active) {
      const act = el("button", { class: "primary", text: "Activar" });
      act.addEventListener("click", () => activateProfile(p.id));
      acts.append(act);
    }
    const edit = el("button", { class: "ghost", text: "Editar" });
    edit.addEventListener("click", () => selectProfile(p.id));
    acts.append(edit);
    if (!p.is_active) {
      const del = el("button", { class: "ghost danger", text: "Borrar" });
      del.addEventListener("click", () => deleteProfile(p.id, p.name));
      acts.append(del);
    }

    const card = el("div", { class: "pcard" + (p.id === editingId ? " sel" : "") },
      name,
      el("div", { class: "sh", text: p.server_header }),
      acts);
    list.append(card);
  });
}

function setEditor(p) {
  $("#e-name").value = p.name || "";
  $("#e-server").value = p.server_header || "";
  $("#e-idx-status").value = p.index_status ?? 200;
  $("#e-idx-body").value = p.index_body || "";
  $("#e-nf-status").value = p.notfound_status ?? 404;
  $("#e-nf-body").value = p.notfound_body || "";
  $("#e-extra").value = JSON.stringify(p.extra_headers || {}, null, 2);
  $("#e-routes").value = JSON.stringify(p.routes || [], null, 2);
  msg("");
}

async function selectProfile(id) {
  const p = await api("/api/profiles/" + id);
  editingId = id;
  setEditor(p);
  loadProfiles();
}

function newProfile() {
  editingId = null;
  setEditor({ name: "", server_header: "Apache/2.4.41 (Ubuntu)", index_status: 200,
    notfound_status: 404, extra_headers: {}, routes: [] });
  loadProfiles();
}

function msg(text, kind) {
  const m = $("#e-msg");
  m.textContent = text || "";
  m.className = "msg" + (kind ? " " + kind : "");
}

async function saveProfile() {
  let extra, routes;
  try { extra = JSON.parse($("#e-extra").value || "{}"); }
  catch (e) { return msg("Headers extra: JSON inválido", "err"); }
  try { routes = JSON.parse($("#e-routes").value || "[]"); }
  catch (e) { return msg("Rutas: JSON inválido", "err"); }

  const payload = {
    name: $("#e-name").value.trim(),
    server_header: $("#e-server").value,
    index_status: Number($("#e-idx-status").value),
    index_body: $("#e-idx-body").value,
    notfound_status: Number($("#e-nf-status").value),
    notfound_body: $("#e-nf-body").value,
    extra_headers: extra,
    routes: routes,
  };
  const opts = {
    method: editingId ? "PUT" : "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  };
  const url = editingId ? "/api/profiles/" + editingId : "/api/profiles";
  try {
    const res = await api(url, opts);
    if (!editingId && res.id) editingId = res.id;
    msg("Guardado ✓", "ok");
    loadProfiles();
  } catch (e) {
    msg(e.message, "err");
  }
}

async function activateProfile(id) {
  try { await api("/api/profiles/" + id + "/activate", { method: "POST" }); loadProfiles(); }
  catch (e) { msg(e.message, "err"); }
}

async function deleteProfile(id, name) {
  if (!confirm(`¿Borrar el perfil "${name}"?`)) return;
  try {
    await api("/api/profiles/" + id, { method: "DELETE" });
    if (editingId === id) newProfile();
    loadProfiles();
  } catch (e) { msg(e.message, "err"); }
}

$("#p-new")?.addEventListener("click", newProfile);
$("#e-save")?.addEventListener("click", saveProfile);
$("#e-cancel")?.addEventListener("click", newProfile);

/* ======================= Alertas ======================= */
async function loadAlertStats() {
  const d = await api("/api/alerts/stats?" + rangeQS());
  const s = $("#alert-stats");
  s.replaceChildren();
  const card = (label, value, cls) => {
    const v = el("div", { class: "v", text: String(value ?? 0) });
    if (cls) v.classList.add(cls);
    return el("div", { class: "card" }, el("div", { class: "k", text: label }), v);
  };
  const sev = d.by_severity || {};
  s.append(
    card("Alertas (total)", d.total),
    card("Alertas (" + (d.range_label || "") + ")", d.inwin),
    card("Critical", sev.critical || 0, "sev-critical"),
    card("High", sev.high || 0, "sev-high"),
    card("Medium", sev.medium || 0, "sev-medium"),
    card("Low", sev.low || 0, "sev-low"),
  );

  // poblar el dropdown de reglas (preservando la selección actual)
  const sel = $("#a-rule");
  if (sel) {
    const cur = sel.value;
    sel.replaceChildren(el("option", { value: "", text: "todas las reglas" }));
    (d.rules || []).forEach((r) => sel.append(el("option", { value: r, text: r })));
    sel.value = cur;
  }
}

async function loadAlerts() {
  const p = new URLSearchParams();
  const sevs = Array.from(document.querySelectorAll(".a-sev:checked")).map((c) => c.value);
  if (sevs.length) p.set("severity", sevs.join(","));
  const rule = $("#a-rule")?.value;
  if (rule) p.set("rule", rule);
  p.set("limit", "150");
  const d = await api("/api/alerts?" + rangeQS() + "&" + p);
  const tb = $("#alert-rows");
  tb.replaceChildren();
  d.rows.forEach((r) => {
    const sevCell = el("td", {}, el("span", { class: "sev sev-" + r.severity, text: r.severity }));
    let reqCell = el("td", { class: "muted", text: "—" });
    if (r.request_id != null) {
      const a = el("a", { class: "reqlink", text: "#" + r.request_id });
      a.addEventListener("click", () => openDetail(r.request_id));
      reqCell = el("td", {}, a);
    }
    const bodyInfo = r.body_size
      ? `${fmtNum(r.body_size)}B ${r.body_encoding || ""}` : "—";
    tb.append(el("tr", {},
      el("td", { text: String(r.id) }),
      el("td", { text: fmtTime(r.ts) }),
      sevCell,
      el("td", { text: String(r.rule) }),
      el("td", { text: String(r.remote_addr ?? "") }),
      el("td", { class: "summary", text: String(r.summary ?? "") }),
      el("td", { class: "bodyinfo", text: bodyInfo }),
      reqCell));
  });
  $("#alert-empty").style.display = d.rows.length ? "none" : "block";
  $("#a-count").textContent = `${d.rows.length} mostradas`;
}

async function loadHoneytokens() {
  const d = await api("/api/honeytokens");
  const tb = $("#ht-rows");
  tb.replaceChildren();
  d.rows.forEach((h) => {
    const rot = el("button", { class: "ghost", text: "rotar" });
    rot.style.fontSize = "12px"; rot.style.padding = "3px 10px"; rot.style.marginRight = "6px";
    rot.addEventListener("click", async () => {
      if (!confirm("¿Rotar este honeytoken? Se genera un valor nuevo y se resetean los contadores; el canario viejo deja de valer.")) return;
      try { await api("/api/honeytokens/" + h.id + "/rotate", { method: "POST" }); loadHoneytokens(); }
      catch (e) { alert(e.message); }
    });
    const del = el("button", { class: "ghost danger", text: "borrar" });
    del.style.fontSize = "12px"; del.style.padding = "3px 10px";
    del.addEventListener("click", async () => {
      if (!confirm(`¿Borrar el honeytoken "${h.token}"?`)) return;
      try { await api("/api/honeytokens/" + h.id, { method: "DELETE" }); loadHoneytokens(); }
      catch (e) { alert(e.message); }
    });
    const trig = el("td", { text: String(h.trigger_count) });
    if (h.trigger_count > 0) trig.classList.add("sev-critical");
    tb.append(el("tr", {},
      el("td", { text: String(h.id) }),
      el("td", { text: h.kind }),
      el("td", { class: "summary", text: h.token }),
      trig,
      el("td", { text: h.last_triggered ? fmtTime(h.last_triggered) : "—" }),
      el("td", {}, rot, del)));
  });
}

async function createHoneytoken() {
  const payload = {
    kind: $("#ht-kind").value,
    token: $("#ht-token").value.trim(),
    description: $("#ht-desc").value.trim(),
  };
  const m = $("#ht-msg");
  try {
    const res = await api("/api/honeytokens", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    m.textContent = "creado: " + res.token; m.className = "msg ok";
    $("#ht-token").value = ""; $("#ht-desc").value = "";
    loadHoneytokens();
  } catch (e) { m.textContent = e.message; m.className = "msg err"; }
}

async function loadWhitelist() {
  const d = await api("/api/whitelist");
  const tb = $("#wl-rows");
  tb.replaceChildren();
  d.rows.forEach((w) => {
    const del = el("button", { class: "ghost danger", text: "borrar" });
    del.style.fontSize = "12px"; del.style.padding = "3px 10px";
    del.addEventListener("click", async () => {
      if (!confirm(`¿Quitar ${w.cidr} de la whitelist?`)) return;
      try { await api("/api/whitelist/" + w.id, { method: "DELETE" }); loadWhitelist(); }
      catch (e) { alert(e.message); }
    });
    tb.append(el("tr", {},
      el("td", { text: String(w.id) }),
      el("td", { class: "summary", text: w.cidr }),
      el("td", { text: w.note || "" }),
      el("td", {}, del)));
  });
}

async function addWhitelist() {
  const m = $("#wl-msg");
  const payload = { cidr: $("#wl-cidr").value.trim(), note: $("#wl-note").value.trim() };
  try {
    await api("/api/whitelist", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    m.textContent = "agregado"; m.className = "msg ok";
    $("#wl-cidr").value = ""; $("#wl-note").value = "";
    loadWhitelist();
  } catch (e) { m.textContent = e.message; m.className = "msg err"; }
}

$("#a-refresh")?.addEventListener("click", () => { loadAlertStats(); loadAlerts(); });
document.querySelectorAll(".a-sev").forEach((c) => c.addEventListener("change", loadAlerts));
$("#a-rule")?.addEventListener("change", loadAlerts);
$("#ht-create")?.addEventListener("click", createHoneytoken);
$("#wl-add")?.addEventListener("click", addWhitelist);

/* ---- Wordlist de vectores ---- */
const fmtBytes = (n) => n < 1024 ? n + " B"
  : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB";

function updateWlLink() {
  const mode = $("#wl-mode")?.value || "paths";
  const min = Math.max(1, parseInt($("#wl-min")?.value || "1", 10) || 1);
  const strip = $("#wl-strip")?.checked ? "1" : "0";
  const a = $("#wl-dl");
  if (a) {
    a.href = `/api/wordlist?range=all&mode=${mode}&min_count=${min}&strip_slash=${strip}`;
    a.setAttribute("download", `wordlist-${mode}.txt`);
  }
}

async function loadWordlists() {
  const d = await api("/api/wordlists");
  const tb = $("#wl-snaps");
  tb.replaceChildren();
  if (!d.rows.length) {
    tb.append(el("tr", {}, el("td", { colspan: "4", class: "chart-empty",
      text: "aún no hay snapshots (se genera uno por día)" })));
    return;
  }
  d.rows.forEach((s) => {
    const a = el("a", { class: "reqlink", href: "/api/wordlists/" + encodeURIComponent(s.name), text: "descargar" });
    a.setAttribute("download", s.name);
    tb.append(el("tr", {},
      el("td", { text: s.name }),
      el("td", { text: fmtNum(s.lines) }),
      el("td", { text: fmtBytes(s.bytes) }),
      el("td", {}, a)));
  });
}

["wl-mode", "wl-min", "wl-strip"].forEach((id) => {
  $("#" + id)?.addEventListener("change", updateWlLink);
});

/* ======================= Panel (dataviz) ======================= */
const SVGNS = "http://www.w3.org/2000/svg";
const fmtNum = (n) => Number(n || 0).toLocaleString();

function sv(tag, attrs = {}, ...kids) {
  const n = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, String(v));
  for (const c of kids) if (c != null) n.append(c);
  return n;
}

// Paleta categórica validada (skill dataviz, modo oscuro) para las tortas.
const CAT = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#9085e9", "#008300", "#e66767"];
const SEVC = { critical: "#e66767", high: "#d95926", medium: "#c98500", low: "#3987e5" };
const STC = { "2xx": "#199e70", "3xx": "#3987e5", "4xx": "#c98500", "5xx": "#e66767" };
const SCHEMEC = { http: "#3987e5", https: "#199e70", "?": "#8a8a8a" };
let gradSeq = 0;

// Barras horizontales (HTML). Color por ítem o gradiente de marca; etiqueta siempre visible.
function renderBars(c, items) {
  c.replaceChildren();
  items = items.filter((i) => i.value > 0);
  if (!items.length) { c.append(el("div", { class: "chart-empty", text: "sin datos" })); return; }
  const max = Math.max(...items.map((i) => i.value), 1);
  const wrap = el("div", { class: "hbars" });
  items.forEach((it) => {
    const label = el("span", { class: "hbar-label", text: String(it.label) });
    label.title = String(it.label);
    const fill = el("span", { class: "hbar-fill" });
    fill.style.width = Math.max(it.value / max * 100, 1.5) + "%";
    fill.style.background = it.color || "linear-gradient(90deg, #bf0d57, #7b5cff)";
    const row = el("div", { class: "hbar" },
      label, el("span", { class: "hbar-track" }, fill),
      el("span", { class: "hbar-val", text: fmtNum(it.value) }));
    row.title = `${it.label}: ${it.value}`;
    wrap.append(row);
  });
  c.append(wrap);
}

// Donut (torta con agujero) + leyenda con valor y %. Identidad por leyenda, no color-solo.
// keepZero=true deja en la leyenda los ítems en 0 (ej. severidad: muestra 'critical: 0').
function renderDonut(c, items, keepZero = false) {
  c.replaceChildren();
  const legendItems = keepZero ? items : items.filter((i) => i.value > 0);
  items = items.filter((i) => i.value > 0);
  const total = items.reduce((a, b) => a + b.value, 0);
  if (!total) { c.append(el("div", { class: "chart-empty", text: "sin datos en el rango" })); return; }
  const size = 130, r = 46, sw = 20, cx = size / 2, cy = size / 2, C = 2 * Math.PI * r, gap = 2.5;
  const svg = sv("svg", { width: size, height: size, viewBox: `0 0 ${size} ${size}` });
  svg.append(sv("circle", { cx, cy, r, fill: "none", stroke: "rgba(255,255,255,.06)", "stroke-width": sw }));
  let acc = 0;
  items.forEach((it) => {
    const frac = it.value / total;
    const seg = Math.max(frac * C - gap, 0.6);
    const arc = sv("circle", {
      cx, cy, r, fill: "none", stroke: it.color, "stroke-width": sw,
      "stroke-dasharray": `${seg} ${C - seg}`, "stroke-dashoffset": -acc,
      transform: `rotate(-90 ${cx} ${cy})`,
    });
    const tt = sv("title"); tt.textContent = `${it.label}: ${fmtNum(it.value)} (${(frac * 100).toFixed(1)}%)`;
    arc.append(tt); svg.append(arc);
    acc += frac * C;
  });
  const t1 = sv("text", { x: cx, y: cy - 1, "text-anchor": "middle", "dominant-baseline": "middle", fill: "#d6deeb", "font-size": 19, "font-weight": 700 });
  t1.textContent = fmtNum(total);
  const t2 = sv("text", { x: cx, y: cy + 15, "text-anchor": "middle", fill: "#7e8aa0", "font-size": 9, "letter-spacing": 0.5 });
  t2.textContent = "TOTAL";
  svg.append(t1, t2);

  const leg = el("div", { class: "legend" });
  legendItems.forEach((it) => {
    const dot = el("span", { class: "legend-dot" }); dot.style.background = it.color;
    const right = el("span", {},
      el("span", { class: "legend-val", text: fmtNum(it.value) }),
      el("span", { class: "legend-pct", text: ` ${total ? (it.value / total * 100).toFixed(0) : 0}%` }));
    leg.append(el("div", { class: "legend-item" }, dot,
      el("span", { class: "legend-label", text: String(it.label) }), right));
  });
  c.append(el("div", { class: "donut-wrap" }, svg, leg));
}

// Área temporal (SVG) con relleno en gradiente; grilla recesiva; hover por bucket.
function renderArea(c, rows, color = "#bf0d57", bucket = "hour") {
  c.replaceChildren();
  if (!rows.length) { c.append(el("div", { class: "chart-empty", text: "sin datos" })); return; }
  const W = 1000, H = 190, padL = 46, padR = 12, padT = 12, padB = 24;
  const iw = W - padL - padR, ih = H - padT - padB;
  const max = Math.max(...rows.map((r) => r.n), 1);
  const n = rows.length;
  const x = (i) => padL + (n <= 1 ? 0 : (i / (n - 1)) * iw);
  const y = (v) => padT + ih - (v / max) * ih;
  const svg = sv("svg", { class: "area", viewBox: `0 0 ${W} ${H}`, role: "img" });

  const gid = "grad" + (gradSeq++);
  const defs = sv("defs");
  const lg = sv("linearGradient", { id: gid, x1: 0, y1: 0, x2: 0, y2: 1 });
  lg.append(sv("stop", { offset: "0%", "stop-color": color, "stop-opacity": 0.45 }));
  lg.append(sv("stop", { offset: "100%", "stop-color": color, "stop-opacity": 0.02 }));
  defs.append(lg); svg.append(defs);

  [0, 0.5, 1].forEach((f) => {
    const val = Math.round(max * f), yy = y(val);
    svg.append(sv("line", { x1: padL, y1: yy, x2: W - padR, y2: yy, stroke: "#242b38", "stroke-width": 1 }));
    const t = sv("text", { x: padL - 7, y: yy + 3, "text-anchor": "end", fill: "#7e8aa0", "font-size": 11 });
    t.textContent = fmtNum(val); svg.append(t);
  });

  const line = rows.map((r, i) => `${x(i)},${y(r.n)}`).join(" ");
  svg.append(sv("polygon", { points: `${padL},${y(0)} ${line} ${x(n - 1)},${y(0)}`, fill: `url(#${gid})` }));
  svg.append(sv("polyline", { points: line, fill: "none", stroke: color, "stroke-width": 2.5, "stroke-linejoin": "round", "stroke-linecap": "round" }));

  const step = Math.max(1, Math.ceil(n / 7));
  const fmtX = (d) => bucket === "day"
    ? d.toLocaleDateString(undefined, { day: "2-digit", month: "2-digit" })
    : d.toLocaleString(undefined, { day: "2-digit", hour: "2-digit" }).replace(",", " ");
  rows.forEach((r, i) => {
    if (i % step === 0 || i === n - 1) {
      const t = sv("text", { x: x(i), y: H - 7, "text-anchor": "middle", fill: "#7e8aa0", "font-size": 11 });
      t.textContent = fmtX(new Date(r.t));
      svg.append(t);
    }
  });
  const bw = iw / Math.max(n - 1, 1);
  rows.forEach((r, i) => {
    const rect = sv("rect", { x: x(i) - bw / 2, y: padT, width: bw, height: ih, fill: "transparent" });
    const tt = sv("title"); tt.textContent = `${new Date(r.t).toLocaleString()} — ${fmtNum(r.n)}`;
    rect.append(tt); svg.append(rect);
  });
  c.append(svg);
}

async function loadPanel() {
  const d = await api("/api/analytics?" + rangeQS());
  gradSeq = 0;
  const win = d.range_label;
  const k = $("#kpi-row"); k.replaceChildren();
  const accent = ["#bf0d57", "#3987e5", "#d95926", "#e66767", "#199e70"];
  const tile = (label, val, i) => {
    const t = el("div", { class: "card kpi" },
      el("div", { class: "k", text: label }), el("div", { class: "v", text: fmtNum(val) }));
    t.style.borderLeft = "3px solid " + accent[i];
    return t;
  };
  k.append(
    tile("Requests (total)", d.kpis.total, 0),
    tile("Requests (" + win + ")", d.kpis.inwin, 1),
    tile("IPs únicas (" + win + ")", d.kpis.ipswin, 2),
    tile("Alertas (" + win + ")", d.kpis.alertswin, 3),
    tile("Honeytokens disparados", d.kpis.honeytokens, 4),
  );

  renderArea($("#ch-requests"), d.requests_ts, "#bf0d57", d.bucket);
  renderArea($("#ch-alerts"), d.alerts_ts, "#e66767", d.bucket);

  renderDonut($("#ch-severity"),
    d.severity.map((s) => ({ label: s.severity, value: s.n, color: SEVC[s.severity] })), true);
  renderDonut($("#ch-methods"),
    d.methods.map((m, i) => ({ label: m.k, value: m.n, color: CAT[i % CAT.length] })));
  renderDonut($("#ch-status"),
    d.status_classes.map((s) => ({ label: s.k, value: s.n, color: STC[s.k] || "#8a8a8a" })));
  renderDonut($("#ch-schemes"),
    d.schemes.map((s) => ({ label: s.k, value: s.n, color: SCHEMEC[s.k] || "#8a8a8a" })));

  renderBars($("#ch-ips"), d.top_ips.map((r) => ({ label: r.k, value: r.n })));
  renderBars($("#ch-paths"), d.top_paths.map((r) => ({ label: r.k, value: r.n })));
  renderBars($("#ch-rules"), d.top_rules.map((r, i) => ({ label: r.k, value: r.n, color: CAT[i % CAT.length] })));
  renderBars($("#ch-uas"), d.top_uas.map((r) => ({ label: r.k, value: r.n })));

  const subReq = $("#ch-requests").closest(".card").querySelector(".chart-sub");
  if (subReq) subReq.textContent = `· ${win} · sin IPs propias`;
  const subAlt = $("#ch-alerts").closest(".card").querySelector(".chart-sub");
  if (subAlt) subAlt.textContent = `· ${win}`;
}

document.querySelectorAll("#range-sel button").forEach((b) => {
  b.addEventListener("click", () => {
    document.querySelectorAll("#range-sel button").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    panelRange = b.dataset.range;
    panelCustom = null;               // preset pisa el custom
    reloadActiveTab();
  });
});
$("#range-apply")?.addEventListener("click", () => {
  const f = $("#range-from").value, t = $("#range-to").value;
  if (!f || !t) { alert("Elegí fecha desde y hasta"); return; }
  if (t < f) { alert("'hasta' debe ser posterior a 'desde'"); return; }
  panelCustom = { from: f, to: t };
  document.querySelectorAll("#range-sel button").forEach((x) => x.classList.remove("active"));
  reloadActiveTab();
});

/* ======================= init ======================= */
loadStats();
loadRows();

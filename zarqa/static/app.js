// Zarqa UI. All data from the server (and above all anything collected from the internet) is
// untrusted: it is only ever set with textContent, never parsed as HTML.
"use strict";
const $ = (s, el = document) => el.querySelector(s);
const mainEl = $("#main");
let main = mainEl;
let navToken = 0;

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "value") el.value = v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
function fill(el, ...kids) {
  el.replaceChildren(...kids.flat(Infinity).filter((k) => k !== null && k !== undefined && k !== false)
    .map((k) => (k instanceof Node ? k : document.createTextNode(String(k)))));
  return el;
}
const icon = (n) => h("span", { class: "mdi mdi-" + n });
const section = (title, ic, ...kids) => h("section", {}, h("h2", {}, icon(ic), title), ...kids);
const when = (s) => (s || "").replace("T", " ").slice(0, 16);

function toast(msg, ms = 3500) {
  const t = $("#toast"); t.textContent = msg; t.classList.remove("hidden");
  clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.add("hidden"), ms);
}
async function api(url, body, method) {
  const opt = body === undefined && !method ? {} : { method: method || "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}) };
  const r = await fetch(url, opt);
  let data = null;
  try { data = await r.json(); } catch (e) { data = null; }
  if (!r.ok) {
    const msg = (data && data.error) || (r.status === 403 ? "Not allowed for your role." : `Request failed (${r.status})`);
    toast(msg); const err = new Error(msg); err.shown = true; throw err;
  }
  return data;
}
// Actions always POST, even with no body (api() with no body is a GET).
const post = (url, body) => api(url, body || {}, "POST");

// Buttons marked data-need="op" or "admin" are hidden for roles that cannot use them (the server enforces it too).
const meReady = api("/api/me").then((m) => {
  document.body.dataset.role = m.role || "viewer";
  fill($("#me"), icon("account-circle-outline"), " ", m.name || m.user || "local", " ", h("span", { class: "badge" }, m.role));
}).catch(() => {});

let poll = null;
function route() {
  clearInterval(poll); poll = null;
  const [tab] = (location.hash.slice(1) || "overview").split("/");
  document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("on", a.dataset.tab === tab));
  const pages = { overview, jobs, settings };
  const token = ++navToken;
  const view = h("div");
  main = view;
  const done = () => { if (token === navToken) { fill(mainEl, view); main = mainEl; } };
  (pages[tab] || overview)().then(done, (e) => { view.append(h("p", { class: "bad" }, String(e.message || e))); done(); });
}
window.addEventListener("hashchange", route);
window.addEventListener("unhandledrejection", (e) => { if (e.reason && e.reason.shown) e.preventDefault(); });

// ---------------- Overview ----------------
async function overview() {
  const s = await api("/api/status");
  const kpi = (n, l) => h("div", { class: "kpi-card" }, h("b", {}, n), h("span", { class: "muted small" }, l));
  main.append(h("div", { class: "kpi-row" }, kpi(s.version, "version"), kpi(s.connectors, "connectors"), kpi(s.auth_mode, "login mode")));
  main.append(section("Models", "brain", h("table", {}, h("tbody", {}, Object.entries(s.roles).map(([r, c]) =>
    h("tr", {}, h("td", {}, r), h("td", {}, c.provider || "ollama"), h("td", { class: "muted" }, c.model || "provider default")))))));
}

// ---------------- Jobs ----------------
async function jobs() {
  const body = h("tbody");
  const load = async () => {
    const rows = await api("/api/jobs");
    fill(body, rows.length ? rows.map((j) => h("tr", {}, h("td", { class: "small" }, when(j.created)), h("td", {}, j.kind),
      h("td", {}, h("span", { class: "badge st-" + j.status }, j.status)), h("td", { class: "small muted" }, j.error || ""),
      h("td", {}, ["queued", "running"].includes(j.status) && h("button", { "data-need": "op", class: "ghost",
        onclick: async () => { await post(`/api/jobs/${j.id}/cancel`); load(); } }, icon("stop"), "Stop"))))
      : h("tr", {}, h("td", { class: "muted" }, "No jobs yet.")));
  };
  await load();
  poll = setInterval(load, 5000);
  main.append(section("Jobs", "progress-clock", h("table", {}, h("thead", {}, h("tr", {}, ["Started", "Kind", "Status", "Error", ""].map((x) => h("th", {}, x)))), body)));
}

// ---------------- Settings ----------------
async function settings() {
  const s = await api("/api/settings/llm");
  const rows = Object.entries(s.roles).map(([r, c]) => {
    const sel = h("select", { "data-role": r }, s.providers.map((p) => h("option", { value: p, selected: p === (c.provider || "ollama") }, p)));
    const model = h("input", { class: "grow", "data-model": r, placeholder: "model (blank = provider default)", value: c.model || "" });
    return h("div", { class: "row" }, h("span", { class: "grow" }, r), sel, model);
  });
  const diff = h("pre", { class: "hidden" });
  const testOut = h("pre", { class: "hidden" });
  const collect = () => Object.fromEntries([...document.querySelectorAll("[data-role]")].map((e) =>
    [e.dataset.role, { provider: e.value, model: $(`[data-model="${e.dataset.role}"]`).value }]));
  main.append(section("Models", "brain", h("p", { class: "muted small" }, "One provider and model per role. Keys stay in .env. Admins only."), rows,
    h("div", { class: "row" }, h("button", { "data-need": "admin", onclick: async () => {
      const p = await api("/api/settings/llm", { roles: collect(), preview: true });
      if (!p.changed) return toast("No changes.");
      diff.textContent = p.diff; diff.classList.remove("hidden");
      if (!confirm("Apply this change to config.yaml?")) return;
      await api("/api/settings/llm", { roles: collect() }); toast("Saved."); diff.classList.add("hidden");
    } }, icon("content-save"), "Save"),
    h("button", { "data-need": "admin", class: "ghost", onclick: async (e) => {
      e.target.disabled = true; testOut.textContent = "Testing each role..."; testOut.classList.remove("hidden");
      try {
        const r = await post("/api/settings/llm/test");
        testOut.textContent = r.map((x) => `${x.ok ? "OK  " : "FAIL"} ${x.role}  ${x.provider}/${x.model}  ${x.ok ? x.ms + " ms" : x.error}`).join("\n");
      } finally { e.target.disabled = false; }
    } }, icon("lan-check"), "Test models")), diff, testOut));
  const doc = h("div");
  main.append(section("Health check", "stethoscope", h("p", { class: "muted small" }, "Checks config, storage, login, models and the organization profile. Admins only."),
    h("button", { "data-need": "admin", class: "ghost", onclick: async (e) => {
      e.target.disabled = true; fill(doc, h("p", { class: "muted" }, "Checking..."));
      try {
        const rows = await api("/api/doctor");
        fill(doc, h("table", { class: "wrap" }, h("tbody", {}, rows.map((r) => h("tr", {}, h("td", {}, h("span", { class: "badge lv-" + r.level }, r.level)),
          h("td", { class: "small" }, r.area), h("td", {}, r.message, r.hint ? h("div", { class: "muted small" }, r.hint) : null))))));
      } finally { e.target.disabled = false; }
    } }, icon("stethoscope"), "Run health check"), doc));
}

meReady.then(route);

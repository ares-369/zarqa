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
  for (const kid of kids.flat(Infinity)) {
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
  const [tab, arg] = (location.hash.slice(1) || "overview").split("/");
  const navTab = { doc: "intel", entity: "entities", add: "intel", inv: "ask" }[tab] || tab;
  document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("on", a.dataset.tab === navTab));
  const pages = { overview, intel, doc: () => docPage(arg), entities, entity: () => entityPage(arg), add, sources,
    ask, inv: () => invPage(arg), brand,
    connectors, jobs, settings };
  const token = ++navToken;
  const view = h("div");
  main = view;
  const done = () => { if (token === navToken) { fill(mainEl, view); main = mainEl; } };
  (pages[tab] || overview)().then(done, (e) => { view.append(h("p", { class: "bad" }, String(e.message || e))); done(); });
}
window.addEventListener("hashchange", route);
window.addEventListener("unhandledrejection", (e) => { if (e.reason && e.reason.shown) e.preventDefault(); });

// ---------------- shared bits ----------------
const TYPE_ICON = { actor: "account-group", malware: "bug", tool: "hammer-wrench", campaign: "flag-variant", technique: "chess-knight",
  cve: "shield-alert-outline", sector: "domain", country: "earth", ipv4: "ip-network", ipv6: "ip-network", domain: "web",
  url: "link-variant", email: "email-outline", md5: "pound", sha1: "pound", sha256: "pound" };
const typeBadge = (t) => h("span", { class: "badge t-" + t }, icon(TYPE_ICON[t] || "tag"), t);
const entLink = (id, label, t) => h("a", { href: `#entity/${id}` }, t ? [typeBadge(t), " "] : null, label);
const ctxBadge = (c) => c ? h("span", { class: "badge c-" + c }, c) : null;
const statusBadge = (s) => h("span", { class: "badge st-" + s }, s);
const kpi = (n, l, href) => h(href ? "a" : "div", { class: "kpi-card", href }, h("b", {}, n), h("span", { class: "muted small" }, l));
const methodBadge = (m) => h("span", { class: "badge small m-" + m.split(" ")[0].replace("+", "-") }, m);

// ---------------- Overview ----------------
async function overview() {
  const [s, st] = await Promise.all([api("/api/status"), api("/api/intel/stats")]);
  const e = st.entities || {};
  const sum = (...ks) => ks.reduce((a, k) => a + (e[k] || 0), 0);
  const docs = Object.values(st.documents || {}).reduce((a, b) => a + b, 0);
  main.append(h("div", { class: "kpi-row" }, kpi(docs, "documents", "#intel"),
    kpi(sum("ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256"), "indicators", "#entities"),
    kpi(sum("actor", "campaign"), "actors and campaigns", "#entities"), kpi(sum("malware", "tool"), "malware and tools", "#entities"),
    kpi(e.cve || 0, "CVEs", "#entities"), kpi(st.relations, "relations", "#entities")));
  const recent = await api("/api/documents?limit=8");
  main.append(section("Latest documents", "newspaper-variant-outline", recent.length ? docTable(recent)
    : h("p", { class: "muted" }, "Nothing collected yet. Add sources in config.yaml (sources:), or add a report.", " ",
      h("a", { href: "#add" }, "Add a report"))));
  main.append(section("Models", "brain", h("table", {}, h("tbody", {}, Object.entries(s.roles).map(([r, c]) =>
    h("tr", {}, h("td", {}, r), h("td", {}, c.provider || "ollama"), h("td", { class: "muted" }, c.model || "provider default")))))));
}

// ---------------- sharing ----------------
let _targets = null;
function shareBox(what) {
  const box = h("span", { class: "row", "data-need": "op" });
  (async () => {
    _targets = _targets || await api("/api/share/targets").catch(() => []);
    if (!_targets.length) return;
    const sel = h("select", {}, _targets.map((t) => h("option", { value: t.name }, `${t.name} (${t.format})`)));
    fill(box, sel, h("button", { class: "ghost", onclick: async (e) => {
      if (!confirm(`Send this to ${sel.value}? It is written to another platform and recorded in the audit log.`)) return;
      e.target.disabled = true;
      try { const r = await post("/api/share", { target: sel.value, ...what }); toast(r.ok ? `Sent ${r.items} items to ${r.target}.` : `Failed: ${r.text}`); }
      finally { e.target.disabled = false; } } }, icon("share-variant"), "Share"));
  })();
  return box;
}

// ---------------- Intel: documents ----------------
const relBadge = (r) => r === null || r === undefined ? h("span", { class: "badge muted", title: "not scored" }, "-")
  : h("span", { class: "badge rel " + (r >= 70 ? "rel-high" : r >= 30 ? "rel-mid" : "rel-low"), title: "relevance to you" }, r);
function docTable(rows) {
  return h("table", { class: "wrap cards" }, h("thead", {}, h("tr", {}, ["Rel.", "Collected", "Title", "Source", "Status"].map((x) => h("th", {}, x)))),
    h("tbody", {}, rows.map((d) => h("tr", {}, h("td", { title: d.relevance_reason || "" }, relBadge(d.relevance)), h("td", { class: "small muted" }, when(d.fetched)),
      h("td", {}, h("a", { href: `#doc/${d.id}` }, d.title || "(untitled)"), d.summary ? h("div", { class: "muted small clamp" }, d.summary) : null,
        d.review ? h("div", { class: "warn small" }, icon("alert-outline"), " ", d.review) : null,
        d.tags.filter((t) => t.startsWith("pir:")).map((t) => h("span", { class: "badge pir" }, t.slice(4)))),
      h("td", { class: "small" }, d.source), h("td", {}, h("span", { class: "badge st-" + d.status }, d.status), " ", d.method ? methodBadge(d.method) : null)))));
}

async function intel() {
  const q = h("input", { class: "grow", placeholder: "Search titles and text" });
  const status = h("select", {}, ["", "new", "extracted", "error"].map((x) => h("option", { value: x }, x || "any status")));
  const order = h("select", {}, [["newest", "newest first"], ["relevance", "most relevant first"]].map(([v, l]) => h("option", { value: v }, l)));
  const box = h("div");
  let offset = 0;
  const load = async () => {
    const rows = await api(`/api/documents?limit=50&offset=${offset}&q=${encodeURIComponent(q.value)}&status=${status.value}&order=${order.value}`);
    fill(box, rows.length ? docTable(rows) : h("p", { class: "muted" }, "No documents."),
      h("div", { class: "row" }, offset > 0 && h("button", { class: "ghost", onclick: () => { offset = Math.max(0, offset - 50); load(); } }, icon("chevron-left"), "Newer"),
        rows.length === 50 && h("button", { class: "ghost", onclick: () => { offset += 50; load(); } }, "Older", icon("chevron-right"))));
  };
  q.addEventListener("keydown", (e) => { if (e.key === "Enter") { offset = 0; load(); } });
  [status, order].forEach((x) => x.addEventListener("change", () => { offset = 0; load(); }));
  main.append(section("Intel", "newspaper-variant-outline", h("div", { class: "row" }, q, status, order,
    h("a", { href: "#add", "data-need": "op" }, h("button", {}, icon("plus"), "Add"))), box));
  await load();
}

async function docPage(id) {
  const d = await api(`/api/documents/${id}`);
  const byType = {};
  d.mentions.forEach((m) => { (byType[m.type] = byType[m.type] || new Map()).set(m.entity_id, m); });
  const ctx = {};
  d.mentions.forEach((m) => { if (m.context) ctx[m.entity_id] = m.context; });
  main.append(section(d.title || "Document", "file-document-outline",
    h("div", { class: "small muted" }, `${d.source} | ${d.kind} | collected ${when(d.fetched)}`, d.published ? ` | published ${d.published}` : ""),
    d.url ? h("div", { class: "small" }, h("a", { href: d.url, rel: "noopener noreferrer", target: "_blank" }, d.url)) : null,
    h("div", { class: "row" }, h("span", { class: "badge st-" + d.status }, d.status), d.method ? methodBadge(d.method) : null,
      h("button", { "data-need": "op", class: "ghost", onclick: async () => { await post(`/api/documents/${id}/process`); toast("Processing; refresh in a moment."); } }, icon("refresh"), "Process again"),
      h("a", { href: `/api/export/stix?document=${id}&download=1` }, h("button", { class: "ghost" }, icon("download"), "STIX")),
      h("a", { href: `/api/export/misp?document=${id}&download=1` }, h("button", { class: "ghost" }, icon("download"), "MISP format")),
      shareBox({ document_id: Number(id) })),
    d.review ? h("p", { class: "warn" }, icon("alert-outline"), " ", d.review) : null,
    d.error ? h("p", { class: "bad small" }, d.error) : null,
    d.summary ? h("p", {}, d.summary, h("span", { class: "muted small" }, "  (model summary)")) : null,
    h("div", { class: "row" }, h("b", {}, "Relevance to you "), relBadge(d.relevance),
      d.tags.filter((t) => t.startsWith("pir:")).map((t) => h("span", { class: "badge pir" }, "requirement " + t.slice(4))),
      h("button", { "data-need": "op", class: "ghost", onclick: async (ev) => { ev.target.disabled = true; try { await post(`/api/documents/${id}/relevance`); route(); } finally { ev.target.disabled = false; } } }, icon("target"), "Score again")),
    d.relevance_reason ? h("ul", { class: "small" }, d.relevance_reason.split("; ").map((x) => h("li", {}, x))) : null));
  const groups = Object.entries(byType).sort();
  main.append(section("Found in this document", "tag-multiple-outline", groups.length ? groups.map(([t, m]) => h("div", { class: "found" },
    h("h3", {}, typeBadge(t), ` ${m.size}`),
    h("table", { class: "wrap cards" }, h("tbody", {}, [...m.values()].slice(0, 300).map((x) => h("tr", {},
      h("td", { class: "val" }, entLink(x.entity_id, x.display)), h("td", {}, ctxBadge(ctx[x.entity_id])),
      h("td", { class: "small muted" }, x.snippet ? `"${x.snippet}"` : ""), h("td", {}, methodBadge(x.method))))))))
    : h("p", { class: "muted" }, "Nothing extracted.")));
  if (d.relations.length) {
    main.append(section("Relations", "graph-outline", h("table", { class: "wrap cards" }, h("tbody", {}, d.relations.map((r) => h("tr", {},
      h("td", {}, entLink(r.src, r.src_display)), h("td", {}, h("b", {}, r.rel.replace(/_/g, " "))), h("td", {}, entLink(r.dst, r.dst_display)),
      h("td", { class: "small muted" }, r.snippet ? `"${r.snippet}"` : "")))))));
  }
  main.append(section("Text", "text-long", h("details", {}, h("summary", {}, "Show the collected text"), h("pre", {}, d.text))));
}

// ---------------- Entities ----------------
async function entities() {
  const types = ["", "actor", "campaign", "malware", "tool", "technique", "cve", "sector", "country", "ipv4", "ipv6", "domain", "url", "email", "sha256", "sha1", "md5"];
  const t = h("select", {}, types.map((x) => h("option", { value: x }, x || "all types")));
  const q = h("input", { class: "grow", placeholder: "Search values and names" });
  const order = h("select", {}, [["last_seen", "recently seen"], ["seen", "most seen"], ["first_seen", "newest"], ["confidence", "confidence"]].map(([v, l]) => h("option", { value: v }, l)));
  const box = h("div");
  const load = async () => {
    const rows = await api(`/api/entities?limit=200&type=${t.value}&q=${encodeURIComponent(q.value)}&order=${order.value}`);
    fill(box, rows.length ? h("table", { class: "wrap cards" }, h("thead", {}, h("tr", {}, ["Type", "Value", "Seen", "First", "Last", "Conf."].map((x) => h("th", {}, x)))),
      h("tbody", {}, rows.map((e) => h("tr", {}, h("td", {}, typeBadge(e.type)), h("td", { class: "val" }, h("a", { href: `#entity/${e.id}` }, e.display)),
        h("td", {}, e.seen_count), h("td", { class: "small muted" }, when(e.first_seen)), h("td", { class: "small muted" }, when(e.last_seen)), h("td", {}, e.confidence)))))
      : h("p", { class: "muted" }, "Nothing found."));
  };
  [t, order].forEach((x) => x.addEventListener("change", load));
  q.addEventListener("keydown", (e) => { if (e.key === "Enter") load(); });
  main.append(section("Entities", "tag-multiple-outline", h("div", { class: "row" }, t, q, order), box));
  await load();
}

async function entityPage(id) {
  const e = await api(`/api/entities/${id}`);
  const a = e.attack;
  main.append(section(e.display, TYPE_ICON[e.type] || "tag",
    h("div", { class: "row" }, typeBadge(e.type), statusBadge(e.status), e.ref ? h("span", { class: "badge" }, "ATT&CK " + e.ref) : null,
      e.tags.map((x) => h("span", { class: "badge" }, x))),
    h("div", { class: "small muted" }, `seen ${e.seen_count} times | first ${when(e.first_seen)} | last ${when(e.last_seen)} | confidence ${e.confidence}`,
      e.expires ? ` | expires ${e.expires.slice(0, 10)}` : ""),
    e.note ? h("p", { class: "small" }, e.note) : null,
    h("div", { class: "row", "data-need": "op" }, [["active", "check"], ["false_positive", "close-circle-outline"], ["allowlisted", "shield-check-outline"]].map(([st, ic]) =>
      e.status !== st && h("button", { class: "ghost", onclick: async () => { const note = st === "active" ? "" : (prompt("Note (why)") || ""); await post(`/api/entities/${id}/status`, { status: st, note }); route(); } }, icon(ic), "Mark " + st.replace("_", " "))))));
  const enrBox = h("div");
  main.append(section("Enrichment", "magnify-plus-outline",
    e.enrichers.length ? h("div", { class: "row", "data-need": "op" }, e.enrichers.map((n) => h("button", { class: "ghost", onclick: async (ev) => {
      ev.target.disabled = true; const r = await post(`/api/entities/${id}/enrich`, { only: n, force: true }); toast(`Looking up with ${n} (job ${r.job_id}); refresh in a moment.`); } }, icon("magnify"), n)))
      : h("p", { class: "muted small" }, "No enricher handles this type. Add enrich: to a connector, or turn on a built-in under enrich.builtin (docs/enrichment.md)."),
    e.enrichments.length ? h("table", { class: "wrap cards" }, h("tbody", {}, e.enrichments.map((x) => h("tr", {},
      h("td", {}, h("b", {}, x.enricher), h("div", { class: "small muted" }, when(x.ts))), h("td", { class: x.ok ? "" : "bad" }, x.summary),
      h("td", {}, h("details", {}, h("summary", {}, "data"), h("pre", {}, typeof x.data === "string" ? x.data : JSON.stringify(x.data, null, 2)))))))) : enrBox));
  if (a && a.n) {
    main.append(section("Known from ATT&CK", "chess-knight", a.a && a.a.length ? h("p", { class: "small" }, "Also called: ", a.a.join(", ")) : null,
      a.tech && a.tech.length ? h("details", {}, h("summary", {}, `${a.tech.length} techniques`), h("ul", { class: "small" }, a.tech.map((x) => h("li", {}, `${x.id} ${x.name}`)))) : null,
      a.sw && a.sw.length ? h("details", {}, h("summary", {}, `${a.sw.length} software`), h("p", { class: "small" }, a.sw.map((x) => x.name).join(", "))) : null));
  } else if (a && a.name) {
    main.append(section("ATT&CK", "chess-knight", h("p", {}, `${a.id} ${a.name}`, h("span", { class: "muted small" }, "  " + a.tactics.join(", ")),
      a.replaced ? h("div", { class: "small muted" }, `${a.replaced} was retired and replaced by ${a.id}`) : null)));
  }
  if (e.relations.length) {
    main.append(section("Relations", "graph-outline", h("table", { class: "wrap cards" }, h("tbody", {}, e.relations.map((r) => h("tr", {},
      h("td", {}, r.src === e.id ? h("b", {}, r.src_display) : entLink(r.src, r.src_display, r.src_type)), h("td", {}, r.rel.replace(/_/g, " ")),
      h("td", {}, r.dst === e.id ? h("b", {}, r.dst_display) : entLink(r.dst, r.dst_display, r.dst_type)),
      h("td", { class: "small muted" }, r.snippet ? `"${r.snippet}" ` : "", h("a", { href: `#doc/${r.document_id}` }, r.title))))))));
  }
  main.append(section("Where it was found", "file-search-outline", e.mentions.length ? h("table", { class: "wrap cards" }, h("tbody", {}, e.mentions.map((m) => h("tr", {},
    h("td", {}, h("a", { href: `#doc/${m.document_id}` }, m.title), h("div", { class: "small muted" }, m.source)),
    h("td", { class: "small" }, m.snippet ? `"${m.snippet}"` : ""), h("td", {}, methodBadge(m.method), " ", ctxBadge(m.context)))))) : h("p", { class: "muted" }, "No mentions.")));
}

// ---------------- Add ----------------
async function add() {
  const text = h("textarea", { placeholder: "Paste a report, advisory or email text. Indicators may be defanged (hxxp, [.])." });
  const title = h("input", { class: "grow", placeholder: "Title (optional)" });
  const url = h("input", { class: "grow", placeholder: "Address of a public page or PDF" });
  const values = h("textarea", { placeholder: "One indicator per line" });
  const stix = h("input", { type: "file", accept: ".json,application/json" });
  const done = (r) => { toast(r.new === false ? "Already stored." : "Added; extraction is running."); if (r.id) location.hash = `#doc/${r.id}`; };
  main.append(section("Add a report", "file-document-plus-outline", text, h("div", { class: "row" }, title,
    h("button", { onclick: async () => done(await post("/api/documents", { text: text.value, title: title.value })) }, icon("plus"), "Add text"))));
  main.append(section("Add from a URL", "link-variant", h("div", { class: "row" }, url,
    h("button", { onclick: async (e) => { e.target.disabled = true; try { done(await post("/api/documents", { url: url.value })); } finally { e.target.disabled = false; } } }, icon("download"), "Fetch"))));
  main.append(section("Add indicators", "format-list-bulleted", values, h("div", { class: "row" },
    h("button", { onclick: async () => { const r = await post("/api/values", { values: values.value.split(/\s+/).filter(Boolean) }); toast(`${r.values} added, ${r.skipped} skipped`); } }, icon("plus"), "Add indicators"))));
  main.append(section("Import a STIX bundle", "code-json", h("div", { class: "row" }, stix,
    h("button", { onclick: async () => { const f = stix.files[0]; if (!f) return toast("Choose a file."); let b;
      try { b = JSON.parse(await f.text()); } catch (e) { return toast("Not valid JSON."); }
      const r = await post("/api/import/stix", b); toast(`${r.indicators} indicators, ${r.entities} entities, ${r.relations} relations`); location.hash = `#doc/${r.document_id}`; } }, icon("upload"), "Import"))));
}

// ---------------- Ask: investigations ----------------
const outcomeBadge = (o) => o ? h("span", { class: "badge o-" + o }, o.replace(/_/g, " ")) : null;
async function ask() {
  const q = h("textarea", { "data-need": "op", placeholder: "Ask a question, for example: what do we know about update-check.example-cdn.net? Which actors target our sector this month, and how do they get in?" });
  main.append(section("Ask", "chat-question-outline", h("p", { class: "muted small" }, "The analyst model searches what Zarqa has collected and your connectors, then answers. Every claim must cite its evidence; claims without it are set aside."),
    q, h("div", { class: "row" }, h("button", { "data-need": "op", onclick: async () => { const r = await post("/api/investigations", { question: q.value }); location.hash = `#inv/${r.id}`; } }, icon("send"), "Investigate"))));
  const rows = await api("/api/investigations");
  main.append(section("Earlier questions", "history", rows.length ? h("table", { class: "wrap cards" }, h("tbody", {}, rows.map((r) => h("tr", {},
    h("td", { class: "small muted" }, when(r.created)), h("td", {}, h("a", { href: `#inv/${r.id}` }, r.question)),
    h("td", {}, r.status === "done" ? outcomeBadge(r.outcome) : statusBadge(r.status)), h("td", {}, r.confidence ?? ""))))) : h("p", { class: "muted" }, "None yet.")));
}

async function invPage(id) {
  const d = await api(`/api/investigations/${id}`);
  const a = d.assessment;
  const stepBox = (s) => h("details", { class: "step " + (s.ok ? "good" : "fail"), id: `E${s.n}` },
    h("summary", {}, h("b", {}, `E${s.n} `), `${s.connector}.${s.tool} `, h("span", { class: "muted small" }, JSON.stringify(s.arguments).slice(0, 160)), s.ok ? "" : h("span", { class: "bad small" }, " failed")),
    s.thought ? h("div", { class: "small muted" }, s.thought) : null, h("pre", {}, s.result));
  const cite = (e) => h("a", { href: "#", class: "cite", onclick: (ev) => { ev.preventDefault(); const el = document.getElementById(e); if (el) { el.open = true; el.scrollIntoView({ block: "center" }); } } }, e);
  main.append(section(d.question, "chat-question-outline", h("div", { class: "row" }, d.status === "done" ? outcomeBadge(d.outcome) : statusBadge(d.status),
    a ? h("span", { class: "badge" }, `confidence ${a.confidence}`) : null, h("span", { class: "small muted" }, `${d.actor || ""} ${when(d.created)}`),
    d.status === "running" && h("button", { "data-need": "op", class: "ghost", onclick: async () => { await post(`/api/investigations/${id}/stop`); route(); } }, icon("stop"), "Stop")),
    d.review ? h("p", { class: "warn" }, icon("alert-outline"), " Text in a result addressed an AI: ", d.review) : null,
    d.error ? h("p", { class: "bad" }, d.error) : null,
    a ? h("p", { class: "answer" }, a.answer) : d.status === "running" ? h("p", { class: "muted" }, icon("progress-clock"), ` Working... ${d.steps.length} step(s) so far.`) : null));
  if (a) {
    main.append(section("Findings", "check-decagram-outline", a.findings.length ? h("ul", {}, a.findings.map((f) => h("li", {}, f.claim, " ", f.evidence.flatMap((e) => [cite(e), " "])))) : h("p", { class: "muted" }, "No supported findings."),
      a.unsupported.length ? h("details", {}, h("summary", {}, `${a.unsupported.length} claim(s) set aside`), h("ul", { class: "small" }, a.unsupported.map((u) => h("li", {}, u.claim, h("span", { class: "muted" }, ` (${u.why})`))))) : null,
      a.gaps.length ? [h("h3", {}, "Gaps"), h("ul", { class: "small" }, a.gaps.map((g) => h("li", {}, g)))] : null,
      a.next_steps.length ? [h("h3", {}, "Next steps"), h("ul", { class: "small" }, a.next_steps.map((g) => h("li", {}, g)))] : null,
      a.checks.length ? h("p", { class: "small muted" }, a.checks.join(" ")) : null));
  }
  main.append(section("Evidence", "file-search-outline", d.steps.length ? d.steps.map(stepBox) : h("p", { class: "muted" }, "No tool calls.")));
  if (d.status === "running") poll = setInterval(async () => { const x = await api(`/api/investigations/${id}`); if (x.status !== "running" || x.steps.length !== d.steps.length) route(); }, 3000);
}

// ---------------- Brand watch ----------------
async function brand() {
  const st = h("select", {}, ["", "new", "reviewing", "benign", "takedown", "closed"].map((x) => h("option", { value: x }, x || "any status")));
  const box = h("div");
  const load = async () => {
    const d = await api(`/api/brand?status=${st.value}`);
    const lr = d.last_run || {};
    fill(box, h("p", { class: "small muted" }, d.watch.length ? `Watching ${d.watch.map((w) => w.domain).join(", ")}. ` : "Nothing to watch: set brand.watch or organization.domains in config.yaml. ",
      lr.finished ? `Last run ${when(lr.finished)}: ${lr.candidates} names checked, ${lr.resolving} resolve, ${lr.new} new.` : "Not run yet.",
      lr.errors ? h("span", { class: "bad" }, " " + lr.errors) : null),
      d.findings.length ? h("table", { class: "wrap cards" }, h("thead", {}, h("tr", {}, ["Score", "Lookalike", "How", "Signals", "Status", ""].map((x) => h("th", {}, x)))),
        h("tbody", {}, d.findings.map((f) => { const ev = f.evidence || {}; const page = ev.page || {}; const r = ev.rdap || {};
          const sig = [r.age_days !== undefined ? `registered ${r.age_days} days ago` : null, ev.mx && ev.mx.length ? "mail servers" : null,
            page.parked ? "parked or for sale" : page.shows_brand && page.shows_brand.length ? "page shows the brand" : null, page.asks_password ? "asks for a password" : null,
            ev.redirects_to_you ? "redirects to your own domain: likely yours" : page.redirects_to ? `redirects to ${page.redirects_to}` : null, page.title ? `title: ${page.title}` : null].filter(Boolean);
          return h("tr", { class: f.resolves ? "" : "muted" }, h("td", {}, relBadge(f.score)),
            h("td", { class: "val" }, f.domain, h("div", { class: "small muted" }, `of ${f.watched}${f.resolves ? "" : " | no longer resolves"}`)),
            h("td", { class: "small" }, f.technique), h("td", { class: "small" }, sig.join("; "), h("div", { class: "muted" }, (ev.ips || []).join(", "))),
            h("td", {}, statusBadge(f.status), f.note ? h("div", { class: "small muted" }, f.note) : null),
            h("td", {}, h("select", { "data-need": "op", onchange: async (e) => { const note = prompt("Note (optional)") || ""; await post(`/api/brand/${f.id}/status`, { status: e.target.value, note }); load(); } },
              ["new", "reviewing", "benign", "takedown", "closed"].map((x) => h("option", { value: x, selected: x === f.status }, x))))); })))
        : h("p", { class: "muted" }, "No lookalikes found yet."));
  };
  st.addEventListener("change", load);
  main.append(section("Brand watch", "shield-search", h("p", { class: "muted small" }, "Lookalike domains of your own: generated, resolved, checked (registration date, the page) and scored. Status is yours to set."),
    h("div", { class: "row" }, st, h("button", { "data-need": "op", onclick: async () => { const r = await post("/api/brand/run"); toast(`Watch started (job ${r.job_id}); it can take a few minutes.`); } }, icon("play"), "Run now")), box));
  await load();
}

// ---------------- Sources ----------------
async function sources() {
  const rows = await api("/api/sources");
  main.append(section("Sources", "rss", h("p", { class: "muted small" }, "Feeds, pages, indicator lists and connector pulls, configured in config.yaml (sources:). Each new item is stored once and extracted."),
    rows.length ? h("table", { class: "wrap cards" }, h("thead", {}, h("tr", {}, ["Name", "Kind", "Every", "Last pull", "Documents", ""].map((x) => h("th", {}, x)))),
      h("tbody", {}, rows.map((s) => h("tr", {}, h("td", {}, h("b", {}, s.name), h("div", { class: "small muted" }, s.url || `${s.connector}/${s.tool}`)),
        h("td", {}, s.kind || "feed"), h("td", {}, s.interval_minutes ? `${s.interval_minutes} min` : "by hand"),
        h("td", { class: "small" }, when(s.state.last_pull) || "never", s.state.last_error ? h("div", { class: "bad small" }, s.state.last_error) : null),
        h("td", {}, s.state.documents || 0),
        h("td", {}, h("button", { "data-need": "op", class: "ghost", onclick: async () => { const r = await post(`/api/sources/${s.name}/pull`); toast("Pull started (job " + r.job_id + ")."); } }, icon("download"), "Pull now"))))))
      : h("p", { class: "muted" }, "No sources yet. Add them under sources: in config.yaml; see docs/collection.md.")));
}

// ---------------- Connectors ----------------
async function connectors() {
  const list = await api("/api/connectors");
  const detail = h("div");
  const showTools = async (name) => {
    fill(detail, h("p", { class: "muted" }, "Loading tools..."));
    const tools = await api(`/api/connectors/${encodeURIComponent(name)}/tools?refresh=1`);
    fill(detail, h("h2", {}, icon("tools"), `Tools of ${name}`), h("table", { class: "wrap cards" }, h("tbody", {}, tools.map((t) =>
      h("tr", {}, h("td", {}, h("span", { class: "badge " + (t.allowed ? "lv-OK" : "lv-WARN") }, t.allowed ? "allowed" : "blocked")),
        h("td", {}, t.name, h("div", { class: "muted small clamp", title: t.description }, t.description)), h("td", { class: "small muted" }, t.reason))))));
  };
  const rows = list.map((c) => {
    const res = h("span", { class: "small muted" });
    return h("tr", {}, h("td", {}, h("b", {}, c.name), h("div", { class: "muted small" }, c.description || "")),
      h("td", {}, c.roles.map((r) => h("span", { class: "badge" }, r.replace("_", " ")))),
      h("td", { class: "small" }, c.transport, c.allow_write ? h("div", { class: "warn small" }, "writes allowed") : null),
      h("td", {}, c.enabled ? "on" : h("span", { class: "muted" }, "off")),
      h("td", {}, h("div", { class: "row" },
        h("button", { "data-need": "admin", class: "ghost", onclick: async (e) => {
          e.target.disabled = true; res.textContent = "testing...";
          try { const r = await post(`/api/connectors/${encodeURIComponent(c.name)}/test`);
            res.className = "small " + (r.ok ? "ok" : "bad");
            res.textContent = r.ok ? `ok, ${r.allowed}/${r.tools} tools, ${r.ms} ms` : r.error;
          } finally { e.target.disabled = false; } } }, icon("lan-check"), "Test"),
        h("button", { "data-need": "admin", class: "ghost", onclick: () => showTools(c.name) }, icon("tools"), "Tools")), res));
  });
  main.append(section("Connectors", "connection",
    h("p", { class: "muted small" }, "Other intel platforms, enrichment and search services, each an MCP server with roles. Read-only unless a connector allows writes. Configured in config.yaml (connectors:)."),
    list.length ? h("table", { class: "wrap cards" }, h("thead", {}, h("tr", {}, ["Name", "Roles", "Transport", "", ""].map((x) => h("th", {}, x)))), h("tbody", {}, rows))
      : h("p", { class: "muted" }, "No connectors yet. Add them under connectors: in config.yaml; see docs/connectors.md.")));
  main.append(h("section", {}, detail));
  const audit = h("div", {}, h("button", { "data-need": "admin", class: "ghost", onclick: async () => {
    const [rows, chain] = await Promise.all([api("/api/audit?limit=100"), api("/api/audit/verify")]);
    fill(audit, h("p", { class: "small " + (chain.ok ? "ok" : "bad") }, chain.ok ? `Hash chain intact (${chain.rows_checked} rows).` : `Hash chain broken at row ${(chain.broken[0] || {}).id}: ${(chain.broken[0] || {}).problem || ""}`),
      h("table", { class: "wrap cards" }, h("thead", {}, h("tr", {}, ["Time", "Who", "Connector", "Tool", "Status", "Decision", "ms"].map((x) => h("th", {}, x)))),
        h("tbody", {}, rows.map((r) => h("tr", {}, h("td", { class: "small" }, when(r.ts)), h("td", { class: "small" }, r.actor || ""), h("td", {}, r.connector),
          h("td", {}, r.tool), h("td", {}, h("span", { class: ["ok", "shared"].includes(r.status) ? "ok" : "bad" }, r.status)),
          h("td", { class: "small muted" }, r.decision), h("td", {}, r.duration_ms))))));
  } }, icon("clipboard-text-clock"), "Show audit log"));
  main.append(section("Audit log", "clipboard-text-clock", h("p", { class: "muted small" }, "Every connector call, allowed or blocked, in an append-only log with a hash chain. Admins only."), audit));
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

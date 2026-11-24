// Shared frame: rail, bottom bar, theme, stacked tables and the assistant panel.
// The same file is used by OniOps, Actaeon and Zarqa; each page's own script sets window.SUITE before or after it loads.
"use strict";
(() => {
  const $ = (id) => document.getElementById(id), root = document.documentElement;
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text) e.textContent = text; return e; };
  const store = { get: (k) => { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set: (k, v) => { try { localStorage.setItem(k, v); } catch (e) { /* private window */ } } };
  const shell = $("shell") || $("appShell"), rail = shell.querySelector(".rail"), menu = $("menuBtn");
  const small = () => window.matchMedia("(max-width: 1024px)").matches;

  // Rail: closed by default; the menu button pins it open and the choice is remembered.
  const pin = (on) => { shell.classList.toggle("pinned", on); menu.setAttribute("aria-expanded", String(on));
    menu.title = on ? "Close the sidebar" : "Keep the sidebar open"; };
  pin(store.get("suite_rail") === "open");
  menu.addEventListener("click", () => { const on = !shell.classList.contains("pinned"); pin(on); store.set("suite_rail", on ? "open" : "closed"); });
  const closeNav = () => shell.classList.remove("nav-open");
  $("scrim").addEventListener("click", closeNav);

  // Bottom bar on phones: the four main pages and everything else under More.
  const items = [...rail.querySelectorAll("[data-tab],[data-view]")];
  const key = (i) => i.dataset.tab || i.dataset.view, label = (i) => i.querySelector(".lbl,.nav-label").textContent.trim();
  const isOn = (i) => i.classList.contains("on") || i.classList.contains("active");
  const bar = el("nav", "bottombar"); bar.setAttribute("aria-label", "Main pages");
  const quick = (bar.dataset.keys = document.body.dataset.quick || "").split(" ").map((k) => items.find((i) => key(i) === k)).filter(Boolean);
  const tabs = quick.map((i) => { const b = el("button"); b.type = "button";
    b.append(el("span", i.querySelector(".mdi").className), el("span", "", label(i)));
    b.addEventListener("click", () => { closeNav(); i.click(); window.scrollTo(0, 0); }); bar.append(b); return [i, b]; });
  const more = el("button"); more.type = "button"; more.id = "moreBtn"; more.setAttribute("aria-expanded", "false");
  more.append(el("span", "mdi mdi-menu"), el("span", "", "More"));
  more.addEventListener("click", () => more.setAttribute("aria-expanded", String(shell.classList.toggle("nav-open"))));
  bar.append(more); document.body.append(bar);
  const sync = () => {
    const on = items.find(isOn);
    items.forEach((i) => i === on ? i.setAttribute("aria-current", "page") : i.removeAttribute("aria-current"));
    tabs.forEach(([i, b]) => b.classList.toggle("on", i === on));
    more.classList.toggle("on", !!on && !quick.includes(on));
    if (on && $("pageTitle").textContent !== label(on)) { $("pageTitle").textContent = label(on); document.title = label(on) + " - " + (document.body.dataset.name || ""); }
  };
  items.forEach((i) => { i.title = label(i); i.addEventListener("click", () => { closeNav(); rail.classList.add("hush"); }); });
  rail.addEventListener("mouseleave", () => rail.classList.remove("hush"));   // opened by hover: closes once a page is chosen
  new MutationObserver(sync).observe(rail, { subtree: true, attributes: true, attributeFilter: ["class"] });

  // Theme
  const themeBtn = $("themeBtn");
  const paint = () => { themeBtn.firstElementChild.className = root.dataset.theme === "light" ? "mdi mdi-white-balance-sunny" : "mdi mdi-weather-night"; };
  themeBtn.addEventListener("click", () => { root.dataset.theme = root.dataset.theme === "light" ? "dark" : "light"; store.set("suite_theme", root.dataset.theme); paint(); });

  // Keyboard users can jump over the rail.
  const main0 = document.querySelector("main"); main0.id = main0.id || "content"; main0.tabIndex = -1;
  const skip = el("a", "skip-link", "Skip to content"); skip.href = "#" + main0.id;
  skip.addEventListener("click", (e) => { e.preventDefault(); main0.focus(); }); document.body.prepend(skip);

  // Anything slower than a moment shows a thin bar; the button that started it cannot be pressed twice.
  const busy = el("div", "busybar"); document.body.append(busy);
  let open0 = 0, lastBtn = null, lastAt = 0;
  document.addEventListener("click", (e) => { lastBtn = e.target.closest("main button, .ai-drawer button"); lastAt = performance.now(); }, true);
  const fetch0 = window.fetch.bind(window);
  window.fetch = (url, opt) => {
    const write = opt && opt.method && opt.method !== "GET", btn = write && lastBtn && performance.now() - lastAt < 80 ? lastBtn : null;
    if (btn) { btn.classList.add("busy"); btn.setAttribute("aria-busy", "true"); }
    const slow = setTimeout(() => { open0++; busy.classList.add("on"); slowOn = true; }, 350); let slowOn = false;
    return fetch0(url, opt).finally(() => { clearTimeout(slow); if (slowOn && --open0 === 0) busy.classList.remove("on");
      if (btn) { btn.classList.remove("busy"); btn.removeAttribute("aria-busy"); } });
  };

  // Names for controls that only have a placeholder, a title or a nearby heading; rows that open something work with Enter.
  const nameOf = (e) => e.title || e.placeholder || (e.type === "file" ? "Choose a file" : "") ||
    (e.tagName === "SELECT" && e.options[0] ? "Choose: " + e.options[0].text : "") ||
    (e.closest("section,.panel") && (e.closest("section,.panel").querySelector("h2,.panel-title") || {}).textContent || "").trim();
  const label0 = (root0) => {
    root0.querySelectorAll("input,select,textarea").forEach((e) => { if (e.type === "hidden" || e.getAttribute("aria-label") || e.labels.length) return; const n = nameOf(e); if (n) e.setAttribute("aria-label", n); });
    root0.querySelectorAll(".mdi:not([aria-hidden])").forEach((e) => e.setAttribute("aria-hidden", "true"));
    root0.querySelectorAll("button").forEach((b) => { if (b.textContent.trim() || b.getAttribute("aria-label")) return;
      const n = b.title || (b.querySelector(".mdi-magnify") ? "Search" : b.querySelector(".mdi-close,.mdi-delete,.mdi-delete-outline,.mdi-archive") ? "Remove" : ""); if (n) b.setAttribute("aria-label", n); });
    root0.querySelectorAll("tr.click,tr.f-row-click").forEach((r) => { if (r.tabIndex >= 0) return; r.tabIndex = 0;
      r.addEventListener("keydown", (e) => { if (e.target === r && e.key === "Enter") r.click(); }); });
    root0.querySelectorAll("th").forEach((t) => { if (!t.textContent.trim() && !t.querySelector("*")) { const s = el("span", "sr-only", "Actions"); s.dataset.sr = "1"; t.append(s); } });
  };

  // Sorting: press a column heading. Understands numbers, dates, ages ("4 h ago") and severity words.
  const SEV = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }, UNIT = { s: 1, sec: 1, min: 60, h: 3600, d: 86400 };
  const val = (cell) => { const t = (cell ? cell.textContent : "").trim().toLowerCase(), w = t.split(/\s+/)[0]; if (!t || t === "-") return null;
    if (w in SEV) return SEV[w]; const a = t.match(/^([\d.]+) (s|sec|min|h|d)\w* ago/); if (a) return +a[1] * UNIT[a[2]];
    if (/^\d{4}-\d\d-\d\d/.test(t)) return t; const n = t.match(/^#?(-?\d+(\.\d+)?)%?( |$)/); return n ? +n[1] : t; };
  const sortBody = (t) => { const s = t._sort; if (!s) return; [...t.tBodies].forEach((b) => {
    const rows = [...b.rows]; if (rows.some((r) => r.cells.length !== t.tHead.rows[0].cells.length)) return;
    const next = rows.map((r, i) => [val(r.cells[s.col]), i, r]).sort((x, y) => x[0] === null ? (y[0] === null ? x[1] - y[1] : 1) : y[0] === null ? -1
      : (typeof x[0] === typeof y[0] ? (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0) : typeof x[0] === "number" ? -1 : 1) * s.dir || x[1] - y[1]);
    if (next.some((n, i) => n[1] !== i)) b.append(...next.map((n) => n[2])); }); };
  const sortable = (t) => { if (!t.tHead || t._sortable) return; t._sortable = true;
    [...t.tHead.rows[0].cells].forEach((th, i) => { const name = th.textContent.trim(); if (!name || name === "Actions" || /^(action|view|assess|zero-token retest)$/i.test(name)) return;
      const b = el("button", "thsort", name); b.type = "button"; if (th.title) b.title = th.title; th.replaceChildren(b);
      b.addEventListener("click", () => { const dir = t._sort && t._sort.col === i ? -t._sort.dir : 1; t._sort = { col: i, dir };
        [...t.tHead.rows[0].cells].forEach((x) => x.removeAttribute("aria-sort")); th.setAttribute("aria-sort", dir > 0 ? "ascending" : "descending"); sortBody(t); }); }); };

  // Tables: copy each column heading to its cells, so phones can show rows as records.
  const main = document.querySelector("main");
  const mark = () => main.querySelectorAll("table").forEach((t) => {
    const heads = t.tHead ? [...t.tHead.rows[0].cells].map((c) => c.querySelector("[data-sr]") ? "" : c.textContent.trim()) : [];
    if (!t.classList.contains("stack")) t.classList.add("stack");
    sortable(t); sortBody(t);
    [...t.tBodies].forEach((b) => [...b.rows].forEach((r) => { if (r.dataset.st) return; r.dataset.st = "1";
      [...r.cells].forEach((c, i) => { if (c.colSpan > 1 || !heads[i]) return;
        c.dataset.label = heads[i]; const box = el("div", "cellbox"); while (c.firstChild) box.append(c.firstChild); if (box.childNodes.length) c.append(box); else c.removeAttribute("data-label"); }); }));
  });
  let queued = false;
  new MutationObserver(() => { if (queued) return; queued = true; requestAnimationFrame(() => { queued = false; label0(document.body); mark(); }); }).observe(main, { childList: true, subtree: true });

  // Assistant panel
  const drawer = $("aiDrawer"), botBtn = $("drawerToggle");
  const open = (on) => { drawer.classList.toggle("closed", !on); botBtn.setAttribute("aria-expanded", String(on));
    if (on) { closeNav(); drawer.querySelector("textarea,input").focus(); } else if (drawer.contains(document.activeElement)) botBtn.focus(); };
  const toggle = () => open(drawer.classList.contains("closed"));
  window.toggleDrawer = toggle;
  botBtn.addEventListener("click", toggle);
  const x = $("drawerClose"); if (x) x.addEventListener("click", () => open(false));
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey && e.key.toLowerCase() === "i") { e.preventDefault(); toggle(); }
    if (e.key !== "Escape") return;
    if (shell.classList.contains("nav-open")) { closeNav(); more.focus(); } else if (!drawer.classList.contains("closed") && drawer.contains(document.activeElement)) open(false);
  });

  // Actaeon and Zarqa give the panel a SUITE_BOT: { intro, tries, send(text, state) -> {text, links, done}, poll(state) }
  const bot = window.SUITE_BOT;
  if (bot) {
    const log = $("chatMessages"), input = $("chatInput"), sendBtn = $("chatSend");
    const say = (who, text, links) => { const b = el("div", "chat-bubble pre " + who, text);
      (links || []).forEach(([href, t]) => { const a = el("a", "", t); a.href = href; a.addEventListener("click", () => { if (small()) open(false); }); b.append(a); });
      log.append(b); log.scrollTop = log.scrollHeight; return b; };
    let state = {}, busy = false;
    const start = () => { state = {}; log.replaceChildren(); say("assistant", bot.intro); const box = el("div", "drawer-tries");
      bot.tries.forEach((t) => { const b = el("button", "", t); b.type = "button"; b.addEventListener("click", () => { input.value = t; send(); }); box.append(b); }); log.append(box); };
    const send = async () => {
      const text = input.value.trim(); if (!text || busy) return;
      busy = true; sendBtn.disabled = true; input.value = ""; say("user", text);
      const wait = say("assistant", "Working on it...");
      try {
        const mine = state; let r = await bot.send(text, mine);
        for (let i = 0; i < 300 && r && !r.done; i++) { await new Promise((k) => setTimeout(k, 2000)); if (state !== mine) return; r = await bot.poll(mine); if (r && r.note) wait.textContent = r.note; }
        wait.remove();
        say("assistant", r && r.done ? r.text : "No answer yet. It is still running; check back on the Ask page.", r && r.links);
      } catch (e) { wait.textContent = "That did not work: " + (e.message || e); } finally { busy = false; sendBtn.disabled = false; }
    };
    sendBtn.addEventListener("click", send);
    input.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); send(); } });
    $("chatNew").addEventListener("click", () => { if (!busy) { start(); input.focus(); } });
    start();
  }
  paint(); sync(); label0(document.body); mark();
})();

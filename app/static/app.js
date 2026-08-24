"use strict";
// Frontend dynamique de VulnTrack (etape 13).
// - Recupere les donnees en JSON depuis /ui/api/* (cookie de session).
// - Construit le DOM via textContent : aucune donnee n'est injectee en HTML,
//   donc pas de XSS possible depuis un titre de finding.
// - Graphiques en SVG (attributs de presentation), compatibles CSP stricte.

(function () {
  // Theme clair/sombre : preference persistee (localStorage, same-origin donc
  // compatible CSP stricte). Applique tot pour limiter le flash au chargement.
  (function initTheme() {
    const KEY = "vt-theme";
    const root = document.documentElement;
    const apply = (t) => t === "light" ? root.setAttribute("data-theme", "light") : root.removeAttribute("data-theme");
    let saved = null;
    try { saved = localStorage.getItem(KEY); } catch (e) { /* stockage indispo */ }
    apply(saved);
    const wire = () => {
      const btn = document.getElementById("theme-toggle");
      if (!btn) return;
      btn.addEventListener("click", () => {
        let cur = null;
        try { cur = localStorage.getItem(KEY); } catch (e) { /* ignore */ }
        const next = cur === "light" ? "dark" : "light";
        try { localStorage.setItem(KEY, next); } catch (e) { /* ignore */ }
        apply(next);
      });
    };
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", wire);
    else wire();
  })();

  const SEVERITIES = ["critical", "high", "medium", "low", "info"];
  const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const SEV_LABEL = {
    critical: "Critique", high: "Élevée", medium: "Moyenne", low: "Faible", info: "Info",
  };
  const STATUS_LABEL = {
    open: "Ouvert", in_progress: "En cours", fixed: "Corrigé",
    accepted: "Accepté", false_positive: "Faux positif",
  };

  // -------------------------------------------------------------- utilitaires

  function el(tag, opts, children) {
    const node = document.createElement(tag);
    opts = opts || {};
    if (opts.class) node.className = opts.class;
    if (opts.text != null) node.textContent = opts.text;
    if (opts.href) node.href = opts.href;
    if (opts.type) node.type = opts.type;
    if (opts.attrs) for (const k in opts.attrs) node.setAttribute(k, opts.attrs[k]);
    if (opts.on) for (const ev in opts.on) node.addEventListener(ev, opts.on[ev]);
    (children || []).forEach((c) => c != null && node.appendChild(c));
    return node;
  }

  function svg(tag, attrs) {
    const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const k in attrs) node.setAttribute(k, attrs[k]);
    return node;
  }

  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function byId(id) { return document.getElementById(id); }

  async function api(path) {
    const res = await fetch(path, { credentials: "same-origin", headers: { Accept: "application/json" } });
    if (res.status === 401) { window.location.href = "/ui/login"; throw new Error("session expiree"); }
    if (!res.ok) throw new Error("Erreur " + res.status);
    return res.json();
  }

  function csrfToken() {
    const m = document.cookie.match(/(?:^|; )vulntrack_csrf=([^;]+)/);
    return m ? decodeURIComponent(m[1]) : "";
  }

  async function apiSend(method, path, body) {
    const res = await fetch(path, {
      method, credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json", "X-CSRF-Token": csrfToken() },
      body: body != null ? JSON.stringify(body) : undefined,
    });
    if (res.status === 401) { window.location.href = "/ui/login"; throw new Error("session expiree"); }
    if (!res.ok) {
      let detail = "Erreur " + res.status;
      try { const j = await res.json(); if (j.detail) detail = typeof j.detail === "string" ? j.detail : "Requête invalide"; } catch (e) { /* ignore */ }
      throw new Error(detail);
    }
    return res.json();
  }

  let toastTimer = null;
  function toast(msg, kind) {
    const t = byId("toast");
    if (!t) return;
    t.textContent = msg;
    t.className = "toast" + (kind ? " toast-" + kind : "");
    t.hidden = false;
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.hidden = true; }, 3200);
  }

  function debounce(fn, ms) {
    let h; return function () { clearTimeout(h); const a = arguments, self = this; h = setTimeout(() => fn.apply(self, a), ms); };
  }

  // Animation "compteur qui monte" pour donner vie aux chiffres.
  function countUp(node, target, dur) {
    target = Number(target) || 0;
    if (target <= 0) { node.textContent = "0"; return; }
    dur = dur || 700;
    const start = performance.now();
    function step(t) {
      const p = Math.min(1, (t - start) / dur);
      const eased = 1 - Math.pow(1 - p, 3);
      node.textContent = String(Math.round(target * eased));
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  function sevBadge(sev) { return el("span", { class: "sev sev-" + sev, text: SEV_LABEL[sev] || sev }); }
  function statusBadge(s) { return el("span", { class: "status status-" + s, text: STATUS_LABEL[s] || s }); }

  const RISK_LABEL = { critical: "Critique", high: "Élevé", medium: "Moyen", low: "Faible" };
  const CRIT_LABEL = { crown: "Joyau", high: "Haute", medium: "Moyenne", low: "Faible" };
  function kevBadge() { return el("span", { class: "kev-badge", text: "KEV", attrs: { title: "CISA KEV : activement exploitée" } }); }
  function overdueBadge() { return el("span", { class: "overdue-badge", text: "En retard", attrs: { title: "SLA de remédiation dépassé" } }); }
  function riskBadge(score, band) {
    return el("span", { class: "risk-badge risk-" + (band || "low"), text: String(score), attrs: { title: "Score de risque : " + score + "/100" } });
  }
  function critPill(crit) { return el("span", { class: "crit-pill crit-" + crit, text: CRIT_LABEL[crit] || crit }); }

  function empty(msg) { return el("p", { class: "empty", text: msg || "Aucune donnée." }); }

  // -------------------------------------------------------------- graphiques

  // Anneau (donut) : un cercle par severite (stroke-dasharray).
  function donut(counts, total) {
    const s = svg("svg", { viewBox: "0 0 42 42", class: "donut", role: "img" });
    const R = 15.915;
    s.appendChild(svg("circle", { class: "donut-track", cx: 21, cy: 21, r: R, fill: "none", "stroke-width": 4 }));
    let offset = 25;
    if (total > 0) {
      SEVERITIES.forEach((sev) => {
        const n = counts[sev] || 0;
        if (!n) return;
        const pct = (n / total) * 100;
        const seg = svg("circle", {
          class: "donut-seg sev-stroke-" + sev, cx: 21, cy: 21, r: R, fill: "none", "stroke-width": 4,
          "stroke-dasharray": pct.toFixed(3) + " " + (100 - pct).toFixed(3), "stroke-dashoffset": offset.toFixed(3),
        });
        seg.appendChild(svgTitle(SEV_LABEL[sev] + " : " + n + " (" + Math.round(pct) + "%)"));
        s.appendChild(seg);
        offset -= pct;
      });
    }
    const totalEl = el("span", { class: "donut-total", text: "0" });
    countUp(totalEl, total);
    return el("div", { class: "donut-inner" }, [
      s, el("div", { class: "donut-center" }, [
        totalEl,
        el("span", { class: "donut-label", text: "ouvertes" }),
      ]),
    ]);
  }

  // Liste de barres horizontales. items: [{label, value, cls, badge, href, tip}]
  function hbars(items) {
    if (!items.length) return empty();
    const max = Math.max(1, ...items.map((i) => i.value));
    const wrap = el("div", { class: "hbars" });
    items.forEach((it) => {
      const pct = (it.value / max) * 100;
      const bar = svg("svg", { viewBox: "0 0 100 8", preserveAspectRatio: "none", class: "hbar" });
      bar.appendChild(svg("rect", { class: "hbar-track", x: 0, y: 0, width: 100, height: 8, rx: 4 }));
      const fill = svg("rect", { class: it.cls || "hbar-fill", x: 0, y: 0, width: pct.toFixed(2), height: 8, rx: 4 });
      fill.appendChild(svgTitle(it.tip || (it.label + " : " + it.value)));
      bar.appendChild(fill);
      const kids = [
        it.badge ? it.badge : el("span", { class: "hbar-label", text: it.label }),
        bar,
        el("span", { class: "hbar-val", text: String(it.value) }),
      ];
      wrap.appendChild(it.href
        ? el("a", { class: "hbar-row hbar-link", href: it.href }, kids)
        : el("div", { class: "hbar-row" }, kids));
    });
    return wrap;
  }

  function svgTitle(text) {
    const t = document.createElementNS("http://www.w3.org/2000/svg", "title");
    t.textContent = text;
    return t;
  }

  function findingsHref(params) {
    const p = new URLSearchParams();
    Object.keys(params).forEach((key) => {
      const v = params[key];
      if (Array.isArray(v)) v.forEach((x) => p.append(key, x));
      else if (v != null) p.append(key, v);
    });
    return "/ui/findings?" + p.toString();
  }

  // Histogramme temporel : barres verticales (rects, non deformes par
  // preserveAspectRatio none) + libelles de dates en HTML dessous.
  function timelineChart(series) {
    if (!series.length) return empty("Pas encore de découvertes.");
    const max = Math.max(1, ...series.map((s) => s.count));
    const n = series.length;
    const slot = 100 / n;
    const bw = Math.min(slot * 0.6, 6);
    const s = svg("svg", { viewBox: "0 0 100 40", preserveAspectRatio: "none", class: "timeline" });
    series.forEach((pt, i) => {
      const h = (pt.count / max) * 36;
      const r = svg("rect", {
        class: "timeline-bar", x: (i * slot + (slot - bw) / 2).toFixed(2), y: (40 - h).toFixed(2),
        width: bw.toFixed(2), height: h.toFixed(2), rx: 0.6,
      });
      r.appendChild(svgTitle(pt.date + " : " + pt.count + " découverte(s)"));
      s.appendChild(r);
    });
    // Libelles : premiere, milieu, derniere date.
    const idxs = n === 1 ? [0] : [0, Math.floor(n / 2), n - 1];
    const labels = el("div", { class: "timeline-axis" },
      idxs.map((i) => el("span", { text: series[i].date })));
    return el("div", {}, [s, labels]);
  }

  // Histogramme empile par severite dans le temps (facon Grafana).
  function stackedTimeline(series) {
    if (!series.length) return empty("Pas encore de découvertes.");
    const totals = series.map((d) => SEVERITIES.reduce((s, sev) => s + (d[sev] || 0), 0));
    const max = Math.max(1, ...totals);
    const n = series.length;
    const slot = 100 / n;
    const bw = Math.min(slot * 0.64, 5);
    const s = svg("svg", { viewBox: "0 0 100 42", preserveAspectRatio: "none", class: "timeline" });
    series.forEach((d, i) => {
      let yTop = 42;
      const x = i * slot + (slot - bw) / 2;
      SEVERITIES.forEach((sev) => {
        const v = d[sev] || 0;
        if (!v) return;
        const h = (v / max) * 40;
        yTop -= h;
        const r = svg("rect", { class: "tl-seg sev-fill-" + sev, x: x.toFixed(2), y: yTop.toFixed(2), width: bw.toFixed(2), height: h.toFixed(2) });
        r.appendChild(svgTitle(d.date + " · " + SEV_LABEL[sev] + " : " + v));
        s.appendChild(r);
      });
    });
    const idxs = n === 1 ? [0] : [0, Math.floor(n / 2), n - 1];
    const axis = el("div", { class: "timeline-axis" }, idxs.map((i) => el("span", { text: series[i].date })));
    const legend = el("div", { class: "bar-legend" },
      SEVERITIES.map((sev) => el("span", { class: "bar-legend-item" }, [
        el("span", { class: "dot sev-bg-" + sev }), el("span", { text: SEV_LABEL[sev] }),
      ])));
    return el("div", {}, [s, axis, legend]);
  }

  function kpi(value, label, tone, href) {
    const valEl = el("span", { class: "kpi-value", text: "0" });
    countUp(valEl, value);
    const inner = [valEl, el("span", { class: "kpi-label", text: label })];
    if (href) return el("a", { class: "kpi kpi-link kpi-" + (tone || "default"), href }, inner);
    return el("div", { class: "kpi kpi-" + (tone || "default") }, inner);
  }

  function epssCell(score) {
    if (score == null) return el("span", { class: "muted", text: "—" });
    const cls = score >= 0.5 ? "epss epss-high" : score >= 0.1 ? "epss epss-mid" : "epss";
    return el("span", { class: cls, text: score.toFixed(2) });
  }

  function th(label, opts) { return el("th", opts || {}, [document.createTextNode(label)]); }

  // -------------------------------------------------------------- page overview

  async function renderOverview() {
    let d;
    try { d = await api("/ui/api/overview"); }
    catch (e) { return toast("Impossible de charger les données : " + e.message); }

    // KPI — chaque tuile amene vers la liste filtree correspondante.
    const kpis = byId("kpis"); clear(kpis);
    kpis.appendChild(kpi(d.totals.assets, "Assets", "default", "/ui/findings"));
    kpis.appendChild(kpi(d.totals.open, "Findings ouverts", "default", findingsHref({ status: "open" })));
    kpis.appendChild(kpi(d.totals.critical_open, "Critiques ouverts", "critical", findingsHref({ severity: "critical", status: "open" })));
    kpis.appendChild(kpi(d.totals.high_open, "Élevés ouverts", "high", findingsHref({ severity: "high", status: "open" })));
    kpis.appendChild(kpi(d.totals.kev_open || 0, "KEV (exploitées)", "critical", findingsHref({ kev: "true", status: "open" })));
    kpis.appendChild(kpi(d.totals.overdue_open || 0, "SLA dépassé", "high", "/ui/posture"));
    kpis.appendChild(kpi(d.totals.exploitable_open, "Exploitables (EPSS≥.5)", "critical", findingsHref({ min_epss: "0.5", status: "open" })));
    kpis.appendChild(kpi(d.totals.fixed, "Corrigés", "low", findingsHref({ status: "fixed" })));

    // Donut severite + legende
    const donutHost = byId("donut"); clear(donutHost);
    donutHost.appendChild(donut(d.open_by_severity, d.totals.open));
    const legend = byId("severity-legend"); clear(legend);
    SEVERITIES.forEach((sev) => {
      const n = d.open_by_severity[sev] || 0;
      const inner = [
        el("span", { class: "dot sev-bg-" + sev }),
        el("span", { class: "legend-name", text: SEV_LABEL[sev] }),
        el("span", { class: "legend-val", text: String(n) }),
      ];
      legend.appendChild(el("li", {}, [
        n ? el("a", { class: "legend-item legend-link", href: findingsHref({ severity: sev, status: "open" }) }, inner)
          : el("span", { class: "legend-item" }, inner),
      ]));
    });

    // Cycle de vie (statuts) — clic = liste filtree par statut.
    const lifeHost = byId("lifecycle"); clear(lifeHost);
    const statusItems = Object.keys(d.by_status).sort().map((st) => ({
      label: STATUS_LABEL[st] || st, value: d.by_status[st], cls: "hbar-fill status-fill-" + st,
      badge: statusBadge(st), href: findingsHref({ status: st }), tip: (STATUS_LABEL[st] || st) + " : " + d.by_status[st],
    }));
    lifeHost.appendChild(hbars(statusItems));

    // Scanner breakdown — clic = liste filtree par scanner (ouverts).
    const scanHost = byId("scanner-breakdown"); clear(scanHost);
    const scanItems = Object.keys(d.by_scanner).sort().map((sc) => ({
      label: sc, value: d.by_scanner[sc], cls: "hbar-fill",
      href: findingsHref({ scanner: sc, status: "open" }), tip: sc + " : " + d.by_scanner[sc],
    }));
    scanHost.appendChild(scanItems.length ? hbars(scanItems) : empty("Aucun finding ouvert."));

    // Timeline empilee par severite
    const tl = byId("timeline-chart"); clear(tl);
    tl.appendChild(stackedTimeline(d.timeline_sev || []));

    // Top assets a risque
    const ta = byId("top-assets"); clear(ta);
    if (!d.top_assets.length) ta.appendChild(empty("Aucun asset à risque."));
    else ta.appendChild(hbars(d.top_assets.map((a) => ({
      value: a.open, cls: "hbar-fill sev-fill-" + (a.worst || "info"),
      badge: el("a", { class: "hbar-label link", href: "/ui/assets/" + a.id, text: a.name }),
      tip: a.name + " : " + a.open + " ouverts (" + a.critical + " crit., " + a.high + " élevés)",
    }))));

    // A prioriser
    renderPrioritize(byId("prioritize"), d.prioritize);

    // Top CVE
    renderTopCves(byId("top-cves"), d.top_cves);

    // Activite recente
    renderRecentScans(byId("recent-scans"), d.recent_scans);

    // Assets (recherche)
    const search = byId("asset-search");
    const host = byId("assets-table");
    const draw = () => renderAssetsTable(host, d.assets, search.value.trim().toLowerCase());
    search.addEventListener("input", draw);
    draw();
  }

  function renderPrioritize(host, rows) {
    clear(host);
    if (!rows.length) { host.appendChild(empty("Rien d'urgent. 🎉")); return; }
    const table = el("table", { class: "grid compact" }, [
      el("thead", {}, [el("tr", {}, [th("Sév."), th("Vulnérabilité"), th("Asset"), th("CVE"), th("EPSS")])]),
    ]);
    const tb = el("tbody");
    rows.forEach((f) => {
      tb.appendChild(el("tr", {}, [
        el("td", {}, [sevBadge(f.severity)]),
        el("td", { class: "title", text: f.title }),
        el("td", {}, [el("a", { class: "link", href: "/ui/assets/" + f.asset_id, text: f.asset_name })]),
        el("td", { class: "ref", text: f.cve || "—" }),
        el("td", {}, [epssCell(f.epss_score)]),
      ]));
    });
    table.appendChild(tb);
    host.appendChild(table);
  }

  function renderTopCves(host, rows) {
    clear(host);
    if (!rows.length) { host.appendChild(empty("Aucune CVE.")); return; }
    const ul = el("ul", { class: "cve-list" });
    rows.forEach((c) => {
      ul.appendChild(el("li", {}, [
        el("a", { class: "cve-row cve-link", href: findingsHref({ q: c.cve }) }, [
          el("span", { class: "dot sev-bg-" + c.worst }),
          el("span", { class: "cve-id ref", text: c.cve }),
          el("span", { class: "cve-count", text: "×" + c.count }),
        ]),
      ]));
    });
    host.appendChild(ul);
  }

  function renderRecentScans(host, rows) {
    clear(host);
    if (!rows.length) { host.appendChild(empty("Aucun scan.")); return; }
    const table = el("table", { class: "grid compact" }, [
      el("thead", {}, [el("tr", {}, [th("Asset"), th("Scanner"), th("Statut"), th("Findings"), th("Quand")])]),
    ]);
    const tb = el("tbody");
    rows.forEach((s) => {
      tb.appendChild(el("tr", {}, [
        el("td", {}, [el("a", { class: "link", href: "/ui/assets/" + s.asset_id, text: s.asset_name })]),
        el("td", {}, [el("span", { class: "tag", text: s.scanner })]),
        el("td", {}, [el("span", { class: "scan-status scan-" + s.status, text: s.status })]),
        el("td", { class: "muted", text: s.findings_count == null ? "—" : String(s.findings_count) }),
        el("td", { class: "muted nowrap", text: s.started_at || "—" }),
      ]));
    });
    table.appendChild(tb);
    host.appendChild(table);
  }

  function renderAssetsTable(host, assets, q) {
    clear(host);
    const rows = assets.filter((a) => !q || a.name.toLowerCase().includes(q));
    if (!rows.length) { host.appendChild(empty("Aucun asset ne correspond.")); return; }
    const table = el("table", { class: "grid compact" }, [
      el("thead", {}, [el("tr", {}, [th("Nom"), th("Pire"), th("Ouv."), th("")])]),
    ]);
    const tb = el("tbody");
    rows.forEach((a) => {
      tb.appendChild(el("tr", {}, [
        el("td", { class: "strong", text: a.name }),
        el("td", {}, [a.worst ? sevBadge(a.worst) : el("span", { class: "muted", text: "—" })]),
        el("td", {}, [el("span", { class: a.open ? "count-open" : "muted", text: String(a.open) })]),
        el("td", {}, [el("a", { class: "row-link", href: "/ui/assets/" + a.id, text: "→" })]),
      ]));
    });
    table.appendChild(tb);
    host.appendChild(table);
  }

  // -------------------------------------------------------------- page asset

  async function renderAsset(assetId) {
    let data;
    try { data = await api("/ui/api/assets/" + assetId); }
    catch (e) { return toast("Impossible de charger les données : " + e.message); }

    const kpis = byId("asset-kpis"); clear(kpis);
    kpis.appendChild(kpi(data.stats.total, "Findings"));
    kpis.appendChild(kpi(data.stats.open, "Ouverts"));
    kpis.appendChild(kpi((data.stats.by_severity.critical || 0) + (data.stats.by_severity.high || 0), "Critiques + Élevés", "high"));

    const barHost = byId("asset-sevbar"); clear(barHost);
    barHost.appendChild(severityBar(data.stats.severity_segments));

    const state = { q: "", sev: new Set(), status: new Set(), sortKey: "severity", sortDir: 1 };

    const sevHost = byId("severity-filters"); clear(sevHost);
    SEVERITIES.filter((s) => (data.stats.by_severity[s] || 0) > 0).forEach((s) => {
      sevHost.appendChild(chip(SEV_LABEL[s] + " (" + data.stats.by_severity[s] + ")", "chip-sev sev-outline-" + s, () => { toggle(state.sev, s); redraw(); }));
    });

    const statuses = Array.from(new Set(data.findings.map((f) => f.status))).sort();
    const stHost = byId("status-filters"); clear(stHost);
    statuses.forEach((st) => stHost.appendChild(chip(st, "chip-status", () => { toggle(state.status, st); redraw(); })));

    const search = byId("finding-search");
    search.addEventListener("input", () => { state.q = search.value.trim().toLowerCase(); redraw(); });

    const host = byId("findings-table");
    const countEl = byId("result-count");

    function redraw() {
      let rows = data.findings.slice();
      if (state.sev.size) rows = rows.filter((f) => state.sev.has(f.severity));
      if (state.status.size) rows = rows.filter((f) => state.status.has(f.status));
      if (state.q) rows = rows.filter((f) => matches(f, state.q));
      rows.sort(comparator(state.sortKey, state.sortDir));
      countEl.textContent = rows.length + " finding(s) affiché(s) sur " + data.findings.length;
      renderFindingsTable(host, rows, state, redraw);
    }
    redraw();
  }

  function severityBar(segments) {
    const s = svg("svg", { viewBox: "0 0 100 6", preserveAspectRatio: "none", class: "sevbar" });
    if (!segments.length) s.appendChild(svg("rect", { class: "sevbar-empty", x: 0, y: 0, width: 100, height: 6 }));
    else segments.forEach((seg) => s.appendChild(svg("rect", { class: "sev-fill-" + seg.severity, x: seg.offset, y: 0, width: seg.width, height: 6 })));
    const legend = el("div", { class: "bar-legend" },
      segments.map((seg) => el("span", { class: "bar-legend-item" }, [
        el("span", { class: "dot sev-bg-" + seg.severity }),
        el("span", { text: SEV_LABEL[seg.severity] + " · " + seg.count }),
      ])));
    return el("div", {}, [s, legend]);
  }

  function matches(f, q) {
    return [f.title, f.cve, f.rule_id, f.file_path, f.component].some((v) => v && String(v).toLowerCase().includes(q));
  }

  function comparator(key, dir) {
    return (a, b) => {
      let va, vb;
      if (key === "severity") { va = SEV_RANK[a.severity] ?? 9; vb = SEV_RANK[b.severity] ?? 9; }
      else if (key === "epss") { va = a.epss_score ?? -1; vb = b.epss_score ?? -1; }
      else { va = a[key] || ""; vb = b[key] || ""; }
      if (va < vb) return -1 * dir;
      if (va > vb) return 1 * dir;
      return a.id - b.id;
    };
  }

  function renderFindingsTable(host, rows, state, redraw) {
    clear(host);
    const sortableTh = (label, key) => {
      const active = state.sortKey === key;
      const arrow = active ? (state.sortDir === 1 ? " ▲" : " ▼") : "";
      return el("th", {
        class: "sortable" + (active ? " active" : ""),
        on: { click: () => { if (state.sortKey === key) state.sortDir *= -1; else { state.sortKey = key; state.sortDir = 1; } redraw(); } },
      }, [document.createTextNode(label + arrow)]);
    };
    if (!rows.length) { host.appendChild(empty("Aucun finding ne correspond aux filtres.")); return; }

    const table = el("table", { class: "grid findings" }, [
      el("thead", {}, [el("tr", {}, [
        sortableTh("Sévérité", "severity"), th("Titre"), th("Référence"),
        sortableTh("EPSS", "epss"), th("Statut"), th("Vu le"),
      ])]),
    ]);
    const tb = el("tbody");
    rows.forEach((f) => {
      const ref = el("td", { class: "ref" });
      if (f.cve) {
        ref.appendChild(document.createTextNode(f.cve));
        if (f.component) ref.appendChild(el("span", { class: "muted", text: " · " + f.component }));
      } else if (f.rule_id) {
        ref.appendChild(document.createTextNode(f.rule_id));
        if (f.file_path) { ref.appendChild(el("br")); ref.appendChild(el("span", { class: "loc", text: f.file_path + (f.line_number ? ":" + f.line_number : "") })); }
      } else ref.appendChild(el("span", { class: "muted", text: "—" }));
      tb.appendChild(el("tr", {}, [
        el("td", {}, [sevBadge(f.severity)]),
        el("td", { class: "title", text: f.title }),
        ref,
        el("td", {}, [epssCell(f.epss_score)]),
        el("td", {}, [statusBadge(f.status)]),
        el("td", { class: "muted nowrap", text: f.last_seen || "—" }),
      ]));
    });
    table.appendChild(tb);
    host.appendChild(table);
  }

  function chip(label, cls, onClick) {
    return el("button", {
      class: "chip " + cls, type: "button", text: label,
      on: { click: (e) => { e.currentTarget.classList.toggle("active"); onClick(); } },
    });
  }
  function toggle(set, v) { if (set.has(v)) set.delete(v); else set.add(v); }

  // -------------------------------------------------------------- workspace Findings

  async function renderFindings(canWrite) {
    const state = {
      q: "", sev: new Set(), status: new Set(), scanner: "", asset_id: "",
      has_cve: false, kev: false, min_epss: 0, sort: "severity", order: "asc", page: 1,
    };
    const selected = new Set();
    let lastData = null;

    // Charge la liste des assets/scanners/statuts pour les filtres.
    let meta;
    try { meta = await api("/ui/api/assets"); }
    catch (e) { return toast("Chargement impossible : " + e.message, "error"); }

    const assetSel = byId("f-asset");
    meta.assets.forEach((a) => assetSel.appendChild(el("option", { attrs: { value: String(a.id) }, text: a.name })));
    const scanSel = byId("f-scanner");
    meta.scanners.forEach((s) => scanSel.appendChild(el("option", { attrs: { value: s }, text: s })));

    // Chips severite
    const sevHost = byId("sev-chips");
    SEVERITIES.forEach((s) => sevHost.appendChild(chip(SEV_LABEL[s], "chip-sev sev-outline-" + s, () => { toggleSet(state.sev, s); reload(); })));
    // Chips statut
    const stHost = byId("status-chips");
    meta.statuses.forEach((s) => stHost.appendChild(chip(STATUS_LABEL[s] || s, "chip-status", () => { toggleSet(state.status, s); reload(); })));

    // Filtres
    const search = byId("f-search");
    search.addEventListener("input", debounce(() => { state.q = search.value.trim(); state.page = 1; reload(); }, 300));
    assetSel.addEventListener("change", () => { state.asset_id = assetSel.value; state.page = 1; reload(); });
    scanSel.addEventListener("change", () => { state.scanner = scanSel.value; state.page = 1; reload(); });
    const epss = byId("f-epss");
    epss.addEventListener("input", () => { byId("epss-val").textContent = Number(epss.value).toFixed(2); });
    epss.addEventListener("change", debounce(() => { state.min_epss = Number(epss.value); state.page = 1; reload(); }, 200));
    const hascve = byId("f-hascve");
    hascve.addEventListener("change", () => { state.has_cve = hascve.checked; state.page = 1; reload(); });
    const kevChk = byId("f-kev");
    kevChk.addEventListener("change", () => { state.kev = kevChk.checked; state.page = 1; reload(); });
    byId("f-reset").addEventListener("click", () => {
      state.q = ""; state.sev.clear(); state.status.clear(); state.scanner = ""; state.asset_id = "";
      state.has_cve = false; state.kev = false; state.min_epss = 0; state.page = 1;
      search.value = ""; assetSel.value = ""; scanSel.value = ""; hascve.checked = false; kevChk.checked = false; epss.value = 0; byId("epss-val").textContent = "0.00";
      document.querySelectorAll("#sev-chips .chip, #status-chips .chip").forEach((c) => c.classList.remove("active"));
      reload();
    });

    // Pre-remplissage des filtres depuis l'URL (drill-down du tableau de bord).
    const params = new URLSearchParams(window.location.search);
    if (params.get("asset_id")) { state.asset_id = params.get("asset_id"); assetSel.value = state.asset_id; }
    if (params.get("scanner")) { state.scanner = params.get("scanner"); scanSel.value = state.scanner; }
    if (params.get("q")) { state.q = params.get("q"); search.value = state.q; }
    if (params.get("has_cve") === "true") { state.has_cve = true; hascve.checked = true; }
    if (params.get("kev") === "true") { state.kev = true; kevChk.checked = true; }
    if (params.get("min_epss")) {
      state.min_epss = Number(params.get("min_epss"));
      epss.value = state.min_epss; byId("epss-val").textContent = state.min_epss.toFixed(2);
    }
    params.getAll("severity").forEach((s) => {
      if (SEVERITIES.includes(s)) { state.sev.add(s); markChipActive("#sev-chips", SEVERITIES.indexOf(s)); }
    });
    params.getAll("status").forEach((s) => {
      const idx = meta.statuses.indexOf(s);
      if (idx >= 0) { state.status.add(s); markChipActive("#status-chips", idx); }
    });

    function markChipActive(sel, idx) {
      const chips = document.querySelectorAll(sel + " .chip");
      if (chips[idx]) chips[idx].classList.add("active");
    }

    function buildQuery(extra) {
      const p = new URLSearchParams();
      if (state.q) p.set("q", state.q);
      state.sev.forEach((s) => p.append("severity", s));
      state.status.forEach((s) => p.append("status", s));
      if (state.scanner) p.append("scanner", state.scanner);
      if (state.asset_id) p.set("asset_id", state.asset_id);
      if (state.has_cve) p.set("has_cve", "true");
      if (state.kev) p.set("kev", "true");
      if (state.min_epss > 0) p.set("min_epss", String(state.min_epss));
      Object.assign({}, extra || {});
      for (const k in (extra || {})) p.set(k, extra[k]);
      return p;
    }

    // Bulk bar
    const bulkbar = byId("bulkbar");
    const bulkActions = byId("bulk-actions");
    if (canWrite) {
      meta.statuses.forEach((s) => bulkActions.appendChild(
        el("button", { class: "chip chip-status", type: "button", text: STATUS_LABEL[s] || s, on: { click: () => bulkSet(s) } })));
    }
    byId("bulk-clear").addEventListener("click", () => { selected.clear(); render(); });

    async function bulkSet(status) {
      if (!selected.size) return;
      try {
        const r = await apiSend("POST", "/ui/api/findings/bulk", { ids: Array.from(selected), status });
        toast(r.changed + " finding(s) → " + (STATUS_LABEL[status] || status), "ok");
        selected.clear();
        reload();
      } catch (e) { toast(e.message, "error"); }
    }

    // Export : href reflete les filtres courants.
    const exportBtn = byId("export-btn");
    function refreshExport() {
      exportBtn.href = "/ui/api/export.csv?" + buildQuery().toString();
    }

    async function reload() {
      const p = buildQuery({ sort: state.sort, order: state.order, page: state.page, page_size: 25 });
      try { lastData = await api("/ui/api/findings?" + p.toString()); }
      catch (e) { return toast("Chargement impossible : " + e.message, "error"); }
      refreshExport();
      render();
    }

    function render() {
      const host = byId("findings-table");
      const d = lastData;
      updateFacetChips(d.facets);
      byId("result-count").textContent = d.total + " finding(s) · page " + d.page + "/" + d.pages;
      renderPager(d);
      renderBulkbar();

      clear(host);
      if (!d.items.length) { host.appendChild(empty("Aucun finding ne correspond aux filtres.")); return; }

      const headCheck = canWrite ? el("th", { class: "cktd" }, [checkbox(allOnPageSelected(d), (on) => {
        d.items.forEach((f) => on ? selected.add(f.id) : selected.delete(f.id)); render();
      })]) : null;

      const table = el("table", { class: "grid findings" }, [
        el("thead", {}, [el("tr", {}, [
          headCheck, sortTh("Risque", "risk"), sortTh("Sév.", "severity"), th("Titre"), th("Asset"), th("Référence"),
          sortTh("EPSS", "epss"), sortTh("Statut", "status"), sortTh("MAJ", "last_seen"),
        ].filter(Boolean))]),
      ]);
      const tb = el("tbody");
      d.items.forEach((f) => {
        const tr = el("tr", { class: selected.has(f.id) ? "sel" : "" });
        if (canWrite) {
          tr.appendChild(el("td", { class: "cktd", on: { click: (e) => e.stopPropagation() } }, [
            checkbox(selected.has(f.id), (on) => { on ? selected.add(f.id) : selected.delete(f.id); tr.classList.toggle("sel", on); renderBulkbar(); syncHeadCheck(); }),
          ]));
        }
        tr.appendChild(el("td", {}, [riskBadge(f.risk, f.risk_band)]));
        tr.appendChild(el("td", {}, [sevBadge(f.severity)]));
        const titleCell = el("td", { class: "title" }, [el("span", { text: f.title })]);
        if (f.kev) titleCell.appendChild(kevBadge());
        if (f.overdue) titleCell.appendChild(overdueBadge());
        tr.appendChild(titleCell);
        tr.appendChild(el("td", { class: "muted nowrap", text: f.asset_name || "—" }));
        tr.appendChild(refCell(f));
        tr.appendChild(el("td", {}, [epssCell(f.epss_score)]));
        tr.appendChild(el("td", {}, [statusBadge(f.status)]));
        tr.appendChild(el("td", { class: "muted nowrap", text: f.updated_at ? f.updated_at.slice(0, 10) : (f.last_seen || "—") }));
        tr.addEventListener("click", () => openDrawer(f.id));
        tr.classList.add("clickable");
        tb.appendChild(tr);
      });
      table.appendChild(tb);
      host.appendChild(table);
    }

    function allOnPageSelected(d) { return d.items.length > 0 && d.items.every((f) => selected.has(f.id)); }
    function syncHeadCheck() { const h = document.querySelector("thead .cktd input"); if (h && lastData) h.checked = allOnPageSelected(lastData); }

    function renderBulkbar() {
      if (!canWrite) return;
      bulkbar.hidden = selected.size === 0;
      byId("bulk-count").textContent = selected.size + " sélectionné(s)";
    }

    const sortTh = (label, key) => {
      const active = state.sort === key;
      const arrow = active ? (state.order === "asc" ? " ▲" : " ▼") : "";
      return el("th", { class: "sortable" + (active ? " active" : ""), on: { click: () => {
        if (state.sort === key) state.order = state.order === "asc" ? "desc" : "asc";
        else { state.sort = key; state.order = (key === "epss" || key === "risk") ? "desc" : "asc"; }
        reload();
      } } }, [document.createTextNode(label + arrow)]);
    };

    function updateFacetChips(facets) {
      document.querySelectorAll("#sev-chips .chip").forEach((c, i) => {
        const s = SEVERITIES[i]; const n = (facets.severity || {})[s] || 0;
        c.textContent = SEV_LABEL[s] + (n ? " (" + n + ")" : "");
        c.classList.toggle("active", state.sev.has(s));
      });
    }

    function renderPager(d) {
      const pager = byId("pager"); clear(pager);
      if (d.pages <= 1) return;
      const mk = (label, page, disabled) => el("button", { class: "btn btn-sm btn-ghost" + (disabled ? " disabled" : ""), type: "button", text: label, on: { click: () => { if (!disabled) { state.page = page; reload(); } } } });
      pager.appendChild(mk("‹", d.page - 1, d.page <= 1));
      pager.appendChild(el("span", { class: "pager-info", text: d.page + " / " + d.pages }));
      pager.appendChild(mk("›", d.page + 1, d.page >= d.pages));
    }

    reload();
  }

  function refCell(f) {
    const ref = el("td", { class: "ref" });
    if (f.cve) { ref.appendChild(document.createTextNode(f.cve)); if (f.component) ref.appendChild(el("span", { class: "muted", text: " · " + f.component })); }
    else if (f.rule_id) { ref.appendChild(document.createTextNode(f.rule_id)); if (f.file_path) { ref.appendChild(el("br")); ref.appendChild(el("span", { class: "loc", text: f.file_path + (f.line_number ? ":" + f.line_number : "") })); } }
    else ref.appendChild(el("span", { class: "muted", text: "—" }));
    return ref;
  }

  function checkbox(checked, onChange) {
    const c = el("input", { type: "checkbox" });
    c.checked = !!checked;
    c.addEventListener("change", (e) => onChange(e.currentTarget.checked));
    return c;
  }
  function toggleSet(set, v) { if (set.has(v)) set.delete(v); else set.add(v); }

  // -------------------------------------------------------------- drawer détail + triage

  async function openDrawer(findingId) {
    const overlay = byId("drawer-overlay"), drawer = byId("drawer"), host = byId("drawer-content");
    overlay.hidden = false; drawer.hidden = false;
    document.body.classList.add("no-scroll");
    clear(host); host.appendChild(el("p", { class: "muted", text: "Chargement…" }));
    const onKey = (e) => { if (e.key === "Escape") close(); };
    const close = () => {
      overlay.hidden = true; drawer.hidden = true;
      document.body.classList.remove("no-scroll");
      document.removeEventListener("keydown", onKey);
    };
    overlay.onclick = close;
    document.addEventListener("keydown", onKey);

    let d;
    try { d = await api("/ui/api/findings/" + findingId); }
    catch (e) { clear(host); host.appendChild(empty("Erreur : " + e.message)); return; }
    renderDrawer(host, d, close, () => openDrawer(findingId));
  }

  function renderDrawer(host, d, close, reopen) {
    const f = d.finding;
    clear(host);
    const titleRow = el("div", { class: "drawer-title-row" }, [sevBadge(f.severity), statusBadge(f.status)]);
    if (f.risk != null) titleRow.appendChild(riskBadge(f.risk, f.risk_band));
    if (f.kev) titleRow.appendChild(kevBadge());
    if (f.overdue) titleRow.appendChild(overdueBadge());
    host.appendChild(el("div", { class: "drawer-head" }, [
      titleRow,
      el("button", { class: "drawer-close", type: "button", text: "✕", on: { click: close } }),
    ]));
    host.appendChild(el("h2", { class: "drawer-title", text: f.title }));

    const meta = el("dl", { class: "meta-grid" });
    const addMeta = (k, v) => { if (v == null || v === "") return; meta.appendChild(el("dt", { text: k })); meta.appendChild(el("dd", { text: String(v) })); };
    meta.appendChild(el("dt", { text: "Asset" }));
    meta.appendChild(el("dd", {}, [el("a", { class: "link", href: "/ui/assets/" + f.asset_id, text: f.asset_name || "—" })]));
    if (f.criticality) { meta.appendChild(el("dt", { text: "Criticité asset" })); meta.appendChild(el("dd", {}, [critPill(f.criticality)])); }
    addMeta("Scanner", f.scanner);
    addMeta("CVE", f.cve);
    addMeta("Composant", f.component);
    addMeta("Règle", f.rule_id);
    addMeta("Emplacement", f.file_path ? f.file_path + (f.line_number ? ":" + f.line_number : "") : null);
    if (f.epss_score != null) { meta.appendChild(el("dt", { text: "EPSS" })); meta.appendChild(el("dd", {}, [epssCell(f.epss_score)])); }
    addMeta("Vu le", f.last_seen);
    addMeta("1re vue", f.first_seen);
    host.appendChild(meta);

    if (f.description) {
      host.appendChild(el("h3", { class: "drawer-sub", text: "Description" }));
      host.appendChild(el("p", { class: "desc", text: f.description }));
    }

    // Triage
    if (d.can_write) {
      host.appendChild(el("h3", { class: "drawer-sub", text: "Triage" }));
      const noteInput = el("textarea", { class: "note-input", attrs: { placeholder: "Justification (optionnelle)…", rows: "2" } });
      host.appendChild(noteInput);
      const actions = el("div", { class: "status-actions" });
      d.statuses.forEach((s) => {
        if (s === f.status) return;
        actions.appendChild(el("button", {
          class: "btn btn-sm status-btn status-btn-" + s, type: "button", text: "→ " + (STATUS_LABEL[s] || s),
          on: { click: async () => {
            try {
              await apiSend("PATCH", "/ui/api/findings/" + f.id, { status: s, note: noteInput.value.trim() || null });
              toast("Statut mis à jour", "ok"); reopen();
            } catch (e) { toast(e.message, "error"); }
          } },
        }));
      });
      host.appendChild(actions);
    }

    // Notes / historique
    host.appendChild(el("h3", { class: "drawer-sub", text: "Historique & notes" }));
    if (d.can_write) {
      const commentInput = el("textarea", { class: "note-input", attrs: { placeholder: "Ajouter un commentaire…", rows: "2" } });
      const addBtn = el("button", {
        class: "btn btn-sm btn-primary", type: "button", text: "Commenter",
        on: { click: async () => {
          const body = commentInput.value.trim();
          if (!body) return;
          try { await apiSend("POST", "/ui/api/findings/" + f.id + "/notes", { body }); toast("Note ajoutée", "ok"); reopen(); }
          catch (e) { toast(e.message, "error"); }
        } },
      });
      host.appendChild(el("div", { class: "add-note" }, [commentInput, addBtn]));
    }

    const timeline = el("ul", { class: "note-timeline" });
    if (!d.notes.length) timeline.appendChild(el("li", { class: "muted", text: "Aucune activité." }));
    d.notes.forEach((n) => {
      const head = el("div", { class: "note-head" }, [
        el("span", { class: "note-author", text: n.author }),
        el("span", { class: "note-date", text: n.created_at || "" }),
      ]);
      const body = el("div", { class: "note-body" });
      if (n.kind === "status_change") {
        body.appendChild(el("span", { class: "note-transition" }, [
          statusBadge(n.old_status || "?"), document.createTextNode(" → "), statusBadge(n.new_status || "?"),
        ]));
        if (n.body) body.appendChild(el("p", { class: "note-text", text: n.body }));
      } else {
        body.appendChild(el("p", { class: "note-text", text: n.body || "" }));
      }
      timeline.appendChild(el("li", { class: "note-item note-" + n.kind }, [head, body]));
    });
    host.appendChild(timeline);
  }

  // -------------------------------------------------------------- modules (Wazuh-style)

  // KPI dont la valeur est un texte (pas d'animation de comptage).
  function kpiText(value, label, tone) {
    return el("div", { class: "kpi kpi-" + (tone || "default") }, [
      el("span", { class: "kpi-value kpi-value-text", text: value }),
      el("span", { class: "kpi-label", text: label }),
    ]);
  }

  // Legende de severite generique, liee a une liste de findings filtree.
  function severityLegend(host, counts, baseParams) {
    clear(host);
    SEVERITIES.forEach((sev) => {
      const n = counts[sev] || 0;
      const inner = [
        el("span", { class: "dot sev-bg-" + sev }),
        el("span", { class: "legend-name", text: SEV_LABEL[sev] }),
        el("span", { class: "legend-val", text: String(n) }),
      ];
      const params = Object.assign({ severity: sev }, baseParams || {});
      host.appendChild(el("li", {}, [
        n ? el("a", { class: "legend-item legend-link", href: findingsHref(params) }, inner)
          : el("span", { class: "legend-item" }, inner),
      ]));
    });
  }

  // Table generique. cols = [{label, cls}], rows = [[cell,...]] (cell = node|texte)
  function dataTable(cols, rows, emptyMsg) {
    if (!rows.length) return empty(emptyMsg);
    const head = el("tr", {}, cols.map((c) => th(c.label, c.cls ? { class: c.cls } : {})));
    const tb = el("tbody");
    rows.forEach((r) => {
      tb.appendChild(el("tr", {}, r.map((cell) =>
        (cell && cell.nodeType) ? el("td", {}, [cell]) : el("td", { text: cell == null ? "—" : String(cell) })
      )));
    });
    return el("table", { class: "grid compact" }, [el("thead", {}, [head]), tb]);
  }

  function pill(text, cls) { return el("span", { class: "pill " + (cls || ""), text: text }); }

  // ---- Détection de vulnérabilités (CVE / EPSS)
  const EPSS_CLS = {
    critique: "sev-fill-critical", eleve: "sev-fill-high", moyen: "sev-fill-medium",
    faible: "sev-fill-low", minime: "sev-fill-info", inconnu: "hbar-fill-muted",
  };
  async function renderVulnDetection() {
    let d;
    try { d = await api("/ui/api/vulnerabilities"); }
    catch (e) { return toast("Impossible de charger les données : " + e.message); }
    const t = d.totals;
    const k = byId("kpis"); clear(k);
    k.appendChild(kpi(t.with_cve, "CVE suivies", "default", findingsHref({ has_cve: "true" })));
    k.appendChild(kpi(t.open, "Ouvertes", "default", findingsHref({ has_cve: "true", status: "open" })));
    k.appendChild(kpi(t.kev_open || 0, "KEV (exploitées)", "critical", findingsHref({ kev: "true", status: "open" })));
    k.appendChild(kpi(t.exploitable, "Exploitables (EPSS≥.5)", "critical", findingsHref({ min_epss: "0.5", status: "open" })));
    k.appendChild(kpi(t.critical_open, "Critiques ouvertes", "critical", findingsHref({ has_cve: "true", severity: "critical", status: "open" })));

    const dh = byId("cve-donut"); clear(dh);
    dh.appendChild(donut(d.by_severity, Object.values(d.by_severity).reduce((a, b) => a + b, 0)));
    severityLegend(byId("cve-legend"), d.by_severity, { has_cve: "true", status: "open" });

    const ed = byId("epss-dist"); clear(ed);
    ed.appendChild(hbars(d.epss_dist.map((b) => ({
      label: b.label, value: b.count, cls: "hbar-fill " + (EPSS_CLS[b.key] || "hbar-fill-muted"),
      tip: b.label + " : " + b.count,
    }))));

    const tc = byId("top-components"); clear(tc);
    tc.appendChild(d.top_components.length ? hbars(d.top_components.map((c) => ({
      label: c.name, value: c.count, cls: "hbar-fill",
      href: findingsHref({ q: c.name, has_cve: "true" }), tip: c.name + " : " + c.count,
    }))) : empty("Aucun composant."));

    const cp = byId("cve-priority"); clear(cp);
    cp.appendChild(dataTable(
      [{ label: "Sév." }, { label: "CVE" }, { label: "Composant" }, { label: "Asset" }, { label: "EPSS" }],
      d.priority.map((f) => [
        sevBadge(f.severity),
        el("span", { class: "cve-cell" }, [
          el("a", { class: "ref link", href: findingsHref({ q: f.cve }), text: f.cve }),
          f.kev ? kevBadge() : null,
        ]),
        el("span", { class: "muted", text: f.component || "—" }),
        el("a", { class: "link", href: "/ui/assets/" + f.asset_id, text: f.asset_name }),
        epssCell(f.epss_score),
      ]),
      "Aucune CVE prioritaire. 🎉"
    ));
  }

  // ---- Analyse de code (SAST / Semgrep)
  async function renderSca() {
    let d;
    try { d = await api("/ui/api/sca"); }
    catch (e) { return toast("Impossible de charger les données : " + e.message); }
    const t = d.totals;
    const k = byId("kpis"); clear(k);
    k.appendChild(kpi(t.total, "Défauts SAST", "default", findingsHref({ scanner: "semgrep" })));
    k.appendChild(kpi(t.open, "Ouverts", "default", findingsHref({ scanner: "semgrep", status: "open" })));
    k.appendChild(kpi(t.high_open, "Critiques + élevés", "high", findingsHref({ scanner: "semgrep", severity: ["critical", "high"], status: "open" })));
    k.appendChild(kpi(t.rules, "Règles déclenchées", "default"));
    k.appendChild(kpi(t.files, "Fichiers touchés", "default"));

    const dh = byId("sca-donut"); clear(dh);
    dh.appendChild(donut(d.by_severity, Object.values(d.by_severity).reduce((a, b) => a + b, 0)));
    severityLegend(byId("sca-legend"), d.by_severity, { scanner: "semgrep", status: "open" });

    const cat = byId("sca-category"); clear(cat);
    cat.appendChild(d.by_category.length ? hbars(d.by_category.map((c) => ({
      label: c.category, value: c.count, cls: "hbar-fill",
      href: findingsHref({ scanner: "semgrep", q: c.category }), tip: c.category + " : " + c.count,
    }))) : empty("Aucune règle déclenchée."));

    const rules = byId("sca-rules"); clear(rules);
    rules.appendChild(d.top_rules.length ? hbars(d.top_rules.map((r) => ({
      label: r.rule_id, value: r.count, cls: "hbar-fill",
      href: findingsHref({ q: r.rule_id }), tip: r.rule_id + " : " + r.count,
    }))) : empty("Aucune règle."));

    const files = byId("sca-files"); clear(files);
    files.appendChild(d.top_files.length ? hbars(d.top_files.map((f) => ({
      label: f.file_path, value: f.count, cls: "hbar-fill hbar-fill-muted",
      href: findingsHref({ q: f.file_path }), tip: f.file_path + " : " + f.count,
    }))) : empty("Aucun fichier."));
  }

  // ---- Secrets & fuites (Gitleaks)
  async function renderSecrets() {
    let d;
    try { d = await api("/ui/api/secrets"); }
    catch (e) { return toast("Impossible de charger les données : " + e.message); }
    const t = d.totals;
    const k = byId("kpis"); clear(k);
    k.appendChild(kpi(t.total, "Secrets détectés", "default", findingsHref({ scanner: "gitleaks" })));
    k.appendChild(kpi(t.open, "Ouverts", "critical", findingsHref({ scanner: "gitleaks", status: "open" })));
    k.appendChild(kpi(t.repos, "Dépôts exposés", "high"));
    k.appendChild(kpi(t.remediated, "Révoqués (corrigés)", "low", findingsHref({ scanner: "gitleaks", status: "fixed" })));

    const ba = byId("secrets-by-asset"); clear(ba);
    ba.appendChild(d.by_asset.length ? hbars(d.by_asset.map((a) => ({
      label: a.name, value: a.count, cls: "hbar-fill sev-fill-critical",
      href: "/ui/assets/" + a.id, tip: a.name + " : " + a.count + " secret(s) ouvert(s)",
    }))) : empty("Aucun secret ouvert. 🎉"));

    const lc = byId("secrets-lifecycle"); clear(lc);
    const statuses = Object.keys(d.by_status).sort();
    lc.appendChild(statuses.length ? hbars(statuses.map((st) => ({
      label: STATUS_LABEL[st] || st, value: d.by_status[st], cls: "hbar-fill status-fill-" + st,
      badge: statusBadge(st), href: findingsHref({ scanner: "gitleaks", status: st }),
      tip: (STATUS_LABEL[st] || st) + " : " + d.by_status[st],
    }))) : empty("Aucun secret."));

    const tbl = byId("secrets-table"); clear(tbl);
    tbl.appendChild(dataTable(
      [{ label: "Dépôt" }, { label: "Type de secret" }, { label: "Emplacement" }, { label: "Règle" }, { label: "Statut" }, { label: "Vu le" }],
      d.items.map((s) => [
        el("a", { class: "link", href: "/ui/assets/" + s.asset_id, text: s.asset_name }),
        el("span", { class: "title", text: s.title }),
        el("span", { class: "ref", text: s.file_path ? (s.file_path + (s.line_number != null ? ":" + s.line_number : "")) : "—" }),
        el("span", { class: "muted", text: s.rule_id || "—" }),
        statusBadge(s.status),
        el("span", { class: "muted nowrap", text: s.last_seen || "—" }),
      ]),
      "Aucun secret ouvert. 🎉"
    ));
  }

  // ---- MITRE ATT&CK
  async function renderAttack() {
    let d;
    try { d = await api("/ui/api/attack"); }
    catch (e) { return toast("Impossible de charger les données : " + e.message); }
    const t = d.totals;
    const k = byId("kpis"); clear(k);
    k.appendChild(kpi(t.mapped, "Findings cartographiés", "default"));
    k.appendChild(kpi(t.tactics_covered, "Tactiques couvertes", "high"));
    k.appendChild(kpi(t.techniques, "Techniques observées", "default"));
    k.appendChild(kpiText(t.top_tactic, "Tactique dominante", "critical"));

    const host = byId("attack-matrix"); clear(host);
    const maxCount = Math.max(1, ...d.tactics.map((x) => x.count));
    d.tactics.forEach((tac) => {
      const head = el("div", { class: "tactic-head sev-outline-" + (tac.worst || "info") }, [
        el("span", { class: "tactic-name", text: tac.name }),
        el("span", { class: "tactic-id", text: tac.id }),
        el("span", { class: "tactic-count", text: String(tac.count) }),
      ]);
      const meter = svg("svg", { viewBox: "0 0 100 3", preserveAspectRatio: "none", class: "tactic-meter" });
      meter.appendChild(svg("rect", { class: "tactic-meter-track", x: 0, y: 0, width: 100, height: 3 }));
      meter.appendChild(svg("rect", { class: "tactic-meter-fill sev-fill-" + (tac.worst || "info"), x: 0, y: 0, width: (tac.count / maxCount * 100).toFixed(1), height: 3 }));
      const cards = el("div", { class: "tech-list" },
        tac.techniques.length ? tac.techniques.map((tk) => el("div", { class: "tech-card" }, [
          el("div", { class: "tech-top" }, [
            el("span", { class: "dot sev-bg-" + (tk.worst || "info") }),
            el("span", { class: "tech-id", text: tk.id }),
            el("span", { class: "tech-count", text: "×" + tk.count }),
          ]),
          el("span", { class: "tech-name", text: tk.name }),
        ])) : [el("div", { class: "tech-empty", text: "—" })]);
      host.appendChild(el("div", { class: "tactic-col" }, [head, meter, cards]));
    });
  }

  // ---- Inventaire système / hygiène
  function hygieneBar(score) {
    const cls = score >= 70 ? "hyg-good" : score >= 40 ? "hyg-mid" : "hyg-bad";
    const bar = svg("svg", { viewBox: "0 0 100 8", preserveAspectRatio: "none", class: "hyg-bar" });
    bar.appendChild(svg("rect", { class: "hyg-track", x: 0, y: 0, width: 100, height: 8, rx: 4 }));
    bar.appendChild(svg("rect", { class: "hyg-fill " + cls, x: 0, y: 0, width: String(Math.max(2, score)), height: 8, rx: 4 }));
    return el("div", { class: "hyg-cell" }, [bar, el("span", { class: "hyg-num", text: String(score) })]);
  }
  function criticalitySelect(assetId, current) {
    const sel = el("select", { class: "crit-select crit-" + current });
    ["crown", "high", "medium", "low"].forEach((c) => {
      const o = el("option", { attrs: { value: c }, text: CRIT_LABEL[c] });
      if (c === current) o.selected = true;
      sel.appendChild(o);
    });
    sel.addEventListener("change", async () => {
      try {
        await apiSend("PATCH", "/ui/api/assets/" + assetId + "/criticality", { criticality: sel.value });
        sel.className = "crit-select crit-" + sel.value;
        toast("Criticité mise à jour", "ok");
      } catch (e) { toast(e.message, "error"); }
    });
    return sel;
  }
  async function renderInventory(canWrite) {
    let d;
    try { d = await api("/ui/api/inventory"); }
    catch (e) { return toast("Impossible de charger les données : " + e.message); }
    const t = d.totals;
    const avgHyg = d.items.length ? Math.round(d.items.reduce((s, i) => s + i.hygiene, 0) / d.items.length) : 0;
    const k = byId("kpis"); clear(k);
    k.appendChild(kpi(t.assets, "Assets suivis", "default"));
    k.appendChild(kpi(t.with_critical, "Avec critiques", "critical"));
    k.appendChild(kpi(t.incomplete_coverage, "Couverture incomplète", "high"));
    k.appendChild(kpi(avgHyg, "Hygiène moyenne", avgHyg >= 70 ? "low" : avgHyg >= 40 ? "high" : "critical"));

    const host = byId("inventory-table"); clear(host);
    const cols = [{ label: "Asset" }, { label: "Type" }, { label: "Criticité" }, { label: "Pire" }, { label: "Ouv." }, { label: "Crit." }, { label: "Couverture scan" }, { label: "Hygiène" }, { label: "Dernier scan" }];
    const rows = d.items.map((a) => [
      el("a", { class: "link strong", href: "/ui/assets/" + a.id, text: a.name }),
      pill(a.type === "image" ? "image" : "dépôt", a.type === "image" ? "pill-image" : "pill-repo"),
      canWrite ? criticalitySelect(a.id, a.criticality) : critPill(a.criticality),
      a.worst ? sevBadge(a.worst) : el("span", { class: "muted", text: "—" }),
      el("span", { class: a.open ? "count-open" : "muted", text: String(a.open) }),
      el("span", { class: a.critical ? "count-crit" : "muted", text: String(a.critical) }),
      el("div", { class: "cov-cell" }, a.coverage.map((c) =>
        el("span", { class: "cov-pill " + (c.present ? "cov-on" : "cov-off"), text: c.scanner, attrs: { title: c.scanner + (c.present ? " : couvert" : " : absent") } }))),
      hygieneBar(a.hygiene),
      el("span", { class: "muted nowrap", text: a.last_scan || "jamais" }),
    ]);
    host.appendChild(dataTable(cols, rows, "Aucun asset."));
  }

  // ---- Posture & SLA (pilotage RBVM)

  const RISK_BANDS = ["critical", "high", "medium", "low"];

  // Flux divergent : decouvertes au-dessus de l'axe, corrigees en dessous.
  function flowChart(series) {
    if (!series.length) return empty("Pas de données.");
    const max = Math.max(1, ...series.map((d) => Math.max(d.opened, d.closed)));
    const n = series.length;
    const slot = 100 / n;
    const bw = Math.min(slot * 0.7, 3.2);
    const mid = 21, half = 18;
    const s = svg("svg", { viewBox: "0 0 100 42", preserveAspectRatio: "none", class: "timeline" });
    s.appendChild(svg("line", { class: "flow-axis", x1: 0, y1: mid, x2: 100, y2: mid }));
    series.forEach((d, i) => {
      const x = i * slot + (slot - bw) / 2;
      if (d.opened) {
        const h = (d.opened / max) * half;
        const r = svg("rect", { class: "flow-opened", x: x.toFixed(2), y: (mid - h).toFixed(2), width: bw.toFixed(2), height: h.toFixed(2) });
        r.appendChild(svgTitle(d.date + " · découvertes : " + d.opened));
        s.appendChild(r);
      }
      if (d.closed) {
        const h = (d.closed / max) * half;
        const r = svg("rect", { class: "flow-closed", x: x.toFixed(2), y: mid.toFixed(2), width: bw.toFixed(2), height: h.toFixed(2) });
        r.appendChild(svgTitle(d.date + " · corrigées : " + d.closed));
        s.appendChild(r);
      }
    });
    const idxs = n === 1 ? [0] : [0, Math.floor(n / 2), n - 1];
    const axis = el("div", { class: "timeline-axis" }, idxs.map((i) => el("span", { text: series[i].date.slice(5) })));
    const legend = el("div", { class: "bar-legend" }, [
      el("span", { class: "bar-legend-item" }, [el("span", { class: "dot dot-opened" }), el("span", { text: "Découvertes" })]),
      el("span", { class: "bar-legend-item" }, [el("span", { class: "dot dot-closed" }), el("span", { text: "Corrigées" })]),
    ]);
    return el("div", {}, [s, axis, legend]);
  }

  async function renderPosture() {
    let d;
    try { d = await api("/ui/api/posture"); }
    catch (e) { return toast("Impossible de charger les données : " + e.message); }
    const t = d.totals;
    const k = byId("kpis"); clear(k);
    k.appendChild(kpi(t.overdue, "SLA dépassé", "critical", findingsHref({ status: "open" })));
    k.appendChild(kpi(t.due_soon, "Échéance < 3j", "high"));
    k.appendChild(kpiText(t.mttr != null ? t.mttr + " j" : "—", "MTTR (correction)", "default"));
    k.appendChild(kpiText(t.sla_compliance != null ? t.sla_compliance + " %" : "—", "Conformité SLA",
      t.sla_compliance != null && t.sla_compliance >= 90 ? "low" : "high"));
    k.appendChild(kpi(t.kev_open, "KEV ouverts", "critical", findingsHref({ kev: "true", status: "open" })));
    k.appendChild(kpi(t.open_total, "Ouverts", "default", findingsHref({ status: "open" })));

    // Distribution du risque (donut : les bandes reprennent les couleurs de sévérité)
    const dh = byId("risk-donut"); clear(dh);
    dh.appendChild(donut(d.risk.bands, d.risk.open_total));
    const legend = byId("risk-legend"); clear(legend);
    RISK_BANDS.forEach((b) => {
      legend.appendChild(el("li", {}, [el("span", { class: "legend-item" }, [
        el("span", { class: "dot sev-bg-" + b }),
        el("span", { class: "legend-name", text: RISK_LABEL[b] }),
        el("span", { class: "legend-val", text: String(d.risk.bands[b] || 0) }),
      ])]));
    });

    byId("flow-chart").appendChild(flowChart(d.flow));

    // En retard par sévérité
    const ov = byId("overdue-sev"); clear(ov);
    const ovItems = SEVERITIES.filter((s) => (d.sla.overdue_by_severity[s] || 0) > 0).map((s) => ({
      label: SEV_LABEL[s], value: d.sla.overdue_by_severity[s], cls: "hbar-fill sev-fill-" + s,
      badge: sevBadge(s), href: findingsHref({ severity: s, status: "open" }),
      tip: SEV_LABEL[s] + " en retard : " + d.sla.overdue_by_severity[s],
    }));
    ov.appendChild(ovItems.length ? hbars(ovItems) : empty("Aucun finding en retard. 🎉"));

    // MTTR par sévérité
    const mt = byId("mttr-sev"); clear(mt);
    const mttrItems = SEVERITIES.filter((s) => d.mttr.by_severity[s] != null).map((s) => ({
      label: SEV_LABEL[s], value: d.mttr.by_severity[s], cls: "hbar-fill sev-fill-" + s,
      badge: sevBadge(s), tip: SEV_LABEL[s] + " : " + d.mttr.by_severity[s] + " jours",
    }));
    mt.appendChild(mttrItems.length ? hbars(mttrItems) : empty("Aucune remédiation enregistrée."));

    // Top risques
    const tr = byId("top-risk"); clear(tr);
    tr.appendChild(dataTable(
      [{ label: "Risque" }, { label: "Sév." }, { label: "Menace" }, { label: "Vulnérabilité" }, { label: "Asset" }, { label: "CVE" }, { label: "EPSS" }],
      d.risk.top.map((f) => [
        riskBadge(f.risk, f.risk_band),
        sevBadge(f.severity),
        el("span", { class: "threat-cell" }, [f.kev ? kevBadge() : el("span", { class: "muted", text: "—" })]),
        el("span", { class: "title", text: f.title }),
        el("span", { class: "asset-crit" }, [
          el("a", { class: "link", href: "/ui/assets/" + f.asset_id, text: f.asset_name }),
          critPill(f.criticality),
        ]),
        f.cve ? el("a", { class: "ref link", href: findingsHref({ q: f.cve }), text: f.cve }) : el("span", { class: "muted", text: "—" }),
        epssCell(f.epss_score),
      ]),
      "Aucun risque ouvert. 🎉"
    ));
  }

  // -------------------------------------------------------------- amorçage

  const script = document.currentScript || document.querySelector('script[data-page]');
  const page = script && script.getAttribute("data-page");
  const canWrite = script && script.getAttribute("data-can-write") === "true";
  if (page === "overview") renderOverview();
  else if (page === "asset") renderAsset(script.getAttribute("data-asset-id"));
  else if (page === "findings") renderFindings(canWrite);
  else if (page === "vulnerabilities") renderVulnDetection();
  else if (page === "sca") renderSca();
  else if (page === "secrets") renderSecrets();
  else if (page === "attack") renderAttack();
  else if (page === "inventory") renderInventory(canWrite);
  else if (page === "posture") renderPosture();
})();

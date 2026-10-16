// ============================================================
// Security Findings view
// ============================================================
// Findings are produced by the scan engine from simulated state. Each one
// shows its evidence, the rule that produced it, and a controlled
// preview -> apply -> verify remediation workflow.

import { get, post } from '../api.js';
import { canAnalyze, registerActions, rerender } from '../state.js';
import {
  badge, dateTime, empty, errorBanner, fmtValue, html, kv, mount, money, openDrawer, pager, raw, setDrawerBody, sevBadge, table, titleCase,
  toast, typeLabel,
} from '../utils.js';

export const view = { id: 'security', title: ['Threat Detection', 'Security Findings'], render };

const f = { status: 'OPEN', severity: '', category: '', text: '', page: 1 };
let tab = 'findings';
let compare = [];

export function evidenceHtml(ev) {
  const parts = [];
  if (Array.isArray(ev.steps)) {
    parts.push(html`<div class="section-title">Why it is reachable (step by step)</div><ul class="steps">${ev.steps.map((s) => html`<li><span class="mark ${s.ok ? 'ok' : 'no'}">${s.ok ? '✓' : '✕'}</span><div><b>${s.check}</b><div class="panel-note">${s.detail}</div></div></li>`)}</ul>`);
  }
  const rest = Object.fromEntries(Object.entries(ev).filter(([k]) => k !== 'steps'));
  parts.push(html`<div class="section-title">Evidence</div><dl class="kv">${Object.entries(rest).map(([k, v]) => html`<dt>${titleCase(k)}</dt><dd>${fmtValue(v)}</dd>`)}</dl>`);
  return html`${parts}`;
}

async function render(box) {
  let summary;
  try {
    const [s, all] = await Promise.all([get('/api/sim/dashboard'), get('/api/sim/findings', { page_size: 1 })]);
    summary = { dash: s, total: all.total };
  } catch (e) {
    if (e.code === 'no_environment') { mount(box, html`<div class="card panel">${empty('No simulated environment', 'Generate one on the Simulator page.')}</div>`); return; }
    throw e;
  }
  const d = summary.dash;
  const sev = d.security.severity_counts;
  const tabs = [['findings', 'Findings'], ['scans', 'Scan history'], ['remediations', 'Remediation & verification'], ['rules', 'Detection rules']];
  mount(box, html`
    <p class="page-intro">Each finding is detected from the live simulated state by a documented rule, with the evidence that triggered it. A finding is marked resolved only when a later scan no longer detects the condition - never because a button was clicked.</p>
    ${d.stale ? html`<div class="banner warn"><span>State has changed since scan #${d.latest_scan.id}. The list may not reflect the current environment.</span></div>` : ''}
    <div class="stat-grid">
      <div class="card stat-card"><div class="label">Security score</div><div class="value ${d.security.score >= 80 ? 'v-ok' : d.security.score >= 50 ? 'v-warn' : 'v-bad'}">${d.security.score ?? '—'}<span style="font-size:14px;font-weight:500"> / 100</span></div></div>
      <div class="card stat-card"><div class="label">Critical / High</div><div class="value v-bad">${sev.CRITICAL} / ${sev.HIGH}</div></div>
      <div class="card stat-card"><div class="label">Medium / Low</div><div class="value v-warn">${sev.MEDIUM} / ${sev.LOW}</div></div>
      <div class="card stat-card"><div class="label">Last scan</div><div class="value" style="font-size:18px">${d.latest_scan ? '#' + d.latest_scan.id : '—'}</div>
        <div class="delta">${d.latest_scan ? dateTime(d.latest_scan.started_at) + ' UTC' : 'never'}</div></div>
    </div>
    <div class="row" style="margin-bottom:12px">
      <button class="btn btn-primary" data-action="run-scan" ${raw(canAnalyze() ? '' : 'disabled title="Analyst or administrator role required"')}>Run scan</button>
      <span class="panel-note">Scans never change the environment; they evaluate it and update finding history.</span>
    </div>
    <div class="tabs" role="tablist">${tabs.map(([id, label]) => html`<button class="tab ${tab === id ? 'active' : ''}" role="tab" aria-selected="${tab === id}" data-action="sec-tab" data-tab="${id}">${label}</button>`)}</div>
    <div id="sec-body"></div>`);
  const body = document.getElementById('sec-body');
  if (tab === 'findings') await renderFindings(body);
  else if (tab === 'scans') await renderScans(body);
  else if (tab === 'remediations') await renderRemediations(body);
  else await renderRules(body);
}

async function renderFindings(body) {
  const list = await get('/api/sim/findings', { status: f.status, severity: f.severity, category: f.category, q: f.text, page: f.page, page_size: 20 });
  const chip = (key, val, label) => html`<button class="chip-btn ${f[key] === val ? 'active' : ''}" data-action="sec-filter" data-key="${key}" data-val="${val}">${label}</button>`;
  mount(body, html`
    <div class="filter-bar">
      ${chip('status', 'OPEN', 'Open')}${chip('status', 'RESOLVED', 'Resolved')}${chip('status', '', 'All')}
      <span style="width:12px"></span>
      ${chip('severity', '', 'Any severity')}${['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => chip('severity', s, titleCase(s)))}
      <label class="sr-only" for="sec-cat">Category</label>
      <select id="sec-cat" data-change="sec-cat"><option value="">Any category</option>${['Network', 'Storage', 'Encryption', 'Resilience', 'Identity', 'Cost'].map((c) => html`<option ${raw(f.category === c ? 'selected' : '')}>${c}</option>`)}</select>
      <label class="sr-only" for="sec-q">Search</label>
      <input id="sec-q" type="text" placeholder="Search title or resource…" value="${f.text}" data-change="sec-search" style="min-width:220px">
    </div>
    <div class="card panel">
      ${list.items.length ? table([
        { label: 'Severity', render: (x) => sevBadge(x.severity) },
        { label: 'Finding', render: (x) => html`<b>${x.title}</b><div class="panel-note">${x.rule_id} · ${x.category}</div>` },
        { label: 'Resource', render: (x) => html`${x.resource_name}<div class="panel-note mono">${x.resource_id}</div>` },
        { label: 'Status', render: (x) => html`${badge(x.status, x.status === 'OPEN' ? 'open' : 'resolved')}${x.resolution ? html`<div class="panel-note">${x.resolution.replace('_', ' ').toLowerCase()}</div>` : ''}` },
        { label: 'First seen (sim)', render: (x) => x.first_seen_sim.slice(0, 10) },
        { label: 'Last seen (sim)', render: (x) => x.last_seen_sim.slice(0, 10) },
      ], list.items, { caption: 'Security findings', rowClass: (x) => (x.status === 'RESOLVED' ? 'row-resolved' : ''), rowAttrs: (x) => `data-action="sec-open" data-id="${x.id}" tabindex="0"` })
        : empty(f.status === 'OPEN' ? 'No open findings match' : 'No findings match', 'Adjust the filters, trigger a scenario, or run a scan.')}
      ${pager(list.page, list.page_size, list.total, 'sec-page')}
    </div>`);
}

export async function openFinding(id) {
  openDrawer('Finding #' + id, html`<div class="loading"><span class="spinner"></span>Loading…</div>`);
  let r;
  try { r = await get('/api/sim/findings/' + id); } catch (e) { setDrawerBody(errorBanner(e)); return; }
  const x = r.finding;
  const plan = x.remediation;
  mount('drawer-title', x.title);
  setDrawerBody(html`
    <div class="row">${sevBadge(x.severity)}${badge(x.status, x.status === 'OPEN' ? 'open' : 'resolved')}<span class="chip">${x.rule_id} · ${x.rule_name}</span></div>
    <p class="panel-note">Severity: ${x.severity_reason}.</p>
    <div class="section-title">Affected resource</div>
    <p><button class="link-btn" data-action="inv-open" data-id="${x.resource_id}">${x.resource_name}</button> <span class="panel-note mono">${x.resource_id} · ${typeLabel(x.resource_type)}</span></p>
    <div class="section-title">Explanation</div><p>${x.explanation}</p>
    <div class="section-title">Impact</div><p>${x.impact}</p>
    <div class="section-title">Recommended remediation</div><p>${x.recommendation}</p>
    ${evidenceHtml(x.evidence)}
    <div class="section-title">Detection rule</div><p class="panel-note">${x.detection_rule}</p>
    <div class="section-title">Timeline</div>
    ${kv({ 'first seen (sim)': dateTime(x.first_seen_sim), 'last seen (sim)': dateTime(x.last_seen_sim), 'first scan': '#' + x.first_scan_id, 'last scan': '#' + x.last_scan_id,
      ...(x.status === 'RESOLVED' ? { 'resolved (sim)': dateTime(x.resolved_sim), 'resolved by scan': '#' + x.resolved_scan_id, resolution: titleCase(x.resolution), 'remediation record': x.remediation_id ? '#' + x.remediation_id : '—' } : {}) })}
    ${x.status === 'OPEN' ? html`<div class="section-title">Remediation</div>
      ${plan.supported ? html`<p>${plan.summary}</p><ol class="steps">${plan.operations.map((o, i) => html`<li><span class="mark ok">${i + 1}</span><div>${o.description}<div class="panel-note mono">${o.action} → ${o.target_id}</div></div></li>`)}</ol>
          <div class="banner warn"><span><b>Risk:</b> ${plan.risk}</span></div>
          <button class="btn btn-primary" data-action="remediate" data-kind="finding" data-id="${x.id}" ${raw(canAnalyze() ? '' : 'disabled title="Analyst or administrator role required"')}>Preview and remediate…</button>`
        : html`<div class="banner info"><span>No automated remediation: ${plan.summary}. ${plan.risk}</span></div>`}` : ''}
    ${r.remediations.length ? html`<div class="section-title">Remediation records</div>${r.remediations.map((m) => html`<div class="card panel" style="margin-bottom:8px;padding:12px">
        <div class="row">${badge(m.status, 'applied')}${badge(m.verification, m.verification === 'VERIFIED' ? 'verified' : m.verification === 'NOT_RESOLVED' ? 'not_resolved' : 'pending')}<span class="panel-note">#${m.id} by ${m.actor} at sim ${dateTime(m.executed_sim)}</span></div>
        <p style="margin-top:6px">${m.message}</p>
        <div class="compare"><div class="cell"><div class="k">Score</div><div class="v">${m.score_before} → ${m.score_after}</div></div><div class="cell"><div class="k">Run-rate</div><div class="v" style="font-size:15px">${money(m.cost_before)} → ${money(m.cost_after)}</div></div></div></div>`)}` : ''}
    ${r.history.length > 1 ? html`<div class="section-title">History of this condition</div>${r.history.map((h) => html`<div class="item-row">${badge(h.status, h.status === 'OPEN' ? 'open' : 'resolved')}<div class="txt"><b>Record #${h.id}</b><span>first seen ${h.first_seen_sim.slice(0, 10)}${h.resolved_sim ? ', resolved ' + h.resolved_sim.slice(0, 10) : ''}</span></div></div>`)}` : ''}
    ${r.audit.length ? html`<div class="section-title">Related audit events</div>${r.audit.map((e) => html`<div class="item-row"><div class="txt"><b>${e.action}</b><span>${dateTime(e.timestamp)} · ${e.actor || 'system'} · ${e.outcome}</span></div></div>`)}` : ''}`);
}

async function renderScans(body) {
  const r = await get('/api/sim/scans', { page_size: 50 });
  mount(body, html`<div class="card panel"><div class="panel-head"><h3>Scan history</h3>
      <div class="row"><span class="panel-note">Tick two scans to compare them</span><button class="btn btn-sm" data-action="scan-compare" ${raw(compare.length === 2 ? '' : 'disabled')}>Compare selected</button></div></div>
    ${table([
      { label: '', render: (s) => html`<input type="checkbox" data-change="scan-pick" data-id="${s.id}" aria-label="Select scan ${s.id}" ${raw(compare.includes(s.id) ? 'checked' : '')}>` },
      { label: 'Scan', render: (s) => '#' + s.id, strong: true }, { label: 'Trigger', render: (s) => titleCase(s.trigger) },
      { label: 'Sim time', render: (s) => dateTime(s.sim_time).slice(0, 16) }, { label: 'Score', render: (s) => s.security_score, num: true },
      { label: 'Open', render: (s) => s.findings_open, num: true }, { label: 'New', render: (s) => s.new_findings, num: true },
      { label: 'Resolved', render: (s) => s.resolved_findings, num: true }, { label: 'Run-rate', render: (s) => money(s.monthly_run_rate, 0), num: true },
      { label: 'By', render: (s) => s.actor || 'system' },
    ], r.items, { caption: 'Scan history' })}
    <div id="compare-result"></div></div>`);
}

async function renderRemediations(body) {
  const r = await get('/api/sim/remediation');
  mount(body, html`<div class="card panel"><div class="panel-head"><h3>Executed remediations</h3><span class="tag">proposed → executed → verified</span></div>
    ${r.items.length ? r.items.map((m) => html`<div class="card panel" style="margin-bottom:10px;padding:14px">
      <div class="row">${badge(m.status, 'applied')}${badge(m.verification, m.verification === 'VERIFIED' ? 'verified' : 'not_resolved')}<b>${m.plan.summary}</b><span class="spacer"></span><span class="panel-note">#${m.id} · ${m.actor} · ${dateTime(m.executed_sim).slice(0, 16)}</span></div>
      <div class="compare"><div class="cell"><div class="k">Security score</div><div class="v">${m.score_before} → ${m.score_after}</div></div>
        <div class="cell"><div class="k">Monthly run-rate</div><div class="v" style="font-size:16px">${money(m.cost_before)} → ${money(m.cost_after)}</div><div class="s">${m.realized_monthly_savings > 0 ? 'Verified saving ' + money(m.realized_monthly_savings) + ' (simulated)' : 'No cost change'}</div></div>
        <div class="cell"><div class="k">Target</div><div class="v" style="font-size:14px">${titleCase(m.target_kind)} #${m.target_id}</div><div class="s mono">${m.target_key}</div></div></div>
      <ol class="steps">${m.results.map((s, i) => html`<li><span class="mark ok">${i + 1}</span><div>${s.message}</div></li>`)}</ol></div>`)
      : empty('No remediation has been executed yet', 'Open a finding and choose "Preview and remediate".')}</div>`);
}

async function renderRules(body) {
  const r = await get('/api/sim/rules');
  mount(body, html`<div class="card panel"><div class="panel-head"><h3>Detection rules</h3><span class="tag">${r.items.length} rules - transparent severity logic</span></div>
    <p class="panel-note" style="margin-top:0">These rules read configuration, derived reachability, the IAM policy graph and recent metrics. CloudShield does not claim to detect every real-world attack.</p>
    ${table([{ label: 'Rule', key: 'rule_id', strong: true, mono: true }, { label: 'Name', key: 'name' }, { label: 'Category', key: 'category' },
      { label: 'Base severity', render: (x) => sevBadge(x.severity) }, { label: 'Detection and severity logic', key: 'logic' }], r.items, { caption: 'Detection rules' })}</div>`);
}

export function init() {
  registerActions({
    'sec-tab': (el) => { tab = el.dataset.tab; rerender(); },
    'sec-filter': (el) => { f[el.dataset.key] = el.dataset.val; f.page = 1; rerender(); },
    'sec-cat': (el) => { f.category = el.value; f.page = 1; rerender(); },
    'sec-search': (el) => { f.text = el.value.trim(); f.page = 1; rerender(); },
    'sec-page': (el) => { f.page = Number(el.dataset.page); rerender(); },
    'sec-open': (el) => openFinding(el.dataset.id),
    'scan-pick': (el) => {
      const id = Number(el.dataset.id);
      compare = el.checked ? [...compare, id].slice(-2) : compare.filter((x) => x !== id);
      rerender();
    },
    'scan-compare': async () => {
      const [a, b] = [...compare].sort((x, y) => x - y);
      const r = await get('/api/sim/scans/compare', { a, b });
      mount('compare-result', html`<div class="section-title">Scan #${a} → #${b}</div>
        <div class="compare"><div class="cell"><div class="k">Security score</div><div class="v">${r.from.security_score} → ${r.to.security_score}</div><div class="s">${r.score_delta >= 0 ? '+' : ''}${r.score_delta}</div></div>
          <div class="cell"><div class="k">Resolved</div><div class="v">${r.resolved.length}</div></div><div class="cell"><div class="k">Introduced</div><div class="v">${r.introduced.length}</div></div>
          <div class="cell"><div class="k">Unchanged</div><div class="v">${r.unchanged}</div></div></div>
        ${r.resolved.length ? html`<b>Resolved</b>${r.resolved.map((x) => html`<div class="item-row">${badge('resolved', 'resolved')}<div class="txt"><b>${x.title}</b><span class="mono">${x.finding_key}</span></div></div>`)}` : ''}
        ${r.introduced.length ? html`<b>Introduced</b>${r.introduced.map((x) => html`<div class="item-row">${badge('new', 'open')}<div class="txt"><b>${x.title}</b><span class="mono">${x.finding_key}</span></div></div>`)}` : ''}`);
    },
  });
}

export { toast };

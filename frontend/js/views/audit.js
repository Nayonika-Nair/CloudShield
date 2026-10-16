// ============================================================
// Audit Log & Configuration Drift view
// ============================================================
// The audit trail is append-only. Drift (current state vs a saved baseline)
// is shown separately because a change is an observation, not necessarily a risk.

import { get, post } from '../api.js';
import { isAdmin, registerActions, rerender } from '../state.js';
import { badge, dateTime, empty, fmtValue, html, jsonBlock, mount, openDrawer, pager, raw, table, titleCase, toast, typeLabel } from '../utils.js';

export const view = { id: 'audit', title: ['Governance', 'Audit Log & Drift'], render };

let tab = 'audit';
const q = { action: '', outcome: '', page: 1 };

async function render(box) {
  try { await get('/api/sim/environment'); } catch (e) {
    if (e.code === 'no_environment') { mount(box, html`<div class="card panel">${empty('No simulated environment', 'Generate one on the Simulator page.')}</div>`); return; }
    throw e;
  }
  mount(box, html`
    <p class="page-intro">Every state-changing action - generation, lifecycle operations, scenarios, scans, remediations, what-ifs and configuration changes - is recorded with its actor, target, outcome and before/after values. Records cannot be edited or deleted through the API.</p>
    <div class="tabs" role="tablist">
      <button class="tab ${tab === 'audit' ? 'active' : ''}" role="tab" aria-selected="${tab === 'audit'}" data-action="aud-tab" data-tab="audit">Audit log</button>
      <button class="tab ${tab === 'drift' ? 'active' : ''}" role="tab" aria-selected="${tab === 'drift'}" data-action="aud-tab" data-tab="drift">Configuration drift</button>
    </div><div id="aud-body"></div>`);
  const body = document.getElementById('aud-body');
  if (tab === 'audit') await renderAudit(body); else await renderDrift(body);
}

async function renderAudit(body) {
  const data = await get('/api/sim/audit', { action: q.action, outcome: q.outcome, page: q.page, page_size: 25 });
  const groups = ['', 'ENVIRONMENT', 'ACTION', 'SCENARIO', 'SCAN', 'REMEDIATION', 'WHATIF', 'TIME', 'CONFIG', 'REPORT', 'BASELINE'];
  mount(body, html`
    <div class="filter-bar">
      <label class="sr-only" for="aud-action">Action</label>
      <select id="aud-action" data-change="aud-action">${groups.map((g) => html`<option value="${g}" ${raw(q.action === g ? 'selected' : '')}>${g ? g + '*' : 'All actions'}</option>`)}</select>
      <label class="sr-only" for="aud-outcome">Outcome</label>
      <select id="aud-outcome" data-change="aud-outcome">${['', 'SUCCESS', 'REJECTED', 'FAILURE'].map((o) => html`<option value="${o}" ${raw(q.outcome === o ? 'selected' : '')}>${o || 'Any outcome'}</option>`)}</select>
      <span class="spacer"></span><span class="panel-note">${data.total} events</span>
    </div>
    <div class="card panel">
      ${data.items.length ? table([
        { label: '#', render: (e) => e.id, num: true }, { label: 'Time (UTC)', render: (e) => dateTime(e.timestamp) },
        { label: 'Sim time', render: (e) => (e.sim_time ? dateTime(e.sim_time).slice(0, 10) : '') },
        { label: 'Actor', render: (e) => e.actor || 'system' }, { label: 'Action', render: (e) => html`<b>${e.action}</b>` },
        { label: 'Target', render: (e) => html`${e.target_type || ''} <span class="mono">${e.target_id || ''}</span>` },
        { label: 'Outcome', render: (e) => badge(e.outcome, e.outcome === 'SUCCESS' ? 'ok' : e.outcome === 'REJECTED' ? 'warn' : 'fail') },
        { label: 'Summary', render: (e) => summary(e) },
      ], data.items, { caption: 'Audit events', rowAttrs: (e) => `data-action="aud-open" data-id="${e.id}" tabindex="0"` }) : empty('No events match')}
      ${pager(data.page, data.page_size, data.total, 'aud-page')}
    </div>`);
  window.__audit = Object.fromEntries(data.items.map((e) => [e.id, e]));
}

function summary(e) {
  const d = e.details || {};
  if (d.error) return d.error;
  if (d.message) return d.message;
  if (d.messages) return d.messages[0];
  if (d.summary) return d.summary;
  if (d.findings_open !== undefined) return `${d.findings_open} open, ${d.new} new, ${d.resolved} resolved, score ${d.security_score}`;
  if (d.verification) return `${d.verification} (score ${d.score}, run-rate ${d.run_rate})`;
  if (e.after && Object.keys(e.after).length) return Object.keys(e.after).length + ' resource(s) changed';
  return '';
}

async function renderDrift(body) {
  const d = await get('/api/sim/drift');
  if (!d.has_baseline) { mount(body, html`<div class="card panel">${empty('No baseline', 'Capture a baseline to start tracking drift.')}</div>`); return; }
  const s = d.summary;
  mount(body, html`
    <div class="banner info"><span><b>Drift is not a finding.</b> It lists resources whose configuration differs from the baseline captured at ${dateTime(d.baseline_time)} (simulated time). Security-relevant drift is listed first; whether it is risky is decided by the security rules and the scan.</span></div>
    <div class="stat-grid">
      <div class="card stat-card"><div class="label">Drifted resources</div><div class="value">${s.total}</div></div>
      <div class="card stat-card"><div class="label">Security-relevant</div><div class="value ${s.security_relevant ? 'v-warn' : 'v-ok'}">${s.security_relevant}</div></div>
      <div class="card stat-card"><div class="label">Created / deleted</div><div class="value">${s.created} / ${s.deleted}</div></div>
      <div class="card stat-card"><div class="label">Modified</div><div class="value">${s.modified}</div></div>
    </div>
    <div class="row" style="margin-bottom:12px"><button class="btn" data-action="drift-baseline" ${raw(isAdmin() ? '' : 'disabled title="Administrator role required"')}>Accept current state as the new baseline…</button>
      <span class="panel-note">Resets drift to zero. The audit log keeps the history.</span></div>
    <div class="card panel">
      ${d.items.length ? table([
        { label: 'Resource', render: (i) => html`<b>${i.name}</b><div class="panel-note mono">${i.resource_id}</div>` }, { label: 'Type', render: (i) => typeLabel(i.resource_type) },
        { label: 'Change', render: (i) => badge(i.change, i.change === 'deleted' ? 'fail' : i.change === 'created' ? 'info' : 'warn') },
        { label: 'Security-relevant', render: (i) => (i.security_relevant ? badge('yes', 'fail') : badge('no', 'neutral')) },
        { label: 'Changed fields', render: (i) => (i.fields.length ? html`${i.fields.map((f) => html`<div><b>${f.field}</b>: <span style="color:var(--critical)">${fmtValue(f.before)}</span> → <span style="color:var(--ok)">${fmtValue(f.after)}</span></div>`)}` : '') },
      ], d.items, { caption: 'Configuration drift' }) : empty('No drift', 'The environment matches its baseline.')}
    </div>`);
}

export function init() {
  registerActions({
    'aud-tab': (el) => { tab = el.dataset.tab; rerender(); },
    'aud-action': (el) => { q.action = el.value; q.page = 1; rerender(); },
    'aud-outcome': (el) => { q.outcome = el.value; q.page = 1; rerender(); },
    'aud-page': (el) => { q.page = Number(el.dataset.page); rerender(); },
    'aud-open': (el) => {
      const e = (window.__audit || {})[el.dataset.id];
      if (!e) return;
      openDrawer(`${e.action} #${e.id}`, html`
        <div class="row">${badge(e.outcome, e.outcome === 'SUCCESS' ? 'ok' : 'warn')}<span class="panel-note">${dateTime(e.timestamp)} UTC · actor ${e.actor || 'system'}</span></div>
        <dl class="kv" style="margin-top:10px"><dt>Target</dt><dd class="mono">${e.target_type || ''} ${e.target_id || ''}</dd><dt>Sim time</dt><dd>${e.sim_time ? dateTime(e.sim_time) : '—'}</dd></dl>
        ${e.details ? html`<div class="section-title">Details</div>${jsonBlock(e.details)}` : ''}
        ${e.before ? html`<div class="section-title">Before</div>${jsonBlock(e.before)}` : ''}
        ${e.after ? html`<div class="section-title">After</div>${jsonBlock(e.after)}` : ''}`);
    },
    'drift-baseline': async () => {
      if (!window.confirm('Accept the current state as the new baseline? Drift will reset to zero.')) return;
      await post('/api/sim/drift/baseline');
      toast('New baseline captured', 'success');
      rerender();
    },
  });
}

export { titleCase };

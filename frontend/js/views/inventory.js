// ============================================================
// Resource Inventory view
// ============================================================
// Browse every simulated resource, inspect relationships, metrics and
// network reachability, and perform validated lifecycle operations.

import { get, post } from '../api.js';
import { actionCatalog, invalidateIndex, paramFields, readParams, resourceIndex, targetTypes } from '../actionform.js';
import { isAdmin, registerActions, registerForms, rerender, state } from '../state.js';
import {
  badge, closeModal, date, dateTime, empty, errorBanner, html, kv, loading, money, mount, num, openDrawer, openModal, pager, raw, setDrawerBody,
  setModalActions, setModalBody, sevBadge, sparkline, table, tagChips, titleCase, toast, typeLabel, fmtValue,
} from '../utils.js';

export const view = { id: 'inventory', title: ['Cloud Assets', 'Resource Inventory'], render };

const q = { type: '', state: '', text: '', page: 1 };
const PAGE = 25;
let debounce = null;
let openId = null;

async function render(box) {
  let list;
  try {
    list = await get('/api/sim/resources', { type: q.type, state: q.state, q: q.text, page: q.page, page_size: PAGE });
  } catch (e) {
    if (e.code === 'no_environment') { mount(box, html`<div class="card panel">${empty('No simulated environment', 'Generate one on the Simulator page.')}</div>`); return; }
    throw e;
  }
  const counts = list.counts;
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  mount(box, html`
    <p class="page-intro">Every resource in the simulated account, with its real relationships and monthly cost. Select a row to see metrics, network reachability, findings and the operations you can perform.</p>
    <div class="filter-bar" role="group" aria-label="Filter by resource type">
      <button class="chip-btn ${q.type === '' ? 'active' : ''}" data-action="inv-type" data-type="">All (${total})</button>
      ${Object.entries(counts).filter(([, c]) => c).map(([t, c]) => html`<button class="chip-btn ${q.type === t ? 'active' : ''}" data-action="inv-type" data-type="${t}">${typeLabel(t)} (${c})</button>`)}
    </div>
    <div class="filter-bar">
      <label class="sr-only" for="inv-search">Search resources</label>
      <input id="inv-search" type="text" placeholder="Search id, name or tag…" value="${q.text}" data-input="inv-search" style="min-width:260px">
      <label class="sr-only" for="inv-state">State</label>
      <select id="inv-state" data-change="inv-state"><option value="">Any state</option>
        ${['running', 'stopped', 'terminated', 'available', 'in-use', 'completed', 'associated', 'unassociated', 'active', 'attached', 'detached'].map((s) => html`<option value="${s}" ${raw(q.state === s ? 'selected' : '')}>${s}</option>`)}</select>
      <span class="spacer"></span>
      <button class="btn btn-primary" data-action="inv-create" ${raw(isAdmin() ? '' : 'disabled title="Administrator role required"')}>Create resource…</button>
    </div>
    <div class="card panel">
      ${list.items.length ? table([
        { label: 'Name', render: (r) => html`<b>${r.name}</b>`, strong: true },
        { label: 'ID', render: (r) => r.id, mono: true },
        { label: 'Type', render: (r) => typeLabel(r.type) },
        { label: 'State', render: (r) => (r.state ? badge(r.state, r.state) : '') },
        { label: 'Key attributes', render: (r) => html`${Object.entries(r.attributes).filter(([, v]) => v !== null && v !== undefined && typeof v !== 'object').slice(0, 3).map(([k, v]) => html`<span class="chip">${k.replace(/_/g, ' ')}: ${String(v)}</span>`)}` },
        { label: 'Env', render: (r) => r.tags.environment || '' },
        { label: 'Monthly cost', num: true, render: (r) => (r.monthly_cost ? money(r.monthly_cost) : '') },
      ], list.items, { caption: 'Simulated resources', rowAttrs: (r) => `data-action="inv-open" data-id="${esc2(r.id)}" tabindex="0"` })
        : empty('No resources match', 'Change the filters or search text.')}
      ${pager(list.page, list.page_size, list.total, 'inv-page')}
    </div>`);
}

const esc2 = (s) => String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');

// ------------------------------------------------------------------ drawer
export function exposureHtml(re) {
  if (!re) return '';
  const ex = re.exposures;
  return html`
    <div class="section-title">Network reachability</div>
    <div class="banner ${re.internet_reachable ? 'warn' : 'ok'}">${re.internet_reachable ? 'Reachable from the internet on at least one rule.' : 'Not reachable from the internet.'}</div>
    ${ex.length ? ex.map((e) => html`<div class="card panel" style="margin-bottom:8px;padding:10px 12px">
        <div class="row" style="justify-content:space-between"><b>${e.security_group} · ${e.protocol}/${e.from_port}${e.to_port !== e.from_port ? '-' + e.to_port : ''} from ${e.source}</b>${e.reachable ? badge('reachable', 'fail') : badge('blocked', 'ok')}</div>
        <ul class="steps">${e.steps.map((s) => html`<li><span class="mark ${s.ok ? 'ok' : 'no'}">${s.ok ? '✓' : '✕'}</span><div><b>${s.check}</b><div class="panel-note">${s.detail}</div></div></li>`)}</ul>
        <div class="panel-note">${e.explanation}</div></div>`) : html`<p class="panel-note">No security-group rule allows traffic from 0.0.0.0/0.</p>`}
    ${re.egress ? html`<p class="panel-note"><b>Outbound internet:</b> ${re.egress.open ? 'open' : 'closed'} — ${re.egress.detail}${re.egress.unrestricted ? ' (all ports allowed)' : ''}</p>` : ''}`;
}

function metricsHtml(metrics) {
  const names = Object.keys(metrics);
  if (!names.length) return '';
  return html`<div class="section-title">Metrics (last 30 simulated days)</div>
    ${names.map((m) => {
      const vals = metrics[m].map((p) => p.value);
      const last = vals[vals.length - 1];
      const avg = vals.reduce((a, b) => a + b, 0) / vals.length;
      return html`<div class="row" style="justify-content:space-between;border-bottom:1px solid var(--border);padding:4px 0"><span style="width:110px"><b>${m}</b></span>${sparkline(vals)}<span class="panel-note" style="width:150px;text-align:right">last ${num(last, 1)} · avg ${num(avg, 1)}</span></div>`;
    })}`;
}

export async function openResource(id) {
  openId = id;
  openDrawer(id, html`<div class="loading"><span class="spinner"></span>Loading resource…</div>`);
  let d;
  try { d = await get('/api/sim/resources/' + encodeURIComponent(id)); } catch (e) { setDrawerBody(errorBanner(e)); return; }
  const r = d.resource;
  const catalog = await actionCatalog();
  const applicable = catalog.filter((a) => targetTypes(a).includes(d.type));
  const simple = {};
  Object.entries(r).forEach(([k, v]) => { if (!['tags', 'type', 'id', 'name', 'ingress', 'egress', 'routes', 'statements', 'access_keys', 'trust'].includes(k)) simple[k] = v; });
  mount('drawer-title', `${r.name || r.id}`);
  setDrawerBody(html`
    <div class="row" style="margin-bottom:8px">${badge(typeLabel(d.type), 'neutral')}${r.state ? badge(r.state, r.state) : ''}<span class="mono panel-note">${r.id}</span></div>
    <div class="compare"><div class="cell"><div class="k">Monthly cost (simulated)</div><div class="v">${money(d.monthly_cost)}</div><div class="s">at the environment price list</div></div>
      <div class="cell"><div class="k">Created (sim)</div><div class="v" style="font-size:15px">${date(r.created_at)}</div></div></div>
    <div class="section-title">Tags</div><div>${tagChips(r.tags)}</div>
    ${d.open_findings.length ? html`<div class="section-title">Open findings</div>${d.open_findings.map((f) => html`<div class="item-row">${sevBadge(f.severity)}<div class="txt"><b>${f.title}</b><span>${f.rule_id}</span></div></div>`)}` : ''}
    ${d.recommendations.length ? html`<div class="section-title">Optimization recommendations</div>${d.recommendations.map((x) => html`<div class="item-row">${badge(x.priority, x.priority.toLowerCase())}<div class="txt"><b>${x.title}</b><span>Estimated saving ${money(x.estimated_monthly_savings)}/mo</span></div></div>`)}` : ''}
    ${exposureHtml(d.reachability)}
    ${r.ingress ? html`<div class="section-title">Inbound rules</div>${table([{ label: 'Protocol', key: 'protocol' }, { label: 'From', key: 'from_port' }, { label: 'To', key: 'to_port' }, { label: 'Source', render: (x) => x.cidr || x.source_sg }, { label: 'Description', key: 'description' }], r.ingress)}<div class="section-title">Outbound rules</div>${table([{ label: 'Protocol', key: 'protocol' }, { label: 'From', key: 'from_port' }, { label: 'To', key: 'to_port' }, { label: 'Destination', render: (x) => x.cidr || x.source_sg }], r.egress)}` : ''}
    ${r.routes ? html`<div class="section-title">Routes</div>${table([{ label: 'Destination', key: 'destination', mono: true }, { label: 'Target', render: (x) => x.target }], r.routes)}` : ''}
    ${r.statements ? html`<div class="section-title">Policy statements</div>${table([{ label: 'Effect', key: 'effect' }, { label: 'Actions', render: (x) => x.actions.join(', ') }, { label: 'Resources', render: (x) => x.resources.join(', ') }], r.statements)}` : ''}
    ${r.trust ? html`<div class="section-title">Trust policy</div>${table([{ label: 'Principal type', key: 'type' }, { label: 'Principal', key: 'value', mono: true }], r.trust)}` : ''}
    ${r.access_keys ? html`<div class="section-title">Access keys</div>${r.access_keys.length ? table([{ label: 'Key', key: 'id', mono: true }, { label: 'Status', render: (k) => badge(k.status, k.status === 'active' ? 'ok' : 'neutral') }, { label: 'Created', render: (k) => date(k.created_at) }, { label: 'Last used', render: (k) => date(k.last_used) }], r.access_keys) : '<p class="panel-note">No access keys.</p>'}` : ''}
    <div class="section-title">Properties</div>${kv(simple)}
    ${metricsHtml(d.metrics)}
    <div class="section-title">Relationships</div>
    ${d.relationships_out.length || d.relationships_in.length ? html`<ul style="margin-left:18px;font-size:13px">
      ${d.relationships_out.map((x) => html`<li>${x.relation.replace(/_/g, ' ')} → <button class="link-btn mono" data-action="inv-open" data-id="${x.target}">${x.target}</button></li>`)}
      ${d.relationships_in.map((x) => html`<li><button class="link-btn mono" data-action="inv-open" data-id="${x.source}">${x.source}</button> ${x.relation.replace(/_/g, ' ')} → this</li>`)}</ul>` : html`<p class="panel-note">None.</p>`}
    <div class="section-title">Operations</div>
    ${applicable.length ? html`<form data-form="inv-action" id="inv-action-form" novalidate>
      <div class="field"><label for="inv-action-select">Operation</label><select id="inv-action-select" data-change="inv-action-select">${applicable.map((a) => html`<option value="${a.name}">${a.label} (${a.name})</option>`)}</select></div>
      <div id="inv-action-params"></div>
      <button class="btn btn-primary" type="submit" ${raw(isAdmin() ? '' : 'disabled title="Administrator role required"')}>Run operation…</button>
      ${isAdmin() ? '' : html`<span class="panel-note"> Administrator role required.</span>`}
    </form>` : html`<p class="panel-note">No operations are defined for this resource type.</p>`}
  `);
  if (applicable.length) renderParams(applicable[0]);
}

function renderParams(spec) {
  const box = document.getElementById('inv-action-params');
  if (!box) return;
  mount(box, html`<p class="panel-note">${spec.description} <b>Risk: ${spec.risk}</b></p>${paramFields(spec, 'inv')}`);
}

async function confirmAndRun(spec, target, params) {
  return new Promise((resolve) => {
    openModal({
      title: 'Run operation on the simulated environment',
      body: html`<p><b>${spec.label}</b> <span class="mono">(${spec.name})</span></p>
        <dl class="kv"><dt>Target</dt><dd class="mono">${target || '(new resource)'}</dd><dt>Risk</dt><dd>${badge(spec.risk, spec.risk === 'high' ? 'fail' : spec.risk === 'medium' ? 'warn' : 'ok')}</dd>
        <dt>Parameters</dt><dd>${Object.keys(params).length ? html`<pre class="code">${JSON.stringify(params, null, 2)}</pre>` : 'none'}</dd></dl>
        <p class="panel-note">${spec.description} The change is validated, applied atomically and recorded in the audit log.</p>`,
      actions: [{ label: 'Cancel', onClick: () => { closeModal(); resolve(null); } },
        { label: 'Run operation', kind: spec.risk === 'high' ? 'danger' : 'primary', onClick: async (btn) => {
          btn.disabled = true;
          try { const r = await post('/api/sim/resources/actions', { action: spec.name, target_id: target, params }); closeModal(); resolve(r); } catch (e) {
            setModalBody(html`<div class="banner error" role="alert">${e.message}</div><p class="panel-note">Nothing was changed. The rejected attempt was recorded in the audit log.</p>`);
            setModalActions([{ label: 'Close', onClick: () => { closeModal(); resolve(null); } }]);
          }
        } }],
    });
  });
}

export function init() {
  registerActions({
    'inv-type': (el) => { q.type = el.dataset.type; q.page = 1; rerender(); },
    'inv-state': (el) => { q.state = el.value; q.page = 1; rerender(); },
    'inv-page': (el) => { q.page = Number(el.dataset.page); rerender(); },
    'inv-search': (el) => {
      clearTimeout(debounce);
      debounce = setTimeout(async () => { q.text = el.value; q.page = 1; await rerender(); const i = document.getElementById('inv-search'); if (i) { i.focus(); i.setSelectionRange(i.value.length, i.value.length); } }, 350);
    },
    'inv-open': (el) => openResource(el.dataset.id),
    'inv-action-select': async (el) => {
      const cat = await actionCatalog();
      renderParams(cat.find((a) => a.name === el.value));
    },
    'inv-create': async () => {
      const cat = (await actionCatalog()).filter((a) => !a.target_type);
      openModal({
        title: 'Create a resource',
        body: html`<form id="create-form" data-form="inv-create" novalidate><div class="field"><label for="create-action">What to create</label>
          <select id="create-action" data-change="inv-create-select">${cat.map((a) => html`<option value="${a.name}">${a.label} (${a.name})</option>`)}</select></div>
          <div id="create-params"></div></form>`,
        actions: [{ label: 'Cancel', onClick: closeModal }, { label: 'Review and create', kind: 'primary', onClick: submitCreate }],
      });
      renderCreate(cat[0]);
    },
    'inv-create-select': async (el) => renderCreate((await actionCatalog()).find((a) => a.name === el.value)),
  });
  registerForms({
    'inv-action': async (form) => {
      const cat = await actionCatalog();
      const spec = cat.find((a) => a.name === form.querySelector('#inv-action-select').value);
      let params;
      try { params = readParams(spec, form); } catch (e) { toast(e.message, 'error'); return; }
      const res = await confirmAndRun(spec, openId, params);
      if (res) {
        toast(res.result.message, 'success');
        invalidateIndex();
        await rerender();
        if (res.result.created && res.result.created[0]) await openResource(res.result.created[0]);
        else if (document.getElementById('drawer-root')) await openResource(openId);
      }
    },
    'inv-create': () => submitCreate(),
  });
}

async function renderCreate(spec) {
  const idx = await resourceIndex();
  const box = document.getElementById('create-params');
  if (!box) return;
  const hint = {
    subnet_id: idx.filter((r) => r.type === 'subnet').slice(0, 3).map((r) => r.id).join(', '),
    vpc_id: idx.filter((r) => r.type === 'vpc').map((r) => r.id).join(', '),
    sg_ids: idx.filter((r) => r.type === 'security_group').slice(0, 2).map((r) => r.id).join(', '),
  };
  mount(box, html`<p class="panel-note">${spec.description}</p>${paramFields(spec, 'cr')}
    ${Object.entries(hint).filter(([k, v]) => spec.params.some((p) => p.name === k) && v).map(([k, v]) => html`<p class="panel-note">Example ${k}: <span class="mono">${v}</span></p>`)}`);
  box.dataset.action = spec.name;
}

async function submitCreate() {
  const box = document.getElementById('create-params');
  const cat = await actionCatalog();
  const spec = cat.find((a) => a.name === box.dataset.action);
  let params;
  try { params = readParams(spec, box); } catch (e) { toast(e.message, 'error'); return; }
  closeModal();
  const res = await confirmAndRun(spec, null, params);
  if (res) { toast(res.result.message, 'success'); invalidateIndex(); await rerender(); if (res.result.created && res.result.created[0]) await openResource(res.result.created[0]); }
}

export { fmtValue, loading, dateTime, titleCase, state };

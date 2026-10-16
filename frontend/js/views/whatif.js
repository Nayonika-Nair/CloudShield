// ============================================================
// What-If Simulation view
// ============================================================
// Evaluate proposed changes on an isolated copy of the environment and
// compare cost, security, availability and compliance with the baseline.
// Discarding a simulation leaves the live environment untouched; only an
// explicit, confirmed apply changes it.

import { get, post } from '../api.js';
import { actionCatalog, invalidateIndex, paramFields, readParams, resourceIndex, targetTypes } from '../actionform.js';
import { whatIfSummary } from '../remediation.js';
import { canAnalyze, registerActions, registerForms, rerender, state } from '../state.js';
import { badge, closeModal, dateTime, empty, esc, html, mount, openModal, raw, setModalBody, table, toast } from '../utils.js';

export const view = { id: 'whatif', title: ['Simulation', 'What-If Analysis'], render };

let changes = [];
let lastResult = null;   // { id, status, result }

async function render(box) {
  let env;
  try { env = await get('/api/sim/environment'); } catch (e) {
    if (e.code === 'no_environment') { mount(box, html`<div class="card panel">${empty('No simulated environment', 'Generate one on the Simulator page.')}</div>`); return; }
    throw e;
  }
  const [catalog, idx, hist, recs] = await Promise.all([actionCatalog(), resourceIndex(), get('/api/sim/whatif'), get('/api/sim/recommendations', { status: 'OPEN', page_size: 50 })]);
  const usable = recs.items.filter((r) => r.remediation.supported).slice(0, 12);
  mount(box, html`
    <p class="page-intro">Build a hypothetical change set - resize an instance, stop an idle host, close a port, make a bucket private, enable encryption - and see its effect on cost, exposure, availability and compliance <b>before</b> touching anything. The simulation runs on a copy; the baseline fingerprint is checked afterwards to prove it did not change.</p>
    <div class="grid-main-side">
      <div class="stack">
        <div class="card panel">
          <div class="panel-head"><h3>1. Proposed changes</h3>
            <div class="row"><label class="sr-only" for="wi-load">Load from recommendation</label>
              <select id="wi-load" data-change="wi-load" style="width:auto;max-width:320px"><option value="">Load a plan from a recommendation…</option>${usable.map((r) => html`<option value="${r.id}">${r.title}</option>`)}</select></div></div>
          ${changes.length ? html`<ol class="steps">${changes.map((c, i) => html`<li><span class="mark ok">${i + 1}</span><div><b>${c.action}</b> → <span class="mono">${c.target_id || '(new resource)'}</span>${Object.keys(c.params).length ? html`<div class="panel-note mono">${JSON.stringify(c.params)}</div>` : ''}</div>
              <button class="icon-btn" style="margin-left:auto" data-action="wi-remove" data-i="${i}" aria-label="Remove change ${i + 1}">Remove</button></li>`)}</ol>` : html`<p class="panel-note">No changes yet. Add one below or load a recommendation's plan.</p>`}
          <form data-form="wi-add" novalidate>
            <div class="form-grid">
              <div class="field"><label for="wi-action">Operation</label><select id="wi-action" data-change="wi-action">${[...catalog].sort((x, y) => x.label.localeCompare(y.label)).map((a) => html`<option value="${a.name}">${a.label} (${a.name})</option>`)}</select></div>
              <div class="field" id="wi-target-field"><label for="wi-target">Target resource</label><input id="wi-target" type="text" list="wi-targets" autocomplete="off" placeholder="resource id"><datalist id="wi-targets"></datalist></div>
            </div>
            <div id="wi-params"></div>
            <button class="btn" type="submit">Add change</button>
          </form>
          <div class="row" style="margin-top:14px"><button class="btn btn-primary" data-action="wi-run" ${raw(changes.length && canAnalyze() ? '' : 'disabled')}>2. Run what-if simulation</button>
            <button class="btn" data-action="wi-clear" ${raw(changes.length ? '' : 'disabled')}>Discard changes</button></div>
        </div>
        <div id="wi-result">${lastResult ? resultCard(lastResult) : html`<div class="card panel">${empty('No simulation yet', 'Run a what-if to see the comparison with the baseline.')}</div>`}</div>
      </div>
      <div class="card panel"><div class="panel-head"><h3>Simulation history</h3></div>
        ${hist.items.length ? table([
          { label: '#', render: (w) => w.id }, { label: 'Title', render: (w) => w.title || 'Untitled', strong: true },
          { label: 'Cost Δ', render: (w) => (w.cost_delta === 0 ? '—' : (w.cost_delta > 0 ? '+' : '−') + '$' + Math.abs(w.cost_delta).toFixed(0)), num: true },
          { label: 'Score Δ', render: (w) => (w.score_delta > 0 ? '+' : '') + w.score_delta, num: true },
          { label: 'Status', render: (w) => badge(w.status, w.status === 'APPLIED' ? 'applied' : 'simulated') },
        ], hist.items, { caption: 'What-if history', rowAttrs: (w) => `data-action="wi-open" data-id="${w.id}" tabindex="0"` }) : empty('No simulations run')}
        <p class="panel-note">Every simulation is recorded in the audit log.</p>
      </div>
    </div>`);
  await fillAction([...catalog].sort((x, y) => x.label.localeCompare(y.label))[0]);
  if (!state.user) return;
}

function resultCard(w) {
  const r = w.result;
  return html`<div class="card panel">
    <div class="panel-head"><h3>3. Result ${w.title ? '— ' + w.title : ''}</h3><div class="row">${badge(w.status, w.status === 'APPLIED' ? 'applied' : 'simulated')}<span class="tag">#${w.id} · ${dateTime(w.created_at)}</span></div></div>
    <ol class="steps">${r.steps.map((s, i) => html`<li><span class="mark ok">${i + 1}</span><div>${s.message}</div></li>`)}</ol>
    ${whatIfSummary(r)}
    <div class="section-title">Assumptions and limits</div><ul style="margin-left:18px;font-size:12.5px;color:var(--text-dim)">${r.limitations.map((l) => html`<li>${l}</li>`)}</ul>
    <div class="row" style="margin-top:14px">
      <button class="btn btn-danger" data-action="wi-apply" data-id="${w.id}" ${raw(w.status === 'SIMULATED' && canAnalyze() ? '' : 'disabled')}>Apply to the simulated environment…</button>
      <span class="panel-note">${w.status === 'APPLIED' ? 'Already applied.' : 'Applying is a separate, confirmed step - the baseline stays untouched until then.'}</span></div>
  </div>`;
}

async function fillAction(spec) {
  const params = document.getElementById('wi-params');
  const dl = document.getElementById('wi-targets');
  const tField = document.getElementById('wi-target-field');
  if (!params) return;
  const idx = await resourceIndex();
  const types = targetTypes(spec);
  tField.classList.toggle('hidden', !types.length);
  dl.innerHTML = types.length ? idx.filter((r) => types.includes(r.type)).map((r) => `<option value="${esc(r.id)}">${esc(r.name)}</option>`).join('') : '';
  document.getElementById('wi-target').value = '';
  mount(params, html`<p class="panel-note">${spec.description} <b>Risk: ${spec.risk}</b></p>${paramFields(spec, 'wi')}`);
}

export function init() {
  registerActions({
    'wi-action': async (el) => fillAction((await actionCatalog()).find((a) => a.name === el.value)),
    'wi-remove': (el) => { changes.splice(Number(el.dataset.i), 1); rerender(); },
    'wi-clear': () => { changes = []; lastResult = null; rerender(); },
    'wi-load': async (el) => {
      if (!el.value) return;
      const recs = await get('/api/sim/recommendations', { status: 'OPEN', page_size: 50 });
      const rec = recs.items.find((r) => String(r.id) === el.value);
      if (rec) { changes = rec.remediation.operations.map((o) => ({ action: o.action, target_id: o.target_id, params: o.params })); toast(`Loaded ${changes.length} step(s) from "${rec.title}"`, 'info'); }
      rerender();
    },
    'wi-run': async (el) => {
      el.disabled = true;
      try {
        const w = await post('/api/sim/whatif', { changes, title: changes.length ? `${changes[0].action} +${changes.length - 1}` : undefined });
        lastResult = w;
        toast('Simulation complete. The live environment was not changed.', 'success');
      } finally { el.disabled = false; }
      rerender();
    },
    'wi-open': async (el) => { lastResult = await get('/api/sim/whatif/' + el.dataset.id); rerender(); },
    'wi-apply': (el) => {
      const id = Number(el.dataset.id);
      openModal({
        title: 'Apply this what-if to the simulated environment?',
        body: html`<p>This executes the ${lastResult.changes.length} simulated step(s) for real in the simulated account, atomically, and records them in the audit log.</p><p class="panel-note">Nothing here touches real AWS.</p>
          <label class="check"><input type="checkbox" id="wi-ack"> I understand and want to apply this change.</label>`,
        actions: [{ label: 'Cancel', onClick: closeModal }, { label: 'Apply', kind: 'danger', onClick: async (btn) => {
          if (!document.getElementById('wi-ack').checked) { toast('Tick the confirmation box first', 'error'); return; }
          btn.disabled = true;
          try { await post(`/api/sim/whatif/${id}/apply`, { confirm: true }); closeModal(); toast('Applied. Run a scan to refresh findings.', 'success'); lastResult = await get('/api/sim/whatif/' + id); invalidateIndex(); rerender(); } catch (e) {
            setModalBody(html`<div class="banner error" role="alert">${e.message}</div>`); btn.disabled = false;
          }
        } }],
      });
    },
  });
  registerForms({
    'wi-add': async (form) => {
      const cat = await actionCatalog();
      const spec = cat.find((a) => a.name === document.getElementById('wi-action').value);
      let params;
      try { params = readParams(spec, form); } catch (e) { toast(e.message, 'error'); return; }
      const target = targetTypes(spec).length ? document.getElementById('wi-target').value.trim() : null;
      if (targetTypes(spec).length && !target) { toast('Choose a target resource', 'error'); return; }
      changes.push({ action: spec.name, target_id: target, params });
      rerender();
    },
  });
}

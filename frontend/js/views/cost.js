// ============================================================
// Cost Analysis view
// ============================================================
// Spend history, run-rate, service breakdown and anomaly detection,
// all derived from the simulated resources and the environment's price list.

import { get } from '../api.js';
import { registerActions, rerender } from '../state.js';
import { badge, colorFor, dateTime, empty, hbars, html, lineChart, mount, money, raw, stackedBars, table, titleCase, typeLabel } from '../utils.js';

export const view = { id: 'cost', title: ['FinOps', 'Cost Analysis'], render };

let mode = 'total';
let days = 30;

async function render(box) {
  let summary; let hist; let anomalies; let breakdown;
  try {
    [summary, hist, anomalies, breakdown] = await Promise.all([
      get('/api/sim/costs/summary'), get('/api/sim/costs/history', { days }), get('/api/sim/costs/anomalies'), get('/api/sim/costs/breakdown'),
    ]);
  } catch (e) {
    if (e.code === 'no_environment') { mount(box, html`<div class="card panel">${empty('No simulated environment', 'Generate one on the Simulator page.')}</div>`); return; }
    throw e;
  }
  const items = hist.items;
  const services = Object.keys(summary.by_service);
  const points = items.map((h) => ({ x: h.date, y: h.total }));
  const markers = anomalies.items.filter((a) => a.scope === 'total').map((a) => ({ x: a.date, label: `Anomaly: +${a.increase_pct}% vs baseline` }));
  const last = items[items.length - 1];
  const prev = items.length > 7 ? items[items.length - 8] : null;
  const wow = last && prev ? ((last.total / prev.total - 1) * 100) : null;
  const active = anomalies.items.filter((a) => a.active);
  mount(box, html`
    <div class="banner info"><span><b>Simulated prices.</b> ${summary.pricing_note} Run-rate is projected from today's configuration; billed history is what the simulator actually accrued day by day.</span></div>
    <div class="stat-grid">
      <div class="card stat-card"><div class="label">Monthly run-rate</div><div class="value">${money(summary.monthly_run_rate, 0)}</div><div class="delta">30-day projection of the current setup</div></div>
      <div class="card stat-card"><div class="label">Billed, last ${summary.days_of_history} days</div><div class="value">${money(summary.last_30_days_total, 0)}</div><div class="delta">accrued in the simulator</div></div>
      <div class="card stat-card"><div class="label">Latest day vs a week earlier</div><div class="value ${wow !== null && wow > 10 ? 'v-bad' : ''}">${wow === null ? '—' : (wow >= 0 ? '+' : '') + wow.toFixed(1) + '%'}</div><div class="delta">${last ? money(last.total) + ' on ' + last.date : ''}</div></div>
      <div class="card stat-card"><div class="label">Active anomalies</div><div class="value ${active.length ? 'v-bad' : 'v-ok'}">${active.length}</div><div class="delta">${anomalies.total} detected in history</div></div>
    </div>
    <div class="card panel">
      <div class="panel-head"><h3>Daily cost</h3>
        <div class="row">
          <button class="chip-btn ${mode === 'total' ? 'active' : ''}" data-action="cost-mode" data-mode="total">Total</button>
          <button class="chip-btn ${mode === 'service' ? 'active' : ''}" data-action="cost-mode" data-mode="service">By service</button>
          <label class="sr-only" for="cost-days">Range</label>
          <select id="cost-days" data-change="cost-days" style="width:auto">${[14, 30, 60, 120].map((d) => html`<option value="${d}" ${raw(days === d ? 'selected' : '')}>Last ${d} days</option>`)}</select></div></div>
      ${mode === 'total' ? lineChart(points, { markers, width: 1100, height: 280 }) : stackedBars(items.map((h) => ({ label: h.date, parts: h.by_service })), services, { width: 1100, height: 280 })}
      <p class="panel-note">${markers.length ? 'Red markers are days flagged as anomalous (cost above the trailing mean by the configured number of standard deviations and percentage).' : 'No total-cost anomalies in this range.'}</p>
    </div>
    <div class="grid-2" style="margin-top:16px">
      <div class="card panel"><div class="panel-head"><h3>Monthly run-rate by service</h3></div>
        ${hbars(Object.entries(breakdown.by_service).map(([label, value]) => ({ label, value })), { colorOf: (it, i) => colorFor(services.indexOf(it.label)) })}
        <div class="section-title">By resource type</div>
        ${hbars(Object.entries(breakdown.by_resource_type).sort((a, b) => b[1] - a[1]).map(([t, value]) => ({ label: typeLabel(t), value })), {})}</div>
      <div class="card panel"><div class="panel-head"><h3>Most expensive resources</h3><span class="tag">monthly, simulated</span></div>
        ${table([{ label: 'Resource', render: (r) => html`<b>${r.name}</b><div class="panel-note mono">${r.resource_id}</div>` }, { label: 'Type', render: (r) => typeLabel(r.type) }, { label: 'Monthly', render: (r) => money(r.monthly), num: true }],
          summary.top_resources, { caption: 'Top resources', rowAttrs: (r) => `data-action="inv-open" data-id="${r.resource_id}" tabindex="0"` })}</div>
    </div>
    <div class="card panel" style="margin-top:16px"><div class="panel-head"><h3>Cost anomalies</h3><span class="tag">simulated anomaly detection</span></div>
      ${anomalies.items.length ? table([
        { label: 'Date', key: 'date' }, { label: 'Scope', render: (a) => titleCase(a.scope) }, { label: 'Cost', render: (a) => money(a.value), num: true },
        { label: 'Baseline mean', render: (a) => money(a.baseline_mean), num: true }, { label: 'Increase', render: (a) => `+${a.increase_pct}%`, num: true },
        { label: 'z-score', render: (a) => a.zscore, num: true }, { label: 'Status', render: (a) => (a.active ? badge('active', 'fail') : badge('historic', 'neutral')) },
        { label: 'Top contributors', render: (a) => html`${a.top_contributors.slice(0, 3).map((c) => html`<div>${c.name} <span class="panel-note">+${money(c.increase)}/day</span></div>`)}` },
      ], anomalies.items, { caption: 'Cost anomalies' }) : empty('No anomalies detected', 'Trigger the "Unexpected cost spike" scenario on the Simulator page and advance time to see one.')}
    </div>`);
}

export function init() {
  registerActions({
    'cost-mode': (el) => { mode = el.dataset.mode; rerender(); },
    'cost-days': (el) => { days = Number(el.value); rerender(); },
  });
}

export { dateTime };

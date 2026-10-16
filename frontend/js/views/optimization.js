// ============================================================
// Optimization Recommendations view
// ============================================================
// Every recommendation cites the metrics behind it, the assumptions in its
// estimate and its risk. Estimated, simulated and verified values are labelled
// separately so projected savings are never presented as realized ones.

import { get } from '../api.js';
import { canAnalyze, registerActions, rerender } from '../state.js';
import { badge, dateTime, empty, fmtValue, html, mount, money, pager, raw, titleCase, typeLabel } from '../utils.js';

export const view = { id: 'optimization', title: ['FinOps', 'Optimization Recommendations'], render };

const q = { status: 'OPEN', page: 1 };

function statusBadge(r) {
  const map = { OPEN: ['open', 'open'], APPLIED: ['applied', 'applied'], VERIFIED: ['verified', 'verified'], STALE: ['stale', 'stale'] };
  const [text, kind] = map[r.status];
  return badge(text, kind);
}

function card(r) {
  const verified = r.status === 'VERIFIED' && r.realized_monthly_savings !== null;
  const ev = Object.entries(r.evidence).filter(([, v]) => v !== null && typeof v !== 'object');
  return html`<article class="rec-card ${r.status === 'VERIFIED' || r.status === 'STALE' ? 'done' : ''}" aria-label="${r.title}">
    <div class="rec-head"><h4>${r.title}</h4>
      ${badge(r.priority, r.priority.toLowerCase())}${statusBadge(r)}${r.simulated ? badge('simulated', 'simulated') : ''}${r.remediation.supported ? '' : badge('manual', 'neutral')}</div>
    <div class="panel-note"><button class="link-btn mono" data-action="inv-open" data-id="${r.resource_id}">${r.resource_id}</button> · ${typeLabel(r.resource_type)} · ${r.rule_id}</div>
    <div class="rec-money">
      <div>Current monthly cost<b>${money(r.current_monthly_cost)}</b></div>
      <div>Estimated saving <span class="badge estimated">estimated</span><b class="save">${money(r.estimated_monthly_savings)}/mo</b></div>
      ${verified ? html`<div>Verified saving <span class="badge verified">verified (simulated)</span><b class="save">${money(r.realized_monthly_savings)}/mo</b></div>` : ''}
    </div>
    <div class="rec-body"><p><b>Why:</b> ${r.reason}</p><p><b>Recommended action:</b> ${r.recommended_action}</p></div>
    <details class="more"><summary>Evidence, assumptions and risk</summary><div class="rec-body">
      <p><b>Supporting metrics</b></p><div>${ev.map(([k, v]) => html`<span class="chip">${titleCase(k)}: ${String(v)}</span>`)}</div>
      <p><b>Assumptions</b></p><ul>${r.assumptions.map((a) => html`<li>${a}</li>`)}</ul>
      <p><b>Risk / impact:</b> ${r.risk}</p>
      ${r.remediation.supported ? html`<p><b>Plan</b></p><ol class="steps">${r.remediation.operations.map((o, i) => html`<li><span class="mark ok">${i + 1}</span><div>${o.description}<div class="panel-note mono">${o.action}</div></div></li>`)}</ol>` : ''}
      <p class="panel-note">First seen ${dateTime(r.first_seen_sim).slice(0, 10)} (sim) · confidence ${Math.round(r.confidence * 100)}%${r.applied_at ? ' · applied ' + dateTime(r.applied_at) : ''}${r.verified_at ? ' · verified ' + dateTime(r.verified_at) : ''}</p>
    </div></details>
    <div class="row" style="margin-top:10px">
      ${r.status === 'OPEN' && r.remediation.supported ? html`<button class="btn btn-primary btn-sm" data-action="remediate" data-kind="recommendation" data-id="${r.id}" ${raw(canAnalyze() ? '' : 'disabled title="Analyst or administrator role required"')}>Simulate and apply…</button>` : ''}
      ${r.status === 'VERIFIED' ? html`<span class="v-ok">✓ Applied in the simulator and confirmed by re-analysis</span>` : ''}
      ${r.status === 'STALE' ? html`<span class="panel-note">The condition no longer exists (changed outside this recommendation).</span>` : ''}
      ${r.status === 'OPEN' && !r.remediation.supported ? html`<span class="panel-note">Needs a human decision - no automated action.</span>` : ''}
    </div>
  </article>`;
}

async function render(box) {
  let data;
  try { data = await get('/api/sim/recommendations', { status: q.status, page: q.page, page_size: 12 }); } catch (e) {
    if (e.code === 'no_environment') { mount(box, html`<div class="card panel">${empty('No simulated environment', 'Generate one on the Simulator page.')}</div>`); return; }
    throw e;
  }
  const chip = (val, label) => html`<button class="chip-btn ${q.status === val ? 'active' : ''}" data-action="opt-status" data-val="${val}">${label}</button>`;
  mount(box, html`
    <p class="page-intro">Recommendations come from simulated utilization metrics, attachment state, snapshot age and the price list. <b>Estimated</b> savings are projections; <b>verified</b> savings appear only after the change is applied in the simulator and the analysis is re-run.</p>
    <div class="stat-grid">
      <div class="card stat-card"><div class="label">Open recommendations</div><div class="value">${data.totals.open}</div></div>
      <div class="card stat-card"><div class="label">Estimated monthly savings</div><div class="value v-ok">${money(data.totals.estimated_monthly_savings, 0)}</div><div class="delta"><span class="badge estimated">estimated</span> actionable items, no double counting</div></div>
      <div class="card stat-card"><div class="label">Verified monthly savings</div><div class="value">${money(data.totals.verified_monthly_savings, 0)}</div><div class="delta"><span class="badge verified">verified</span> measured after applying</div></div>
      <div class="card stat-card"><div class="label">Simulation</div><div class="value" style="font-size:16px">Preview first</div><div class="delta">Every apply shows a what-if comparison</div></div>
    </div>
    <div class="filter-bar">${chip('OPEN', 'Open')}${chip('VERIFIED', 'Verified')}${chip('APPLIED', 'Applied (unverified)')}${chip('STALE', 'No longer applicable')}${chip('', 'All')}</div>
    ${data.items.length ? data.items.map(card) : html`<div class="card panel">${empty('Nothing here', q.status === 'OPEN' ? 'No open recommendations. Advance time or trigger the cost scenarios to generate some.' : 'No recommendations with this status.')}</div>`}
    ${pager(data.page, data.page_size, data.total, 'opt-page')}`);
}

export function init() {
  registerActions({
    'opt-status': (el) => { q.status = el.dataset.val; q.page = 1; rerender(); },
    'opt-page': (el) => { q.page = Number(el.dataset.page); rerender(); },
  });
}

export { fmtValue };

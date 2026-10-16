// ============================================================
// CloudShield Dashboard View
// ============================================================
// Every number and chart here is computed by the backend from the
// persisted simulated environment and its latest scan.

import { get, post } from '../api.js';
import { canAnalyze, isAdmin, registerActions, rerender, state } from '../state.js';
import {
  badge, empty, gauge, hbars, html, lineChart, mount, money, num, progressBar, raw, sevBadge, sevBar, sevColor, toast,
  dateTime, typeLabel,
} from '../utils.js';

export const view = { id: 'dashboard', title: ['Overview', 'Dashboard'], render };

export function init() {
  registerActions({
    'run-scan': async () => {
      const r = await post('/api/sim/scans');
      toast(`Scan #${r.scan.id} complete: ${r.scan.findings_open} open findings, ${r.scan.new_findings} new, ${r.scan.resolved_findings} resolved`, 'success');
      await rerender();
    },
    'advance-days': async (el) => {
      const days = Number(el.dataset.days);
      const r = await post('/api/sim/time/advance', { days });
      toast(`Simulated time advanced ${days} day${days > 1 ? 's' : ''} to ${dateTime(r.sim_time).slice(0, 10)}. Run a scan to refresh findings.`, 'success');
      await rerender();
    },
  });
}

async function render(box) {
  let d;
  try {
    d = await get('/api/sim/dashboard');
  } catch (e) {
    if (e.code === 'no_environment') {
      mount(box, html`<div class="card panel">${empty('No simulated environment yet', 'Open the Simulator page and generate one to begin.')}
        <div class="row" style="justify-content:center"><button class="btn btn-primary" data-action="goto-view" data-view="simulator">Open Simulator</button></div></div>`);
      return;
    }
    throw e;
  }
  const sec = d.security;
  const sev = sec.severity_counts;
  const cost = d.cost;
  const history = cost.history.map((h) => ({ x: h.date, y: h.total }));
  const markers = cost.anomalies.map((a) => ({ x: a.date, label: `Cost anomaly on ${a.date} (${a.scope}): +${a.increase_pct}% vs baseline` }));
  const services = Object.entries(cost.by_service).map(([label, value]) => ({ label, value }));
  const scoreClass = sec.score === null ? '' : sec.score >= 80 ? 'v-ok' : sec.score >= 50 ? 'v-warn' : 'v-bad';
  const rec = d.recommendations;

  mount(box, html`
    ${d.stale ? html`<div class="banner warn"><span>The environment changed since the last scan (scan #${d.latest_scan.id}). Findings and recommendations below may be out of date.</span>
      ${canAnalyze() ? html`<button class="btn btn-sm btn-primary" data-action="run-scan">Run scan now</button>` : ''}</div>` : ''}
    <div class="stat-grid">
      <div class="card stat-card"><div class="label">Security score</div><div class="value ${scoreClass}">${sec.score === null ? '—' : sec.score + ' / 100'}</div>
        <div class="delta">${sec.open_findings} open findings · ${d.exposed_resources} with risky internet exposure</div></div>
      <div class="card stat-card"><div class="label">Monthly run-rate</div><div class="value">${money(cost.monthly_run_rate, 0)}</div>
        <div class="delta">Projected from current configuration (simulated prices)</div></div>
      <div class="card stat-card"><div class="label">Estimated savings</div><div class="value v-ok">${money(rec.estimated_monthly_savings, 0)}<span style="font-size:14px;font-weight:500"> /mo</span></div>
        <div class="delta">${rec.open} open recommendations · <b>estimated</b>, not realized</div></div>
      <div class="card stat-card"><div class="label">Verified savings</div><div class="value">${money(rec.verified_monthly_savings, 0)}<span style="font-size:14px;font-weight:500"> /mo</span></div>
        <div class="delta">Confirmed by re-analysis after applying changes</div></div>
    </div>

    <div class="grid-2">
      <div class="card panel">
        <div class="panel-head"><h3>Security posture</h3><span class="tag">scan #${d.latest_scan ? d.latest_scan.id : '—'} · ${d.latest_scan ? dateTime(d.latest_scan.sim_time).slice(0, 10) : 'no scan'}</span></div>
        <div class="gauge-wrap">
          ${gauge(sec.score)}
          <div class="risk-breakdown">
            ${['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((k) => html`<div class="risk-row"><span class="chipbox" style="background:${sevColor(k)}"></span><span class="name">${k[0] + k.slice(1).toLowerCase()}</span><b>${sev[k] || 0}</b></div>`)}
            ${sevBar(sev)}
          </div>
        </div>
        <p class="panel-note">Score = 100 minus 8 per critical, 4 per high, 2 per medium and 1 per low finding.</p>
      </div>
      <div class="card panel">
        <div class="panel-head"><h3>Daily cost — last 30 simulated days</h3><span class="tag">USD / day</span></div>
        ${lineChart(history, { markers })}
        <p class="panel-note">${cost.anomalies.length ? 'Red markers show detected cost anomalies.' : 'No cost anomalies in the recent window.'} ${cost.pricing_note}</p>
      </div>
    </div>

    <div class="grid-2">
      <div class="card panel">
        <div class="panel-head"><h3>Cost by service (monthly run-rate)</h3><button class="link-btn" data-action="goto-view" data-view="cost">Cost analysis →</button></div>
        ${services.length ? hbars(services) : empty('No billable resources')}
      </div>
      <div class="card panel">
        <div class="panel-head"><h3>Compliance posture</h3><span class="tag">from the latest scan</span></div>
        ${d.compliance.length ? html`${d.compliance.map((c) => html`<div style="margin-bottom:10px"><div class="row" style="justify-content:space-between;font-size:13px"><span>${c.name}</span><b>${c.compliant}/${c.total} · ${c.pct}%</b></div>${progressBar(c.pct, c.status === 'PASS' ? 'ok' : c.pct >= 70 ? 'warn' : 'bad')}</div>`)}` : empty('Run a scan to see compliance results')}
      </div>
    </div>

    <div class="grid-2">
      <div class="card panel">
        <div class="panel-head"><h3>Top open findings</h3><button class="link-btn" data-action="goto-view" data-view="security">All findings →</button></div>
        ${d.top_findings.length ? html`${d.top_findings.map((f) => html`<div class="item-row">${sevBadge(f.severity)}<div class="txt"><b>${f.title}</b><span>${f.rule_id} · ${f.resource_id}</span></div></div>`)}` : empty('No open findings', 'Great — or run a scan to check.')}
      </div>
      <div class="card panel">
        <div class="panel-head"><h3>Environment & quick actions</h3></div>
        <dl class="kv">
          <dt>Environment</dt><dd>${d.environment.name} (#${d.environment.id})</dd>
          <dt>Account / region</dt><dd>${d.environment.account_id} / ${d.environment.region}</dd>
          <dt>Simulated time</dt><dd>${dateTime(d.environment.sim_time)} UTC</dd>
          <dt>Seed</dt><dd>${d.environment.seed}</dd>
          <dt>Resources</dt><dd>${Object.entries(d.environment.counts).filter(([, c]) => c).map(([t, c]) => `${c} ${typeLabel(t).toLowerCase()}`).slice(0, 6).join(', ')}…</dd>
          <dt>Cost anomalies</dt><dd>${cost.anomalies.length ? cost.anomalies.map((a) => `${a.date} ${a.scope} +${a.increase_pct}%`).join('; ') : 'none active'}</dd>
        </dl>
        <div class="row" style="margin-top:14px">
          <button class="btn btn-primary" data-action="run-scan" ${raw(canAnalyze() ? '' : 'disabled title="Analyst or administrator role required"')}>Run scan</button>
          <button class="btn" data-action="advance-days" data-days="1" ${raw(isAdmin() ? '' : 'disabled title="Administrator role required"')}>Advance 1 day</button>
          <button class="btn" data-action="advance-days" data-days="7" ${raw(isAdmin() ? '' : 'disabled title="Administrator role required"')}>Advance 7 days</button>
        </div>
        <p class="panel-note">Opening pages never changes the environment or the clock; only these explicit actions do.</p>
      </div>
    </div>`);
}

export { badge, num, state };

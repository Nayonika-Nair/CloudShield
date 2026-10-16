// ============================================================
// Remediation workflow UI (shared by Findings and Optimization)
// ============================================================
// Propose -> preview (what-if on an isolated copy) -> explicit confirmation
// -> execute in the simulated environment -> re-scan and verify.

import { post } from './api.js';
import { canAnalyze, registerActions, rerender } from './state.js';
import {
  badge, closeModal, esc, html, kv, money, openModal, raw, setModalActions, setModalBody, sevBadge, toast, typeLabel,
} from './utils.js';

export function initRemediationUi() {
  registerActions({
    remediate: (el) => openRemediation(el.dataset.kind, Number(el.dataset.id)),
    'rem-ack': (el) => {
      const btn = document.getElementById('rem-apply');
      if (btn) btn.disabled = !el.checked;
    },
  });
}

const arrow = (a, b) => html`${a} <span aria-hidden="true">→</span><span class="sr-only"> becomes </span> ${b}`;

const ruleText = (r) => `${r.protocol === '-1' ? 'all traffic' : r.protocol + '/' + r.from_port + (r.to_port !== r.from_port ? '-' + r.to_port : '')} from ${r.cidr || r.source_sg}`;
export function fmtDiffValue(v) {
    if (v === null || v === undefined) return '—';
    if (Array.isArray(v) && v.length === 0) return '(none)';
    if (Array.isArray(v) && v.every((x) => x && typeof x === 'object' && 'protocol' in x)) return v.map(ruleText).join('; ');
    if (typeof v === 'object') { const t = JSON.stringify(v); return t.length > 140 ? t.slice(0, 140) + '…' : t; }
    return String(v);
}

export function diffRows(diff) {
  const rows = [];
  Object.entries(diff.modified || {}).forEach(([rid, fields]) => {
    Object.entries(fields).forEach(([f, c]) => rows.push({ rid, f, before: c.before, after: c.after }));
  });
  const cell = fmtDiffValue;
  return html`
    ${(diff.created || []).length ? html`<p class="panel-note"><b>Created:</b> ${(diff.created || []).join(', ')}</p>` : ''}
    ${(diff.deleted || []).length ? html`<p class="panel-note"><b>Deleted:</b> ${(diff.deleted || []).join(', ')}</p>` : ''}
    ${rows.length ? html`<div class="diff-row" style="font-weight:700;color:var(--text-faint)"><span>Resource · field</span><span>Before</span><span>After</span></div>` : ''}
    ${rows.slice(0, 40).map((r) => html`<div class="diff-row"><span class="mono">${r.rid} · ${r.f}</span><span class="before">${cell(r.before)}</span><span class="after">${cell(r.after)}</span></div>`)}
    ${rows.length > 40 ? html`<p class="panel-note">${rows.length - 40} more changed fields not shown.</p>` : ''}`;
}

/** Shared presentation of a what-if / preview result. */
export function whatIfSummary(r) {
  const c = r.cost;
  const s = r.security;
  const delta = c.delta_monthly;
  return html`
    <div class="compare">
      <div class="cell"><div class="k">Monthly cost (est.)</div>
        <div class="v">${arrow(money(c.baseline_monthly), money(c.hypothetical_monthly))}</div>
        <div class="s ${delta < 0 ? 'up' : delta > 0 ? 'down' : ''}">${delta < 0 ? 'Saves ' + money(-delta) : delta > 0 ? 'Costs ' + money(delta) + ' more' : 'No change'} · ${c.basis}</div></div>
      <div class="cell"><div class="k">Security score</div>
        <div class="v">${arrow(s.score_before, s.score_after)}</div>
        <div class="s ${s.score_delta > 0 ? 'up' : s.score_delta < 0 ? 'down' : ''}">${s.score_delta > 0 ? '+' : ''}${s.score_delta} points · findings ${s.findings_before} → ${s.findings_after}</div></div>
      <div class="cell"><div class="k">Availability</div>
        <div class="v">${r.operational.requires_restart ? 'Restart needed' : 'No downtime'}</div>
        <div class="s">${r.operational.downtime.length ? r.operational.downtime.map((d) => d.resource_id).join(', ') : 'No stop, resize or delete steps'}</div></div>
    </div>
    ${s.findings_resolved.length ? html`<div class="section-title">Findings this would resolve</div>${s.findings_resolved.map((f) => html`<div class="item-row">${sevBadge(f.severity)}<div class="txt"><b>${f.title}</b><span>${f.rule_id} · ${f.resource_id}</span></div></div>`)}` : ''}
    ${s.findings_introduced.length ? html`<div class="section-title">New findings this would introduce</div>${s.findings_introduced.map((f) => html`<div class="item-row">${sevBadge(f.severity)}<div class="txt"><b>${f.title}</b><span>${f.rule_id} · ${f.resource_id}</span></div></div>`)}` : ''}
    <div class="section-title">Compliance checks that change</div>
    ${r.compliance.filter((x) => x.delta !== 0).length
      ? html`${r.compliance.filter((x) => x.delta !== 0).map((x) => html`<div class="item-row"><div class="txt"><b>${x.name}</b><span>${x.before_pct}% → ${x.after_pct}% (${x.delta > 0 ? '+' : ''}${x.delta})</span></div>${badge(x.after_status, x.after_status.toLowerCase())}</div>`)}`
      : html`<p class="panel-note">No compliance check changes.</p>`}
    <div class="section-title">Resource configuration changes</div>
    ${diffRows(r.resource_diff)}
    <div class="banner ${r.baseline_unchanged ? 'ok' : 'error'}" style="margin-top:12px">
      ${r.baseline_unchanged ? 'Verified: the live baseline is unchanged by this simulation.' : 'WARNING: the baseline fingerprint changed during simulation.'}</div>`;
}

export async function openRemediation(kind, id) {
  openModal({ title: 'Remediation', body: html`<div class="loading" role="status"><span class="spinner"></span>Building a preview on an isolated copy…</div>`, actions: [{ label: 'Close', onClick: closeModal }] });
  let pv;
  try {
    pv = await post('/api/sim/remediation/preview', { kind, id });
  } catch (e) {
    setModalBody(html`<div class="banner error" role="alert">${e.message}</div>`);
    return;
  }
  if (!pv.supported) {
    setModalBody(html`<div class="banner warn">${pv.message}</div><p>${pv.plan.summary}</p>`);
    return;
  }
  const plan = pv.plan;
  const mayApply = canAnalyze();
  setModalBody(html`
    <div class="row" style="margin-bottom:8px">${badge('PROPOSED', 'proposed')}<b>${plan.summary}</b></div>
    <p class="panel-note">Proposed only — nothing has been changed yet. The comparison below was computed on an isolated copy of the environment.</p>
    <div class="section-title">Steps (applied in order, all-or-nothing)</div>
    <ol class="steps">${plan.operations.map((o, i) => html`<li><span class="mark ok">${i + 1}</span><div><b>${o.description || o.action}</b><div class="panel-note mono">${o.action} → ${o.target_id || '(new)'}</div></div></li>`)}</ol>
    <div class="banner warn"><span><b>Risk / impact:</b> ${plan.risk}</span></div>
    ${whatIfSummary(pv.preview)}
    <div class="field" style="margin-top:14px"><label class="check"><input type="checkbox" data-change="rem-ack" id="rem-ack" ${raw(mayApply ? '' : 'disabled')}> I confirm this change may be applied to the simulated environment.</label>
      ${mayApply ? '' : html`<div class="hint">Your role cannot apply changes; ask an analyst or administrator.</div>`}</div>`);
  setModalActions([
    { label: 'Cancel', onClick: closeModal },
    {
      label: 'Apply to simulated environment', kind: 'primary', id: 'rem-apply', disabled: true,
      onClick: async (btn) => {
        btn.disabled = true;
        btn.textContent = 'Applying and verifying…';
        try {
          const res = await post('/api/sim/remediation/apply', { kind, id, plan_hash: plan.plan_hash, confirm: true });
          showResult(res);
          toast(res.message, res.verification === 'VERIFIED' ? 'success' : 'error');
          rerender();
        } catch (e) {
          setModalBody(html`<div class="banner error" role="alert">${e.message}</div>`);
          setModalActions([{ label: 'Close', onClick: closeModal }]);
          rerender();
        }
      },
    },
  ]);
}

function showResult(res) {
  const r = res.remediation;
  const ok = res.verification === 'VERIFIED';
  setModalBody(html`
    <div class="row" style="margin-bottom:10px">${badge('EXECUTED', 'applied')}${badge(res.verification, ok ? 'verified' : 'not_resolved')}</div>
    <div class="banner ${ok ? 'ok' : 'error'}">${res.message}</div>
    <div class="compare">
      <div class="cell"><div class="k">Security score</div><div class="v">${arrow(r.score_before, r.score_after)}</div><div class="s">measured by the verification scan #${res.verification_scan.id}</div></div>
      <div class="cell"><div class="k">Monthly run-rate (simulated)</div><div class="v">${arrow(money(r.cost_before), money(r.cost_after))}</div>
        <div class="s">${r.realized_monthly_savings > 0 ? 'Verified change: −' + money(r.realized_monthly_savings) + ' (' + r.savings_basis + ')' : 'No cost change'}</div></div>
      <div class="cell"><div class="k">Open findings</div><div class="v">${res.verification_scan.findings_open}</div><div class="s">${res.verification_scan.resolved_findings} resolved by this action</div></div>
    </div>
    <div class="section-title">What changed (before → after)</div>
    ${Object.entries(r.before).map(([rid, fields]) => html`<div class="diff-row"><span class="mono">${rid}</span><span class="before">${raw(Object.entries(fields).map(([k, v]) => esc(`${k}: ${fmtDiffValue(v)}`)).join('<br>'))}</span><span class="after">${raw(Object.entries(r.after[rid] || {}).map(([k, v]) => esc(`${k}: ${fmtDiffValue(v)}`)).join('<br>'))}</span></div>`)}
    <div class="section-title">Executed steps</div>
    <ol class="steps">${r.results.map((s, i) => html`<li><span class="mark ok">${i + 1}</span><div>${s.message}</div></li>`)}</ol>`);
  setModalActions([{ label: 'Close', kind: 'primary', onClick: closeModal }]);
}

export { kv, typeLabel };

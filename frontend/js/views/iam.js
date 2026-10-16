// ============================================================
// IAM Security view
// ============================================================
// Principals, policy evaluation, trust relationships and the privilege
// escalation graph, all computed by the backend from the simulated IAM state.

import { get } from '../api.js';
import { registerActions, registerForms } from '../state.js';
import { badge, date, empty, esc, html, mount, raw, table, titleCase } from '../utils.js';

export const view = { id: 'iam', title: ['Identity', 'IAM Security'], render };

const W = 210; const H = 34; const GAP = 12;

function graphSvg(g) {
  const users = g.nodes.filter((n) => n.type === 'iam_user');
  const roles = g.nodes.filter((n) => n.type === 'iam_role');
  const virt = g.nodes.filter((n) => n.type === 'virtual');
  const colX = { iam_user: 30, iam_role: 380, virtual: 740 };
  const pos = {};
  const place = (arr, x, y0 = 50) => arr.forEach((n, i) => { pos[n.id] = { x, y: y0 + i * (H + GAP), w: W, h: H }; });
  place(users, colX.iam_user); place(roles, colX.iam_role);
  const midY = 50 + (Math.max(users.length, roles.length) * (H + GAP)) / 2 - H / 2;
  virt.forEach((n) => { pos[n.id] = { x: colX.virtual, y: midY, w: 170, h: 46 }; });
  const height = 70 + Math.max(users.length, roles.length) * (H + GAP);
  let out = `<defs><marker id="arr" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L8,4 L0,8 z" fill="#8da0b8"></path></marker>
    <marker id="arr-red" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L8,4 L0,8 z" fill="var(--critical)"></path></marker></defs>`;
  out += `<text class="g-title" x="${colX.iam_user}" y="30">Users</text><text class="g-title" x="${colX.iam_role}" y="30">Roles</text><text class="g-title" x="${colX.virtual}" y="30">Outcome</text>`;
  const admins = new Set(g.nodes.filter((n) => n.admin && n.type !== 'virtual').map((n) => n.id));
  g.edges.filter((e) => !admins.has(e.source)).forEach((e) => {
    const a = pos[e.source]; const b = pos[e.target];
    if (!a || !b) return;
    const esc_ = e.on_escalation_path;
    const cls = esc_ ? 'g-edge esc' : 'g-edge';
    const mk = esc_ ? 'url(#arr-red)' : 'url(#arr)';
    let d;
    if (a.x === b.x) { const x = a.x + a.w; d = `M${x},${a.y + a.h / 2} C${x + 70},${a.y + a.h / 2} ${x + 70},${b.y + b.h / 2} ${x},${b.y + b.h / 2}`; }
    else { const x1 = a.x + a.w; const x2 = b.x; const mx = (x1 + x2) / 2; d = `M${x1},${a.y + a.h / 2} C${mx},${a.y + a.h / 2} ${mx},${b.y + b.h / 2} ${x2 - 2},${b.y + b.h / 2}`; }
    out += `<path class="${cls}" d="${d}" marker-end="${mk}"><title>${esc(e.source)} -> ${esc(e.target)} via ${esc(e.via)}</title></path>`;
  });
  g.nodes.forEach((n) => {
    const p = pos[n.id];
    const fill = n.admin ? '#fff7f7' : '#fff';
    const stroke = n.admin ? 'var(--critical)' : 'var(--border-strong)';
    out += `<g><rect class="g-node" x="${p.x}" y="${p.y}" width="${p.w}" height="${p.h}" rx="5" style="fill:${fill};stroke:${stroke};cursor:default"></rect>
      <text class="g-label" x="${p.x + 8}" y="${p.y + 14}">${esc(n.label)}</text>
      <text class="g-sub" x="${p.x + 8}" y="${p.y + 27}">${n.type === 'iam_user' ? (n.mfa ? 'MFA on' : 'no MFA') + (n.admin ? ' · admin' : '') : n.type === 'virtual' ? 'full control' : 'role' + (n.admin ? ' · admin' : '')}</text></g>`;
  });
  return `<svg viewBox="0 0 960 ${height}" width="960" height="${height}" role="img" aria-label="IAM relationship graph; red arrows are privilege escalation paths">${out}</svg>`;
}

async function render(box) {
  let a;
  try { a = await get('/api/sim/iam/analysis'); } catch (e) {
    if (e.code === 'no_environment') { mount(box, html`<div class="card panel">${empty('No simulated environment', 'Generate one on the Simulator page.')}</div>`); return; }
    throw e;
  }
  const s = a.summary;
  const users = a.principals.filter((p) => p.type === 'iam_user');
  const roles = a.principals.filter((p) => p.type === 'iam_role');
  mount(box, html`
    <p class="page-intro">Policies are evaluated with explicit-deny-wins semantics. Edges show who can assume which role or reach administrator control; <b style="color:var(--critical)">red</b> edges form a privilege-escalation path from a non-admin identity.</p>
    <div class="stat-grid">
      <div class="card stat-card"><div class="label">Users / roles</div><div class="value">${s.users} / ${s.roles}</div></div>
      <div class="card stat-card"><div class="label">Full administrators</div><div class="value ${s.admins > 2 ? 'v-warn' : ''}">${s.admins}</div><div class="delta">Action * on Resource *</div></div>
      <div class="card stat-card"><div class="label">Console users without MFA</div><div class="value ${s.users_without_mfa ? 'v-bad' : 'v-ok'}">${s.users_without_mfa}</div></div>
      <div class="card stat-card"><div class="label">Escalation paths</div><div class="value ${s.escalation_paths ? 'v-bad' : 'v-ok'}">${s.escalation_paths}</div><div class="delta">${s.risky_trusts} risky trust relationship(s)</div></div>
    </div>
    <div class="card panel"><div class="panel-head"><h3>Identity graph</h3><span class="tag">arrows = can assume / can obtain (administrators can already do anything, so their edges are hidden)</span></div>
      <div class="graph-wrap graph">${raw(graphSvg(a.graph))}</div></div>
    <div class="grid-2" style="margin-top:16px">
      <div class="card panel"><div class="panel-head"><h3>Privilege-escalation paths</h3></div>
        ${a.escalation_paths.length ? a.escalation_paths.map((p) => html`<div class="item-row">${badge('HIGH', 'high')}<div class="txt"><b>${p.origin} → ${p.target === 'ADMIN' ? 'administrator control' : p.target}</b><span>${p.description}</span></div></div>`) : empty('No escalation paths', 'No non-admin identity can reach administrator access within 4 hops.')}</div>
      <div class="card panel"><div class="panel-head"><h3>Evaluate a permission</h3></div>
        <form data-form="iam-eval" novalidate>
          <div class="field"><label for="ev-principal">Principal</label><select id="ev-principal">${a.principals.map((p) => html`<option value="${p.id}">${p.id}</option>`)}</select></div>
          <div class="field"><label for="ev-action">Action</label><input id="ev-action" type="text" value="s3:GetObject"></div>
          <div class="field"><label for="ev-resource">Resource</label><input id="ev-resource" type="text" value="*"></div>
          <button class="btn btn-primary" type="submit">Evaluate</button>
        </form><div id="ev-result" style="margin-top:12px" aria-live="polite"></div></div>
    </div>
    <div class="card panel" style="margin-top:16px"><div class="panel-head"><h3>Users</h3></div>
      ${table([
        { label: 'User', render: (u) => html`<b>${u.id}</b>` }, { label: 'Kind', key: 'kind' },
        { label: 'Admin', render: (u) => (u.admin ? badge(u.designated_admin ? 'designated' : 'UNAPPROVED', u.designated_admin ? 'info' : 'fail') : '') },
        { label: 'Console / MFA', render: (u) => (u.console_access ? (u.mfa_enabled ? badge('MFA on', 'ok') : badge('no MFA', 'fail')) : badge('programmatic', 'neutral')) },
        { label: 'Access keys', render: (u) => (u.keys.length ? html`${u.keys.map((k) => html`<div>${badge(k.status, k.status === 'active' ? 'ok' : 'neutral')} ${k.age_days}d old, unused ${k.unused_days ?? '—'}d${k.reasons.length ? html` <span class="v-warn">⚠ ${k.reasons[0]}</span>` : ''}</div>`)}` : 'none') },
        { label: 'Policies', render: (u) => u.policies.map((p) => p.replace('policy:', '')).join(', ') },
      ], users, { caption: 'IAM users' })}</div>
    <div class="card panel" style="margin-top:16px"><div class="panel-head"><h3>Roles</h3></div>
      ${table([
        { label: 'Role', render: (r) => html`<b>${r.id}</b>` },
        { label: 'Admin', render: (r) => (r.admin ? badge(r.designated_admin ? 'designated' : 'UNAPPROVED', r.designated_admin ? 'info' : 'fail') : '') },
        { label: 'Trusted principals', render: (r) => r.trust.map((t) => `${t.type}: ${t.value}`).join('; ') },
        { label: 'Risky trust', render: (r) => (r.risky_trust.length ? html`${r.risky_trust.map((x) => html`<div class="v-bad">${x.reason}</div>`)}` : '') },
        { label: 'Policies', render: (r) => r.policies.map((p) => p.replace('policy:', '')).join(', ') },
      ], roles, { caption: 'IAM roles' })}</div>`);
}

export function init() {
  registerForms({
    'iam-eval': async (form) => {
      const principal = document.getElementById('ev-principal').value;
      const action = document.getElementById('ev-action').value.trim();
      const resource = document.getElementById('ev-resource').value.trim() || '*';
      const r = await get('/api/sim/iam/evaluate', { principal, action, resource });
      const kind = r.decision === 'ALLOW' ? 'ok' : r.decision === 'DENY' ? 'fail' : 'warn';
      mount('ev-result', html`<div class="banner ${kind}"><b>${r.decision.replace('_', ' ')}</b> <span>${r.policy ? 'via ' + r.policy : 'no statement matches'}</span></div>${r.statement ? html`<pre class="code">${JSON.stringify(r.statement, null, 2)}</pre>` : ''}`);
    },
  });
  registerActions({});
}

export { date, titleCase };

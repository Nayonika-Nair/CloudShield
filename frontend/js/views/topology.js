// ============================================================
// Network Topology view
// ============================================================
// Draws the simulated VPCs, subnets, gateways and resources from
// GET /api/sim/network/topology. Exposure highlighting comes from the
// backend reachability analysis, not from labels.

import { get, post } from '../api.js';
import { isAdmin, registerActions, rerender } from '../state.js';
import {
  badge, closeModal, empty, esc, errorBanner, html, mount, openDrawer, openModal, raw, setDrawerBody, table, toast, typeLabel,
  setModalActions, setModalBody,
} from '../utils.js';
import { exposureHtml } from './inventory.js';
import { topologySvg } from './topology_graph.js';

export const view = { id: 'topology', title: ['Network', 'Topology & Reachability'], render };

let showSg = false;
async function render(box) {
  let topo; let exp;
  try {
    [topo, exp] = await Promise.all([get('/api/sim/network/topology'), get('/api/sim/network/exposures')]);
  } catch (e) {
    if (e.code === 'no_environment') { mount(box, html`<div class="card panel">${empty('No simulated environment', 'Generate one on the Simulator page.')}</div>`); return; }
    throw e;
  }
  const issues = (await get('/api/sim/network/issues')).items;
  const risky = exp.items.filter((e) => e.reachable && (e.sensitive_ports.length || e.all_ports));
  const latent = exp.items.filter((e) => !e.reachable && (e.sensitive_ports.length || e.all_ports));
  const sm = topo.summary;
  mount(box, html`
    <p class="page-intro">Reachability is computed from the model: a resource is exposed only if a security group allows the traffic <b>and</b> it has a public address <b>and</b> its subnet routes to an attached internet gateway. Click any node to see why.</p>
    <div class="stat-grid">
      <div class="card stat-card"><div class="label">VPCs / subnets</div><div class="value">${sm.vpcs} / ${sm.subnets}</div><div class="delta">${sm.public_subnets} subnets route to an internet gateway</div></div>
      <div class="card stat-card"><div class="label">Risky exposures</div><div class="value ${risky.length ? 'v-bad' : 'v-ok'}">${sm.exposed_resources}</div><div class="delta">reachable on SSH, RDP, database or all ports</div></div>
      <div class="card stat-card"><div class="label">Internet-facing</div><div class="value">${sm.internet_facing}</div><div class="delta">reachable on any port (e.g. HTTPS)</div></div>
      <div class="card stat-card"><div class="label">Routing issues</div><div class="value ${issues.length ? 'v-warn' : 'v-ok'}">${issues.length}</div><div class="delta">inconsistent or unintended routes</div></div>
    </div>
    <div class="card panel">
      <div class="panel-head"><h3>Topology</h3>
        <label class="check"><input type="checkbox" data-change="topo-sg" ${raw(showSg ? 'checked' : '')}> Show security-group links</label></div>
      <div class="topo-legend"><span><i style="border-color:var(--critical);background:#fff7f7"></i>Exposed to the internet (sensitive port)</span><span><i style="border-color:var(--c7)"></i>Internet-facing (public web)</span><span><i style="border-style:dashed"></i>Stopped</span><span><i style="background:#eef6ef;border-color:#aac8b0"></i>Public subnet</span><span><i style="background:#f1f3f7"></i>Private subnet</span></div>
      <div class="graph-wrap graph" id="topo-graph">${raw(topologySvg(topo, { showSg }))}</div>
    </div>
    <div class="grid-2" style="margin-top:16px">
      <div class="card panel"><div class="panel-head"><h3>Risky exposures (reachable)</h3></div>
        ${risky.length ? table([
          { label: 'Resource', render: (e) => html`<b>${e.resource_name}</b><div class="panel-note mono">${e.resource_id}</div>` },
          { label: 'Rule', render: (e) => `${e.protocol}/${e.from_port}${e.to_port !== e.from_port ? '-' + e.to_port : ''} from ${e.source}` },
          { label: 'Via', key: 'security_group', mono: true },
        ], risky, { caption: 'Reachable risky exposures', rowAttrs: (e) => `data-action="topo-node" data-id="${esc(e.resource_id)}" tabindex="0"` }) : empty('No risky exposure', 'No sensitive port is reachable from the internet.')}</div>
      <div class="card panel"><div class="panel-head"><h3>Latent rules and routing issues</h3></div>
        ${latent.length || issues.length ? html`${latent.map((e) => html`<div class="item-row">${badge('latent', 'warn')}<div class="txt"><b>${e.resource_name}</b><span>${e.protocol}/${e.from_port} from ${e.source} — blocked: ${e.blocked_at}</span></div></div>`)}
          ${issues.map((i) => html`<div class="item-row">${badge(i.kind.replace(/_/g, ' '), 'warn')}<div class="txt"><b>${i.subnet_id || i.resource_id}</b><span>${i.detail}</span></div></div>`)}` : empty('Nothing latent', 'No world-open rule sits on an unreachable resource.')}</div>
    </div>`);
}

async function nodeDetails(id) {
  openDrawer(id, html`<div class="loading"><span class="spinner"></span>Loading…</div>`);
  let d;
  try { d = await get('/api/sim/resources/' + encodeURIComponent(id)); } catch (e) { setDrawerBody(errorBanner(e)); return; }
  const r = d.resource;
  const adminOnly = isAdmin() ? '' : 'disabled title="Administrator role required"';
  let extra = '';
  if (d.type === 'security_group') {
    extra = html`<div class="section-title">Inbound rules</div>${table([
      { label: 'Rule', render: (x) => `${x.protocol}/${x.from_port}${x.to_port !== x.from_port ? '-' + x.to_port : ''}` }, { label: 'Source', render: (x) => x.cidr || x.source_sg, mono: true },
      { label: '', render: (x) => (x.cidr === '0.0.0.0/0' ? html`<button class="btn btn-sm btn-danger" data-action="topo-revoke" data-sg="${r.id}" data-proto="${x.protocol}" data-from="${x.from_port}" data-to="${x.to_port}" data-cidr="${x.cidr}" ${raw(adminOnly)}>Remove rule</button>` : '') },
    ], r.ingress)}<p class="panel-note">Removing a world-open rule changes the live state. Re-open the topology afterwards to see exposure change.</p>`;
  } else if (d.type === 'subnet') {
    extra = html`<div class="section-title">Routing</div><p class="panel-note">Route table <span class="mono">${r.route_table_id}</span>. ${html`<button class="btn btn-sm" data-action="topo-route" data-rt="${r.route_table_id}" data-subnet="${r.id}" ${raw(adminOnly)}>Toggle default internet route</button>`}</p>`;
  } else if (d.type === 'internet_gateway') {
    extra = html`<div class="section-title">Gateway</div><p class="panel-note">State: ${r.state}. <button class="btn btn-sm" data-action="topo-igw" data-id="${r.id}" data-state="${r.state}" ${raw(adminOnly)}>${r.state === 'attached' ? 'Detach' : 'Attach'}</button></p>`;
  }
  mount('drawer-title', r.name || r.id);
  setDrawerBody(html`<div class="row">${badge(typeLabel(d.type), 'neutral')}${r.state ? badge(r.state, r.state) : ''}<span class="mono panel-note">${r.id}</span></div>
    ${exposureHtml(d.reachability)}${extra}
    <div class="section-title">Open findings</div>${d.open_findings.length ? d.open_findings.map((f) => html`<div class="item-row"><div class="txt"><b>${f.title}</b><span>${f.rule_id} · ${f.severity}</span></div></div>`) : html`<p class="panel-note">None.</p>`}
    <p style="margin-top:14px"><button class="link-btn" data-action="inv-open" data-id="${r.id}">Open full resource details →</button></p>`);
}

async function runAction(action, target, params, label) {
  const res = await post('/api/sim/resources/actions', { action, target_id: target, params });
  toast(res.result.message + ' — run a scan to refresh findings.', 'success');
  await rerender();
  return res;
}

export function init() {
  registerActions({
    'topo-node': (el) => nodeDetails(el.dataset.id),
    'topo-sg': (el) => { showSg = el.checked; rerender(); },
    'topo-revoke': async (el) => {
      await runAction('sg.revoke_ingress', el.dataset.sg, { protocol: el.dataset.proto, from_port: Number(el.dataset.from), to_port: Number(el.dataset.to), cidr: el.dataset.cidr });
      await nodeDetails(el.dataset.sg);
    },
    'topo-route': async (el) => {
      const rt = (await get('/api/sim/resources/' + encodeURIComponent(el.dataset.rt))).resource;
      const has = rt.routes.some((x) => x.destination === '0.0.0.0/0');
      if (has) await runAction('route.delete', rt.id, { destination: '0.0.0.0/0' });
      else {
        const vpc = (await get('/api/sim/resources/' + encodeURIComponent(rt.vpc_id))).resource;
        await runAction('route.set', rt.id, { destination: '0.0.0.0/0', target_type: 'igw', target: vpc.igw_id });
      }
      await nodeDetails(el.dataset.subnet);
    },
    'topo-igw': async (el) => {
      await runAction(el.dataset.state === 'attached' ? 'igw.detach' : 'igw.attach', el.dataset.id, {});
      await nodeDetails(el.dataset.id);
    },
  });
}

export { closeModal, openModal, setModalActions, setModalBody };

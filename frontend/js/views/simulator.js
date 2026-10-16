// ============================================================
// Fake AWS Simulator view
// ============================================================
// Configure -> generate the environment, control simulated time,
// trigger / revert scenarios and tune live pricing and thresholds.

import { get, patch, post } from '../api.js';
import { isAdmin, registerActions, registerForms, rerender, roleNote, state } from '../state.js';
import {
  badge, closeModal, dateTime, empty, esc, html, kv, mount, openModal, raw, table, titleCase, toast, typeLabel, setModalActions,
} from '../utils.js';

export const view = { id: 'simulator', title: ['Fake AWS', 'Simulator'], render };

let tab = 'config';
let meta = null;      // presets, scenarios, defaults, regions
let draft = null;     // working copy of the configuration form

const PCT = (path, label, help) => ({ path, label, type: 'number', min: 0, max: 100, step: 1, scale: 100, unit: '%', help });
const N = (path, label, min, max, help) => ({ path, label, type: 'number', min, max, step: 1, help });

function groups(regions) {
  return [
    { title: 'Environment', fields: [
      { path: 'name', label: 'Environment name', type: 'text' },
      N('seed', 'Random seed', 0, 2147483647, 'Same seed and configuration always generate the identical environment.'),
      { path: 'account_name', label: 'Account name', type: 'text' },
      { path: 'account_id', label: 'Account ID (12 digits)', type: 'text', optional: true, help: 'Leave blank to derive one from the seed.' },
      { path: 'region', label: 'AWS-like region', type: 'select', options: regions },
      { path: 'naming/org', label: 'Naming prefix', type: 'text', help: 'Resources are named <prefix>-<env>-<role>-NN.' },
      { path: 'naming/separator', label: 'Name separator', type: 'select', options: ['-', '_'] },
    ] },
    { title: 'Resource counts', fields: [
      N('counts/vpcs', 'VPCs', 1, 5), N('counts/subnets_per_vpc', 'Subnets per VPC (even)', 2, 8),
      N('counts/ec2_instances', 'EC2 instances', 0, 200), N('counts/unattached_volumes', 'Unattached EBS volumes', 0, 50),
      N('counts/snapshots', 'Manual snapshots', 0, 300), N('counts/s3_buckets', 'S3 buckets', 0, 60),
      N('counts/rds_instances', 'RDS instances', 0, 20), N('counts/elastic_ips', 'Elastic IPs', 0, 20),
      N('counts/load_balancers', 'Load balancers', 0, 10), N('counts/iam_users', 'IAM users', 1, 40),
      N('counts/iam_roles', 'IAM roles', 1, 20),
    ] },
    { title: 'Utilization distribution (must total 100%)', fields: [
      PCT('utilization/idle', 'Idle'), PCT('utilization/underutilized', 'Underutilized'),
      PCT('utilization/normal', 'Normal'), PCT('utilization/busy', 'Busy'),
    ] },
    { title: 'Security misconfiguration rates', fields: [
      PCT('security/public_s3_pct', 'Public S3 buckets'), PCT('security/open_ssh_pct', 'SSH open to internet'),
      PCT('security/open_rdp_pct', 'RDP open to internet'), PCT('security/public_rds_pct', 'Public databases'),
      PCT('security/unencrypted_pct', 'Missing encryption'), PCT('security/no_backup_pct', 'Missing backups'),
      PCT('security/no_mfa_pct', 'Users without MFA'), PCT('security/stale_key_pct', 'Stale access keys'),
      PCT('security/wildcard_admin_pct', 'Wildcard-admin roles'), PCT('security/risky_trust_pct', 'Risky role trust'),
      PCT('security/untagged_pct', 'Missing owner tag'), PCT('security/windows_pct', 'Windows hosts'), PCT('security/stopped_pct', 'Stopped instances'),
    ] },
    { title: 'IAM', fields: [
      N('iam/admin_users', 'Designated admin users', 0, 10), { path: 'iam/mfa_required', label: 'MFA required for console users', type: 'checkbox' },
      N('iam/access_key_max_age_days', 'Access key max age (days)', 7, 730), N('iam/excessive_admin_threshold', 'Max administrators before warning', 1, 20),
    ] },
    { title: 'Quotas and capacity limits', fields: [
      N('quotas/ec2_instances', 'EC2 instances', 0, 1000), N('quotas/ebs_volumes', 'EBS volumes', 0, 2000),
      N('quotas/s3_buckets', 'S3 buckets', 0, 1000), N('quotas/rds_instances', 'RDS instances', 0, 200),
      N('quotas/elastic_ips', 'Elastic IPs', 0, 100), N('quotas/vpcs', 'VPCs', 1, 20),
      N('quotas/security_groups', 'Security groups', 0, 1000), N('quotas/iam_users', 'IAM users', 0, 1000),
      N('quotas/load_balancers', 'Load balancers', 0, 100), N('quotas/snapshots', 'Snapshots', 0, 5000),
    ] },
    { title: 'Simulated time', fields: [
      { path: 'time/start_date', label: 'Start date', type: 'date' }, N('time/history_days', 'History to back-fill (days)', 0, 90),
      { path: 'time/auto_advance', label: 'Auto-advance clock (optional)', type: 'checkbox' },
      N('time/auto_advance_interval_seconds', 'Auto-advance interval (real s)', 0, 86400), N('time/days_per_tick', 'Days per tick', 1, 30),
    ] },
    { title: 'Detection thresholds', fields: [
      { path: 'thresholds/idle_cpu_avg_pct', label: 'Idle: avg CPU below %', type: 'number', min: 0, max: 50, step: 0.5 },
      { path: 'thresholds/idle_cpu_max_pct', label: 'Idle: max CPU below %', type: 'number', min: 0, max: 100, step: 0.5 },
      { path: 'thresholds/underutilized_cpu_avg_pct', label: 'Oversized: avg CPU below %', type: 'number', min: 0, max: 80, step: 0.5 },
      { path: 'thresholds/underutilized_cpu_max_pct', label: 'Oversized: max CPU below %', type: 'number', min: 0, max: 100, step: 0.5 },
      N('thresholds/metric_window_days', 'Metric window (days)', 3, 60), N('thresholds/old_snapshot_days', 'Old snapshot age (days)', 7, 730),
      N('thresholds/backup_max_age_days', 'Max backup age (days)', 1, 60),
      { path: 'thresholds/anomaly_zscore', label: 'Anomaly z-score', type: 'number', min: 1.5, max: 10, step: 0.5 },
      { path: 'thresholds/anomaly_min_increase_pct', label: 'Anomaly min increase %', type: 'number', min: 5, max: 500, step: 5 },
      { path: 'thresholds/traffic_spike_factor', label: 'Traffic spike factor (x)', type: 'number', min: 2, max: 100, step: 1 },
    ] },
    { title: 'Scenario probabilities applied while generating', fields: Object.keys(metaScenarioNames()).map((n) => ({ ...PCT('scenario_probabilities/' + n, titleCase(n), ''), optional: true })) },
  ];
}

function metaScenarioNames() {
  const out = {};
  (meta ? meta.scenarios : []).forEach((s) => { out[s.name] = s.label; });
  return out;
}

const pricingFields = (cfg) => [
  ...['s3_gb_month', 'rds_storage_gb_month', 'snapshot_gb_month', 'managed_snapshot_billed_fraction', 'eip_idle_hourly', 'data_transfer_out_gb', 'alb_hourly', 'alb_lcu_hourly']
    .map((k) => ({ path: 'pricing/' + k, label: titleCase(k), type: 'number', min: 0, step: 0.0001 })),
  ...Object.keys(cfg.pricing.ebs_gb_month).map((k) => ({ path: 'pricing/ebs_gb_month/' + k, label: `EBS ${k} $/GB-mo`, type: 'number', min: 0, step: 0.001 })),
];

// ------------------------------------------------------------ form helpers
function getPath(obj, path) { return path.split('/').reduce((o, k) => (o === undefined || o === null ? undefined : o[k]), obj); }
function setPath(obj, path, val) {
  const keys = path.split('/');
  let o = obj;
  keys.slice(0, -1).forEach((k) => { o[k] = o[k] ?? {}; o = o[k]; });
  o[keys[keys.length - 1]] = val;
}

function fieldHtml(f, cfg, prefix) {
  const raw0 = getPath(cfg, f.path);
  const id = `${prefix}-${f.path.replace(/[^a-z0-9]/gi, '_')}`;
  const attrs = `data-path="${esc(f.path)}" data-type="${f.type}" ${f.scale ? `data-scale="${f.scale}"` : ''} ${f.optional ? 'data-optional="1"' : ''}`;
  let input;
  if (f.type === 'select') {
    input = html`<select id="${id}" ${raw(attrs)}>${f.options.map((o) => html`<option value="${o}" ${raw(String(raw0) === String(o) ? 'selected' : '')}>${o}</option>`)}</select>`;
  } else if (f.type === 'checkbox') {
    return html`<div class="field"><label class="check"><input type="checkbox" id="${id}" ${raw(attrs)} ${raw(raw0 ? 'checked' : '')}> ${f.label}</label></div>`;
  } else {
    const value = raw0 === undefined || raw0 === null ? '' : f.scale ? Math.round(raw0 * f.scale * 1000) / 1000 : raw0;
    input = html`<input id="${id}" type="${f.type}" value="${value}" ${raw(attrs)} ${raw(f.min !== undefined ? `min="${f.min}" max="${f.max}" step="${f.step || 1}"` : '')}>`;
  }
  return html`<div class="field"><label for="${id}">${f.label}${f.unit ? ' (' + f.unit + ')' : ''}</label>${input}${f.help ? html`<div class="hint">${f.help}</div>` : ''}</div>`;
}

function readForm(root) {
  const out = {};
  root.querySelectorAll('[data-path]').forEach((el) => {
    const path = el.dataset.path;
    if (el.dataset.type === 'checkbox') { setPath(out, path, el.checked); return; }
    const v = el.value.trim();
    if (v === '') { if (el.dataset.optional) return; throw new Error(`"${path.replace(/\//g, ' > ')}" is required.`); }
    if (el.dataset.type === 'number') {
      const n = Number(v);
      if (Number.isNaN(n)) throw new Error(`"${path}" must be a number.`);
      setPath(out, path, el.dataset.scale ? n / Number(el.dataset.scale) : n);
    } else setPath(out, path, v);
  });
  // drop scenario probabilities of zero to keep the stored config tidy
  if (out.scenario_probabilities) {
    Object.keys(out.scenario_probabilities).forEach((k) => { if (!out.scenario_probabilities[k]) delete out.scenario_probabilities[k]; });
  }
  return out;
}

// -------------------------------------------------------------------- render
async function render(box) {
  if (!meta) meta = await get('/api/sim/presets');
  let env = null;
  try { env = await get('/api/sim/environment'); } catch (e) { if (e.code !== 'no_environment') throw e; }
  if (!draft) draft = JSON.parse(JSON.stringify(env ? env.config : meta.defaults));

  const tabs = [['config', 'Configuration'], ['time', 'Time & scenarios'], ['live', 'Live pricing & thresholds'], ['environments', 'Environments']];
  mount(box, html`
    <p class="page-intro">The simulator is a stateful, seeded model of an AWS account - VPCs, instances, volumes, buckets, databases and IAM - with its own clock and price list. Generate it once, then observe, attack and fix it. No real AWS access is involved.</p>
    ${state.user && !isAdmin() ? roleNote('Administrator') : ''}
    <div class="tabs" role="tablist">${tabs.map(([id, label]) => html`<button class="tab ${tab === id ? 'active' : ''}" role="tab" aria-selected="${tab === id}" data-action="sim-tab" data-tab="${id}">${label}</button>`)}</div>
    <div id="sim-tab-body"></div>`);
  const body = document.getElementById('sim-tab-body');
  if (tab === 'config') renderConfig(body, env);
  else if (tab === 'time') await renderTime(body, env);
  else if (tab === 'live') renderLive(body, env);
  else await renderEnvironments(body);
}

function renderConfig(body, env) {
  const gs = groups(meta.regions);
  const saved = [];
  mount(body, html`
    <div class="grid-main-side">
      <form id="config-form" class="card panel" data-form="generate" novalidate>
        <div class="panel-head"><h3>Environment configuration</h3>
          <div class="row"><label for="preset-select" class="sr-only">Preset</label>
            <select id="preset-select" data-change="sim-preset" style="width:auto">${meta.presets.map((p) => html`<option value="${p.name}" ${raw(draft.preset === p.name ? 'selected' : '')}>${titleCase(p.name)} preset</option>`)}</select>
            <select id="saved-select" data-change="sim-load-saved" style="width:auto" aria-label="Saved configurations"><option value="">Saved configurations…</option></select></div></div>
        <div id="gen-error"></div>
        ${gs.map((g) => html`<fieldset><legend>${g.title}</legend><div class="form-grid">${g.fields.map((f) => fieldHtml(f, draft, 'cfg'))}</div></fieldset>`)}
        <fieldset><legend>Pricing assumptions (simulated, NOT live AWS prices)</legend>
          <div class="form-grid">${pricingFields(draft).map((f) => fieldHtml(f, draft, 'cfg'))}</div>
          <details class="more"><summary>Per-instance-type hourly prices (EC2 and RDS)</summary><div class="form-grid">
            ${Object.keys(draft.pricing.ec2_hourly).map((k) => fieldHtml({ path: 'pricing/ec2_hourly/' + k, label: `EC2 ${k} $/h`, type: 'number', min: 0, step: 0.0001 }, draft, 'cfg'))}
            ${Object.keys(draft.pricing.rds_hourly).map((k) => fieldHtml({ path: 'pricing/rds_hourly/' + k, label: `RDS ${k} $/h`, type: 'number', min: 0, step: 0.0001 }, draft, 'cfg'))}
          </div></details></fieldset>
        <div class="row">
          <button class="btn btn-primary" type="submit" id="generate-btn" ${raw(isAdmin() ? '' : 'disabled title="Administrator role required"')}>Generate environment</button>
          <button class="btn" type="button" data-action="sim-save-config" ${raw(isAdmin() ? '' : 'disabled')}>Save configuration…</button>
          <button class="btn" type="button" data-action="sim-reset-form">Reset form to preset</button>
          <span class="panel-note">Generating archives the active environment. Its scans, findings and audit history are kept.</span>
        </div>
      </form>
      <div class="stack">
        <div class="card panel"><div class="panel-head"><h3>Active environment</h3></div>
          ${env ? html`${kv({ name: env.name, account: `${env.account_name} (${env.account_id})`, region: env.region, seed: env.seed,
            'simulated time': dateTime(env.sim_time) + ' UTC', 'state version': env.state_version,
            fingerprint: env.fingerprint ? env.fingerprint.slice(0, 16) + '…' : '—' })}
            <div class="section-title">Resources</div>${env.counts ? html`${Object.entries(env.counts).filter(([, c]) => c).map(([t, c]) => html`<span class="chip">${c} ${typeLabel(t).toLowerCase()}</span>`)}` : ''}
            <div class="row" style="margin-top:12px"><button class="btn btn-sm" data-action="sim-regenerate" ${raw(isAdmin() ? '' : 'disabled')}>Regenerate with same seed</button></div>`
          : empty('No environment yet', 'Press Generate environment to create one.')}</div>
        <div class="card panel"><div class="panel-head"><h3>How generation works</h3></div>
          <ul style="margin-left:18px;color:var(--text-dim);font-size:13px">
            <li>Network, IAM, compute, storage and data resources are created with consistent relationships.</li>
            <li>Misconfiguration rates decide how many eligible resources get each flaw. Findings are then <b>detected</b> from the state, never inserted.</li>
            <li>The same seed and configuration reproduce identical identifiers and properties.</li>
          </ul></div>
      </div>
    </div>`);
  get('/api/sim/configs').then((r) => {
    const sel = document.getElementById('saved-select');
    if (sel) r.items.forEach((c) => { const o = document.createElement('option'); o.value = c.name; o.textContent = c.name; o.dataset.config = JSON.stringify(c.config); sel.appendChild(o); });
  }).catch(() => {});
}

async function renderTime(body, env) {
  if (!env) { mount(body, empty('Generate an environment first')); return; }
  const data = await get('/api/sim/scenarios');
  const disabledAttr = isAdmin() ? '' : 'disabled title="Administrator role required"';
  mount(body, html`
    <div class="grid-2">
      <div class="card panel">
        <div class="panel-head"><h3>Simulated clock</h3><span class="tag">manual by default</span></div>
        <div class="stat-card" style="padding:0"><div class="value">${dateTime(env.sim_time)} UTC</div></div>
        <p class="panel-note">Time only moves when you advance it. Each day adds metrics and billing, ages access keys and backups, grows storage and runs backup schedules. The same state and seed always give the same future.</p>
        <div class="row" style="margin-top:12px">
          ${[1, 3, 7, 30].map((d) => html`<button class="btn" data-action="advance-days" data-days="${d}" ${raw(disabledAttr)}>+${d} day${d > 1 ? 's' : ''}</button>`)}
          <form class="row" data-form="advance-custom"><label class="sr-only" for="adv-days">Days</label><input id="adv-days" type="number" min="1" max="90" value="2" style="width:80px"><button class="btn" type="submit" ${raw(disabledAttr)}>Advance</button></form>
        </div>
      </div>
      <div class="card panel">
        <div class="panel-head"><h3>Scenario executions</h3></div>
        ${data.executions.length ? table([
          { label: '#', render: (r) => r.id }, { label: 'Scenario', render: (r) => titleCase(r.scenario), strong: true },
          { label: 'Targets', render: (r) => r.targets.join(', '), mono: true }, { label: 'Sim time', render: (r) => dateTime(r.triggered_sim).slice(0, 16) },
          { label: 'Status', render: (r) => badge(r.status, r.status === 'ACTIVE' ? 'applied' : 'neutral') },
          { label: '', render: (r) => (r.status === 'ACTIVE' ? html`<button class="btn btn-sm" data-action="scenario-revert" data-id="${r.id}" ${raw(disabledAttr)}>Revert</button>` : '') },
        ], data.executions, { caption: 'Scenario executions' }) : empty('No scenarios triggered yet')}
      </div>
    </div>
    <div class="section-title">Security and cost scenarios</div>
    <p class="panel-note" style="margin:0 0 10px">A scenario changes simulated state (opens a port, makes a bucket public, launches large instances...). The ordinary detection rules then find - or miss - the result. Nothing is added to the findings list directly.</p>
    <div class="grid-3">${data.items.map((s) => html`
      <div class="card panel">
        <div class="panel-head"><h3>${s.label}</h3>${s.time_dependent ? badge('needs time', 'pending') : ''}</div>
        <p style="font-size:13px;color:var(--text-dim)">${s.description}</p>
        <p class="panel-note">Detected by: ${s.detected_by.map((r) => html`<span class="chip">${r}</span>`)}</p>
        <div class="row" style="margin-top:8px">
          ${s.time_dependent ? html`<label class="sr-only" for="adv-${s.name}">Days to advance</label><input id="adv-${s.name}" type="number" min="0" max="30" value="3" style="width:70px" title="Simulated days to advance after triggering" aria-label="Days to advance">` : ''}
          <button class="btn btn-primary btn-sm" data-action="scenario-trigger" data-name="${s.name}" data-time="${s.time_dependent ? '1' : ''}" ${raw(disabledAttr)}>Trigger</button>
        </div>
      </div>`)}</div>`);
}

function renderLive(body, env) {
  if (!env) { mount(body, empty('Generate an environment first')); return; }
  const cfg = env.config;
  mount(body, html`
    <form class="card panel" data-form="live-config" novalidate>
      <div class="panel-head"><h3>Live pricing and detection thresholds</h3><span class="tag">applied to the active environment</span></div>
      <p class="panel-note" style="margin-top:0">Changing prices re-prices the run-rate and every estimate immediately; history that was already billed does not change. Structural settings (counts, seed, region) need a new environment.</p>
      <fieldset><legend>Pricing (simulated)</legend><div class="form-grid">${pricingFields(cfg).map((f) => fieldHtml(f, cfg, 'live'))}
        ${Object.keys(cfg.pricing.ec2_hourly).slice(0, 8).map((k) => fieldHtml({ path: 'pricing/ec2_hourly/' + k, label: `EC2 ${k} $/h`, type: 'number', min: 0, step: 0.0001 }, cfg, 'live'))}</div></fieldset>
      <fieldset><legend>Thresholds</legend><div class="form-grid">${groups(meta.regions).find((g) => g.title === 'Detection thresholds').fields.map((f) => fieldHtml(f, cfg, 'live'))}</div></fieldset>
      <button class="btn btn-primary" type="submit" ${raw(isAdmin() ? '' : 'disabled title="Administrator role required"')}>Apply to live environment</button>
    </form>`);
}

async function renderEnvironments(body) {
  const r = await get('/api/sim/environments');
  mount(body, html`<div class="card panel"><div class="panel-head"><h3>Environments</h3><span class="tag">archived environments keep their scan, finding and audit history</span></div>
    ${table([
      { label: 'ID', render: (e) => '#' + e.id }, { label: 'Name', key: 'name', strong: true }, { label: 'Status', render: (e) => badge(e.status, e.status === 'ACTIVE' ? 'ok' : 'neutral') },
      { label: 'Seed', key: 'seed' }, { label: 'Region', key: 'region' }, { label: 'Account', key: 'account_id', mono: true },
      { label: 'Created (UTC)', render: (e) => dateTime(e.created_at) }, { label: 'Archived', render: (e) => (e.archived_at ? dateTime(e.archived_at) : '') },
    ], r.items, { caption: 'Simulated environments' })}</div>`);
}

// --------------------------------------------------------------------- actions
function confirmGenerate(cfg, preset) {
  return new Promise((resolve) => {
    openModal({
      title: 'Generate a new environment?',
      body: html`<p>This creates a new simulated AWS account from the form (<b>${cfg.counts.ec2_instances}</b> instances, seed <b>${cfg.seed}</b>, region <b>${cfg.region}</b>).</p>
        <p class="panel-note">The currently active environment is archived, not deleted: its scans, findings, remediations and audit events remain available. An initial scan runs automatically.</p>`,
      actions: [{ label: 'Cancel', onClick: () => { closeModal(); resolve(false); } },
        { label: 'Generate', kind: 'primary', onClick: () => { closeModal(); resolve(true); } }],
    });
  });
}

export function init() {
  registerActions({
    'sim-tab': (el) => { tab = el.dataset.tab; rerender(); },
    'sim-preset': (el) => {
      const p = meta.presets.find((x) => x.name === el.value);
      draft = JSON.parse(JSON.stringify(p.config));
      rerender();
    },
    'sim-reset-form': () => { draft = JSON.parse(JSON.stringify(meta.presets.find((p) => p.name === 'typical').config)); rerender(); },
    'sim-load-saved': (el) => {
      const opt = el.selectedOptions[0];
      if (opt && opt.dataset.config) { draft = JSON.parse(opt.dataset.config); rerender(); }
    },
    'sim-save-config': () => {
      let cfg;
      try { cfg = readForm(document.getElementById('config-form')); } catch (e) { toast(e.message, 'error'); return; }
      openModal({
        title: 'Save configuration',
        body: html`<div class="field"><label for="save-name">Name</label><input id="save-name" type="text" maxlength="64" placeholder="e.g. small-demo"></div>`,
        actions: [{ label: 'Cancel', onClick: closeModal }, { label: 'Save', kind: 'primary', onClick: async () => {
          const name = document.getElementById('save-name').value.trim();
          if (!name) { toast('Enter a name', 'error'); return; }
          await post('/api/sim/configs', { name, config: { ...cfg, preset: draft.preset } });
          closeModal(); toast(`Saved configuration "${name}"`, 'success'); rerender();
        } }],
      });
    },
    'sim-regenerate': async () => {
      const r = await post('/api/sim/environment/reset');
      draft = null;
      toast(`Environment #${r.environment.id} regenerated (same seed). Previous history was kept.`, 'success');
      await rerender();
    },
    'advance-days': async (el) => {
      const days = Number(el.dataset.days);
      const r = await post('/api/sim/time/advance', { days });
      toast(`Advanced ${days} day${days > 1 ? 's' : ''} to ${dateTime(r.sim_time).slice(0, 10)} (cost accrued ${'$' + r.advance.cost_accrued})`, 'success');
      await rerender();
    },
    'scenario-trigger': async (el) => {
      const name = el.dataset.name;
      let advance = 0;
      if (el.dataset.time) advance = Number(document.getElementById('adv-' + name).value || 0);
      const r = await post(`/api/sim/scenarios/${name}/trigger`, { advance_days: advance });
      toast(`${titleCase(name)} triggered: ${r.messages.length} change(s) to the simulated state. Run a scan to see the findings.`, 'success');
      await rerender();
    },
    'scenario-revert': async (el) => {
      await post(`/api/sim/scenarios/executions/${el.dataset.id}/revert`);
      toast('Scenario reverted: touched resources were restored', 'success');
      await rerender();
    },
  });

  registerForms({
    generate: async (form) => {
      const errBox = document.getElementById('gen-error');
      errBox.innerHTML = '';
      let cfg;
      try { cfg = readForm(form); } catch (e) { mount(errBox, html`<div class="banner error" role="alert">${e.message}</div>`); return; }
      cfg.preset = draft.preset || 'custom';
      const u = cfg.utilization;
      if (Math.abs(u.idle + u.underutilized + u.normal + u.busy - 1) > 0.01) {
        mount(errBox, html`<div class="banner error" role="alert">Utilization shares must total 100% (currently ${Math.round((u.idle + u.underutilized + u.normal + u.busy) * 100)}%).</div>`);
        return;
      }
      if (!(await confirmGenerate(cfg))) return;
      const btn = document.getElementById('generate-btn');
      btn.disabled = true; btn.textContent = 'Generating…';
      try {
        const r = await post('/api/sim/environments', { config: cfg });
        draft = null;
        toast(`Environment #${r.environment.id} generated: ${Object.values(r.environment.counts).reduce((a, b) => a + b, 0)} resources, ${r.initial_scan.findings_open} findings detected on the first scan.`, 'success');
        await rerender();
      } catch (e) {
        mount(errBox, html`<div class="banner error" role="alert">${e.message}</div>`);
        btn.disabled = false; btn.textContent = 'Generate environment';
      }
    },
    'advance-custom': async (form) => {
      const days = Number(form.querySelector('input').value);
      const r = await post('/api/sim/time/advance', { days });
      toast(`Advanced ${days} day(s) to ${dateTime(r.sim_time).slice(0, 10)}`, 'success');
      await rerender();
    },
    'live-config': async (form) => {
      const cfg = readForm(form);
      const r = await patch('/api/sim/environment/config', { pricing: cfg.pricing, thresholds: cfg.thresholds });
      toast('Live pricing and thresholds updated. Estimates now use the new values.', 'success');
      draft = null;
      await rerender();
      return r;
    },
  });
}

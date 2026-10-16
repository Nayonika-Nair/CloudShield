// ============================================================
// CloudShield Shared Utilities
// ============================================================
// Safe HTML templating, formatting, small UI primitives (toast,
// drawer, modal, tables) and dependency-free SVG charts.
// Every dynamic value is escaped unless explicitly wrapped in raw().

// ---------------------------------------------------------- escaping / templating
class Raw {
  constructor(s) { this.s = String(s); }
  toString() { return this.s; }
}

export function raw(s) { return new Raw(s); }

export function esc(v) {
  if (v instanceof Raw) return v.s;
  if (v === null || v === undefined || v === false) return '';
  if (Array.isArray(v)) return v.map(esc).join('');
  return String(v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/** Tagged template: interpolations are HTML-escaped; nested html`` fragments and raw() pass through. */
export function html(strings, ...vals) {
  let out = strings[0];
  vals.forEach((v, i) => { out += esc(v) + strings[i + 1]; });
  return new Raw(out);
}

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
export function mount(target, content) {
  const el = typeof target === 'string' ? document.getElementById(target) : target;
  if (el) el.innerHTML = String(content);
  return el;
}

// ------------------------------------------------------------------ formatting
export function money(n, dp = 2) {
  if (n === null || n === undefined || Number.isNaN(Number(n))) return '—';
  return '$' + Number(n).toLocaleString('en-US', { minimumFractionDigits: dp, maximumFractionDigits: dp });
}
export function num(n, dp = 0) {
  if (n === null || n === undefined) return '—';
  return Number(n).toLocaleString('en-US', { minimumFractionDigits: dp, maximumFractionDigits: dp });
}
export function pct(n, dp = 1) {
  if (n === null || n === undefined) return '—';
  return Number(n).toFixed(dp) + '%';
}
export function date(s) { return s ? String(s).slice(0, 10) : '—'; }
export function dateTime(s) { return s ? String(s).replace('T', ' ').slice(0, 19) : '—'; }
export function titleCase(s) { return String(s || '').replace(/[_-]/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()); }
export function shortId(id, n = 14) { const s = String(id || ''); return s.length > n + 3 ? s.slice(0, n) + '…' : s; }
export function typeLabel(t) {
  return ({
    ec2_instance: 'EC2 instance', ebs_volume: 'EBS volume', s3_bucket: 'S3 bucket', rds_instance: 'RDS instance',
    iam_user: 'IAM user', iam_role: 'IAM role', iam_policy: 'IAM policy', security_group: 'Security group',
    vpc: 'VPC', subnet: 'Subnet', route_table: 'Route table', internet_gateway: 'Internet gateway',
    network_interface: 'Network interface', elastic_ip: 'Elastic IP', load_balancer: 'Load balancer', snapshot: 'Snapshot',
    account: 'Account',
  })[t] || titleCase(t);
}

export function badge(text, kind) {
  const k = String(kind || text || '').toLowerCase().replace(/\s+/g, '_');
  return html`<span class="badge ${k}">${String(text).replace(/_/g, ' ')}</span>`;
}
export const sevBadge = (s) => badge(s, String(s).toLowerCase());

export function sevColor(sev) {
  return ({ CRITICAL: 'var(--critical)', HIGH: 'var(--high)', MEDIUM: 'var(--c3)', LOW: 'var(--low)' })[sev] || 'var(--c6)';
}

// ----------------------------------------------------------------- UI states
export function loading(target, msg = 'Loading…') {
  mount(target, html`<div class="loading" role="status"><span class="spinner"></span>${msg}</div>`);
}
export function empty(title, msg = '') {
  return html`<div class="empty"><b>${title}</b>${msg}</div>`;
}
export function errorBanner(err) {
  const msg = err && err.message ? err.message : String(err);
  return html`<div class="banner error" role="alert"><span>${msg}</span></div>`;
}

export function toast(message, type = 'info') {
  let box = document.getElementById('toasts');
  if (!box) {
    box = document.createElement('div');
    box.id = 'toasts';
    box.className = 'toasts';
    box.setAttribute('aria-live', 'polite');
    document.body.appendChild(box);
  }
  const t = document.createElement('div');
  t.className = 'toast ' + type;
  t.setAttribute('role', type === 'error' ? 'alert' : 'status');
  t.textContent = message;
  box.appendChild(t);
  setTimeout(() => t.remove(), type === 'error' ? 8000 : 4500);
}

// ------------------------------------------------------------ drawer / modal
let lastFocus = null;

export function openDrawer(title, body, subtitle = '') {
  closeDrawer();
  lastFocus = document.activeElement;
  const wrap = document.createElement('div');
  wrap.id = 'drawer-root';
  wrap.innerHTML = String(html`
    <div class="overlay" data-action="close-drawer"></div>
    <aside class="drawer" role="dialog" aria-modal="true" aria-labelledby="drawer-title">
      <div class="drawer-head">
        <div><h2 id="drawer-title">${title}</h2>${subtitle ? html`<div class="panel-note">${subtitle}</div>` : ''}</div>
        <button class="icon-btn" data-action="close-drawer" aria-label="Close panel">Close</button>
      </div>
      <div class="drawer-body" id="drawer-body"></div>
    </aside>`);
  document.body.appendChild(wrap);
  mount('drawer-body', body);
  const btn = wrap.querySelector('.icon-btn');
  if (btn) btn.focus();
  return document.getElementById('drawer-body');
}
export function closeDrawer() {
  const d = document.getElementById('drawer-root');
  if (d) d.remove();
  if (lastFocus && lastFocus.focus) { try { lastFocus.focus(); } catch (e) { /* element gone */ } }
}
export function setDrawerBody(body) { mount('drawer-body', body); }

export function openModal({ title, body, actions = [] }) {
  closeModal();
  const wrap = document.createElement('div');
  wrap.id = 'modal-root';
  wrap.innerHTML = String(html`
    <div class="overlay" style="z-index:50" data-action="close-modal"></div>
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title">
      <div class="modal-head"><h2 id="modal-title">${title}</h2>
        <button class="icon-btn" data-action="close-modal" aria-label="Close dialog">Close</button></div>
      <div class="modal-body" id="modal-body">${body}</div>
      <div class="modal-foot" id="modal-foot"></div>
    </div>`);
  document.body.appendChild(wrap);
  setModalActions(actions);
  const first = wrap.querySelector('.modal-foot button, .icon-btn');
  if (first) first.focus();
  return wrap;
}
export function setModalBody(body) { mount('modal-body', body); }
export function setModalActions(actions) {
  const foot = document.getElementById('modal-foot');
  if (!foot) return;
  foot.innerHTML = '';
  actions.forEach((a) => {
    const b = document.createElement('button');
    b.className = 'btn ' + (a.kind === 'primary' ? 'btn-primary' : a.kind === 'danger' ? 'btn-danger' : '');
    b.textContent = a.label;
    if (a.disabled) b.disabled = true;
    if (a.id) b.id = a.id;
    b.addEventListener('click', () => a.onClick && a.onClick(b));
    foot.appendChild(b);
  });
}
export function closeModal() {
  const m = document.getElementById('modal-root');
  if (m) m.remove();
}

document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  if (document.getElementById('modal-root')) closeModal();
  else if (document.getElementById('drawer-root')) closeDrawer();
});

// ------------------------------------------------------------------- tables
/**
 * columns: [{ key, label, num?, mono?, strong?, render?(row) }]
 * rowAttrs?(row) -> string of extra attributes (e.g. data-action)
 */
export function table(columns, rows, { caption = '', rowAttrs, rowClass } = {}) {
  const head = columns.map((c) => html`<th scope="col" class="${c.num ? 'num' : ''}">${c.label}</th>`);
  const body = rows.map((r) => {
    const cls = [rowAttrs ? 'clickable' : '', rowClass ? rowClass(r) : ''].filter(Boolean).join(' ');
    const cells = columns.map((c) => {
      const v = c.render ? c.render(r) : r[c.key];
      return html`<td class="${[c.num ? 'num' : '', c.mono ? 'mono' : '', c.strong ? 'strong' : ''].join(' ')}">${v === undefined || v === null || v === '' ? '—' : v}</td>`;
    });
    return html`<tr class="${cls}" ${raw(rowAttrs ? rowAttrs(r) : '')}>${cells}</tr>`;
  });
  return html`<div class="table-wrap"><table>${caption ? html`<caption class="sr-only">${caption}</caption>` : ''}<thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
}

export function pager(page, pageSize, total, action) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  if (pages <= 1) return html`<div class="pager">${total} item${total === 1 ? '' : 's'}</div>`;
  return html`<div class="pager">
    <span>${(page - 1) * pageSize + 1}–${Math.min(page * pageSize, total)} of ${total}</span>
    <button class="btn btn-sm" data-action="${action}" data-page="${page - 1}" ${raw(page <= 1 ? 'disabled' : '')}>Previous</button>
    <span>Page ${page} / ${pages}</span>
    <button class="btn btn-sm" data-action="${action}" data-page="${page + 1}" ${raw(page >= pages ? 'disabled' : '')}>Next</button>
  </div>`;
}

export function kv(obj, { skip = [] } = {}) {
  const rows = Object.entries(obj).filter(([k, v]) => !skip.includes(k) && v !== undefined);
  return html`<dl class="kv">${rows.map(([k, v]) => html`<dt>${titleCase(k)}</dt><dd>${fmtValue(v)}</dd>`)}</dl>`;
}
export function fmtValue(v) {
  if (v === null || v === undefined) return '—';
  if (typeof v === 'boolean') return v ? 'Yes' : 'No';
  if (Array.isArray(v)) return v.length ? (v.every((x) => typeof x !== 'object') ? v.join(', ') : html`<pre class="code">${JSON.stringify(v, null, 2)}</pre>`) : '—';
  if (typeof v === 'object') return html`<pre class="code">${JSON.stringify(v, null, 2)}</pre>`;
  return String(v);
}
export const jsonBlock = (o) => html`<pre class="code">${JSON.stringify(o, null, 2)}</pre>`;

export function tagChips(tags) {
  const e = Object.entries(tags || {});
  return e.length ? html`${e.map(([k, v]) => html`<span class="chip">${k}=${v}</span>`)}` : '—';
}

// ------------------------------------------------------------------- charts
const PALETTE = ['var(--c1)', 'var(--c2)', 'var(--c3)', 'var(--c4)', 'var(--c5)', 'var(--c6)', 'var(--c7)', 'var(--c8)'];
export const colorFor = (i) => PALETTE[i % PALETTE.length];

function niceMax(v) {
  if (v <= 0) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  const n = v / p;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p;
}

/** Line chart of {x: label, y: number}. markers: [{x, label}] drawn as red points. */
export function lineChart(points, { width = 640, height = 230, money: isMoney = true, markers = [], label = 'Daily cost' } = {}) {
  if (!points.length) return empty('No data yet');
  const m = { l: 52, r: 12, t: 12, b: 28 };
  const w = width - m.l - m.r;
  const h = height - m.t - m.b;
  const ys = points.map((p) => p.y);
  const hi = niceMax(Math.max(...ys) * 1.05);
  const lo = 0;
  const X = (i) => m.l + (points.length === 1 ? w / 2 : (i * w) / (points.length - 1));
  const Y = (v) => m.t + h - ((v - lo) / (hi - lo)) * h;
  const fmt = (v) => (isMoney ? '$' + (hi >= 20 ? Math.round(v) : v.toFixed(1)) : String(Math.round(v)));
  const grid = [0, 1, 2, 3, 4].map((k) => {
    const v = lo + ((hi - lo) * k) / 4;
    return `<g class="grid"><line x1="${m.l}" x2="${m.l + w}" y1="${Y(v)}" y2="${Y(v)}"></line></g><text x="${m.l - 6}" y="${Y(v) + 4}" text-anchor="end">${fmt(v)}</text>`;
  }).join('');
  const line = points.map((p, i) => `${i ? 'L' : 'M'}${X(i).toFixed(1)},${Y(p.y).toFixed(1)}`).join(' ');
  const area = `${line} L${X(points.length - 1).toFixed(1)},${Y(0)} L${X(0).toFixed(1)},${Y(0)} Z`;
  const idx = [0, Math.floor((points.length - 1) / 2), points.length - 1];
  const xl = idx.map((i) => `<text x="${X(i)}" y="${height - 8}" text-anchor="${i === 0 ? 'start' : i === points.length - 1 ? 'end' : 'middle'}">${esc(points[i].x.slice(5))}</text>`).join('');
  const dots = points.map((p, i) => `<circle cx="${X(i)}" cy="${Y(p.y)}" r="9" fill="transparent"><title>${esc(p.x)}: ${esc(fmt(p.y))}</title></circle>`).join('');
  const mk = markers.map((mkr) => {
    const i = points.findIndex((p) => p.x === mkr.x);
    return i < 0 ? '' : `<circle class="anom" cx="${X(i)}" cy="${Y(points[i].y)}" r="5"><title>${esc(mkr.label)}</title></circle>`;
  }).join('');
  return raw(`<div class="chart"><svg viewBox="0 0 ${width} ${height}" role="img" aria-label="${esc(label)} chart, ${points.length} days">${grid}<path class="area" d="${area}"></path><path class="line" d="${line}"></path>${dots}${mk}${xl}</svg></div>`);
}

/** Stacked bars. rows: [{label, parts: {name: value}}], names: ordered series names. */
export function stackedBars(rows, names, { width = 640, height = 230, label = 'Cost by service' } = {}) {
  if (!rows.length) return empty('No data yet');
  const m = { l: 52, r: 12, t: 12, b: 28 };
  const w = width - m.l - m.r;
  const h = height - m.t - m.b;
  const totals = rows.map((r) => names.reduce((s, n) => s + (r.parts[n] || 0), 0));
  const hi = niceMax(Math.max(...totals) * 1.05);
  const bw = Math.max(3, (w / rows.length) * 0.72);
  const grid = [0, 1, 2, 3, 4].map((k) => {
    const v = (hi * k) / 4;
    const y = m.t + h - (v / hi) * h;
    return `<g class="grid"><line x1="${m.l}" x2="${m.l + w}" y1="${y}" y2="${y}"></line></g><text x="${m.l - 6}" y="${y + 4}" text-anchor="end">$${Math.round(v)}</text>`;
  }).join('');
  const bars = rows.map((r, i) => {
    const x = m.l + (i + 0.5) * (w / rows.length) - bw / 2;
    let y = m.t + h;
    const segs = names.map((n, k) => {
      const v = r.parts[n] || 0;
      const sh = (v / hi) * h;
      y -= sh;
      return sh > 0 ? `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${bw.toFixed(1)}" height="${sh.toFixed(1)}" fill="${colorFor(k)}"><title>${esc(r.label)} ${esc(n)}: $${v.toFixed(2)}</title></rect>` : '';
    }).join('');
    return segs;
  }).join('');
  const xl = [0, rows.length - 1].map((i) => `<text x="${m.l + (i + 0.5) * (w / rows.length)}" y="${height - 8}" text-anchor="${i === 0 ? 'start' : 'end'}">${esc(rows[i].label.slice(5))}</text>`).join('');
  const legend = names.map((n, k) => `<span><i style="background:${colorFor(k)}"></i>${esc(n)}</span>`).join('');
  return raw(`<div class="chart"><svg viewBox="0 0 ${width} ${height}" role="img" aria-label="${esc(label)}">${grid}${bars}${xl}</svg><div class="legend">${legend}</div></div>`);
}

/** Ring gauge for a 0-100 score. */
export function gauge(score, { size = 150 } = {}) {
  const r = 58;
  const c = 2 * Math.PI * r;
  const v = score === null || score === undefined ? 0 : Math.max(0, Math.min(100, score));
  const color = v >= 80 ? 'var(--ok)' : v >= 50 ? 'var(--c3)' : 'var(--critical)';
  return raw(`<div class="gauge" style="width:${size}px;height:${size}px"><svg viewBox="0 0 140 140" width="${size}" height="${size}" role="img" aria-label="Security score ${score ?? 'not available'} out of 100">
    <circle cx="70" cy="70" r="${r}" fill="none" stroke="var(--surface-3)" stroke-width="12"></circle>
    <circle cx="70" cy="70" r="${r}" fill="none" stroke="${color}" stroke-width="12" stroke-linecap="round" stroke-dasharray="${c.toFixed(1)}" stroke-dashoffset="${(c * (1 - v / 100)).toFixed(1)}" transform="rotate(-90 70 70)"></circle></svg>
    <div class="gauge-num"><b style="color:${color}">${score === null || score === undefined ? '—' : v}</b><span>/ 100</span></div></div>`);
}

export function progressBar(pctValue, kind = '') {
  const v = Math.max(0, Math.min(100, Number(pctValue) || 0));
  return raw(`<div class="progress ${kind}" role="progressbar" aria-valuenow="${v}" aria-valuemin="0" aria-valuemax="100"><i style="width:${v}%"></i></div>`);
}

export function sparkline(values, { width = 160, height = 34 } = {}) {
  if (!values.length) return '';
  const hi = Math.max(...values);
  const lo = Math.min(...values);
  const span = hi - lo || 1;
  const pts = values.map((v, i) => `${((i / Math.max(1, values.length - 1)) * (width - 4) + 2).toFixed(1)},${(height - 3 - ((v - lo) / span) * (height - 6)).toFixed(1)}`);
  return raw(`<svg viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" aria-hidden="true"><polyline points="${pts.join(' ')}" fill="none" stroke="var(--c1)" stroke-width="1.6"></polyline></svg>`);
}

export function hbars(items, { valueFmt = (v) => money(v, 0), colorOf } = {}) {
  const max = Math.max(...items.map((i) => i.value), 1);
  return html`${items.map((it, i) => html`<div class="hbar"><span>${it.label}</span>
    <span class="track"><span class="fill" style="display:block;width:${((it.value / max) * 100).toFixed(1)}%;background:${colorOf ? colorOf(it, i) : colorFor(i)}"></span></span>
    <span class="amt">${valueFmt(it.value)}</span></div>`)}`;
}

export function sevBar(counts) {
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const total = order.reduce((s, k) => s + (counts[k] || 0), 0);
  if (!total) return html`<div class="sev-bar"></div>`;
  return raw(`<div class="sev-bar" role="img" aria-label="Findings by severity">${order.map((k) => `<i style="width:${((counts[k] || 0) / total) * 100}%;background:${sevColor(k)}" title="${k}: ${counts[k] || 0}"></i>`).join('')}</div>`);
}

export function downloadText(filename, text, type = 'application/json') {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}

// ============================================================
// Generic form for simulator lifecycle actions
// ============================================================
// The action catalog (GET /api/sim/actions) describes every operation and its
// parameters, so the UI never hard-codes what can be done to a resource.

import { get } from './api.js';
import { esc, html, raw } from './utils.js';

let catalogCache = null;
let indexCache = null;

export async function actionCatalog(force = false) {
  if (!catalogCache || force) catalogCache = (await get('/api/sim/actions')).items;
  return catalogCache;
}

export async function resourceIndex(force = false) {
  if (!indexCache || force) {
    const first = await get('/api/sim/resources', { page_size: 200, page: 1 });
    let items = first.items;
    for (let p = 2; items.length < first.total && p <= 5; p++) {
      items = items.concat((await get('/api/sim/resources', { page_size: 200, page: p })).items);
    }
    indexCache = items.map((r) => ({ id: r.id, type: r.type, name: r.name }));
  }
  return indexCache;
}
export function invalidateIndex() { indexCache = null; }

export function targetTypes(spec) {
  if (!spec.target_type) return [];
  return Array.isArray(spec.target_type) ? spec.target_type : [spec.target_type];
}

/** HTML inputs for the parameters of an action. */
export function paramFields(spec, prefix = 'p') {
  return html`${spec.params.map((p) => {
    const id = `${prefix}-${p.name}`;
    const label = html`<label for="${id}">${p.name.replace(/_/g, ' ')}${p.required ? ' *' : ''}</label>`;
    let input;
    if (p.choices) {
      input = html`<select id="${id}" data-param="${p.name}" data-kind="string">${p.required ? '' : raw('<option value="">(default)</option>')}${p.choices.map((c) => html`<option value="${c}" ${raw(String(p.default) === String(c) ? 'selected' : '')}>${c}</option>`)}</select>`;
    } else if (p.type === 'bool') {
      input = html`<select id="${id}" data-param="${p.name}" data-kind="bool"><option value="">(default)</option><option value="true">true</option><option value="false">false</option></select>`;
    } else if (p.type === 'dict') {
      input = html`<textarea id="${id}" data-param="${p.name}" data-kind="dict" placeholder='{"key": "value"}'></textarea>`;
    } else if (p.type === 'list') {
      input = html`<input id="${id}" type="text" data-param="${p.name}" data-kind="list" placeholder="comma separated">`;
    } else if (p.type === 'int') {
      input = html`<input id="${id}" type="number" step="1" data-param="${p.name}" data-kind="int" ${raw(p.default !== null && p.default !== undefined ? `value="${esc(p.default)}"` : '')}>`;
    } else {
      input = html`<input id="${id}" type="text" data-param="${p.name}" data-kind="string" ${raw(p.default ? `value="${esc(p.default)}"` : '')}>`;
    }
    return html`<div class="field">${label}${input}</div>`;
  })}`;
}

/** Read the parameter values the user entered; throws Error with a readable message on bad input. */
export function readParams(spec, root) {
  const out = {};
  spec.params.forEach((p) => {
    const el = root.querySelector(`[data-param="${p.name}"]`);
    if (!el) return;
    const v = el.value.trim();
    if (v === '') {
      if (p.required) throw new Error(`Parameter "${p.name}" is required.`);
      return;
    }
    const kind = el.dataset.kind;
    if (kind === 'int') out[p.name] = Number(v);
    else if (kind === 'bool') out[p.name] = v === 'true';
    else if (kind === 'list') out[p.name] = v.split(',').map((s) => s.trim()).filter(Boolean);
    else if (kind === 'dict') {
      try { out[p.name] = JSON.parse(v); } catch (e) { throw new Error(`Parameter "${p.name}" must be valid JSON.`); }
    } else out[p.name] = v;
  });
  return out;
}

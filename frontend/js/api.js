// ============================================================
// CloudShield API client
// ============================================================
// All data shown in the UI comes through this module. It adds the
// bearer token, turns error responses into ApiError, and signals
// an expired session so the shell can return to the sign-in view.

const cfg = window.CLOUDSHIELD_CONFIG || { apiBase: '' };
export const API_BASE = String(cfg.apiBase || '').replace(/\/$/, '');

const TOKEN_KEY = 'cloudshield.token';

export function getToken() {
  try { return window.sessionStorage.getItem(TOKEN_KEY); } catch (e) { return null; }
}
export function setToken(token) {
  try {
    if (token) window.sessionStorage.setItem(TOKEN_KEY, token);
    else window.sessionStorage.removeItem(TOKEN_KEY);
  } catch (e) { /* storage unavailable: session lasts until reload */ }
}

export class ApiError extends Error {
  constructor(status, code, message, fields) {
    super(message);
    this.status = status;
    this.code = code;
    this.fields = fields || [];
  }
}

function query(params) {
  if (!params) return '';
  const q = Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v));
  return q.length ? '?' + q.join('&') : '';
}

async function parse(res) {
  const text = await res.text();
  if (!text) return null;
  try { return JSON.parse(text); } catch (e) { return text; }
}

export async function api(path, { method = 'GET', body, params, auth = true } = {}) {
  const headers = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const token = getToken();
  if (auth && token) headers.Authorization = 'Bearer ' + token;
  let res;
  try {
    res = await fetch(API_BASE + path + query(params), {
      method, headers, body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (e) {
    throw new ApiError(0, 'network_error', 'Cannot reach the CloudShield API at ' + (API_BASE || window.location.origin) + '. Is the backend running?');
  }
  const data = await parse(res);
  if (!res.ok) {
    if (res.status === 401 && auth && token) window.dispatchEvent(new CustomEvent('cloudshield:session-expired'));
    const err = data && data.error ? data.error : null;
    let message = (err && err.message) || (data && typeof data.detail === 'string' && data.detail) || res.statusText || 'Request failed';
    if (data && Array.isArray(data.detail)) message = data.detail.map((d) => d.msg).join('; ');
    throw new ApiError(res.status, (err && err.code) || 'http_' + res.status, message, err && err.fields);
  }
  return data;
}

export const get = (path, params) => api(path, { params });
export const post = (path, body) => api(path, { method: 'POST', body: body === undefined ? {} : body });
export const patch = (path, body) => api(path, { method: 'PATCH', body });

export async function download(path, filename) {
  const token = getToken();
  const res = await fetch(API_BASE + path, { headers: token ? { Authorization: 'Bearer ' + token } : {} });
  if (!res.ok) throw new ApiError(res.status, 'download_failed', 'Download failed (' + res.status + ')');
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

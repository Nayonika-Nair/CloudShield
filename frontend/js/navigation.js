// ============================================================
// CloudShield Navigation
// ============================================================
// Hash-based router: shows one section at a time, updates the topbar
// title and asks the active view to render its data from the API.

import { registerActions, setRerender, refreshEnv, refreshStale } from './state.js';
import { closeDrawer, closeModal, errorBanner, loading, mount } from './utils.js';

const views = {};
let current = null;

export function registerView(view) { views[view.id] = view; }
export const currentView = () => current;

export async function renderCurrent() {
  const view = views[current];
  if (!view) return;
  const box = document.getElementById('sec-' + view.id);
  try {
    await view.render(box);
  } catch (e) {
    mount(box, errorBanner(e));
  }
}

export async function go(id) {
  if (!views[id]) id = 'dashboard';
  current = id;
  closeDrawer();
  closeModal();
  document.querySelectorAll('.nav-item').forEach((n) => {
    const active = n.dataset.view === id;
    n.classList.toggle('active', active);
    if (active) n.setAttribute('aria-current', 'page'); else n.removeAttribute('aria-current');
  });
  document.querySelectorAll('#content > section').forEach((s) => s.classList.add('hidden'));
  const sec = document.getElementById('sec-' + id);
  sec.classList.remove('hidden');
  document.getElementById('topbar-eyebrow').textContent = views[id].title[0];
  document.getElementById('topbar-title').textContent = views[id].title[1];
  document.title = views[id].title[1] + ' — CloudShield';
  if (!sec.dataset.loaded) loading(sec);
  await renderCurrent();
  sec.dataset.loaded = '1';
}

export function initNavigation() {
  registerActions({
    nav: (el) => { window.location.hash = '#/' + el.dataset.view; },
    'goto-view': (el) => { window.location.hash = '#/' + el.dataset.view; },
  });
  window.addEventListener('hashchange', () => go(window.location.hash.replace('#/', '')));
  setRerender(async () => {
    await refreshEnv();
    await refreshStale();
    await renderCurrent();
  });
}

export function startFromHash() {
  const id = window.location.hash.replace('#/', '') || 'dashboard';
  return go(id);
}

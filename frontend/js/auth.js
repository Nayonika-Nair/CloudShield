// ============================================================
// CloudShield Auth (view toggling)
// ============================================================
// Handles switching between the login screen and the app shell.
// This module has no knowledge of any specific page's data.

export function login() {
  document.getElementById('view-login').classList.add('hidden');
  const app = document.getElementById('view-app');
  app.classList.remove('hidden');
  app.classList.add('fade-in');
}

export function logout() {
  document.getElementById('view-app').classList.add('hidden');
  document.getElementById('view-login').classList.remove('hidden');
}
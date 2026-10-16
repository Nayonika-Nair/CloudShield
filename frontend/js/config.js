// ============================================================
// CloudShield runtime configuration
// ============================================================
// apiBase is the origin of the FastAPI backend.
//   ''                       -> same origin (served by uvicorn, or proxied by the nginx container)
//   'http://localhost:8000'  -> use when the static files are served by another server
// A value stored in localStorage under 'cloudshield.apiBase' overrides this file (handy for demos).

(function () {
  var stored = null;
  try { stored = window.localStorage.getItem('cloudshield.apiBase'); } catch (e) { /* storage unavailable */ }
  window.CLOUDSHIELD_CONFIG = { apiBase: stored !== null ? stored : '' };
})();

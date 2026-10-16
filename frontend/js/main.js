// ============================================================
// CloudShield Frontend Entry Point
// ============================================================
// Wires the shell together: error reporting, authentication,
// navigation and every view. Views own their rendering; all data
// comes from the API through js/api.js.

import { ApiError, getToken } from './api.js';
import { enterApp, initAuth, leaveApp } from './auth.js';
import { initNavigation, registerView, startFromHash } from './navigation.js';
import { registerActions, setErrorSink } from './state.js';
import { closeDrawer, closeModal, toast } from './utils.js';
import { initRemediationUi } from './remediation.js';

import * as dashboard from './views/dashboard.js';
import * as simulator from './views/simulator.js';
import * as inventory from './views/inventory.js';
import * as topology from './views/topology.js';
import * as iam from './views/iam.js';
import * as security from './views/security.js';
import * as cost from './views/cost.js';
import * as optimization from './views/optimization.js';
import * as whatif from './views/whatif.js';
import * as audit from './views/audit.js';
import * as reports from './views/reports.js';

setErrorSink((e) => {
  if (e instanceof ApiError && e.status === 401) return; // handled by the session-expired flow
  console.error(e);
  toast(e && e.message ? e.message : 'Something went wrong', 'error');
});

initNavigation();
initRemediationUi();
registerActions({ 'close-drawer': closeDrawer, 'close-modal': closeModal });

[dashboard, simulator, inventory, topology, iam, security, cost, optimization, whatif, audit, reports].forEach((v) => {
  registerView(v.view);
  if (v.init) v.init();
});

const hasToken = initAuth(() => startFromHash());
if (hasToken) {
  enterApp(() => startFromHash()).catch(() => leaveApp(''));
}

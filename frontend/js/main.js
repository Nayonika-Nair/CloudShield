// ============================================================
// CloudShield Frontend Entry Point
// ============================================================
// The only module that knows every other module exists. Wires
// functions onto window so existing inline onclick="" handlers
// in index.html keep working unchanged, then runs the initial
// render for every view (mirrors the original script's init
// block, which rendered all views' data up front).

import { login, logout } from './auth.js';
import { go } from './navigation.js';
import { initDashboard } from './views/dashboard.js';
import { filterFindings, runScan, initSecurity } from './views/security.js';
import { applyRec, initCost } from './views/cost.js';
import { switchTab, syncAws, initInventory } from './views/inventory.js';
import { selectReport, generateReport, initReports } from './views/reports.js';

window.login = login;
window.logout = logout;
window.go = go;
window.filterFindings = filterFindings;
window.runScan = runScan;
window.applyRec = applyRec;
window.switchTab = switchTab;
window.syncAws = syncAws;
window.selectReport = selectReport;
window.generateReport = generateReport;

initDashboard();
initSecurity();
initCost();
initInventory();
initReports();
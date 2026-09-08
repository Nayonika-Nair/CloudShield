// ============================================================
// CloudShield Dashboard View
// ============================================================
// Owns the dashboard's mock alert data and rendering. No other
// module reads or writes this data.

import { badge, renderBars } from '../utils.js';

const alerts = [
  ['Public S3 bucket detected', 'customer-data-backup', 'high'],
  ['EC2 instance idle 14 days', 'i-0af23bcd991', 'medium'],
  ['IAM user missing MFA', 'svc-deploy-bot', 'high'],
  ['Unattached EBS volume', 'vol-0912ffeaa', 'low'],
  ['Security Group open to 0.0.0.0/0 on port 22', 'sg-04af882', 'high'],
];

function renderAlerts() {
  const el = document.getElementById('alert-list');
  el.innerHTML = alerts
    .map(
      (a) => `
    <div class="alert-row">
      <div class="alert-dot" style="background:var(--${a[2] === 'high' ? 'red' : a[2] === 'medium' ? 'amber' : 'green'})"></div>
      <div class="txt"><b>${a[0]}</b><span>${a[1]}</span></div>
      ${badge(a[2])}
    </div>`
    )
    .join('');
}

export function initDashboard() {
  renderAlerts();
  renderBars('cost-bars');
}
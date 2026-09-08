// ============================================================
// CloudShield Security Findings View
// ============================================================
// Owns findings data, rendering, filtering, and the scan button.

import { badge } from '../utils.js';

const findings = [
  ['Publicly accessible S3 bucket', 'customer-data-backup', 'high', 'Open', '2 days ago'],
  ['Security Group allows 0.0.0.0/0 on port 22 (SSH)', 'sg-04af882e1', 'high', 'Open', '2 days ago'],
  ['IAM user without MFA enabled', 'svc-deploy-bot', 'high', 'Open', '3 days ago'],
  ['Publicly accessible RDS instance', 'prod-db-cluster', 'high', 'Open', '3 days ago'],
  ['Unencrypted EBS volume', 'vol-0912ffeaa', 'medium', 'Open', '4 days ago'],
  ['Security Group allows 0.0.0.0/0 on port 3389 (RDP)', 'sg-0a2c9910', 'high', 'Open', '5 days ago'],
  ['Old snapshot older than 90 days', 'snap-0281ee331', 'low', 'Acknowledged', '6 days ago'],
  ['S3 bucket without encryption', 'app-logs-archive', 'medium', 'Open', '6 days ago'],
  ['IAM policy grants full admin access', 'role-ci-cd-pipeline', 'medium', 'Resolved', '8 days ago'],
  ['Root account access key detected', 'root', 'high', 'Open', '9 days ago'],
];

export function renderFindings(filter) {
  const body = document.getElementById('findings-body');
  const list = filter && filter !== 'all' ? findings.filter((f) => f[2] === filter) : findings;
  body.innerHTML = list
    .map(
      (f) => `
    <tr class="row-fade">
      <td class="strong">${f[0]}</td>
      <td class="mono">${f[1]}</td>
      <td>${badge(f[2])}</td>
      <td>${f[3]}</td>
      <td>${f[4]}</td>
    </tr>`
    )
    .join('');
}

export function filterFindings(sev, el) {
  document.querySelectorAll('[data-sev]').forEach((c) => c.classList.remove('active'));
  el.classList.add('active');
  renderFindings(sev);
}

export function runScan() {
  const btn = event.currentTarget;
  const original = btn.textContent;
  btn.textContent = 'Scanning...';
  btn.style.opacity = '0.7';
  setTimeout(() => {
    btn.textContent = original;
    btn.style.opacity = '1';
    renderFindings('all');
    document.querySelectorAll('[data-sev]').forEach((c) => c.classList.toggle('active', c.dataset.sev === 'all'));
  }, 1100);
}

export function initSecurity() {
  renderFindings('all');
}
// ============================================================
// CloudShield Reports View
// ============================================================
// Owns report type definitions, report history, and the
// generate-report interaction.

import { badge } from '../utils.js';

const reportTypes = [
  { title: 'Security Report', desc: 'Full findings, risk scores, remediation steps' },
  { title: 'Cost Optimization Report', desc: 'Spend breakdown, waste, savings opportunities' },
  { title: 'Full Infrastructure Report', desc: 'Combined security, cost, and inventory summary' },
];

let reportHistory = [
  ['Weekly Security Summary', 'Security', 'Jul 28, 2026', 'ready'],
  ['July Cost Optimization Report', 'Cost', 'Jul 25, 2026', 'ready'],
  ['Full Infra Audit \u2014 Q2', 'Full', 'Jul 10, 2026', 'ready'],
  ['Security Report \u2014 MFA Compliance', 'Security', 'Jul 05, 2026', 'ready'],
];

let selectedReport = 0;

export function renderReportCards() {
  const el = document.getElementById('report-cards');
  el.innerHTML = reportTypes
    .map(
      (r, i) => `
    <div class="glass report-card ${i === 0 ? 'selected' : ''}" data-idx="${i}" onclick="selectReport(${i}, this)">
      <div class="report-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M7 3h7l4 4v14H7z"/><path d="M14 3v4h4M9 13h6M9 17h6"/></svg></div>
      <h4>${r.title}</h4>
      <p>${r.desc}</p>
    </div>`
    )
    .join('');
}

export function renderHistory() {
  const el = document.getElementById('report-history');
  el.innerHTML = reportHistory
    .map(
      (r) => `
    <tr class="row-fade">
      <td class="strong">${r[0]}</td>
      <td>${r[1]}</td>
      <td>${r[2]}</td>
      <td>${badge(r[3])}</td>
      <td>${r[3] === 'ready' ? '<span class="link-btn">Download</span>' : ''}</td>
    </tr>`
    )
    .join('');
}

export function selectReport(i, el) {
  document.querySelectorAll('.report-card').forEach((c) => c.classList.remove('selected'));
  el.classList.add('selected');
  selectedReport = i;
}

export function generateReport() {
  const name = 'Generating: ' + reportTypes[selectedReport].title;
  reportHistory.unshift([name, reportTypes[selectedReport].title.split(' ')[0], 'Jul 29, 2026', 'processing']);
  renderHistory();
  setTimeout(() => {
    reportHistory[0][0] = reportTypes[selectedReport].title + ' \u2014 Jul 29';
    reportHistory[0][3] = 'ready';
    renderHistory();
  }, 1800);
}

export function initReports() {
  renderReportCards();
  renderHistory();
}
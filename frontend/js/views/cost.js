// ============================================================
// CloudShield Cost Optimization View
// ============================================================
// Owns cost recommendation data, rendering, and "apply" state.

import { renderBars } from '../utils.js';

const recs = [
  ['i-0af23bcd991', 'EC2 (idle 14d)', '$62/mo', 'Stop or downsize instance', '$62/mo'],
  ['vol-0912ffeaa', 'EBS (unattached)', '$18/mo', 'Delete unattached volume', '$18/mo'],
  ['eip-0a2f991', 'Elastic IP (unused)', '$4/mo', 'Release unused IP', '$4/mo'],
  ['snap-0281ee331', 'Snapshot (90+ days)', '$9/mo', 'Archive or delete old snapshot', '$9/mo'],
  ['i-0bc77aa213', 'EC2 (oversized)', '$140/mo', 'Right-size to t3.medium', '$70/mo'],
  ['s3-app-logs-archive', 'S3 (infrequent access)', '$31/mo', 'Move to Glacier storage class', '$22/mo'],
];

let savedTotal = 1120;

export function renderRecs() {
  const el = document.getElementById('rec-list');
  el.innerHTML = recs
    .map(
      (r, i) => `
    <div class="rec-row">
      <div class="mono strong">${r[0]}</div>
      <div>${r[1]}</div>
      <div>${r[2]}</div>
      <div>${r[3]}</div>
      <div style="color:var(--green); font-weight:700;">${r[4]}</div>
      <div class="apply-btn" id="apply-${i}" onclick="applyRec(${i})">Apply</div>
    </div>`
    )
    .join('');
}

export function applyRec(i) {
  const btn = document.getElementById('apply-' + i);
  if (btn.classList.contains('applied')) return;
  btn.classList.add('applied');
  btn.textContent = 'Applied \u2713';
  const val = parseInt(recs[i][4].replace(/\D/g, ''));
  savedTotal -= val;
}

export function initCost() {
  renderBars('cost-bars-2');
  renderRecs();
}
// ============================================================
// CloudShield Navigation
// ============================================================
// Controls which top-level section is visible and updates the
// topbar title. Does not know how any section renders its data.

const titles = {
  dashboard: ['Overview', 'Dashboard'],
  security: ['Threat Detection', 'Security Findings'],
  cost: ['FinOps', 'Cost Optimization'],
  inventory: ['Cloud Assets', 'Resource Inventory'],
  reports: ['Exports', 'Reports'],
};

export function go(view) {
  document.querySelectorAll('.nav-item').forEach((n) =>
    n.classList.toggle('active', n.dataset.view === view)
  );
  document.querySelectorAll('#root .content > section').forEach((s) =>
    s.classList.add('hidden')
  );
  const sec = document.getElementById('sec-' + view);
  sec.classList.remove('hidden');
  sec.classList.add('fade-in');
  document.getElementById('topbar-eyebrow').textContent = titles[view][0];
  document.getElementById('topbar-title').textContent = titles[view][1];
}
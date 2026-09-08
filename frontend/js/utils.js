// ============================================================
// CloudShield Shared Utilities
// ============================================================
// Small rendering helpers reused across multiple views.
// No view-specific data or DOM structure lives here.

export function badge(sev) {
  return `<span class="badge ${sev}">${sev}</span>`;
}

export function renderBars(targetId, seed) {
  const el = document.getElementById(targetId);
  const vals = seed || [
    62, 70, 55, 80, 66, 90, 74, 68, 85, 60, 72, 95, 88, 64, 77,
    69, 58, 81, 73, 66, 90, 84, 70, 62, 75, 80, 67, 71, 88, 92,
  ];
  el.innerHTML = vals
    .map((v) => `<div class="bar" style="height:${v}%"><div class="bar-tip">$${(v * 4.1).toFixed(0)}</div></div>`)
    .join('');
}
// ============================================================
// CloudShield Resource Inventory View
// ============================================================
// Owns inventory data for EC2/S3/RDS/IAM tabs and their rendering.

const inventories = {
  ec2: {
    title: 'EC2 Instances (24)',
    head: ['Instance ID', 'Type', 'Region', 'State', 'Public IP', 'Cost/mo', 'Utilization'],
    rows: [
      ['i-0af23bcd991', 't3.large', 'us-east-1', 'Running', '34.221.10.4', '$62', '3%', 'amber'],
      ['i-0bc77aa213', 'm5.xlarge', 'us-east-1', 'Running', '\u2014', '$140', '12%', 'amber'],
      ['i-0cd88bb442', 't3.medium', 'us-west-2', 'Running', '52.14.98.2', '$31', '68%', 'green'],
      ['i-0ef99cc551', 't3.small', 'us-east-1', 'Stopped', '\u2014', '$0', '\u2014', 'dim'],
      ['i-0fa11dd662', 'c5.large', 'eu-west-1', 'Running', '18.203.44.9', '$74', '81%', 'green'],
      ['i-0gb22ee773', 't3.large', 'us-east-1', 'Running', '3.91.201.7', '$62', '5%', 'amber'],
    ],
  },
  s3: {
    title: 'S3 Buckets (18)',
    head: ['Bucket Name', 'Region', 'Public Access', 'Encryption', 'Size', 'Cost/mo'],
    rows: [
      ['customer-data-backup', 'us-east-1', 'Public', 'Disabled', '412 GB', '$9.50', 'red'],
      ['app-logs-archive', 'us-east-1', 'Private', 'Disabled', '1.2 TB', '$27.60', 'amber'],
      ['static-assets-prod', 'us-west-2', 'Public (CDN)', 'Enabled', '88 GB', '$2.00', 'green'],
      ['terraform-state', 'eu-west-1', 'Private', 'Enabled', '2 GB', '$0.10', 'green'],
    ],
  },
  rds: {
    title: 'RDS Databases (5)',
    head: ['Identifier', 'Engine', 'Public Access', 'Multi-AZ', 'Cost/mo', 'Status'],
    rows: [
      ['prod-db-cluster', 'PostgreSQL 15', 'Yes', 'Yes', '$310', 'red'],
      ['staging-db', 'MySQL 8.0', 'No', 'No', '$85', 'green'],
      ['analytics-readonly', 'PostgreSQL 14', 'No', 'Yes', '$140', 'green'],
    ],
  },
  iam: {
    title: 'IAM Users & Roles (31)',
    head: ['Name', 'Type', 'MFA Enabled', 'Last Active', 'Access Level'],
    rows: [
      ['svc-deploy-bot', 'User', 'No', 'Today', 'Admin', 'red'],
      ['root', 'Root Account', 'No', '4 days ago', 'Full Access', 'red'],
      ['role-ci-cd-pipeline', 'Role', 'N/A', 'Today', 'Admin', 'amber'],
      ['j.smith', 'User', 'Yes', 'Today', 'ReadOnly', 'green'],
    ],
  },
};

export function renderInventory(key) {
  const data = inventories[key];
  document.getElementById('inv-title').textContent = data.title;
  document.getElementById('inv-head').innerHTML = '<tr>' + data.head.map((h) => `<th>${h}</th>`).join('') + '</tr>';
  document.getElementById('inv-body').innerHTML = data.rows
    .map((r) => {
      const color = r[r.length - 1];
      const cells = r.slice(0, -1);
      return (
        '<tr class="row-fade">' +
        cells
          .map(
            (c, i) =>
              `<td class="${i === 0 ? 'strong mono' : ''}" style="${i === cells.length - 1 ? `color:var(--${color === 'dim' ? 'text-faint' : color}); font-weight:700;` : ''}">${c}</td>`
          )
          .join('') +
        '</tr>'
      );
    })
    .join('');
}

export function switchTab(key, el) {
  document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t === el));
  renderInventory(key);
}

export function syncAws() {
  const btn = event.currentTarget;
  const original = btn.textContent;
  btn.textContent = 'Syncing...';
  setTimeout(() => {
    btn.textContent = original;
  }, 1000);
}

export function initInventory() {
  renderInventory('ec2');
}
// ============================================================
// Topology SVG renderer
// ============================================================
// Pure function: topology JSON from the API -> SVG markup. Layout is
// computed here; exposure flags come from the backend reachability engine.

import { esc, typeLabel } from '../utils.js';

const NODE_W = 190;
const NODE_H = 36;
const GAP = 8;
const SUB_W = 212;
const SUB_GAP = 14;

const trunc = (s, n) => (String(s).length > n ? String(s).slice(0, n - 1) + '…' : String(s));

function layout(topo) {
  const byParent = {};
  topo.nodes.forEach((n) => { (byParent[n.parent || ''] = byParent[n.parent || ''] || []).push(n); });
  const vpcs = topo.nodes.filter((n) => n.type === 'vpc');
  const pos = {};
  let y = 120;
  let maxW = 640;
  const boxes = [];
  vpcs.forEach((vpc) => {
    const subnets = (byParent[vpc.id] || []).filter((n) => n.type === 'subnet')
      .sort((a, b) => (a.attrs.tier === b.attrs.tier ? a.label.localeCompare(b.label) : a.attrs.tier === 'public' ? -1 : 1));
    const sgs = (byParent[vpc.id] || []).filter((n) => n.type === 'security_group');
    const igw = (byParent[vpc.id] || []).find((n) => n.type === 'internet_gateway');
    const contents = subnets.map((s) => (byParent[s.id] || []).filter((n) => ['ec2_instance', 'rds_instance', 'load_balancer'].includes(n.type)));
    const subH = Math.max(...contents.map((c) => 42 + Math.max(1, c.length) * (NODE_H + GAP) + 4), 80);
    const width = 20 + subnets.length * (SUB_W + SUB_GAP) + 6;
    const per = Math.max(1, Math.floor((width - 20) / 134));
    const sgRows = Math.ceil(sgs.length / per);
    const height = 56 + subH + 20 + sgRows * 28 + 14;
    boxes.push({ vpc, x: 20, y, width, height, subnets, contents, sgs, igw, subH });
    subnets.forEach((s, i) => {
      const sx = 30 + i * (SUB_W + SUB_GAP);
      const sy = y + 56;
      pos[s.id] = { x: sx, y: sy, w: SUB_W, h: subH };
      contents[i].forEach((n, k) => { pos[n.id] = { x: sx + 11, y: sy + 42 + k * (NODE_H + GAP), w: NODE_W, h: NODE_H }; });
    });
    if (igw) pos[igw.id] = { x: 20 + width - 160, y: y + 10, w: 140, h: 28 };
    sgs.forEach((sg, i) => {
      pos[sg.id] = { x: 30 + (i % per) * 134, y: y + 56 + subH + 14 + Math.floor(i / per) * 28, w: 126, h: 22 };
    });
    maxW = Math.max(maxW, width + 20);
    y += height + 22;
  });
  boxes.forEach((b, i) => { b.gutterX = maxW + 10 + i * 9; });
  const buckets = topo.nodes.filter((n) => n.type === 's3_bucket');
  const rx = maxW + 30 + boxes.length * 9;
  buckets.forEach((b, i) => { pos[b.id] = { x: rx, y: 150 + i * (NODE_H + GAP), w: 236, h: NODE_H }; });
  pos.internet = { x: Math.max(240, maxW / 2 - 60), y: 24, w: 120, h: 40 };
  return { boxes, pos, width: rx + 260, height: Math.max(y + 10, 150 + buckets.length * (NODE_H + GAP) + 40), buckets, rx };
}

function drawNode(n, p) {
  const klass = ['g-node'];
  if (n.exposed) klass.push('exposed'); else if (n.internet_facing) klass.push('facing');
  if (n.state === 'stopped') klass.push('stopped');
  let sub = '';
  if (n.type === 'ec2_instance') sub = `${n.attrs.instance_type} · ${n.attrs.public_ip || n.attrs.private_ip}`;
  else if (n.type === 'rds_instance') sub = `${n.attrs.engine} · ${n.attrs.instance_class}`;
  else if (n.type === 'load_balancer') sub = `ALB · ${n.attrs.targets} targets`;
  else if (n.type === 's3_bucket') sub = (n.attrs.public ? 'PUBLIC · ' : '') + 'encryption ' + n.attrs.encryption;
  const ports = n.exposed_ports && n.exposed_ports.length ? n.exposed_ports.map((x) => (x === 0 ? 'ALL' : x)).join(',') : '';
  const flag = n.exposed ? `EXPOSED ${ports}` : n.internet_facing ? 'public web' : '';
  const flagStyle = n.exposed ? '' : ' style="fill:var(--c7);font-weight:700"';
  return `<g data-action="topo-node" data-id="${esc(n.id)}" tabindex="0" role="button" aria-label="${esc(typeLabel(n.type))} ${esc(n.label)}${n.exposed ? ', exposed to the internet' : ''}">
    <title>${esc(n.label)} (${esc(n.id)})${n.exposed ? ' - reachable from the internet on ' + ports : ''}</title>
    <rect class="${klass.join(' ')}" x="${p.x}" y="${p.y}" width="${p.w}" height="${p.h}" rx="5"></rect>
    <text class="g-label" x="${p.x + 8}" y="${p.y + 15}">${esc(trunc(n.label, 27))}</text>
    <text class="g-sub" x="${p.x + 8}" y="${p.y + 28}">${esc(trunc(sub, flag ? 21 : 36))}</text>
    ${flag ? `<text class="${n.exposed ? 'g-badge' : 'g-sub'}" x="${p.x + p.w - 7}" y="${p.y + 28}" text-anchor="end"${flagStyle}>${esc(flag)}</text>` : ''}
  </g>`;
}

function curve(a, b, cls) {
  const x1 = a.x + a.w;
  const y1 = a.y + a.h / 2;
  const x2 = b.x;
  const y2 = b.y + b.h / 2;
  const mx = (x1 + x2) / 2;
  const d = x2 > x1
    ? `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`
    : `M${a.x},${y1} C${a.x - 40},${y1} ${b.x + b.w + 40},${y2} ${b.x + b.w},${y2}`;
  return `<path class="g-edge ${cls}" d="${d}"></path>`;
}

export function topologySvg(topo, { showSg = false } = {}) {
  const L = layout(topo);
  const { pos } = L;
  let out = '';
  L.boxes.forEach((b) => {
    out += `<rect class="g-vpc" x="${b.x}" y="${b.y}" width="${b.width}" height="${b.height}" rx="8"></rect>`;
    out += `<text class="g-title" x="${b.x + 12}" y="${b.y + 24}">${esc(b.vpc.label)} · ${esc(b.vpc.attrs.cidr)}</text>`;
    b.subnets.forEach((s) => {
      const p = pos[s.id];
      const pub = s.attrs.internet_route === 'igw';
      out += `<rect class="g-subnet-${pub ? 'public' : 'private'}" x="${p.x}" y="${p.y}" width="${p.w}" height="${p.h}" rx="6" stroke-width="1.2" data-action="topo-node" data-id="${esc(s.id)}" style="cursor:pointer"><title>${esc(s.label)}: ${pub ? 'routes to the internet gateway' : 'no internet route'}</title></rect>`;
      out += `<text class="g-label" x="${p.x + 10}" y="${p.y + 17}" style="font-weight:700">${esc(trunc(s.label, 22))}</text>`;
      out += `<text class="g-sub" x="${p.x + p.w - 10}" y="${p.y + 17}" text-anchor="end" style="font-weight:700;fill:${pub ? 'var(--ok)' : 'var(--text-faint)'}">${pub ? 'PUBLIC' : 'PRIVATE'}</text>`;
      out += `<text class="g-sub" x="${p.x + 10}" y="${p.y + 31}">${esc(s.attrs.cidr)} · ${esc(s.attrs.az)}</text>`;
    });
  });
  const inet = pos.internet;
  L.boxes.forEach((b) => {
    if (!b.igw) return;
    const g = pos[b.igw.id];
    // elbow from the Internet node, down the right-hand gutter and into the gateway
    out += `<path class="g-edge route" d="M${inet.x + inet.w},${inet.y + inet.h / 2} H${b.gutterX} V${g.y + g.h / 2} H${g.x + g.w}"></path>`;
  });
  topo.edges.forEach((e) => {
    const a = pos[e.source];
    const b = pos[e.target];
    if (!a || !b) return;
    if (e.kind === 'forwards') out += curve(a, b, 'forwards');
    else if (e.kind === 'uses' && showSg) out += curve(a, b, 'dim');
  });
  out += `<g><rect class="g-node" x="${inet.x}" y="${inet.y}" width="${inet.w}" height="${inet.h}" rx="20" style="cursor:default"></rect><text class="g-label" x="${inet.x + inet.w / 2}" y="${inet.y + 25}" text-anchor="middle" style="font-weight:700">Internet</text></g>`;
  L.boxes.forEach((b) => {
    if (b.igw) {
      const p = pos[b.igw.id];
      out += `<g data-action="topo-node" data-id="${esc(b.igw.id)}" tabindex="0" role="button" aria-label="Internet gateway ${esc(b.igw.label)}"><rect class="g-node" x="${p.x}" y="${p.y}" width="${p.w}" height="${p.h}" rx="14"></rect><text class="g-label" x="${p.x + p.w / 2}" y="${p.y + 18}" text-anchor="middle">Internet gateway</text></g>`;
    }
    b.contents.forEach((c) => c.forEach((n) => { out += drawNode(n, pos[n.id]); }));
    b.sgs.forEach((sg) => {
      const p = pos[sg.id];
      out += `<g data-action="topo-node" data-id="${esc(sg.id)}" tabindex="0" role="button" aria-label="Security group ${esc(sg.label)}"><title>${esc(sg.label)}${sg.exposed ? ' - has world-open rules' : ''}</title><rect class="g-node ${sg.exposed ? 'exposed' : ''}" x="${p.x}" y="${p.y}" width="${p.w}" height="${p.h}" rx="11"></rect><text class="g-sub" x="${p.x + 8}" y="${p.y + 15}" style="fill:var(--text)">${esc(trunc(sg.label, 20))}</text></g>`;
    });
  });
  out += `<text class="g-title" x="${L.rx}" y="132">S3 buckets (regional)</text>`;
  L.buckets.forEach((n) => { out += drawNode(n, pos[n.id]); });
  return `<svg viewBox="0 0 ${L.width} ${L.height}" style="width:100%;height:auto" preserveAspectRatio="xMinYMin meet" role="img" aria-label="Network topology diagram of the simulated account">${out}</svg>`;
}

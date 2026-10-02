const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const ui = require(path.resolve(__dirname, '../../boannews_vercel_deploy/dashboard/assets/analysis-flow.js'));
const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/analysis_flow_clickfix.json'), 'utf8'));
const flow = { ...fixture.candidate, version: 1, status: 'ready', basis: 'article',
  title: '기사 기반 공격 흐름', phases: ['유입과 실행 유도', '실행과 방어 회피', '후속 동작과 기능'], source_url: fixture.source_url };
assert.equal(ui.valid(flow), true);
for (const width of [280, 390, 760, 1240, 1400]) {
  const graph = ui.layout(flow, width);
  assert.equal(graph.nodes.length, 10);
  for (const node of graph.nodes) {
    assert.ok(node.x >= 0 && node.x + node.w <= graph.width);
    assert.ok(node.y >= 0 && node.y + node.h <= graph.height);
    for (const other of graph.nodes) {
      if (other.id === node.id) continue;
      assert.ok(node.x + node.w <= other.x || other.x + other.w <= node.x ||
        node.y + node.h <= other.y || other.y + other.h <= node.y, 'node overlap');
    }
  }
  const image = ui.svg(flow, width, 'test');
  assert.match(image, /data-from="n3" data-to="n4"/);
  assert.doesNotMatch(image, /data-from="n3" data-to="n7"/);
  assert.equal((image.match(/data-from="n7"/g) || []).length, 3);
  assert.ok(image.includes('Common.Integrator.Preview\\.wav') || graph.nodes.find(n => n.id === 'n6').lines.join('').includes('Common.Integrator.Preview\\.wav'));
}
const unsafe = structuredClone(flow);
unsafe.nodes[0].detail = ['<script>alert(1)</script>'];
assert.doesNotMatch(ui.svg(unsafe, 1400, 'test'), /<script>/);
const cycle = structuredClone(flow);
cycle.edges.push({ ...cycle.edges[0], from: 'n3', to: 'n1' });
assert.equal(ui.valid(cycle), false);
assert.equal(ui.valid(null), false);
assert.equal(ui.valid({ ...flow, status: 'skipped' }), false);
console.log('Analysis flow: 5 widths, correct edges, branches, overlap and escaping checks passed.');

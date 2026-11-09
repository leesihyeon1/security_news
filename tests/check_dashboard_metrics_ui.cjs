const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync(process.argv[2], 'utf8');
const render = source.slice(source.indexOf('  function renderStatStrip('), source.indexOf('  const LEVEL_LABELS'));
const context = { esc: String, INFO_CATEGORY_TOP_N: 5 };
vm.createContext(context);
vm.runInContext(render, context);
const html = context.renderStatStrip({total: 5, p1: 1, p2: 1, actionable: 3,
  actionable_by_category: {'Unknown': 1, 'Vulnerability': 2}, actionable_info_by_category: {'Wrong': 99}});
assert(html.includes('Vulnerability'));
assert(!html.includes('Wrong'));
const statusCode = source.slice(source.indexOf('    const status = payload.data_status'), source.indexOf('    renderTrendingSidebar();', source.indexOf('    const status = payload.data_status')));
context.payload = {title: 'Test', period: 'daily', period_label: 'Period', generated_at: new Date().toISOString(),
  data_status: {period_end: '2000-01-01T00:00:00Z', stale_after_hours: 36}};
context.$generatedAt = {setAttribute() {}};
context.fmtDate = String;
vm.runInContext(statusCode, context);
assert(context.$generatedAt.textContent.includes('36'));
assert(context.$generatedAt.textContent.includes('갱신 확인 필요'));
console.log('Category rendering and stale-data warning passed.');

const assert = require('node:assert/strict');
const test = require('node:test');
const api = require('../../boannews_vercel_deploy/dashboard/assets/report-pdf.js');
globalThis.AnalysisFlow = require('../../boannews_vercel_deploy/dashboard/assets/analysis-flow.js');
const fixture = require('./report_pdf_fixture.cjs');
const copy = value => JSON.parse(JSON.stringify(value));
test('allowlisted report excludes provenance but preserves uncertainty and full identifiers', () => {
  const original = JSON.stringify(fixture);
  const result = api.model(fixture);
  const doc = JSON.stringify(api.definition(result, fixture.analysis_flow));
  assert(!doc.includes('PRIVATE_EVIDENCE'));
  assert(!doc.includes('https://example.test/citation'));
  assert(doc.includes('미확인'));
  assert(doc.includes('0123456789abcdef'.repeat(4)));
  assert(doc.includes('미검증 후보'));
  assert(doc.includes('리졸버는 C2 서버가 아님'));
  assert.equal(result.cases[0].queries[1].code, 'filename:"jsrepo?rnd="');
  assert.equal(JSON.stringify(fixture), original);
});
test('failed and pending entries cannot be exported; partial research stays explicit', () => {
  assert(!api.available({ title: '대기' }));
  assert(!api.available({ analysis: '수집 실패', collection_failed: true }));
  assert.throws(() => api.model({}), /완료된/);
  assert(api.model(fixture).cases[0].open.length);
});
test('informational reports use review terminology without invented detection sections', () => {
  const entry = { title: '제품 소식', analysis: '[주요 내용]\n제품의 지원 범위 소개\n[권장 대응]\n도입 조건 검토', targets: { article_kind: 'informational' } };
  const doc = JSON.stringify(api.definition(api.model(entry)));
  assert(doc.includes('보안 동향 분석 보고서'));
  assert(doc.includes('검토 과제'));
  assert(!doc.includes('탐지 및 점검 자료'));
});
test('incidents remain independent, stale merged results are not repeated', () => {
  const entry = copy(fixture);
  entry.investigation.incidents = [
    { incident_label: '사건 A', synthesis: { headline: 'A 분석', unconfirmed: ['A 미확인'] } },
    { incident_label: '사건 B', synthesis: { headline: 'B 분석' } },
  ];
  const result = api.model(entry);
  assert.equal(result.cases.length, 2);
  assert.deepEqual(result.cases[0].open, ['A 미확인']);
  assert.deepEqual(result.cases[1].open, []);
  assert(!JSON.stringify(result.cases).includes(fixture.investigation.synthesis.headline));
});
test('source cleanup preserves technical URLs and code is never normalized', () => {
  const entry = copy(fixture);
  entry.analysis = '[기술적 세부사항]\n유포 경로: https://malicious.example/path?q=1\n근거 — 원문 인용\n출처: https://reference.example\n관측값[1]\n[원문 내 관련 링크]\nhttps://reference.example';
  entry.investigation.response.commands = [{ command: 'x[1] = "__value__"; # [1] means index', name: '문법 보존' }];
  const result = api.model(entry);
  assert(result.sections[0].text.includes('https://malicious.example/path?q=1'));
  assert(!JSON.stringify(result).includes('reference.example'));
  assert(!result.sections[0].text.includes('원문 인용'));
  assert.equal(result.cases[0].queries.find(q => q.name === '문법 보존').code, 'x[1] = "__value__"; # [1] means index');
  assert.equal(api.clean('파일 `__init__.py` **분석** [1](https://example.test)\n1. 근거: 생략'), '파일 __init__.py 분석');
});
test('legacy long content and filenames are safe; no silent list truncation', () => {
  const entry = { title: 'A/B:*?"<>|\n.', analysis: '[핵심 요약]\n' + '분석 내용 '.repeat(500),
    investigation: { synthesis: { confirmed: Array.from({ length: 35 }, (_, i) => '결과 ' + i) } } };
  const result = api.model(entry);
  assert.equal(result.cases[0].findings.length, 35);
  assert(result.sections[0].text.length > 2500);
  assert(!/[\\/:*?"<>|\n]/.test(api.filename(entry)));
});
test('failed synthesis, unavailable CVE data and rejected search rules remain explicit', () => {
  const entry = copy(fixture);
  entry.investigation.synthesis_status = { status: 'failed' };
  entry.investigation.vulnerability = { cves: [{ cve: 'CVE-TEST', nvd: {}, kev_checked: false, epss: null }] };
  entry.investigation.seeds = [{ queries: [{ name: '오탐 규칙', query: 'page.title:captcha', validation: 'rejected', caution: '정상 페이지 과다 포함' }] }];
  const result = api.model(entry), doc = JSON.stringify(api.definition(result));
  assert(doc.includes('종합 분석을 완료하지 못했습니다'));
  assert(doc.includes('조회 상태 미확인'));
  assert(doc.includes('사용 금지'));
  assert(doc.includes('정상 페이지 과다 포함'));
  assert.equal(result.cases[0].vulnerabilities[0].epss, '미확인');
});

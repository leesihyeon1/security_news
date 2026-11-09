// Generate a self-contained, offline review artifact from the regression fixture.
const fs = require('node:fs');
const path = require('node:path');
const sample = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/analysis_flow_clickfix.json'), 'utf8'));
const assets = path.resolve(__dirname, '../../boannews_vercel_deploy/dashboard/assets');
const flow = { ...sample.candidate, version: 1, status: 'ready', basis: 'article',
  title: '기사 기반 공격 흐름', phases: ['유입과 실행 유도', '실행과 방어 회피', '후속 동작과 기능'], source_url: sample.source_url };
const read = (name) => fs.readFileSync(path.join(assets, name), 'utf8');
const entry = { ref: 'flow-local-preview', title: 'Custom GPT 악용 ClickFix 공격 흐름',
  category: sample.category, source_label: '제공된 기술적 세부사항 · 로컬 시안',
  analysis_flow: flow, targets: sample.targets, url: sample.source_url,
  analysis: '[핵심 요약]\n제공된 기술적 세부사항을 사용한 화면 검증 예시입니다.\n\n[기술적 세부사항]\n' +
    sample.candidate.nodes.map((n, i) => (i + 1) + '. ' + n.evidence).join('\n'),
  investigation: { route: { label: '사용자 실행 유도와 악성코드' }, targets: sample.targets } };
const html = '<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
  '<title>공격 흐름도 구현 미리보기</title><style>' + read('style.css') + '\n' + read('analysis-flow.css') +
  '\nbody{margin:0;padding:24px;background:var(--bg)}main{max-width:1400px;margin:auto}h1{font-size:20px;margin:0 0 20px}</style>' +
  '<main><h1>Custom GPT 악용 ClickFix · 구현 미리보기</h1><div id="preview"><div class="analysis-layout"></div></div></main>' +
  '<script>' + read('lucide.min.js') + '</script><script>' + read('analysis-flow.js') + '</script><script>window.flowPreview=' +
  JSON.stringify(entry).replace(/</g, '\\u003c') + ';AnalysisFlow.mount(document.getElementById("preview"),flowPreview.analysis_flow);</script></html>';
const out = path.resolve(__dirname, '../output/analysis-flow-preview.html');
fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, html, 'utf8');
console.log(out);

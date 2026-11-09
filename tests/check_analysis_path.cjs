const assert = require('node:assert/strict');
const { test } = require('node:test');
const api = require('../../boannews_vercel_deploy/dashboard/assets/analysis-path.js');
const fixtures = require('./analysis_path_fixture.cjs');
const clone = value => structuredClone(value);

test('saved goal links preserve issues, executions, results and exact plan indices', () => {
  const entry = clone(fixtures.threat);
  const before = JSON.stringify(entry);
  const model = api.build(entry);
  assert.equal(model.goals, 2);
  assert.equal(model.cases[0].goals[0].issue.id, 'issue-0');
  assert.equal(model.cases[0].goals[0].lookups[0].status, 'returned');
  assert.equal(model.cases[0].goals[1].response.action, entry.investigation.synthesis.plan[1].action);
  assert.equal(model.cases[0].goals[0].attempts.length, 1);
  assert.deepEqual(model.counts, { answered: 0, partial: 1, open: 1, unknown: 0 });
  assert.equal(JSON.stringify(entry), before, 'projection must not mutate saved data');
});
test('API success and available outputs never imply goal completion', () => {
  const entry = clone(fixtures.threat);
  entry.investigation.synthesis = {};
  entry.investigation.goal_evidence = [];
  entry.investigation.coverage = { done: [{ key: 'dynamic_analysis' }] };
  const model = api.build(entry);
  assert.equal(model.counts.unknown, 2);
  assert.equal(model.counts.answered, 0);
  assert.equal(model.cases[0].materials.dynamic, 0);
});
test('evidence ceiling only downgrades and does not manufacture answers', () => {
  const entry = clone(fixtures.threat);
  entry.investigation.synthesis.question_status[0].status = 'answered';
  assert.equal(api.build(entry).cases[0].goals[0].status, 'partial');
  entry.investigation.synthesis.question_status = [];
  entry.investigation.goal_evidence = [{ question: fixtures.questions[0], ceiling: 'answered' }];
  assert.equal(api.build(entry).cases[0].goals[0].status, 'unknown');
});
test('partial service failures preserve every execution rather than just the last success', () => {
  const entry = clone(fixtures.threat);
  entry.investigation.lookup_status.unshift({ key: 'user_action', status: 'failed' });
  const lookup = api.build(entry).cases[0].goals[0].lookups[0];
  assert.equal(lookup.status, 'partial');
  assert.equal(lookup.records.length, 2);
});
test('a selected lookup without execution records is never presented as executed', () => {
  const entry = clone(fixtures.threat);
  entry.investigation.lookup_status = [];
  assert.equal(api.build(entry).cases[0].goals[0].lookups[0].status, 'not_recorded');
});
test('legacy, missing, null and collection failure entries remain renderable', () => {
  for (const entry of [fixtures.legacy, fixtures.failed, {}, null]) {
    assert.match(api.render(entry), /분석 경로/);
    assert.equal(api.build(entry).counts.answered, 0);
  }
  assert.equal(api.build(fixtures.failed).hasAnalysis, false);
  assert.match(api.render(fixtures.legacy), /목표별 연결 기록이 없어/);
  assert.match(api.render(fixtures.failed), /원문 수집 실패/);
});
test('informational articles show research and use proposals without inventing threat tools', () => {
  const model = api.build(fixtures.informational);
  assert.equal(model.cases[0].informational, true);
  assert.equal(model.cases[0].goals[0].lookups[0].key, 'web');
  const html = api.render(fixtures.informational);
  assert.match(html, /활용·검토 제안/);
  assert.doesNotMatch(html, /MDE|KQL|동적 분석|공격 캠페인/);
});
test('identical questions and goal IDs in different incidents never cross-link', () => {
  const first = clone(fixtures.threat.investigation);
  first.incident_id = '1'; first.incident_label = '사건 A'; first.targets = clone(fixtures.threat.targets);
  const second = clone(first);
  second.incident_id = '2'; second.incident_label = '사건 B';
  second.synthesis.question_status[0].answer = '사건 B만의 결과';
  second.synthesis.plan[0].action = '사건 B에 대한 조치';
  second.lookup_status = [{ key: 'user_action', status: 'failed' }];
  const model = api.build({ ...fixtures.threat, targets: { incidents: ['사건 A', '사건 B', '사건 C'],
    questions_by_incident: { 3: ['사건 C 조사'] } }, investigation: { incidents: [first, second] } });
  assert.equal(model.cases.length, 3);
  assert.notEqual(model.cases[0].goals[0].answer, model.cases[1].goals[0].answer);
  assert.equal(model.cases[1].goals[0].response.action, '사건 B에 대한 조치');
  assert.equal(model.cases[1].goals[0].lookups[0].status, 'failed');
  assert.equal(model.cases[2].goals[0].status, 'unknown');
});
test('invalid action indices never attach an unrelated action from action_plan', () => {
  const entry = clone(fixtures.threat);
  entry.investigation.synthesis.question_status[0].plan_index = 99;
  entry.investigation.action_plan = [{ action: 'UNRELATED_ACTION' }];
  assert.deepEqual(api.build(entry).cases[0].goals[0].response, {});
  assert.match(api.render(entry), /목표 연결 없는 조치 제안/);
});
test('historical mapping and conclusion failure are explicit', () => {
  const entry = clone(fixtures.threat);
  entry.investigation.question_lookups[0].source = 'historical';
  entry.investigation.synthesis_status = { status: 'failed' };
  const html = api.render(entry);
  assert.match(html, /사후 연결/);
  assert.match(html, /조사 결론 생성 실패/);
  assert.doesNotMatch(html, /조치 완료/);
});
test('unlinked executions and additional research remain visible without guessing goal mappings', () => {
  const entry = clone(fixtures.threat);
  entry.investigation.research_attempts = [{ goal: '다른 질문', label: '추가 확인', status: 'failed' }];
  const item = api.build(entry).cases[0];
  assert.deepEqual(item.unlinked.map(row => row.key), ['primary']);
  assert.equal(item.extras.length, 1);
});
test('all externally supplied text and attributes are escaped', () => {
  const entry = clone(fixtures.threat);
  const unsafe = '\"><img src=x onerror=alert(1)>';
  entry.targets.questions = [unsafe];
  entry.investigation.research_plan[0].goal = unsafe;
  entry.investigation.research_plan[0].attempts[0].result = unsafe;
  const html = api.render(entry);
  assert.doesNotMatch(html, /<img|<script|data-path-match=""><img/);
  assert.match(html, /&lt;img/);
});
test('serialized attempts copied into tasks and investigation are not duplicated as unlinked', () => {
  const entry = clone(fixtures.threat);
  entry.investigation.research_attempts = clone(entry.investigation.research_plan[0].attempts);
  const item = api.build(JSON.parse(JSON.stringify(entry))).cases[0];
  assert.equal(item.goals[0].attempts.length, 1);
  assert.equal(item.extras.length, 0);
});
test('declared incident boundaries survive missing investigation results', () => {
  const entry = { targets: { incidents: ['사건 A', '사건 B'],
    questions_by_incident: { 1: ['A 목표'], 2: ['B 목표'] } } };
  const model = api.build(entry);
  assert.equal(model.cases.length, 2);
  assert.equal(model.cases[0].goals[0].question, 'A 목표');
  assert.equal(model.cases[1].goals[0].question, 'B 목표');
  assert.equal(model.counts.unknown, 2);
});
test('saved shortened stage labels are restored from basic analysis without changing stored data', () => {
  const full = '피싱 이메일로 디지털 서명된 MSP360 RMM 설치 파일을 전달하고 ScreenConnect를 설치함';
  const short = '1단계 · 피싱 이메일로 디지털 서명된 MSP360 RMM 설치 파일을…';
  const question = short + ': 실행 여부와 영향 범위를 확인할 원문·샘플·로그 근거는 무엇인가';
  const entry = {
    analysis: '[기술적 세부사항]\n1. ' + full + '\n[권장 대응]\n관련 파일 확인',
    targets: { questions: [question], issues: [{ id: 'i1-1', step_ids: ['s1'], title: short, question }] },
    investigation: { targets: { questions: [question] },
      research_plan: [{ goal: question, lookup_keys: ['primary'] }],
      synthesis: { question_status: [{ question, status: 'partial', answer: '샘플은 미확인' }] } },
  };
  const original = JSON.stringify(entry);
  const display = api.restoreStageLabels(entry);
  assert.equal(JSON.stringify(entry), original);
  assert.equal(display.targets.issues[0].title, '1단계 · ' + full);
  assert.equal(display.targets.questions[0], '1단계 · ' + full + question.slice(short.length));
  assert.equal(display.investigation.research_plan[0].goal, display.targets.questions[0]);
  assert.equal(display.investigation.synthesis.question_status[0].question, display.targets.questions[0]);
  assert.equal(api.build(display).cases[0].goals.length, 1);
  assert.doesNotMatch(api.render(display), /파일을…/);
});
test('unmatched ellipsis and unrelated multi-case records are not rewritten', () => {
  const entry = { analysis: '[기술적 세부사항]\n1. 완전히 다른 공격 단계\n',
    targets: { issues: [{ title: '1단계 · 외부 설명…', question: '1단계 · 외부 설명…: 확인할 내용', step_ids: ['s1'] }] } };
  assert.equal(api.restoreStageLabels(entry), entry);
  assert.equal(api.restoreStageLabels({ ...entry, investigation: { incidents: [{}] } }).targets, entry.targets);
});

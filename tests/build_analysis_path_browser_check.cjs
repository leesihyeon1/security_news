const fs = require('node:fs');
const path = require('node:path');
const fixtures = require('./analysis_path_fixture.cjs');
const first = structuredClone(fixtures.threat.investigation);
first.incident_id = '1'; first.incident_label = '사건 A'; first.targets = fixtures.threat.targets;
const second = structuredClone(first);
second.incident_id = '2'; second.incident_label = '사건 B';
second.synthesis.question_status[0].answer = '사건 B 고유 조사 결과';
second.synthesis.plan[0].action = '사건 B 고유 대응안';
const entries = [fixtures.threat, fixtures.informational, fixtures.legacy, fixtures.failed,
  { ...fixtures.threat, ref: 'multi-path-test', title: '분석 경로 검증: 사건 분리',
    investigation: { incidents: [first, second] } }];
const code = `async (page) => {
  const entries = ${JSON.stringify(entries)};
  const errors = [];
  const requests = [];
  page.on('pageerror', error => errors.push(String(error)));
  await page.route('https://click-tracker-two.vercel.app/**', async route => {
    requests.push(route.request().method() + ' ' + route.request().url());
    await route.fulfill({ json: route.request().url().includes('/api/insights') ? { insights: entries } : {} });
  });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto('http://127.0.0.1:8086/');
  await page.getByRole('button', { name: '인사이트 열기', exact: true }).click();
  const open = async entry => {
    await page.locator('#insight-drawer-body').getByText(entry.title, { exact: true }).click();
    await page.locator('#insight-detail.is-open').waitFor();
  };
  const tab = name => page.locator('.detail-tabs').getByRole('button', { name, exact: true });
  const body = page.locator('#insight-detail-body');
  await open(entries[0]);
  const baseline = {};
  for (const name of ['분석', '판단', '조사', '대응']) {
    await tab(name).click();
    baseline[name] = await page.locator('.detail-panel.is-active').innerText();
    if (!baseline[name].trim()) throw new Error('empty original tab: ' + name);
  }
  await tab('분석 경로').click();
  await page.locator('.ap-goal').first().waitFor();
  const graph = page.locator('.analysis-path');
  if (await graph.locator('.ap-overview svg').count() !== 5) throw new Error('Lucide diagram icons missing');
  if (await graph.locator('.ap-goal').count() !== 2) throw new Error('goals missing');
  if (!(await graph.innerText()).includes('외부 샌드박스 행위 보고 0/1')) throw new Error('false dynamic analysis');
  await page.screenshot({ path: 'output/playwright/analysis-path-desktop.png' });
  await graph.getByText('수행한 추가 조사 1건', { exact: true }).click();
  if (!await graph.getByText('연결 후보를 얻었으나 실행 명령은 미확인.', { exact: true }).isVisible()) throw new Error('attempt not expanded');
  await graph.getByRole('button', { name: '조사 내용', exact: true }).first().click();
  if (await tab('조사').getAttribute('aria-pressed') !== 'true') throw new Error('research jump failed');
  if (!await page.locator('.detail-panel.is-active .question-trail-head strong').first().evaluate(el => el === document.activeElement)) throw new Error('goal jump focus failed');
  await tab('분석 경로').click();
  await graph.getByRole('button', { name: '대응 내용', exact: true }).first().click();
  if (await tab('대응').getAttribute('aria-pressed') !== 'true') throw new Error('response jump failed');
  for (const name of Object.keys(baseline)) {
    await tab(name).click();
    if (baseline[name] !== await page.locator('.detail-panel.is-active').innerText()) throw new Error('original tab changed after navigation');
  }
  await tab('분석').focus();
  await page.keyboard.press('End');
  if (await tab('분석 경로').getAttribute('aria-pressed') !== 'true') throw new Error('keyboard tabs failed');
  for (const width of [2560, 1024, 768, 680, 390, 320]) {
    await page.setViewportSize({ width, height: 1000 });
    await tab('분석 경로').click();
    const issues = await graph.evaluate(root => {
      const boxes = [...root.querySelectorAll('.ap-overview button, .ap-lane > *, .ap-goal-heading h4, .ap-state, .ap-loop')]
        .filter(el => el.getClientRects().length);
      return boxes.filter(el => el.scrollWidth > el.clientWidth + 2 || el.getBoundingClientRect().right > innerWidth || el.getBoundingClientRect().left < 0)
        .map(el => el.className + ': ' + el.textContent.slice(0, 70));
    });
    if (issues.length) throw new Error(width + ' overflow: ' + issues.join('; '));
    if (width === 390) await page.screenshot({ path: 'output/playwright/analysis-path-mobile.png' });
  }
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.evaluate(() => document.documentElement.dataset.theme = 'dark');
  await page.screenshot({ path: 'output/playwright/analysis-path-dark.png' });
  await page.evaluate(() => document.documentElement.dataset.theme = 'light');
  await page.getByRole('button', { name: '전체 펼치기', exact: true }).click();
  if (await page.locator('.detail-panel:visible').count() !== 5) throw new Error('expand all regression');
  await tab('분석 경로').click();
  if (await page.locator('.detail-panel:visible').count() !== 1) throw new Error('collapse tabs regression');
  for (const entry of entries.slice(1)) {
    await page.getByRole('button', { name: '목록으로', exact: true }).click();
    await open(entry);
    await tab('분석 경로').click();
    const content = await graph.innerText();
    if (entry.ref === 'info-path-test' && (!content.includes('활용·검토 제안') || /MDE|동적 분석/.test(content))) throw new Error('informational branch incorrect');
    if (entry.ref === 'legacy-path-test' && !content.includes('목표별 연결 기록이 없어')) throw new Error('legacy records incorrectly inferred');
    if (entry.ref === 'failed-path-test' && !content.includes('원문 수집 실패')) throw new Error('collection failure missing');
    if (entry.ref === 'multi-path-test') {
      if (await graph.locator('.ap-case').count() !== 2) throw new Error('incident separation missing');
      if ((await graph.locator('.ap-case').first().innerText()).includes('사건 B 고유')) throw new Error('incident cross-contamination');
      if (!(await graph.locator('.ap-case').nth(1).innerText()).includes('사건 B 고유 대응안')) throw new Error('case response missing');
    }
  }
  await page.getByRole('button', { name: '목록으로', exact: true }).click();
  await open(entries[0]);
  await tab('분석 경로').click();
  await graph.getByRole('button', { name: '조사 내용', exact: true }).first().click();
  if (await tab('조사').getAttribute('aria-pressed') !== 'true') throw new Error('reopen navigation failed');
  if (await page.locator('#insight-detail-pdf').isDisabled()) throw new Error('PDF readiness regression');
  if (requests.some(value => value.startsWith('POST') || value.includes('/api/analyze'))) throw new Error('unexpected analysis request');
  if (errors.length) throw new Error(errors.join('\\n'));
  console.log('PASS: five tabs, original content preservation, goal/action jumps, additional attempts, keyboard, expand-all, 6 viewports, light/dark, informational/legacy/failure/multi-case, reopen, PDF readiness, no model calls or JS errors.');
}`;
fs.mkdirSync(path.resolve(__dirname, '../output/playwright'), { recursive: true });
fs.mkdirSync(path.resolve(__dirname, '../tmp'), { recursive: true });
fs.writeFileSync(path.resolve(__dirname, '../tmp/analysis-path-browser.js'), code);

async (page) => {
  const response = await page.request.get('https://click-tracker-two.vercel.app/api/insights');
  if (!response.ok()) throw new Error('Saved reports unavailable: ' + response.status());
  const payload = await response.json();
  const entry = (payload.insights || []).find(item =>
    item.title === 'Attackers Abuse MSP360 to Deploy ScreenConnect in Dual-RMM Phishing Attacks');
  if (!entry) throw new Error('MSP360 report missing');
  const errors = [];
  page.on('pageerror', error => errors.push(String(error)));
  await page.route('https://click-tracker-two.vercel.app/**', route =>
    route.fulfill({ json: route.request().url().includes('/api/insights') ? { insights: [entry] } : {} }));
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto('http://127.0.0.1:8086/');
  await page.getByRole('button', { name: '인사이트 열기', exact: true }).click();
  await page.locator('#insight-drawer-body').getByText(entry.title, { exact: true }).click();
  const tabs = page.locator('.detail-tabs');
  await tabs.getByRole('button', { name: '판단', exact: true }).click();
  const judgement = page.locator('.detail-panel.is-active');
  const issueTitles = await judgement.locator('.question-trail-head strong').allInnerTexts();
  if (issueTitles.length !== 8 || issueTitles.some(value => value.includes('…')))
    throw new Error('Judgement titles still clipped: ' + issueTitles.join(' | '));
  const judgeText = await judgement.innerText();
  if (!judgeText.includes('MSP360을 배포해 지속적 접근을 확보함'))
    throw new Error('Full source sentence missing from judgement');
  await page.screenshot({ path: 'output/playwright/msp-judgement-restored.png' });
  await tabs.getByRole('button', { name: '조사', exact: true }).click();
  const research = page.locator('.detail-panel.is-active');
  const questions = await research.locator('.question-trail-head strong').allInnerTexts();
  if (questions.length < 8 || questions.slice(0, 8).some(value => value.includes('…')))
    throw new Error('Research questions still clipped: ' + questions.slice(0, 8).join(' | '));
  if (!questions[0].includes('위장 파일명으로 배포함') || !questions[0].includes('VIP_ECARD_INVITATION_'))
    throw new Error('First question lost its full action or technical filename');
  await tabs.getByRole('button', { name: '분석 경로', exact: true }).click();
  const pathGoals = await page.locator('.detail-panel.is-active .ap-goal-heading h4').allInnerTexts();
  if (pathGoals.some(value => value.includes('…'))) throw new Error('Path goals still clipped');
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: 'output/playwright/msp-path-restored-mobile.png' });
  const overflow = await page.locator('.analysis-path').evaluate(root =>
    [...root.querySelectorAll('.ap-goal-heading h4')]
      .filter(el => el.scrollWidth > el.clientWidth + 2 || el.getBoundingClientRect().right > innerWidth)
      .map(el => el.innerText.slice(0, 70)));
  if (overflow.length) throw new Error('Mobile goal overflow: ' + overflow.join(' | '));
  const pdfReady = page.waitForEvent('download', { timeout: 120000 });
  await page.getByRole('button', { name: 'PDF 보고서 다운로드', exact: true }).click();
  const pdf = await pdfReady;
  await pdf.saveAs('output/playwright/msp-restored-report.pdf');
  if (await pdf.failure()) throw new Error('Restored PDF download failed');
  if (errors.length) throw new Error(errors.join('\n'));
  return { issues: issueTitles.length, questions: questions.length, pathGoals: pathGoals.length,
    firstTitle: issueTitles[0], firstQuestion: questions[0] };
}

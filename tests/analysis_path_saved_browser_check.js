async (page) => {
  const response = await page.request.get('https://click-tracker-two.vercel.app/api/insights');
  if (!response.ok()) throw new Error('Read-only insight request failed: ' + response.status());
  const { insights = [] } = await response.json();
  if (!insights.length) throw new Error('No saved reports available');
  const summary = await page.evaluate(entries => {
    const errors = [];
    const counts = { reports: entries.length, goals: 0, informational: 0, multi: 0, legacy: 0 };
    for (const entry of entries) {
      try {
        const model = window.AnalysisPath.build(entry);
        const html = window.AnalysisPath.render(entry);
        if (!html.includes('분석 경로')) throw new Error('empty projection');
        counts.goals += model.goals;
        counts.informational += Number(model.cases.some(item => item.informational));
        counts.multi += Number(model.cases.length > 1);
        counts.legacy += Number(model.goals === 0);
      } catch (error) { errors.push({ ref: entry.ref, error: String(error) }); }
    }
    return { ...counts, errors };
  }, insights);
  if (summary.errors.length) throw new Error(JSON.stringify(summary));
  await page.unroute('https://click-tracker-two.vercel.app/**');
  const article = insights.find(entry => /Attackers Abuse ChatGPT Custom GPTs/i.test(entry.title));
  if (!article) throw new Error('ClickFix report absent');
  await page.route('https://click-tracker-two.vercel.app/**', route => route.fulfill({
    json: route.request().url().includes('/api/insights') ? { insights: [article] } : {},
  }));
  await page.reload();
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.getByRole('button', { name: '인사이트 열기', exact: true }).click();
  await page.locator('#insight-drawer-body').getByText(article.title, { exact: true }).click();
  await page.locator('.detail-tabs').getByRole('button', { name: '분석 경로', exact: true }).click();
  await page.screenshot({ path: 'output/playwright/analysis-path-saved-report.png' });
  const graph = page.locator('.analysis-path');
  const state = await graph.locator('.ap-counts').innerText();
  await page.setViewportSize({ width: 390, height: 844 });
  const goal = graph.locator('.ap-goal').first();
  await goal.scrollIntoViewIfNeeded();
  await page.screenshot({ path: 'output/playwright/analysis-path-saved-mobile.png' });
  const overflow = await graph.evaluate(root => [...root.querySelectorAll('.ap-lane > *, .ap-goal-heading h4')]
    .filter(el => el.getClientRects().length && (el.scrollWidth > el.clientWidth + 2 || el.getBoundingClientRect().right > innerWidth))
    .map(el => el.className));
  if (overflow.length) throw new Error('Saved report overflow: ' + overflow.join(', '));
  return { ...summary, displayedGoals: await graph.locator('.ap-goal').count(), state };
}

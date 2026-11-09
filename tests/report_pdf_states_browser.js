async (page) => {
  const entry = { ref: 'saved', title: '저장된 정보성 기사', analysis: '[핵심 요약]\n도입 조건은 미확인입니다.\n[주요 내용]\n제품과 서비스 소개\n[권장 대응]\n적용 조건을 검토합니다.',
    analyzed_at: '2026-10-02T01:00:00Z', targets: { article_kind: 'informational' } };
  const waiting = { ref: 'waiting', title: '분석 대기 중인 기사', status: 'queued', requested_at: '2026-10-02T01:00:00Z' };
  const failed = { ref: 'failed', title: '수집 실패 기사', collection_failed: true, analysis: '원문을 수집하지 못했습니다.' };
  await page.unroute('https://click-tracker-two.vercel.app/**');
  await page.route('https://click-tracker-two.vercel.app/**', route => route.fulfill({ json: route.request().url().includes('/api/insights') ? { insights: [entry, failed], pending: [waiting] } : {} }));
  await page.route('**/NanumGothic-Regular.ttf', route => route.fulfill({ status: 503, body: 'test failure' }), { times: 1 });
  await page.goto('http://127.0.0.1:8086/');
  await page.getByRole('button', { name: '인사이트 열기', exact: true }).click();
  await page.locator('#insight-drawer-body').getByText(entry.title, { exact: true }).click();
  await page.getByRole('button', { name: 'PDF 보고서 다운로드', exact: true }).click();
  await page.locator('#insight-pdf-status.is-error').waitFor();
  if (!await page.locator('#insight-pdf-status').textContent().then(t => t.includes('글꼴'))) throw new Error('font failure not reported');
  if (await page.locator('#insight-detail-pdf').isDisabled()) throw new Error('retry blocked');
  const ready = page.waitForEvent('download');
  await page.getByRole('button', { name: 'PDF 보고서 다운로드', exact: true }).click();
  await (await ready).saveAs('tmp/pdfs/informational.pdf');
  await page.getByRole('button', { name: '목록으로', exact: true }).click();
  await page.locator('#insight-drawer-body').getByText(waiting.title, { exact: true }).click();
  if (!await page.locator('#insight-detail-pdf').isDisabled()) throw new Error('pending export allowed');
  await page.getByRole('button', { name: '목록으로', exact: true }).click();
  await page.locator('#insight-drawer-body').getByText(failed.title, { exact: true }).click();
  if (!await page.locator('#insight-detail-pdf').isDisabled()) throw new Error('failed export allowed');
  await page.getByRole('button', { name: '목록으로', exact: true }).click();
  await page.locator('#insight-drawer-body').getByText(entry.title, { exact: true }).click();
  await page.evaluate(() => {
    window.exportCount = 0;
    window.ReportPdf.download = () => { window.exportCount++; return new Promise(resolve => { window.finishExport = resolve; }); };
  });
  await page.locator('#insight-detail-pdf').click();
  await page.evaluate(() => document.getElementById('insight-detail-pdf').click());
  if (await page.evaluate(() => window.exportCount) !== 1) throw new Error('duplicate export');
  await page.getByRole('button', { name: '목록으로', exact: true }).click();
  await page.locator('#insight-drawer-body').getByText(waiting.title, { exact: true }).click();
  await page.evaluate(() => window.finishExport());
  if (!await page.locator('#insight-detail-pdf').isDisabled()) throw new Error('stale completion enabled pending export');
  if (await page.locator('#insight-pdf-status').textContent()) throw new Error('stale message leaked');
  console.log('PASS: font failure/retry; informational PDF; pending/failed gating; duplicate clicks; article-switch race.');
}

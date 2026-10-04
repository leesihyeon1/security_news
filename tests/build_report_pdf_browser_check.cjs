const fs = require('node:fs');
const path = require('node:path');
const fixture = require('./report_pdf_fixture.cjs');
const code = `async (page) => {
  const entry = ${JSON.stringify(fixture)};
  const errors = [];
  page.on('pageerror', error => errors.push(String(error)));
  await page.route('https://click-tracker-two.vercel.app/**', async route => {
    await route.fulfill({ json: route.request().url().includes('/api/insights') ? { insights: [entry] } : {} });
  });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto('http://127.0.0.1:8086/');
  if (await page.evaluate(() => Boolean(window.pdfMake))) throw new Error('PDF engine loaded eagerly');
  await page.getByRole('button', { name: '인사이트 열기', exact: true }).click();
  await page.locator('#insight-drawer-body').getByText(entry.title, { exact: true }).click();
  await page.locator('#insight-detail-pdf:not([disabled])').waitFor();
  await page.screenshot({ path: 'output/playwright/report-pdf-desktop.png' });
  const ready = page.waitForEvent('download', { timeout: 120000 });
  await page.getByRole('button', { name: 'PDF 보고서 다운로드', exact: true }).click();
  const download = await ready;
  await download.saveAs('output/pdf/analysis-report-preview.pdf');
  if (await download.failure()) throw new Error('PDF download failed');
  await page.locator('#insight-detail-pdf:not([disabled])').waitFor();
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: 'output/playwright/report-pdf-mobile.png' });
  for (const width of [320, 390, 768]) {
    await page.setViewportSize({ width, height: 844 });
    const overlap = await page.evaluate(() => {
      const ids = ['insight-detail-back','insight-detail-pdf','insight-detail-reanalyze','insight-detail-close'];
      const boxes = ids.map(id => document.getElementById(id).getBoundingClientRect());
      return boxes.some((box, i) => box.left < 0 || box.right > innerWidth || (i > 0 && box.left < boxes[i - 1].right));
    });
    if (overlap) throw new Error('toolbar overlap: ' + width);
  }
  if (errors.length) throw new Error(errors.join('\\n'));
  console.log('PASS: actual dashboard PDF download; lazy loading; mobile toolbar; no browser errors.');
}`;
fs.mkdirSync(path.resolve(__dirname, '../tmp/pdfs'), { recursive: true });
fs.writeFileSync(path.resolve(__dirname, '../tmp/pdfs/browser-check.js'), code);

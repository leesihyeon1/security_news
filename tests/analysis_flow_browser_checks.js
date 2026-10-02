async (page) => {
  const entry = await page.evaluate(() => window.flowPreview);
  const failures = [];
  page.on('pageerror', (error) => failures.push(String(error)));
  const verifyText = async () => {
    const errors = await page.evaluate(() => {
      const problems = [];
      document.querySelectorAll('.article-flow-canvas g[data-node]').forEach((group) => {
        const rect = group.querySelector('rect').getBBox();
        group.querySelectorAll(':scope > text').forEach((text) => {
          const box = text.getBBox();
          if (box.x < rect.x || box.x + box.width > rect.x + rect.width + 1 ||
              box.y < rect.y || box.y + box.height > rect.y + rect.height) {
            problems.push({ id: group.dataset.node, text: text.textContent });
          }
        });
      });
      if (document.documentElement.scrollWidth > innerWidth) problems.push('page overflow');
      return problems;
    });
    if (errors.length) throw new Error(JSON.stringify(errors));
  };
  await page.setViewportSize({ width: 1440, height: 1100 });
  await page.locator('[data-node="n10"]').waitFor();
  await verifyText();
  await page.locator('.article-flow').screenshot({ path: 'output/playwright/flow-desktop-final.png' });
  await page.getByRole('button', { name: '흐름도 확대', exact: true }).click();
  await page.getByRole('dialog').waitFor();
  await page.keyboard.press('Escape');
  if (await page.getByRole('dialog').count()) throw new Error('dialog did not close');
  if (!await page.getByRole('button', { name: '흐름도 확대', exact: true }).evaluate(el => el === document.activeElement)) {
    throw new Error('focus not restored');
  }
  for (const ext of ['svg', 'png']) {
    const ready = page.waitForEvent('download');
    await page.getByRole('button', { name: ext.toUpperCase() + ' 다운로드', exact: true }).click();
    const download = await ready;
    await download.saveAs('output/playwright/flow-export.' + ext);
    if (await download.failure()) throw new Error('download failed');
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await page.waitForFunction(() => document.querySelector('.article-flow-canvas > svg').width.baseVal.value < 400);
  await verifyText();
  await page.screenshot({ path: 'output/playwright/flow-mobile.png', fullPage: true });

  await page.route('https://click-tracker-two.vercel.app/**', async (route) => {
    await route.fulfill({ json: route.request().url().includes('/api/insights') ? { insights: [entry] } : {} });
  });
  await page.goto('http://127.0.0.1:8086/');
  await page.getByRole('button', { name: '인사이트 열기', exact: true }).click();
  await page.locator('#insight-drawer-body').getByText(entry.title, { exact: true }).click();
  await page.locator('#insight-detail-body .article-flow [data-node="n10"]').waitFor();
  await verifyText();
  await page.screenshot({ path: 'output/playwright/flow-dashboard-mobile.png' });
  await page.getByRole('button', { name: '판단', exact: true }).click();
  if (await page.locator('.article-flow').isVisible()) throw new Error('diagram leaked into judgment tab');
  await page.getByRole('button', { name: '분석', exact: true }).click();
  await page.setViewportSize({ width: 1440, height: 1100 });
  await page.waitForFunction(() => document.querySelector('.article-flow-canvas > svg').width.baseVal.value > 1000);
  await verifyText();
  await page.screenshot({ path: 'output/playwright/flow-dashboard-desktop.png' });
  await page.getByRole('button', { name: '흐름도 확대', exact: true }).click();
  await page.getByRole('button', { name: '확대 닫기', exact: true }).click();
  await page.evaluate(() => document.documentElement.dataset.theme = 'dark');
  await verifyText();
  await page.screenshot({ path: 'output/playwright/flow-dashboard-dark.png' });
  if (failures.length) throw new Error(failures.join('\n'));
  console.log('PASS: desktop/mobile text bounds, PNG/SVG export, dialog focus, real dashboard integration, tab isolation, dark theme.');
}

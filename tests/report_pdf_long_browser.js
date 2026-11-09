async (page) => {
  await page.goto('http://127.0.0.1:8086/');
  const ready = page.waitForEvent('download');
  await page.evaluate(async () => {
    const entry = {
      title: '긴 제목과 다중 페이지 레이아웃 검증을 위한 기술 분석 보고서 '.repeat(8),
      analyzed_at: '2026-10-02T01:00:00Z',
      analysis: '[핵심 요약]\n긴 내용의 페이지 나눔 검증\n[기술적 세부사항]\n' +
        Array.from({ length: 40 }, (_, i) => (i + 1) + '. 공격 단계에 대한 긴 기술적 설명입니다. '.repeat(10)).join('\n\n'),
      investigation: { synthesis_status: { status: 'failed' }, response: { kql: [{ name: '긴 쿼리', query: Array.from({ length: 100 }, (_, i) => '// query line ' + i).join('\n') }] } },
      iocs: [ { type: 'SHA-256', value: 'a'.repeat(64) }, { type: 'url', value: 'https://example.test/' + 'A'.repeat(250) + '?long_parameter=' + 'B'.repeat(200) } ],
    };
    await ReportPdf.download(entry);
  });
  await (await ready).saveAs('tmp/pdfs/long-content.pdf');
  console.log('PASS: long title, multi-page narrative/query, full long indicator download.');
}

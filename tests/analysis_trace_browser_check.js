async (page) => {
  const entry = {
    ref: "local-execution-trace", title: "실행 경로 화면 검증 기사", source_label: "테스트",
    url: "https://example.test/news", analysis: "[핵심 요약]\n검증용 기사 요약입니다.\n[기술적 세부사항]\n1. 시험 단계",
    category: "공격캠페인", targets: { article_kind: "threat", primary: "user_action",
      objective: "유포 경로 확인", questions: ["유포지를 확인했는가?"], issues: [
        { id: "issue-1", title: "유포지", disposition: "investigate", question: "유포지를 확인했는가?" }] },
    investigation: { route: { primary: "user_action", tracks: ["user_action"] },
      lookup_status: [{ key: "user_action", status: "returned" }] },
    execution_trace: { version: 1, total_events: 4, events: [
      { id: "e1", stage: "source", kind: "extraction", label: "HTML 본문·참고 링크 추출",
        status: "completed", duration_ms: 10, output: { count: 2, sample: [{ chars: 1200 }, { count: 1 }] } },
      { id: "e2", stage: "issues", kind: "llm", label: "이슈 판단 생성", status: "completed", duration_ms: 1200 },
      { id: "e3", parent_id: "e2", stage: "issues", kind: "llm_attempt", label: "LLM API 요청",
        status: "completed", duration_ms: 1000, http_status: 200,
        inputs: { model: "test-model", provider: "test" } },
      { id: "e4", stage: "lookup", kind: "cache", label: "저장된 단계 결과 재사용", status: "cached" },
    ] },
  };
  const errors = [];
  page.on("pageerror", (error) => errors.push(String(error)));
  await page.route("https://click-tracker-two.vercel.app/**", async (route) => {
    await route.fulfill({ json: route.request().url().includes("/api/insights") ?
      { insights: [entry] } : {} });
  });
  await page.goto("http://127.0.0.1:8097/");
  await page.getByRole("link", { name: "인사이트", exact: true }).click();
  await page.locator("#app").getByRole("button", { name: /실행 경로 화면 검증 기사/ }).click();
  await page.getByRole("button", { name: "분석 경로", exact: true }).click();
  const root = page.locator(".analysis-path");
  await root.getByText("실행 기록 4건 · LLM 요청 1회 · 결과 재사용 1건").waitFor();
  await root.locator('.ap-process-node[data-path-stage="issues"]').click();
  await root.locator('#ap-detail-issues').getByText("실제 실행 내역", { exact: true }).waitFor();
  await root.getByText("이슈 판단 생성", { exact: true }).first().click();
  await root.locator('#ap-detail-issues').getByText("LLM API 요청", { exact: true }).click();
  if (!await root.getByText("test-model", { exact: false }).first().isVisible()) {
    throw new Error("LLM call detail not visible");
  }
  await root.getByRole("button", { name: /전체 경로/ }).click();
  await root.locator('.ap-process-node[data-path-stage="source"]').click();
  if (!await root.getByText("HTML 본문·참고 링크 추출", { exact: true }).first().isVisible()) {
    throw new Error("extraction step not shown");
  }
  await page.screenshot({ path: "output/playwright/execution-trace-desktop.png" });
  await page.setViewportSize({ width: 390, height: 844 });
  if (await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 2)) {
    throw new Error("mobile horizontal overflow");
  }
  await page.screenshot({ path: "output/playwright/execution-trace-mobile.png" });
  if (errors.length) throw new Error(errors.join("\n"));
  return { stageButtons: await root.locator(".ap-process-node").count(),
    traceItems: await root.locator(".ap-execution-row").count() };
}

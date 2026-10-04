const flow = require('./fixtures/analysis_flow_clickfix.json');
const hash = '0123456789abcdef'.repeat(4);
module.exports = {
  ref: 'pdf-local-verification', title: 'Custom GPT 악용 ClickFix 공격 분석 (PDF 기능 검증용 예시)',
  category: '공격캠페인', analyzed_at: '2026-10-02T10:30:00Z',
  url: 'https://example.test/reference', source_label: '로컬 검증 데이터',
  analysis: '[핵심 요약]\n사용자가 제공한 공격 흐름을 활용한 PDF 기능 검증용 예시입니다. 아래 조사·대응 항목과 테스트 해시는 화면 검증을 위한 데이터이며 실제 조사 결과나 악성 지표가 아닙니다.\n\n[기술적 세부사항]\n' +
    flow.candidate.nodes.map((node, index) => `${index + 1}. ${node.evidence}`).join('\n\n') +
    '\n\n[분석 근거]\n근거: PRIVATE_EVIDENCE https://example.test/citation\n\n[권장 대응]\n조직 환경에서 해당 사용자 실행 유도 행위가 발생했는지 우선 확인한다.',
  targets: { article_kind: 'threat', objective: '공격 흐름에서 확인해야 할 실행·통신 행위를 정리한다.',
    issues: [{ title: '정상 AI 공유 기능을 악용한 사용자 실행 유도', disposition: 'investigate', evidence: 'PRIVATE_EVIDENCE', reason: 'PRIVATE_EVIDENCE' }] },
  analysis_flow: { ...flow.candidate, version: 1, status: 'ready', basis: 'article',
    title: '기사 기반 공격 흐름', phases: ['유입과 실행 유도', '실행과 방어 회피', '후속 동작과 기능'] },
  iocs: [{ type: 'SHA-256', value: hash, role: 'unknown', evidence: 'PRIVATE_EVIDENCE' }],
  investigation: {
    synthesis: { verdict: '부분 확인', headline: '제공된 기술적 설명을 정리했으며, 외부 서비스 조회 및 실제 샘플 실행은 수행하지 않았다.',
      key_findings: [{ fact: '정상 플랫폼 내 공유 콘텐츠가 외부 ClickFix 페이지로 이어지는 구조다.', sources: [{ label: 'PRIVATE_EVIDENCE' }] }],
      question_status: [{ question: '유포 경로와 실행 단계를 확인할 수 있는가?', status: 'partial', answer: '제공된 설명의 실행 흐름은 확인했으나 현재 유포지 활성 상태는 미확인이다.', evidence: 'PRIVATE_EVIDENCE' }],
      unconfirmed: ['샘플의 실제 실행 결과와 C2 주소는 확인되지 않았다.'],
      exposure: { who: 'Windows 사용자가 명령을 직접 실행하는 환경에서 영향 가능성이 있다. 사내 감염 여부는 미확인이다.', basis: 'PRIVATE_EVIDENCE', confirm: '브라우저 이후 PowerShell·MSI 실행 이력을 확인한다.' } },
    malware: { files: [{ hash, report: { meaningful_name: 'TEST-ONLY-NOT-A-MALWARE-SAMPLE.bin' }, behaviour: { has_dynamic: false } }] },
    action_plan: [{ when: '우선 확인', action: '관련 사용자의 실행 이력을 점검하고 의심 프로세스를 조사한다.', done: '확인 대상 단말과 조사 결과를 기록한다.', why: 'PRIVATE_EVIDENCE' }],
    response: { kql: [{ name: '프로세스 조회 형식 예시 (운영 적용 전 검토)', query: 'DeviceProcessEvents\n| where FileName =~ "powershell.exe"\n| project Timestamp, DeviceName, ProcessCommandLine', note: '단순 조회 예시이며 공격 탐지 규칙으로 검증되지 않았다.' }] },
    patterns: [{ label: '검색 구문 보존 테스트', query: 'filename:"jsrepo?rnd="', validation_status: 'candidate', why: 'PRIVATE_EVIDENCE', what: '인코딩 및 따옴표가 변형되지 않는지 확인하기 위한 테스트 값이다.' }],
    steps: [{ output: 'PRIVATE_EVIDENCE' }],
  },
  glossary: { ClickFix: '가짜 오류나 인증 안내로 사용자의 명령 실행을 유도하는 사회공학 기법.' },
};

"""Validate downloaded PDFs after the Playwright CLI checks (no network access)."""
from pathlib import Path

import pdfplumber
from pypdf import PdfReader


def verify(path):
    reader = PdfReader(path)
    text = "\n".join(page.extract_text() for page in reader.pages)
    assert "PRIVATE_EVIDENCE" not in text
    assert "example.test/citation" not in text
    problems = []
    with pdfplumber.open(path) as pdf:
        for number, page in enumerate(pdf.pages, 1):
            for char in page.chars:
                if (char["x0"] < 45 or char["x1"] > page.width - 42
                        or char["top"] < 18 or char["bottom"] > page.height - 18):
                    problems.append((number, char["text"], round(char["x0"], 1), round(char["x1"], 1)))
    assert not problems, (path, len(problems), problems[:12])
    print(f"PASS {path}: {len(reader.pages)} pages, text within page bounds")
    return text


root = Path(__file__).resolve().parents[1]
sample = verify(root / "output/pdf/analysis-report-preview.pdf")
assert "0123456789abcdef" * 4 in sample.replace("\n", "")
assert "filename:\"jsrepo?rnd=\"" in sample
assert "미검증 후보" in sample
assert "미확인 사항" in sample
info = verify(root / "tmp/pdfs/informational.pdf")
assert "검토 과제" in info
assert "탐지 및 점검 자료" not in info
long = verify(root / "tmp/pdfs/long-content.pdf")
assert "query line 99" in long
assert "A" * 250 in long.replace("\n", "")
assert "B" * 200 in long.replace("\n", "")
assert "종합 분석을 완료하지 못했습니다" in long

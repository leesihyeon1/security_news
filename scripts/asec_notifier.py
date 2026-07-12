import os
import json
import traceback
import requests
from bs4 import BeautifulSoup
from pathlib import Path
import common_utils

# ================= [ 설정 영역 ] =================
ASEC_RSS_URL = "https://asec.ahnlab.com/ko/feed/"
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent if SCRIPT_DIR.name.lower() == "scripts" else SCRIPT_DIR
DB_FILE = common_utils.STATE_DIR / "last_url.txt"
TARGET_EMAIL = common_utils.DEFAULT_TO_EMAIL
# =================================================

def get_all_asec_posts():
    """모든 게시글을 가져오도록 수정"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    try:
        response = requests.get(ASEC_RSS_URL, headers=headers, timeout=10)
        response.raise_for_status()
        
        # RSS(XML) 파싱
        soup = BeautifulSoup(response.text, "xml")
        items = soup.find_all("item") # find가 아닌 find_all 사용
    except Exception as e:
        print(f"[-] ASEC 피드 수집 실패: {e}")
        return []
    return items

def send_email(subject, body):
    """지정된 수신자에게 메일을 발송합니다."""
    common_utils.send_email_message(subject, body, to_email=TARGET_EMAIL)

def ai_summarize(title, description):

    prompt = f"""
당신은 보안관제 전문가이다.

다음 보안 리포트를 분석하라.

[핵심요약]
- 3줄 이내

[예상영향]
- 영향받을 수 있는 시스템

[관제포인트]
- 보안관제 시 확인할 사항

제목:
{title}

내용:
{description}
"""

    try:
        response = requests.post(
            common_utils.OLLAMA_URL,
            json={
                "model": common_utils.OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False
            },
            timeout=120
        )

        print("Ollama Status:", response.status_code)
        print(response.text[:500])

        return response.json()["response"]

    except Exception as e:
        print("===== OLLAMA ERROR =====")
        print(type(e))
        print(e)
        traceback.print_exc()
        print("========================")

        return "AI 요약 생성 실패"

def send_to_slack(title, link, ai_summary):
    """슬랙으로 알림을 전송하는 함수"""
    payload = {
        "text": "🤖 안랩 ASEC 신규 리포트가 게시되었습니다.",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn", 
                    "text": "🤖 *안랩 ASEC 신규 리포트가 게시되었습니다.*" # 이 부분이 채팅창에 보임
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text":
                        f"*📌 {title}*\n\n"
                        f"{ai_summary}\n\n"
                        f"🔗 <{link}|리포트 바로가기>"
                }
            }       
        ]
    }
    webhook_url, _ = common_utils.select_slack_webhook(os.environ.get("SLACK_WEBHOOK_ASEC"), [title, ai_summary])
    common_utils.send_slack_webhook(payload, webhook_url)

def main():
    print("[*] ASEC 신규 게시글 체크 시작...")
    
    # 1. 모든 게시글 가져오기 (find_all로 수정 필요)
    items = get_all_asec_posts() # get_all_asec_posts 내부에서 find_all 사용 필수
    
    # 2. 이전에 확인한 링크 로드
    last_url = ""
    if DB_FILE.exists():
        with DB_FILE.open("r", encoding="utf-8") as f:
            last_url = f.read().strip()

    # 3. 신규 글 수집 (last_url을 만날 때까지)
    new_posts = []
    for item in items:
        link = item.find("link").text.strip()
        if link == last_url:
            break
        new_posts.append(item)

    # 4. 신규 글이 있다면 역순으로(과거순으로) 발송
    if new_posts:
        print(f"[!] {len(new_posts)}개의 신규 게시글 포착")
        
        # 신규 글들을 오래된 순서대로 발송하기 위해 reversed 사용
        for post in reversed(new_posts):
            title = post.find("title").text.strip()
            link = post.find("link").text.strip()
            
            # 각각의 게시글에 대해 알림 발송
            email_subject = f"[ASEC 인텔리전스 알림] {title}"
            email_body = f"📌 제목: {title}\n🔗 링크: {link}"
            
            description = ""

            if post.find("description"):
                 description = post.find("description").text.strip()
            print(f"AI 분석중: {title}")

            ai_summary = ai_summarize(title,description)

            send_email(email_subject, email_body)
            send_to_slack(title, link, ai_summary)
        
        # 5. 가장 최신 글(new_posts[0])의 링크를 DB_FILE에 저장
        with DB_FILE.open("w", encoding="utf-8") as f:
            f.write(new_posts[0].find("link").text.strip())
            
    else:
        print("[-] 업데이트된 새로운 게시글이 없습니다.")

if __name__ == "__main__":
    main()

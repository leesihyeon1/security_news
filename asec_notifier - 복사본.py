import os
import smtplib
import json  # [추가] 슬랙 데이터 처리를 위해 추가
import urllib.request # [추가] 슬랙 전송을 위해 추가
import traceback
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import requests
from bs4 import BeautifulSoup

# ================= [ 설정 영역 ] =================
ASEC_RSS_URL = "https://asec.ahnlab.com/ko/feed/"
DB_FILE = "last_url.txt"
TARGET_EMAIL = "user@example.com"

# 발신용 Gmail 설정 (본인 계정 정보 입력 필요)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "user@example.com"  # 보내는 사람 구글 메일
SENDER_PASSWORD = "REDACTED_APP_PASSWORD"          # 구글 앱 비밀번호 (16자리)

# [추가] 환경 변수에서 슬랙 웹훅 URL을 가져옵니다.
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")
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
    return items

def send_email(subject, body):
    """지정된 수신자에게 메일을 발송합니다."""
    try:
        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        msg["To"] = TARGET_EMAIL
        msg["Subject"] = subject
        
        msg.attach(MIMEText(body, "plain", "utf-8"))
        
        # SMTP 연결 및 메일 발송
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, TARGET_EMAIL, msg.as_string())
        print(f"[+] 메일 발송 성공 -> {TARGET_EMAIL}")
    except Exception as e:
        print(f"[-] 메일 발송 실패: {e}")

def send_to_slack(title, link):
    """슬랙으로 알림을 전송하는 함수"""
    if not SLACK_WEBHOOK_URL:
        return
    
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
                "text": {"type": "mrkdwn", "text": f"*📌 {title}*\n🔗 <{link}|리포트 바로가기>"}
            }
        ]
    }
    try:
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(SLACK_WEBHOOK_URL, data=data, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req) as response:
            if response.status == 200:
                print("[+] 슬랙 알림 발송 성공")
    except Exception as e:
        print(f"[-] 슬랙 발송 실패: {e}")

def main():
    print("[*] ASEC 신규 게시글 체크 시작...")
    
    # 1. 모든 게시글 가져오기 (find_all로 수정 필요)
    items = get_all_asec_posts() # get_all_asec_posts 내부에서 find_all 사용 필수
    
    # 2. 이전에 확인한 링크 로드
    last_url = ""
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r", encoding="utf-8") as f:
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
            
            send_email(email_subject, email_body)
            send_to_slack(title, link)
        
        # 5. 가장 최신 글(new_posts[0])의 링크를 DB_FILE에 저장
        with open(DB_FILE, "w", encoding="utf-8") as f:
            f.write(new_posts[0].find("link").text.strip())
            
    else:
        print("[-] 업데이트된 새로운 게시글이 없습니다.")

if __name__ == "__main__":
    main()
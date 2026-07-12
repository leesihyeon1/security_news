import os
import json
import smtplib
from pathlib import Path
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import urllib.request
import html

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent if BASE_DIR.name.lower() == "scripts" else BASE_DIR
STATE_DIR = PROJECT_ROOT / "state"
ASSETS_DIR = PROJECT_ROOT / "assets"
INVENTORY_FILE = ASSETS_DIR / "inventory.yml"

def load_env_file(dotenv_path=None):
    if dotenv_path is None:
        dotenv_path = PROJECT_ROOT / ".env"
    else:
        dotenv_path = Path(dotenv_path)
    
    if not dotenv_path.exists():
        return
    
    with dotenv_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, val = line.split("=", 1)
                val = val.strip()
                if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
                    val = val[1:-1]
                os.environ[key.strip()] = val

# 모듈 로드 시 즉시 .env 파일을 읽어 환경 변수에 적재합니다.
load_env_file()

SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SENDER_EMAIL = os.environ.get("EMAIL_ADDRESS", "")
SENDER_PASSWORD = os.environ.get("EMAIL_APP_PASSWORD", "")
DEFAULT_TO_EMAIL = os.environ.get("TO_EMAIL") or SENDER_EMAIL
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")
SLACK_WEBHOOK_URGENT = os.environ.get("SLACK_WEBHOOK_URGENT")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen3:8b")

def clean_text(value):
    if value is None:
        return ""
    return " ".join(html.unescape(str(value)).split())

def _parse_inline_list(value):
    value = value.strip()
    if not value.startswith("[") or not value.endswith("]"):
        return []

    items = []
    for item in value[1:-1].split(","):
        item = item.strip().strip("'\"")
        if item:
            items.append(item)
    return items

def load_inventory_terms(inventory_file=None):
    path = Path(inventory_file) if inventory_file else INVENTORY_FILE
    if not path.exists():
        return []

    terms = []
    current_name = ""

    try:
        with path.open("r", encoding="utf-8") as file:
            for raw_line in file:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue

                if line.startswith("- name:"):
                    current_name = line.split(":", 1)[1].strip().strip("'\"")
                    if current_name:
                        terms.append(current_name)
                elif line.startswith("aliases:"):
                    aliases = _parse_inline_list(line.split(":", 1)[1])
                    terms.extend(aliases)
    except OSError:
        return []

    seen = set()
    unique_terms = []
    for term in terms:
        normalized = clean_text(term).lower()
        if normalized and normalized not in seen:
            seen.add(normalized)
            unique_terms.append(term)
    return unique_terms

def match_inventory_terms(values, inventory_file=None):
    if isinstance(values, (str, bytes)):
        values = [values]

    haystack = " ".join(clean_text(value).lower() for value in values if value is not None)
    if not haystack:
        return []

    matched = []
    for term in load_inventory_terms(inventory_file):
        normalized = clean_text(term).lower()
        if normalized and normalized in haystack:
            matched.append(term)
    return matched

def select_slack_webhook(default_webhook=None, match_values=None):
    matched_terms = match_inventory_terms(match_values or [])
    if matched_terms and SLACK_WEBHOOK_URGENT:
        print("[!] Urgent Slack route: matched inventory terms -> {}".format(", ".join(matched_terms)))
        return SLACK_WEBHOOK_URGENT, matched_terms
    return default_webhook, matched_terms

def load_json_state(state_file, default_factory=dict):
    path = Path(state_file)
    if not path.exists():
        return default_factory()
    try:
        with path.open("r", encoding="utf-8") as file:
            state = json.load(file)
            if state is None:
                return default_factory()
            return state
    except (json.JSONDecodeError, OSError):
        return default_factory()

def save_json_state(state_file, state_data, max_items=None, keys_to_trim=None):
    path = Path(state_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    
    # 리스트 데이터의 크기 제한 처리
    if max_items:
        if isinstance(state_data, list):
            state_data = state_data[-max_items:]
        elif isinstance(state_data, dict) and keys_to_trim:
            for key in keys_to_trim:
                if key in state_data and isinstance(state_data[key], list):
                    state_data[key] = state_data[key][-max_items:]

    with path.open("w", encoding="utf-8") as file:
        json.dump(state_data, file, ensure_ascii=False, indent=2)

def send_email_message(subject, text_body, html_body=None, to_email=None):
    to_email = to_email or DEFAULT_TO_EMAIL

    if not SENDER_EMAIL or not SENDER_PASSWORD or not to_email:
        print("[-] Email skipped: EMAIL_ADDRESS, EMAIL_APP_PASSWORD, or TO_EMAIL is not configured.")
        return False
    
    message = MIMEMultipart("alternative") if html_body else MIMEMultipart()
    message["From"] = SENDER_EMAIL
    message["To"] = to_email
    message["Subject"] = subject

    if text_body:
        message.attach(MIMEText(text_body, "plain", "utf-8"))
    if html_body:
        message.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, to_email, message.as_string())
        print(f"[+] 메일 발송 성공 -> {to_email}")
        return True
    except Exception as e:
        print(f"[-] 메일 발송 실패: {e}")
        return False

def send_slack_webhook(payload, webhook_url=None):
    url = webhook_url or SLACK_WEBHOOK_URL
    if not url:
        print("[-] 슬랙 알림 실패: Webhook URL이 설정되지 않았습니다.")
        return False

    try:
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            url, 
            data=data, 
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req) as response:
            if response.status == 200:
                print("[+] 슬랙 메시지 발송 성공")
                return True
            else:
                print(f"[-] 슬랙 메시지 발송 실패 (Status Code: {response.status})")
                return False
    except Exception as e:
        print(f"[-] 슬랙 발송 중 오류 발생: {e}")
        return False

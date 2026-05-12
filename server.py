"""Scam.tj 2.0 Backend - FastAPI service for AI-powered anti-scam detection."""
from fastapi import FastAPI, APIRouter, HTTPException
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import re
import logging
import uuid
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Optional, Literal

import httpx
import tldextract
from pydantic import BaseModel, Field

from emergentintegrations.llm.chat import LlmChat, UserMessage

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
MONGO_URL = os.environ["MONGO_URL"]
DB_NAME = os.environ["DB_NAME"]
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
GEMINI_MODEL = "gemini-3-flash-preview"

client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]

app = FastAPI(title="Scam.tj 2.0 API")
api_router = APIRouter(prefix="/api")

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("scamtj")


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
RiskLevel = Literal["safe", "suspicious", "dangerous"]


class LinkScanRequest(BaseModel):
    url: str
    language: Optional[str] = "tj"


class LinkThreat(BaseModel):
    source: str
    type: str
    description: str


class LinkScanResponse(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    url: str
    risk_level: RiskLevel
    risk_score: int
    title: str
    summary: str
    advice: str
    threats: List[LinkThreat] = []
    checked_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class MessageScanRequest(BaseModel):
    text: str
    language: Optional[str] = "tj"


class MessageScanResponse(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    risk_level: RiskLevel
    risk_score: int
    summary: str
    advice: str
    indicators: List[str] = []
    extracted_urls: List[str] = []
    checked_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class PhoneScanRequest(BaseModel):
    phone: str
    language: Optional[str] = "tj"


class PhoneScanResponse(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    phone: str
    normalized: str
    risk_level: RiskLevel
    risk_score: int
    country: str
    carrier_hint: Optional[str] = None
    summary: str
    advice: str
    indicators: List[str] = []
    local_reports: int = 0
    checked_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class PhoneReportRequest(BaseModel):
    phone: str
    note: Optional[str] = None
    category: Optional[str] = "scam"


class ChatRequest(BaseModel):
    session_id: str
    message: str
    language: Optional[str] = "tj"


class ChatResponse(BaseModel):
    session_id: str
    reply: str
    used_fallback: bool = False
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# Helpers - heuristics
# ---------------------------------------------------------------------------
SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "click", "loan", "country", "men", "work", "tk", "ml", "ga", "cf", "gq", "icu", "cam", "rest"}

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "lnkd.in", "tiny.cc"}

PHISH_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "bank", "wallet", "bonus", "prize", "win", "free", "gift", "claim",
    "password", "support", "recovery", "amonatbonk", "eskhata", "sberbank",
    "alif", "humo", "korti", "telegram", "whatsapp", "ok.ru", "vk-",
    "appleid", "icloud", "paypal", "binance", "metamask",
]

SCAM_MESSAGE_PATTERNS = [
    (r"\b(urgent|urgently|immediately|in\s*\d+\s*hours?|зудан|фавран|срочно)\b", "Urgency / fear tactic"),
    (r"\b(verify|confirm|update).*(account|card|password|otp)\b", "Asking to verify account"),
    (r"\b(otp|one[\s-]?time[\s-]?password|код подтверж|код смс)\b", "Requesting OTP / one-time code"),
    (r"\b(won|winner|congratulations|prize|lottery|таб[её]р|выиграли)\b", "Fake prize / lottery"),
    (r"\b(free|bonus|gift|cashback|бонус|подарок)\b", "Too-good-to-be-true bonus"),
    (r"\b(bank|amonatbonk|eskhata|alif|humo|sberbank|tinkoff)\b", "Mentions a bank by name"),
    (r"\b(card|cvv|cvc|pin|пин|номер карты)\b", "Asking for card / PIN details"),
    (r"\b(suspended|blocked|locked|заблокиров|приостановлен)\b", "Claims account is blocked"),
    (r"https?://\S+", "Contains a link"),
    (r"\b\d{4,6}\b", "Contains short numeric code"),
    (r"(t\.me/|wa\.me/|whatsapp\.com/)", "Redirects to Telegram / WhatsApp"),
]


def extract_urls(text: str) -> List[str]:
    return re.findall(r"https?://[^\s\"'<>]+", text)


def heuristic_url_score(url: str) -> tuple[int, List[LinkThreat]]:
    """Return (score 0-100, threats)."""
    threats: List[LinkThreat] = []
    score = 0
    lower = url.lower()

    if not re.match(r"^https?://", lower):
        score += 5
        threats.append(LinkThreat(source="heuristic", type="format", description="URL is missing http(s) scheme."))

    if lower.startswith("http://"):
        score += 15
        threats.append(LinkThreat(source="heuristic", type="insecure", description="Connection is not encrypted (HTTP)."))

    ext = tldextract.extract(url)
    domain = ".".join(p for p in [ext.domain, ext.suffix] if p)
    host = ext.fqdn or domain or url

    # IP address as host
    if re.match(r"^https?://\d+\.\d+\.\d+\.\d+", lower):
        score += 35
        threats.append(LinkThreat(source="heuristic", type="ip_host", description="URL uses a raw IP address instead of a domain."))

    # Suspicious TLD
    if ext.suffix.split(".")[-1] in SUSPICIOUS_TLDS:
        score += 25
        threats.append(LinkThreat(source="heuristic", type="tld", description=f"Domain uses a high-risk top-level domain (.{ext.suffix})."))

    # Punycode
    if "xn--" in host:
        score += 20
        threats.append(LinkThreat(source="heuristic", type="punycode", description="Domain uses punycode — possible homoglyph attack."))

    # Excess subdomains
    if ext.subdomain and ext.subdomain.count(".") >= 2:
        score += 15
        threats.append(LinkThreat(source="heuristic", type="subdomains", description="URL has many subdomains, a common phishing pattern."))

    # Long URL
    if len(url) > 90:
        score += 10
        threats.append(LinkThreat(source="heuristic", type="length", description="URL is unusually long."))

    # Shorteners
    if domain in SHORTENERS:
        score += 25
        threats.append(LinkThreat(source="heuristic", type="shortener", description="URL uses a link shortener — actual destination hidden."))

    # @ in url
    if "@" in url.split("://", 1)[-1].split("/", 1)[0]:
        score += 30
        threats.append(LinkThreat(source="heuristic", type="userinfo", description="URL contains '@' — destination may be hidden."))

    # Phishing keywords in host or path
    matched_kw = [kw for kw in PHISH_KEYWORDS if kw in lower]
    if matched_kw:
        score += min(25, 6 * len(matched_kw))
        threats.append(LinkThreat(
            source="heuristic",
            type="keywords",
            description=f"Contains suspicious keywords: {', '.join(matched_kw[:6])}.",
        ))

    # Many digits / dashes in domain
    if ext.domain and (sum(c.isdigit() for c in ext.domain) >= 3 or ext.domain.count("-") >= 2):
        score += 10
        threats.append(LinkThreat(source="heuristic", type="domain_shape", description="Domain looks machine-generated (digits / dashes)."))

    return min(score, 100), threats


async def safe_browsing_check(url: str) -> List[LinkThreat]:
    """Call Google Safe Browsing API v4. Returns list of threats found (empty if clean / unavailable)."""
    if not SAFE_BROWSING_API_KEY:
        return []
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
    payload = {
        "client": {"clientId": "scam-tj", "clientVersion": "2.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        async with httpx.AsyncClient(timeout=8.0) as http:
            r = await http.post(endpoint, json=payload)
            if r.status_code != 200:
                logger.warning("Safe Browsing non-200: %s %s", r.status_code, r.text[:200])
                return []
            data = r.json()
    except Exception as exc:  # network / DNS
        logger.warning("Safe Browsing call failed: %s", exc)
        return []

    matches = data.get("matches", [])
    threats: List[LinkThreat] = []
    for m in matches:
        threats.append(LinkThreat(
            source="google_safe_browsing",
            type=m.get("threatType", "UNKNOWN"),
            description=f"Google Safe Browsing flagged this URL as {m.get('threatType', 'malicious')}.",
        ))
    return threats


def score_to_risk(score: int) -> RiskLevel:
    if score >= 70:
        return "dangerous"
    if score >= 30:
        return "suspicious"
    return "safe"


# ---------------------------------------------------------------------------
# Gemini chat
# ---------------------------------------------------------------------------
SYSTEM_PROMPTS = {
    "tj": (
        "Шумо ёрдамчии амнияти Scam.tj 2.0 ҳастед. Ба корбарон оид ба фишинг, "
        "хабарҳои қаллобӣ, занги қаллобӣ ва бехатарии интернет дар Тоҷикистон кӯмак мерасонед. "
        "Бо забони тоҷикӣ кӯтоҳ, дӯстона ва содда ҷавоб диҳед. Ҳамеша ҷавоб диҳед — ҳатто агар савол норавшан бошад, "
        "савол равшанкунанда диҳед. Маслиҳатҳои амалии амният диҳед."
    ),
    "ru": (
        "Ты — Scam.tj 2.0, помощник по кибербезопасности для жителей Таджикистана. "
        "Объясняй фишинг, мошеннические СМС, поддельные звонки и опасные ссылки кратко и понятно. "
        "Отвечай на русском языке, дружелюбно и по делу. Всегда давай ответ, даже если вопрос неясен — "
        "попроси уточнить. Давай конкретные практические советы."
    ),
    "en": (
        "You are Scam.tj 2.0, a friendly cybersecurity assistant focused on protecting users in Tajikistan. "
        "Explain phishing, scam SMS, fake calls, dangerous links and online safety in clear simple English. "
        "Always answer — if the question is unclear, ask a short clarifying question. Give practical, actionable advice."
    ),
}


OFFLINE_KB = {
    "tj": (
        "Барои фаҳмидани он, ки оё хабар ё пайванд қаллобист, ба ин аломатҳо нигаред: "
        "1) Фишори вақт ё таҳдид. 2) Дархости рамзи SMS, рақами корт ё парол. "
        "Ҳеҷ гоҳ рамзи яккаратаро ба касе нагӯед ва пайвандҳои нофаҳморо боз накунед."
    ),
    "ru": (
        "Чтобы понять, мошенничество ли это: 1) есть ли давление и угрозы; "
        "2) просят ли код из СМС, номер карты или пароль. "
        "Никогда не сообщайте одноразовый код и не открывайте подозрительные ссылки."
    ),
    "en": (
        "Quick checks for any suspicious message or link: 1) Does it pressure you or threaten you? "
        "2) Does it ask for an SMS code, card number, or password? "
        "Never share one-time codes and never open links you don't recognise."
    ),
}


def make_chat(session_id: str, language: str) -> LlmChat:
    lang = language if language in SYSTEM_PROMPTS else "tj"
    chat = LlmChat(
        api_key=GEMINI_API_KEY,
        session_id=session_id,
        system_message=SYSTEM_PROMPTS[lang],
    ).with_model("gemini", GEMINI_MODEL)
    return chat


async def ask_gemini(session_id: str, user_text: str, language: str) -> tuple[str, bool]:
    """Returns (reply, used_fallback)."""
    if not GEMINI_API_KEY:
        return OFFLINE_KB.get(language, OFFLINE_KB["en"]), True
    try:
        chat = make_chat(session_id, language)
        reply = await chat.send_message(UserMessage(text=user_text))
        if not reply or not reply.strip():
            return OFFLINE_KB.get(language, OFFLINE_KB["en"]), True
        return reply.strip(), False
    except Exception as exc:
        logger.error("Gemini call failed: %s", exc)
        return OFFLINE_KB.get(language, OFFLINE_KB["en"]), True


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@api_router.get("/health")
async def health():
    return {"status": "ok", "model": GEMINI_MODEL, "safe_browsing": bool(SAFE_BROWSING_API_KEY)}


@api_router.post("/scan/link", response_model=LinkScanResponse)
async def scan_link(req: LinkScanRequest):
    raw = req.url.strip()
    if not raw:
        raise HTTPException(400, "URL is required")
    if not re.match(r"^https?://", raw, re.I):
        raw = "http://" + raw

    score, threats = heuristic_url_score(raw)
    sb_threats = await safe_browsing_check(raw)
    if sb_threats:
        score = max(score, 95)
    threats.extend(sb_threats)

    risk = score_to_risk(score)

    titles = {
        "tj": {"safe": "Пайванд бехатар аст", "suspicious": "Пайванд шубҳанок аст", "dangerous": "Пайванд хатарнок аст"},
        "ru": {"safe": "Ссылка безопасна", "suspicious": "Ссылка подозрительная", "dangerous": "Ссылка опасна"},
        "en": {"safe": "Link looks safe", "suspicious": "Link is suspicious", "dangerous": "Link is dangerous"},
    }
    advice_map = {
        "tj": {
            "safe": "Эҳтиёт бошед, аммо ягон хатари ҷиддӣ муайян нашуд.",
            "suspicious": "Пайвандро накушоед, агар онро интизор набудед. Бо манбаъ тасдиқ кунед.",
            "dangerous": "Ин пайвандро ҳаргиз накушоед. Маълумоти шахсиро ворид накунед.",
        },
        "ru": {
            "safe": "Серьёзных угроз не обнаружено, но будьте внимательны.",
            "suspicious": "Не открывайте ссылку, если не ждали её. Уточните у отправителя.",
            "dangerous": "Не открывайте! Не вводите личные данные.",
        },
        "en": {
            "safe": "No major threats detected, but stay cautious.",
            "suspicious": "Avoid opening the link unless you trust the sender.",
            "dangerous": "Do NOT open this link. Do not enter any personal data.",
        },
    }

    lang = req.language if req.language in titles else "tj"
    title = titles[lang][risk]

    summary_lines = [t.description for t in threats[:4]] or {
        "tj": ["Ягон аломати возеҳи қаллобӣ дида нашуд."],
        "ru": ["Явных признаков мошенничества не найдено."],
        "en": ["No obvious scam indicators found."],
    }[lang]
    summary = " ".join(summary_lines)

    # Ask Gemini for a short explanation
    if GEMINI_API_KEY:
        try:
            prompt = (
                f"In one short paragraph (max 60 words) in language code '{lang}', "
                f"explain why this URL is rated '{risk}'. URL: {raw}. "
                f"Indicators: {[t.description for t in threats] or 'none'}. "
                f"Be plain, no markdown."
            )
            chat = LlmChat(api_key=GEMINI_API_KEY, session_id=f"link-{uuid.uuid4()}",
                           system_message="You are a cybersecurity assistant.").with_model("gemini", GEMINI_MODEL)
            ai_summary = await chat.send_message(UserMessage(text=prompt))
            if ai_summary and ai_summary.strip():
                summary = ai_summary.strip()
        except Exception as exc:
            logger.warning("Gemini link explain failed: %s", exc)

    resp = LinkScanResponse(
        url=raw,
        risk_level=risk,
        risk_score=score,
        title=title,
        summary=summary,
        advice=advice_map[lang][risk],
        threats=threats,
    )
    await db.scan_history.insert_one({**resp.dict(), "kind": "link"})
    return resp


@api_router.post("/scan/message", response_model=MessageScanResponse)
async def scan_message(req: MessageScanRequest):
    text = req.text.strip()
    if not text:
        raise HTTPException(400, "Message text required")

    indicators: List[str] = []
    score = 0
    for pattern, label in SCAM_MESSAGE_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            indicators.append(label)
            score += 12

    urls = extract_urls(text)
    if urls:
        # quickly score urls with heuristics
        for u in urls[:3]:
            s, t = heuristic_url_score(u)
            score += s // 4
            for th in t[:2]:
                indicators.append(f"URL: {th.description}")
    score = min(score, 100)
    risk = score_to_risk(score)
    lang = req.language if req.language in ("tj", "ru", "en") else "tj"

    advice_map = {
        "tj": {
            "safe": "Хатари ҷиддӣ дида нашуд, аммо ҳамеша эҳтиёт бошед.",
            "suspicious": "Ҷавоб надиҳед, пайвандҳоро накушоед, бо манбаъ тасдиқ кунед.",
            "dangerous": "Ин ба қаллобӣ хеле монанд аст. Ҷавоб надиҳед, пайвандро накушоед, рамзи SMS-ро надиҳед.",
        },
        "ru": {
            "safe": "Серьёзных угроз не обнаружено, но оставайтесь бдительны.",
            "suspicious": "Не отвечайте и не переходите по ссылкам. Проверьте у отправителя.",
            "dangerous": "Это похоже на мошенничество. Не отвечайте, не переходите по ссылкам, не сообщайте коды.",
        },
        "en": {
            "safe": "No serious indicators detected, but stay alert.",
            "suspicious": "Don't reply or open links. Verify with the sender directly.",
            "dangerous": "This looks like a scam. Do not reply, do not open links, never share SMS codes.",
        },
    }

    summary_default = {
        "tj": "Таҳлили хабар анҷом ёфт.",
        "ru": "Сообщение проанализировано.",
        "en": "Message analyzed.",
    }
    summary = summary_default[lang]

    if GEMINI_API_KEY:
        try:
            prompt = (
                f"In language '{lang}', 2 short sentences max, plain text. "
                f"Explain to a non-technical user why this SMS is rated '{risk}'. "
                f"SMS: \"{text}\". Indicators: {indicators or 'none'}."
            )
            chat = LlmChat(api_key=GEMINI_API_KEY, session_id=f"msg-{uuid.uuid4()}",
                           system_message="You explain SMS scams clearly.").with_model("gemini", GEMINI_MODEL)
            r = await chat.send_message(UserMessage(text=prompt))
            if r and r.strip():
                summary = r.strip()
        except Exception as exc:
            logger.warning("Gemini message explain failed: %s", exc)

    resp = MessageScanResponse(
        risk_level=risk,
        risk_score=score,
        summary=summary,
        advice=advice_map[lang][risk],
        indicators=indicators,
        extracted_urls=urls,
    )
    await db.scan_history.insert_one({**resp.dict(), "kind": "message"})
    return resp


def normalize_phone(phone: str) -> str:
    digits = re.sub(r"[^\d+]", "", phone)
    if digits.startswith("00"):
        digits = "+" + digits[2:]
    if not digits.startswith("+") and len(digits) >= 9:
        # assume Tajikistan if 9 digits and starts with 9
        if len(digits) == 9 and digits.startswith("9"):
            digits = "+992" + digits
        else:
            digits = "+" + digits
    return digits


# Common Tajik mobile prefixes (operators)
TJ_OPERATORS = {
    "900": "Babilon-M", "901": "Babilon-M", "902": "MegaFon", "903": "MegaFon",
    "904": "MegaFon", "905": "MegaFon", "906": "MegaFon", "907": "Tcell",
    "908": "Tcell", "909": "ZetMobile", "911": "Tcell", "917": "Tcell",
    "918": "Tcell", "919": "Tcell", "927": "Tcell", "928": "Tcell",
    "929": "Tcell", "935": "Babilon-M", "936": "Babilon-M", "937": "Babilon-M",
    "938": "Babilon-M", "939": "Babilon-M", "98": "MegaFon", "988": "MegaFon",
    "987": "MegaFon", "985": "MegaFon",
}


@api_router.post("/scan/phone", response_model=PhoneScanResponse)
async def scan_phone(req: PhoneScanRequest):
    raw = req.phone.strip()
    if not raw:
        raise HTTPException(400, "Phone required")

    norm = normalize_phone(raw)
    indicators: List[str] = []
    score = 0
    country = "Unknown"
    carrier = None

    digits = re.sub(r"\D", "", norm)
    if norm.startswith("+992"):
        country = "Tajikistan"
        local = digits[3:]
        if len(local) >= 3:
            for prefix in (local[:3], local[:2]):
                if prefix in TJ_OPERATORS:
                    carrier = TJ_OPERATORS[prefix]
                    break
        if not carrier:
            score += 20
            indicators.append("Unknown Tajik operator prefix.")
    else:
        # international call to TJ user is suspicious
        if norm.startswith("+"):
            score += 25
            indicators.append("International number — be careful with unexpected calls.")
        else:
            score += 10
            indicators.append("Could not detect country code.")

    if len(digits) < 7 or len(digits) > 15:
        score += 25
        indicators.append("Unusual phone length.")

    # check local reports
    reports = await db.phone_reports.count_documents({"normalized": norm})
    if reports > 0:
        score += min(60, 20 * reports)
        indicators.append(f"Reported by users {reports} time(s).")

    # known scam patterns — repeating digits etc.
    if re.search(r"(\d)\1{4,}", digits):
        score += 20
        indicators.append("Number has many repeating digits.")

    score = min(score, 100)
    risk = score_to_risk(score)
    lang = req.language if req.language in ("tj", "ru", "en") else "tj"

    summary_map = {
        "tj": {
            "safe": "Ягон огоҳии муҳим оид ба ин рақам нест.",
            "suspicious": "Барои ин рақам аломатҳои шубҳанок мавҷуданд.",
            "dangerous": "Эҳтимолияти баланди қаллобӣ — эҳтиёт шавед.",
        },
        "ru": {
            "safe": "По этому номеру нет тревожных сигналов.",
            "suspicious": "По номеру есть подозрительные признаки.",
            "dangerous": "Высокий риск мошенничества — будьте осторожны.",
        },
        "en": {
            "safe": "No warning signs for this number.",
            "suspicious": "There are some suspicious signals about this number.",
            "dangerous": "High scam likelihood — be very careful.",
        },
    }
    advice_map = {
        "tj": {
            "safe": "Бо ҳушёрӣ ҷавоб диҳед, маълумоти шахсиро нагӯед.",
            "suspicious": "Ҷавоб надиҳед ё рақамро баъдан тафтиш кунед.",
            "dangerous": "Ҷавоб надиҳед, рамзҳо нагӯед ва рақамро блок кунед.",
        },
        "ru": {
            "safe": "Отвечайте осторожно, не сообщайте личных данных.",
            "suspicious": "Лучше не отвечать или проверить номер.",
            "dangerous": "Не отвечайте, не сообщайте коды, заблокируйте номер.",
        },
        "en": {
            "safe": "Answer cautiously, never share personal info.",
            "suspicious": "Avoid answering or verify the number first.",
            "dangerous": "Do not answer. Block the number and never share SMS codes.",
        },
    }

    resp = PhoneScanResponse(
        phone=raw,
        normalized=norm,
        risk_level=risk,
        risk_score=score,
        country=country,
        carrier_hint=carrier,
        summary=summary_map[lang][risk],
        advice=advice_map[lang][risk],
        indicators=indicators,
        local_reports=reports,
    )
    await db.scan_history.insert_one({**resp.dict(), "kind": "phone"})
    return resp


@api_router.post("/phone/report")
async def report_phone(req: PhoneReportRequest):
    norm = normalize_phone(req.phone.strip())
    doc = {
        "id": str(uuid.uuid4()),
        "phone": req.phone,
        "normalized": norm,
        "note": req.note or "",
        "category": req.category or "scam",
        "reported_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.phone_reports.insert_one(doc)
    count = await db.phone_reports.count_documents({"normalized": norm})
    return {"ok": True, "normalized": norm, "total_reports": count}


@api_router.get("/phone/reports/{phone}")
async def list_phone_reports(phone: str):
    norm = normalize_phone(phone)
    items = await db.phone_reports.find({"normalized": norm}, {"_id": 0}).sort("reported_at", -1).to_list(50)
    return {"normalized": norm, "count": len(items), "reports": items}


@api_router.post("/ai/chat", response_model=ChatResponse)
async def ai_chat(req: ChatRequest):
    if not req.message.strip():
        raise HTTPException(400, "Message required")
    reply, used_fallback = await ask_gemini(req.session_id, req.message.strip(), req.language or "tj")
    # store
    await db.ai_history.insert_one({
        "session_id": req.session_id,
        "user_message": req.message,
        "ai_reply": reply,
        "language": req.language,
        "used_fallback": used_fallback,
        "ts": datetime.now(timezone.utc).isoformat(),
    })
    return ChatResponse(session_id=req.session_id, reply=reply, used_fallback=used_fallback)


# ---------------------------------------------------------------------------
app.include_router(api_router)
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

"""Scam.tj 2.0 backend API tests."""
import os
import uuid
import pytest
import requests

BASE_URL = os.environ.get("EXPO_PUBLIC_BACKEND_URL", "http://localhost:8001").rstrip("/")
API = f"{BASE_URL}/api"


@pytest.fixture(scope="session")
def api_client():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    return s


# --- health ---
class TestHealth:
    def test_health_ok(self, api_client):
        r = api_client.get(f"{API}/health", timeout=20)
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert data["model"] == "gemini-3-flash-preview"


# --- link scan ---
class TestLinkScan:
    def test_phishing_link_is_dangerous(self, api_client):
        url = "http://192.168.1.1/login-verify-amonatbonk"
        r = api_client.post(f"{API}/scan/link", json={"url": url, "language": "en"}, timeout=60)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["risk_level"] in ("dangerous", "suspicious")
        # Phishing URL with IP+keywords+http should be dangerous
        assert d["risk_score"] >= 70, f"score={d['risk_score']} expected>=70"
        assert d["risk_level"] == "dangerous"
        assert isinstance(d["threats"], list) and len(d["threats"]) > 0
        assert d["summary"] and isinstance(d["summary"], str)
        assert d["advice"]

    def test_safe_link(self, api_client):
        r = api_client.post(f"{API}/scan/link", json={"url": "https://google.com", "language": "en"}, timeout=60)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["risk_level"] == "safe", f"risk_level={d['risk_level']} score={d['risk_score']}"
        assert d["risk_score"] < 30

    def test_empty_url_400(self, api_client):
        r = api_client.post(f"{API}/scan/link", json={"url": "", "language": "en"}, timeout=10)
        assert r.status_code == 400


# --- message scan ---
class TestMessageScan:
    def test_scam_message(self, api_client):
        msg = (
            "URGENT! Your Amonatbonk account has been blocked. Verify your card and OTP "
            "immediately at http://bit.ly/amonat-verify or your account will be locked."
        )
        r = api_client.post(f"{API}/scan/message", json={"text": msg, "language": "en"}, timeout=60)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["risk_level"] in ("suspicious", "dangerous")
        assert len(d["indicators"]) >= 3
        assert d["summary"]
        assert "http://bit.ly/amonat-verify" in d["extracted_urls"]


# --- phone scan + report ---
class TestPhone:
    def test_scan_tajik_phone(self, api_client):
        r = api_client.post(f"{API}/scan/phone", json={"phone": "+992 901234567", "language": "en"}, timeout=20)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["country"] == "Tajikistan"
        assert d["carrier_hint"] == "Babilon-M"
        assert d["normalized"] == "+992901234567"

    def test_report_and_rescan_increments(self, api_client):
        # unique number per test run to avoid pollution
        suffix = str(uuid.uuid4().int)[:7]
        phone = f"+99290{suffix}"
        # initial scan - 0 reports
        r0 = api_client.post(f"{API}/scan/phone", json={"phone": phone}, timeout=20).json()
        assert r0["local_reports"] == 0
        # report
        rep = api_client.post(f"{API}/phone/report", json={"phone": phone, "note": "TEST_scam", "category": "scam"}, timeout=20)
        assert rep.status_code == 200, rep.text
        assert rep.json()["ok"] is True
        # rescan
        r1 = api_client.post(f"{API}/scan/phone", json={"phone": phone}, timeout=20).json()
        assert r1["local_reports"] >= 1, f"expected >=1, got {r1['local_reports']}"


# --- AI chat ---
class TestAIChat:
    def test_chat_reply_and_multi_turn(self, api_client):
        sid = f"test-{uuid.uuid4()}"
        r1 = api_client.post(f"{API}/ai/chat",
                             json={"session_id": sid, "message": "What is phishing?", "language": "en"},
                             timeout=90)
        assert r1.status_code == 200, r1.text
        d1 = r1.json()
        assert d1["session_id"] == sid
        assert d1["reply"] and isinstance(d1["reply"], str)
        assert len(d1["reply"]) > 10
        # Check not just fallback (Gemini works)
        # Even if fallback, must reply
        r2 = api_client.post(f"{API}/ai/chat",
                             json={"session_id": sid, "message": "Give me 2 tips to avoid it.", "language": "en"},
                             timeout=90)
        assert r2.status_code == 200, r2.text
        d2 = r2.json()
        assert d2["reply"] and len(d2["reply"]) > 5

    def test_chat_empty_400(self, api_client):
        r = api_client.post(f"{API}/ai/chat",
                            json={"session_id": "x", "message": "  ", "language": "en"}, timeout=10)
        assert r.status_code == 400

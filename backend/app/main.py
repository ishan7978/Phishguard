from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .analyzers.regex_engine import analyze, extract
from .analyzers.url_analyzer import analyze_url
from .analyzers.vt_reputation import lookup_url
from .analyzers.phishing_reputation import lookup_phishing_url
from .scoring.risk import score

import datetime
import json
import os
import uuid


app = FastAPI(
    title="PHISHGUARD API",
    version="1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)


# ---------------------------------------------------------
# Persistent local history
# ---------------------------------------------------------

DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "data"
)

HISTORY_FILE = os.path.join(
    DATA_DIR,
    "scan_history.json"
)


def _ensure_history_file():
    os.makedirs(DATA_DIR, exist_ok=True)

    if not os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump([], f)


def _load_history():
    _ensure_history_file()

    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        return data if isinstance(data, list) else []

    except Exception:
        return []


def _save_history(item):
    history = _load_history()

    history.insert(0, item)

    # Keep the local history reasonably small.
    history = history[:500]

    temp_file = HISTORY_FILE + ".tmp"

    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(
            history,
            f,
            indent=2,
            ensure_ascii=False
        )

    os.replace(temp_file, HISTORY_FILE)


def _history_record(result):
    return {
        "analysis_id": result["analysis_id"],
        "timestamp": result["timestamp"],
        "input_type": result["input_type"],
        "verdict": result["verdict"],
        "risk_score": result["risk_score"],
        "confidence": result.get("confidence", 0),
        "threat_category": result.get(
            "threat_category",
            "General"
        )
    }


# ---------------------------------------------------------
# Request models
# ---------------------------------------------------------

class URLReq(BaseModel):
    url: str = Field(
        min_length=3,
        max_length=4096
    )


class SMSReq(BaseModel):
    text: str = Field(
        min_length=1,
        max_length=10000
    )


class EmailReq(BaseModel):
    subject: str = Field(
        default="",
        max_length=1000
    )

    body: str = Field(
        min_length=1,
        max_length=30000
    )


# ---------------------------------------------------------
# Metadata
# ---------------------------------------------------------

def with_meta(r, typ):
    recommendations = {
        "LIKELY_PHISHING":
            "Do not click links, submit credentials, or provide OTPs. Verify the organization through an independently obtained official channel.",

        "HIGH_RISK":
            "Treat this content as potentially dangerous. Do not provide sensitive information until the sender and destination are independently verified.",

        "SUSPICIOUS":
            "Pause before acting. Do not click links or provide sensitive information until the request is independently verified.",

        "LIKELY_LEGITIMATE":
            "No significant phishing indicators were detected by the configured checks. This is not proof that the content is safe.",

        "INSUFFICIENT_EVIDENCE":
            "Insufficient evidence. Verify the sender and destination independently."
    }

    r.update({
        "analysis_id":
            "PG-" + uuid.uuid4().hex[:10].upper(),

        "timestamp":
            datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat().replace("+00:00", "Z"),

        "input_type":
            typ,

        "recommendation":
            recommendations.get(
                r["verdict"],
                "Insufficient evidence. Verify the sender and destination independently."
            )
    })

    return r


# ---------------------------------------------------------
# Health
# ---------------------------------------------------------

@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": "PHISHGUARD"
    }


# ---------------------------------------------------------
# URL analysis
# ---------------------------------------------------------

@app.post("/api/analyze/url")
def url(req: URLReq):

    try:
        x = analyze_url(req.url)

        vt = lookup_url(
            x["normalized_url"]
        )

        openphish = lookup_phishing_url(
            x["normalized_url"]
        )

        r = score(
            x["indicators"],
            vt,
            x,
            openphish
        )

        r["url_analysis"] = x
        r["virus_total"] = vt
        r["openphish"] = openphish

        result = with_meta(
            r,
            "url"
        )

        _save_history(
            _history_record(result)
        )

        return result

    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )


# ---------------------------------------------------------
# SMS analysis
# ---------------------------------------------------------

@app.post("/api/analyze/sms")
def sms(req: SMSReq):

    try:
        inds = analyze(req.text)

        ents = extract(req.text)

        # Analyze URLs found inside the SMS.
        for u in ents["urls"][:5]:
            try:
                url_result = analyze_url(u)

                inds += url_result["indicators"]

            except Exception:
                # One malformed/unreachable URL should not
                # prevent the SMS itself from being analyzed.
                continue

        r = score(inds)

        # A clean SMS with no detected phishing indicators is
        # treated as likely legitimate. This does not affect
        # URL scoring, which remains evidence-based.
        if not inds:
            r["verdict"] = "LIKELY_LEGITIMATE"
            r["threat_category"] = "General"
            r["recommendation"] = (
                "No significant phishing indicators were detected "
                "by the configured checks. This is not proof that "
                "the message is safe."
            )

        r["entities"] = ents

        result = with_meta(
            r,
            "sms"
        )

        _save_history(
            _history_record(result)
        )

        return result

    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )


# ---------------------------------------------------------
# EMAIL analysis
# ---------------------------------------------------------

@app.post("/api/analyze/email")
def email(req: EmailReq):

    try:
        # Combine subject and body so the same defensive
        # pattern engine can inspect both.
        combined = ""

        if req.subject.strip():
            combined += (
                "Subject: "
                + req.subject
                + "\n"
            )

        combined += req.body

        # Local email/text analysis.
        inds = analyze(combined)

        # Extract URLs, email addresses and IP addresses.
        ents = extract(combined)

        url_results = []

        # Analyze discovered URLs using the same URL engine.
        for u in ents["urls"][:5]:

            try:
                x = analyze_url(u)

                inds += x["indicators"]

                # Email URL reputation is checked individually.
                vt = lookup_url(
                    x["normalized_url"]
                )

                url_results.append({
                    "url": u,
                    "url_analysis": x,
                    "virus_total": vt
                })

            except Exception:
                continue

        # Generate final risk assessment.
        r = score(inds)

        # A clean email with no detected phishing indicators is
        # treated as likely legitimate. This does not mean the
        # email is guaranteed safe.
        if not inds:
            r["verdict"] = "LIKELY_LEGITIMATE"
            r["threat_category"] = "General"
            r["recommendation"] = (
                "No significant phishing indicators were detected "
                "by the configured checks. This is not proof that "
                "the email is safe."
            )

        r["entities"] = ents
        r["url_results"] = url_results

        result = with_meta(
            r,
            "email"
        )

        _save_history(
            _history_record(result)
        )

        return result

    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )


# ---------------------------------------------------------
# Scan history
# ---------------------------------------------------------

@app.get("/api/history")
def history():

    return _load_history()


# ---------------------------------------------------------
# Dashboard statistics
# ---------------------------------------------------------

@app.get("/api/stats")
def stats():

    history = _load_history()

    total = len(history)

    phishing = sum(
        1
        for x in history
        if x.get("verdict") == "LIKELY_PHISHING"
    )

    high_risk = sum(
        1
        for x in history
        if x.get("verdict") == "HIGH_RISK"
    )

    suspicious = sum(
        1
        for x in history
        if x.get("verdict") == "SUSPICIOUS"
    )

    legitimate = sum(
        1
        for x in history
        if x.get("verdict") == "LIKELY_LEGITIMATE"
    )

    return {
        "total_scans": total,
        "phishing": phishing,
        "high_risk": high_risk,
        "suspicious": suspicious,
        "legitimate": legitimate
    }

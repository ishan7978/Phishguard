import os
import base64
import time
import httpx

VT_API = "https://www.virustotal.com/api/v3"
_CACHE = {}
CACHE_TTL = 3600


def _url_id(url: str) -> str:
    encoded = base64.urlsafe_b64encode(url.encode()).decode()
    return encoded.rstrip("=")


def lookup_url(url: str):
    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        return {
            "available": False,
            "status": "not_configured",
            "message": "VirusTotal API key is not configured."
        }

    now = time.time()
    cached = _CACHE.get(url)

    if cached and now - cached["time"] < CACHE_TTL:
        return cached["data"]

    try:
        response = httpx.get(
            f"{VT_API}/urls/{_url_id(url)}",
            headers={
                "x-apikey": api_key,
                "accept": "application/json",
            },
            timeout=10,
        )

        if response.status_code == 404:
            data = {
                "available": True,
                "status": "not_found",
                "message": "VirusTotal has no existing report for this URL."
            }

        elif response.status_code == 429:
            data = {
                "available": False,
                "status": "rate_limited",
                "message": "VirusTotal rate limit reached."
            }

        elif response.status_code in (401, 403):
            data = {
                "available": False,
                "status": "authentication_error",
                "message": "VirusTotal API authentication failed."
            }

        elif response.status_code >= 400:
            data = {
                "available": False,
                "status": "api_error",
                "message": f"VirusTotal returned HTTP {response.status_code}."
            }

        else:
            obj = response.json().get("data", {})
            attrs = obj.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            malicious = int(stats.get("malicious", 0) or 0)
            suspicious = int(stats.get("suspicious", 0) or 0)
            harmless = int(stats.get("harmless", 0) or 0)
            undetected = int(stats.get("undetected", 0) or 0)

            data = {
                "available": True,
                "status": "found",
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total_engines": malicious + suspicious + harmless + undetected,
                "reputation": attrs.get("reputation", 0),
                "last_analysis_date": attrs.get("last_analysis_date"),
            }

        _CACHE[url] = {"time": now, "data": data}
        return data

    except Exception as exc:
        return {
            "available": False,
            "status": "connection_error",
            "message": str(exc)
        }

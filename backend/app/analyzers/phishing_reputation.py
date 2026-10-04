import time
import httpx


FEED_URL = "https://openphish.com/feed.txt"

_CACHE = {
    "time": 0,
    "urls": set(),
}

CACHE_TTL = 900  # refresh every 15 minutes


def _load_feed():
    now = time.time()

    if _CACHE["urls"] and now - _CACHE["time"] < CACHE_TTL:
        return _CACHE["urls"]

    try:
        response = httpx.get(
            FEED_URL,
            follow_redirects=True,
            timeout=10.0,
            headers={
                "User-Agent": "PHISHGUARD-Defensive-Scanner/1.0"
            },
        )

        response.raise_for_status()

        urls = set()

        for line in response.text.splitlines():
            value = line.strip()

            if value and not value.startswith("#"):
                urls.add(value)

        _CACHE["urls"] = urls
        _CACHE["time"] = now

        return urls

    except Exception:
        # Feed failure must never break PHISHGUARD.
        return _CACHE["urls"]


def lookup_phishing_url(url: str):
    feed = _load_feed()

    if not feed:
        return {
            "available": False,
            "status": "unavailable",
            "match": False,
            "source": "OpenPhish",
        }

    normalized = url.strip().rstrip("/")

    match = normalized in feed

    return {
        "available": True,
        "status": "matched" if match else "not_found",
        "match": match,
        "source": "OpenPhish",
    }

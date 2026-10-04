from datetime import datetime, timezone
import whois


def _first_date(value):
    if isinstance(value, list):
        value = next((x for x in value if x), None)

    if not value:
        return None

    if isinstance(value, datetime):
        return value

    return None


def analyze_domain_age(host: str):
    host = (host or "").lower().rstrip(".")

    if not host:
        return {
            "available": False,
            "status": "invalid_domain",
        }

    try:
        result = whois.whois(host)

        creation_date = _first_date(
            result.creation_date
        )

        expiration_date = _first_date(
            result.expiration_date
        )

        if creation_date is None:
            return {
                "available": True,
                "status": "creation_date_unavailable",
                "domain": host,
            }

        now = datetime.now(timezone.utc)

        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(
                tzinfo=timezone.utc
            )

        age_days = max(
            0,
            (now - creation_date).days
        )

        if age_days < 30:
            category = "very_new"
        elif age_days < 90:
            category = "new"
        elif age_days < 365:
            category = "less_than_one_year"
        elif age_days < 365 * 3:
            category = "established"
        else:
            category = "long_established"

        return {
            "available": True,
            "status": "found",
            "domain": host,
            "creation_date": creation_date.isoformat(),
            "expiration_date": (
                expiration_date.isoformat()
                if expiration_date
                else None
            ),
            "age_days": age_days,
            "age_category": category,
            "registrar": result.registrar,
        }

    except Exception as exc:
        return {
            "available": False,
            "status": "lookup_error",
            "domain": host,
            "error": type(exc).__name__,
        }

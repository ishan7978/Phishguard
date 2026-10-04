from urllib.parse import urlsplit, unquote
import ipaddress
import re
import socket
import ssl

import httpx
from rapidfuzz.fuzz import ratio

from .regex_engine import analyze
from .domain_age import analyze_domain_age


# These are supporting signals, NOT a complete list of trusted websites.
BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com"],
    "google": ["google.com"],
    "amazon": ["amazon.com"],
    "apple": ["apple.com"],
    "facebook": ["facebook.com"],
    "flipkart": ["flipkart.com"],
    "swiggy": ["swiggy.com"],
}


SUSPICIOUS_PORTS = {
    21, 22, 23, 25, 110, 135, 139, 143, 445,
    3389, 5900, 8080, 8443
}

SUSPICIOUS_PATH_WORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "secure",
    "update",
    "password",
    "otp",
    "confirm",
    "billing",
    "payment",
}

SHORTENER_HOSTS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
}


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _registrable_candidate(host: str) -> str:
    """
    Extract the registrable-domain label for fuzzy brand matching.
    """
    import tldextract

    extracted = tldextract.extract(host)

    if extracted.domain:
        return extracted.domain.lower()

    return host.lower().strip(".")


def _is_official_domain(host: str, official_domains: list[str]) -> bool:
    host = host.lower().rstrip(".")

    for domain in official_domains:
        domain = domain.lower().rstrip(".")

        if host == domain or host.endswith("." + domain):
            return True

    return False


def _add(indicators, rule_id, category, matched_text, severity, score,
         explanation, source="heuristic", **extra):
    item = {
        "rule_id": rule_id,
        "category": category,
        "matched_text": matched_text,
        "severity": severity,
        "score": score,
        "explanation": explanation,
        "source": source,
    }

    item.update(extra)
    indicators.append(item)


def _dns_check(host: str):
    if not host or _is_ip(host):
        return {
            "available": False,
            "resolved": False,
            "addresses": [],
        }

    try:
        results = socket.getaddrinfo(
            host,
            None,
            type=socket.SOCK_STREAM
        )

        addresses = sorted(
            {
                result[4][0]
                for result in results
                if result and result[4]
            }
        )

        return {
            "available": True,
            "resolved": bool(addresses),
            "addresses": addresses[:10],
        }

    except Exception as exc:
        return {
            "available": True,
            "resolved": False,
            "addresses": [],
            "error": type(exc).__name__,
        }


def _tls_check(host: str, port: int):
    if not host:
        return {
            "available": False,
            "valid": False,
        }

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (host, port),
            timeout=4
        ) as sock:
            with context.wrap_socket(
                sock,
                server_hostname=host
            ) as tls_sock:
                cert = tls_sock.getpeercert()

                return {
                    "available": True,
                    "valid": True,
                    "version": tls_sock.version(),
                    "subject": str(cert.get("subject", "")),
                    "issuer": str(cert.get("issuer", "")),
                }

    except Exception as exc:
        return {
            "available": True,
            "valid": False,
            "error": type(exc).__name__,
        }


def _redirect_check(url: str):
    """
    Performs a limited GET request to observe redirects.

    This is intentionally conservative:
    - short timeout
    - small redirect limit
    - no credential submission
    - no form interaction
    """

    try:
        with httpx.Client(
            follow_redirects=True,
            max_redirects=5,
            timeout=6.0,
            headers={
                "User-Agent": "PHISHGUARD-Defensive-Scanner/1.0"
            }
        ) as client:

            response = client.get(url)

            history = []

            for item in response.history:
                history.append({
                    "status_code": item.status_code,
                    "url": str(item.url),
                    "location": item.headers.get("location", ""),
                })

            return {
                "available": True,
                "status_code": response.status_code,
                "final_url": str(response.url),
                "redirect_count": len(history),
                "redirects": history[:5],
            }

    except Exception as exc:
        return {
            "available": True,
            "error": type(exc).__name__,
            "redirect_count": 0,
            "redirects": [],
        }


def analyze_url(url: str):
    raw = (url or "").strip()

    if not raw:
        raise ValueError("URL cannot be empty.")

    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw

    try:
        parsed = urlsplit(raw)
    except ValueError as exc:
        raise ValueError("Invalid URL format.") from exc

    host = (parsed.hostname or "").lower().rstrip(".")

    if not host:
        raise ValueError("URL does not contain a valid hostname.")

    port = parsed.port

    if port is None:
        port = 443 if parsed.scheme.lower() == "https" else 80

    indicators = analyze(raw)

    # ---------------------------------------------------------
    # Domain registration / age intelligence
    # ---------------------------------------------------------

    domain_age = analyze_domain_age(host)

    # A newly registered domain is only a supporting signal.
    # It must NOT be treated as proof of phishing.
    if (
        domain_age.get("available")
        and domain_age.get("status") == "found"
    ):
        age_days = domain_age.get("age_days")

        if isinstance(age_days, int):
            if age_days < 30:
                _add(
                    indicators,
                    "DOMAIN_VERY_NEW",
                    "domain_reputation",
                    host,
                    "medium",
                    6,
                    "The domain was registered less than 30 days ago."
                )

            elif age_days < 90:
                _add(
                    indicators,
                    "DOMAIN_NEW",
                    "domain_reputation",
                    host,
                    "low",
                    3,
                    "The domain was registered less than 90 days ago."
                )

    # ---------------------------------------------------------
    # Basic URL structure
    # ---------------------------------------------------------

    if len(raw) > 180:
        _add(
            indicators,
            "URL_LONG",
            "url_heuristic",
            str(len(raw)),
            "low",
            4,
            "Unusually long URL."
        )

    if len(raw) > 300:
        _add(
            indicators,
            "URL_VERY_LONG",
            "url_heuristic",
            str(len(raw)),
            "medium",
            6,
            "Very long URL structure may indicate obfuscation."
        )

    if "xn--" in host:
        _add(
            indicators,
            "URL_IDN",
            "url_obfuscation",
            host,
            "medium",
            10,
            "Punycode/IDN notation is present."
        )

    if _is_ip(host):
        _add(
            indicators,
            "IP_URL",
            "url_obfuscation",
            host,
            "high",
            15,
            "IP address is used directly as the destination."
        )

    if "@" in parsed.netloc:
        _add(
            indicators,
            "AT_URL",
            "url_obfuscation",
            parsed.netloc,
            "high",
            12,
            "An @ symbol can obscure the apparent destination."
        )

    # ---------------------------------------------------------
    # HTTPS / ports
    # ---------------------------------------------------------

    if parsed.scheme.lower() == "http":
        _add(
            indicators,
            "HTTP_NOT_HTTPS",
            "transport_security",
            raw,
            "low",
            5,
            "The destination uses HTTP instead of HTTPS."
        )

    if port in SUSPICIOUS_PORTS:
        _add(
            indicators,
            "SUSPICIOUS_PORT",
            "network_heuristic",
            str(port),
            "medium",
            7,
            "A non-standard or commonly abused network port is being used."
        )

    # ---------------------------------------------------------
    # Hostname structure
    # ---------------------------------------------------------

    labels = [x for x in host.split(".") if x]

    subdomain_count = max(0, len(labels) - 2)

    if subdomain_count >= 4:
        _add(
            indicators,
            "MANY_SUBDOMAINS",
            "domain_heuristic",
            host,
            "medium",
            7,
            "The hostname contains an unusually large number of subdomains."
        )

    if any(len(label) > 50 for label in labels):
        _add(
            indicators,
            "LONG_HOST_LABEL",
            "domain_heuristic",
            host,
            "medium",
            6,
            "A hostname label is unusually long."
        )

    # ---------------------------------------------------------
    # Encoded / obfuscated URL
    # ---------------------------------------------------------

    decoded_path = unquote(parsed.path or "")

    encoded_count = len(re.findall(r"%[0-9a-fA-F]{2}", raw))

    if encoded_count >= 5:
        _add(
            indicators,
            "URL_ENCODING",
            "url_obfuscation",
            str(encoded_count),
            "medium",
            7,
            "The URL contains substantial percent-encoded content."
        )

    if decoded_path != (parsed.path or ""):
        suspicious_decoded = any(
            word in decoded_path.lower()
            for word in SUSPICIOUS_PATH_WORDS
        )

        if suspicious_decoded:
            _add(
                indicators,
                "ENCODED_SENSITIVE_PATH",
                "credential_targeting",
                decoded_path,
                "medium",
                8,
                "Encoded URL content resolves to a sensitive account or credential path."
            )

    # ---------------------------------------------------------
    # Sensitive path analysis
    # ---------------------------------------------------------

    path_lower = decoded_path.lower()

    matched_path_words = [
        word
        for word in SUSPICIOUS_PATH_WORDS
        if word in path_lower
    ]

    if matched_path_words:
        _add(
            indicators,
            "SENSITIVE_PATH",
            "credential_targeting",
            ", ".join(sorted(set(matched_path_words))),
            "low",
            4,
            "The URL path contains account, login, verification, or payment-related terminology."
        )

    # ---------------------------------------------------------
    # URL shortener
    # ---------------------------------------------------------

    if host in SHORTENER_HOSTS:
        _add(
            indicators,
            "URL_SHORTENER",
            "redirect_heuristic",
            host,
            "medium",
            8,
            "A URL-shortening service hides the final destination."
        )

    # ---------------------------------------------------------
    # Brand / typosquatting as ONE supporting signal
    # ---------------------------------------------------------

    candidate = _registrable_candidate(host)

    for brand, official_domains in BRANDS.items():

        if _is_official_domain(host, official_domains):
            continue

        similarity = ratio(brand, candidate)

        if similarity >= 92:
            _add(
                indicators,
                "BRAND_IMPERSONATION",
                "brand_impersonation",
                host,
                "high",
                20,
                f"Domain strongly resembles the protected brand '{brand}' but is not an official domain.",
                source="fuzzy_match",
                brand=brand,
                similarity=similarity
            )

        elif similarity >= 82:
            _add(
                indicators,
                "POSSIBLE_BRAND_IMPERSONATION",
                "brand_impersonation",
                host,
                "medium",
                12,
                f"Domain resembles the protected brand '{brand}' but is not an official domain.",
                source="fuzzy_match",
                brand=brand,
                similarity=similarity
            )

    # ---------------------------------------------------------
    # Live network evidence
    # ---------------------------------------------------------

    dns = _dns_check(host)

    if dns.get("available") and not dns.get("resolved"):
        _add(
            indicators,
            "DNS_RESOLUTION_FAILED",
            "domain_reputation",
            host,
            "medium",
            10,
            "The hostname could not be resolved through DNS."
        )

    tls = None

    if parsed.scheme.lower() == "https":
        tls = _tls_check(host, port)

        if tls.get("available") and not tls.get("valid"):
            _add(
                indicators,
                "TLS_VALIDATION_FAILED",
                "transport_security",
                host,
                "medium",
                8,
                "The HTTPS connection could not be successfully validated."
            )

    # ---------------------------------------------------------
    # Redirect evidence
    # ---------------------------------------------------------

    redirect_info = _redirect_check(raw)

    final_url = redirect_info.get("final_url") or raw

    try:
        final_host = (
            urlsplit(final_url).hostname or ""
        ).lower().rstrip(".")
    except Exception:
        final_host = ""

    if (
        final_host
        and final_host != host
        and redirect_info.get("redirect_count", 0) > 0
    ):
        _add(
            indicators,
            "CROSS_DOMAIN_REDIRECT",
            "redirect_heuristic",
            final_host,
            "medium",
            8,
            "The URL redirects to a different hostname."
        )

    if redirect_info.get("redirect_count", 0) >= 3:
        _add(
            indicators,
            "MULTIPLE_REDIRECTS",
            "redirect_heuristic",
            str(redirect_info["redirect_count"]),
            "medium",
            7,
            "The destination uses multiple redirects."
        )

    # ---------------------------------------------------------
    # Return structured evidence
    # ---------------------------------------------------------

    return {
        "normalized_url": raw,
        "features": {
            "scheme": parsed.scheme.lower(),
            "hostname": host,
            "path": parsed.path,
            "query": parsed.query,
            "https": parsed.scheme.lower() == "https",
            "port": port,
            "url_length": len(raw),
            "subdomains": subdomain_count,
            "host_is_ip": _is_ip(host),
        },
        "network": {
            "dns": dns,
            "tls": tls,
            "redirects": redirect_info,
            "final_url": final_url,
            "final_hostname": final_host,
        },
        "indicators": indicators,
    }

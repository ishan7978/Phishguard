def _dedupe(indicators):
    seen = set()
    clean = []

    for i in indicators:
        key = (
            i.get("rule_id"),
            str(i.get("matched_text", "")).strip().lower()
        )

        if key not in seen:
            seen.add(key)
            clean.append(i)

    return clean


def score(indicators, virus_total=None, url_analysis=None, openphish=None):
    clean = _dedupe(indicators)

    url_analysis = url_analysis or {}
    network = url_analysis.get("network") or {}

    dns = network.get("dns") or {}
    tls = network.get("tls") or {}
    redirects = network.get("redirects") or {}

    # ---------------------------------------------------------
    # VirusTotal
    # ---------------------------------------------------------

    vt_available = bool(
        virus_total and virus_total.get("available")
    )

    vt_malicious = int(
        (virus_total or {}).get("malicious", 0) or 0
    )

    vt_suspicious = int(
        (virus_total or {}).get("suspicious", 0) or 0
    )

    vt_total = int(
        (virus_total or {}).get("total_engines", 0) or 0
    )

    # ---------------------------------------------------------
    # OpenPhish reputation
    # ---------------------------------------------------------

    openphish_available = bool(
        openphish and openphish.get("available")
    )

    openphish_match = bool(
        openphish and openphish.get("match") is True
    )

    # ---------------------------------------------------------
    # Detect unreachable domain
    # ---------------------------------------------------------

    dns_available = bool(dns.get("available"))
    dns_resolved = bool(dns.get("resolved"))

    domain_unreachable = (
        dns_available
        and not dns_resolved
    )

    # ---------------------------------------------------------
    # Local evidence
    # ---------------------------------------------------------

    regex_score = min(
        30,
        sum(
            i.get("score", 0)
            for i in clean
            if i.get("source") == "regex"
        )
    )

    heuristic_score = min(
        30,
        sum(
            i.get("score", 0)
            for i in clean
            if i.get("source") in {
                "heuristic",
                "fuzzy_match",
                "dns"
            }
        )
    )

    # ---------------------------------------------------------
    # Contextual correlation
    # ---------------------------------------------------------

    rule_ids = {i.get("rule_id") for i in clean}
    correlation = 0

    if {"URGENT", "ACCOUNT_THREAT"} <= rule_ids:
        correlation += 5

    if {"OTP", "ACCOUNT_THREAT"} <= rule_ids:
        correlation += 7

    if {"OTP", "LOGIN_PATH"} <= rule_ids:
        correlation += 5

    if any(
        i.get("category") == "brand_impersonation"
        for i in clean
    ):
        correlation += 5

    correlation = min(10, correlation)

    # ---------------------------------------------------------
    # VirusTotal scoring
    # ---------------------------------------------------------

    vt_score = 0

    # OpenPhish is a direct phishing-feed match.
    # A match is strong evidence; not_found is neutral.
    openphish_score = 0

    if openphish_match:
        openphish_score = 40

    if vt_malicious >= 5:
        vt_score = 35
    elif vt_malicious >= 2:
        vt_score = 30
    elif vt_malicious >= 1:
        vt_score = 22
    elif vt_suspicious >= 3:
        vt_score = 15
    elif vt_suspicious >= 1:
        vt_score = 10

    # ---------------------------------------------------------
    # Network evidence
    # ---------------------------------------------------------

    network_score = 0

    if dns_available and not dns_resolved:
        network_score += 0

    if tls.get("available") and not tls.get("valid"):
        network_score += 8

    if redirects.get("redirect_count", 0) >= 3:
        network_score += 7

    # ---------------------------------------------------------
    # Final risk score
    # ---------------------------------------------------------

    total = min(
        100,
        regex_score
        + heuristic_score
        + correlation
        + vt_score
        + openphish_score
        + network_score
    )

    # ---------------------------------------------------------
    # Important indicators
    # ---------------------------------------------------------

    has_brand_impersonation = any(
        i.get("category") == "brand_impersonation"
        for i in clean
    )

    has_high_severity = any(
        i.get("severity") == "high"
        for i in clean
    )

    # ---------------------------------------------------------
    # Verdict
    # ---------------------------------------------------------

    if domain_unreachable:
        verdict = "DOMAIN_UNREACHABLE"

    elif openphish_match:
        verdict = "LIKELY_PHISHING"

    elif vt_malicious >= 5:
        verdict = "LIKELY_PHISHING"

    elif vt_malicious >= 2 and (
        has_brand_impersonation
        or has_high_severity
        or regex_score >= 10
    ):
        verdict = "LIKELY_PHISHING"

    elif total >= 75:
        verdict = "LIKELY_PHISHING"

    elif total >= 50:
        verdict = "HIGH_RISK"

    elif has_brand_impersonation:
        verdict = "SUSPICIOUS"

    elif total >= 20:
        verdict = "SUSPICIOUS"

    elif (
        dns_resolved
        and tls.get("valid") is True
        and not openphish_match
        and vt_malicious == 0
        and vt_suspicious == 0
        and not has_brand_impersonation
        and len(clean) == 0
    ):
        verdict = "LIKELY_LEGITIMATE"

    else:
        verdict = "INSUFFICIENT_EVIDENCE"

    # ---------------------------------------------------------
    # Confidence
    # ---------------------------------------------------------

    confidence = 50

    confidence += min(15, len(clean) * 3)

    if dns_resolved:
        confidence += 8

    if tls.get("valid"):
        confidence += 8

    if redirects.get("available"):
        confidence += 4

    if vt_available:
        confidence += 7

    if vt_malicious:
        confidence += 12

    if domain_unreachable:
        confidence = 90

    confidence = min(98, confidence)

    # ---------------------------------------------------------
    # Threat category
    # ---------------------------------------------------------

    if domain_unreachable:
        category = "Domain Unreachable"

    elif has_brand_impersonation:
        category = "Brand Impersonation"

    elif any(
        i.get("category") == "credential_request"
        for i in clean
    ):
        category = "Credential / OTP Scam"

    elif any(
        i.get("category") == "financial_scam"
        for i in clean
    ):
        category = "Financial Scam"

    elif any(
        i.get("category") == "social_engineering"
        for i in clean
    ):
        category = "Social Engineering"

    else:
        category = "General"

    # ---------------------------------------------------------
    # VirusTotal summary
    # ---------------------------------------------------------

    virus_total_summary = {
        "available": vt_available,
        "malicious": vt_malicious,
        "suspicious": vt_suspicious,
        "total_engines": vt_total,
    }

    return {
        "risk_score": total,
        "confidence": confidence,
        "verdict": verdict,
        "threat_category": category,
        "indicators": clean,
        "virus_total_summary": virus_total_summary,
        "contributions": [
            {
                "indicator": "regex_patterns",
                "score": regex_score
            },
            {
                "indicator": "url_heuristics_and_brand",
                "score": heuristic_score
            },
            {
                "indicator": "contextual_correlation",
                "score": correlation
            },
            {
                "indicator": "network_evidence",
                "score": network_score
            },
            {
                "indicator": "virus_total_reputation",
                "score": vt_score
            },
        ],
    }

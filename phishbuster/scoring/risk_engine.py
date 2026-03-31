# Risk scoring weights.
# Positive = raises risk.  Negative = lowers risk (safe signal when True).
# IMPORTANT: negative-weight booleans only give credit when they ARE True (safe),
# they do NOT penalise when False — a missing safe signal is not itself a risk signal.

WEIGHTS = {
    # ── URL signals ──────────────────────────────────────────────
    "is_long_url":                 0.5,
    "has_ip_address":              3.0,
    "has_at_symbol":               2.5,
    "hyphen_count":                0.3,
    "subdomain_count":             0.3,
    "suspicious_keyword_count":    1.0,
    "is_shortened":                2.0,
    "has_hex_encoding":            1.2,
    "has_double_slash":            0.5,
    "has_port":                    1.0,

    # ── Safe URL signals (True = reduce score) ──────────────────
    "uses_https":                 -1.5,

    # ── Domain signals ───────────────────────────────────────────
    "domain_is_new":               2.5,

    # ── Safe domain signals (True = reduce score) ────────────────
    "ssl_valid":                  -1.5,
    "dns_resolves":               -0.5,

    # ── Content risk signals ─────────────────────────────────────
    "has_login_form":              0.8,
    "hidden_element_count":        0.3,   # capped at 5 in content_analyzer
    "external_script_count":       0.4,   # capped at 3 in content_analyzer
    "has_iframe":                  0.8,
    "has_js_redirect":             2.0,
    "favicon_is_external":         1.2,
    "urgency_word_count":          1.0,
    "has_obfuscated_js":           2.5,
    "brand_impersonation":         2.0,

    # ── Blacklist ─────────────────────────────────────────────────
    "blacklisted":                 6.0,

    # ── ML (handled separately) ───────────────────────────────────
    "ml_phishing_probability":     3.0,
}

# Extra safe credit when all three safety signals are present together
_SAFE_COMBO_BONUS = -1.0


def compute_score(features: dict) -> dict:
    score     = 0.0
    triggered = []

    for key, weight in WEIGHTS.items():
        val = features.get(key)
        if val is None:
            continue

        # ── ML probability ────────────────────────────────────────
        if key == "ml_phishing_probability":
            if isinstance(val, float) and val > 0.5:
                contribution = weight * (val - 0.5) * 2
                score += contribution
                triggered.append(f"ML model: {val:.0%} phishing confidence")
            continue

        # ── Boolean features ──────────────────────────────────────
        if isinstance(val, bool):
            if weight > 0 and val:
                # Risk signal fired
                score += weight
                triggered.append(_label(key))
            elif weight < 0 and val:
                # Safe signal present — give the credit
                score += weight          # weight is negative, so this reduces score
            # weight < 0 and val is False → missing safe signal → no change
            # weight > 0 and val is False → risk signal absent  → no change
            continue

        # ── Numeric features ──────────────────────────────────────
        if isinstance(val, (int, float)) and val != 0:
            contribution = val * weight
            if contribution > 0.2:
                score += contribution
                triggered.append(f"{_label(key)}: {val}")
            elif contribution < -0.2:
                score += contribution    # safe numeric bonus

    # Combo safe bonus: HTTPS + valid SSL + DNS all confirmed good
    if (features.get("uses_https") is True and
            features.get("ssl_valid") is True and
            features.get("dns_resolves") is True):
        score += _SAFE_COMBO_BONUS

    score = round(max(0.0, min(score, 10.0)), 2)

    if score <= 3.0:
        verdict, color = "Safe",       "green"
    elif score <= 6.5:
        verdict, color = "Suspicious", "orange"
    else:
        verdict, color = "Phishing",   "red"

    return {
        "score":     score,
        "verdict":   verdict,
        "color":     color,
        "triggered": triggered,
    }


def _label(key: str) -> str:
    return key.replace("_", " ").capitalize()

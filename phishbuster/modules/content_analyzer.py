import re
from bs4 import BeautifulSoup

URGENCY_PHRASES = [
    "verify now", "act now", "immediate action",
    "account suspended", "click here to confirm",
    "your account will be", "confirm your identity",
    "unusual activity detected", "security alert",
    "update your information immediately",
]

# Brands that should NOT be on a page that isn't their own domain
BRAND_KEYWORDS = [
    "paypal", "amazon", "apple", "microsoft",
    "facebook", "instagram", "netflix", "bank of america",
    "chase bank", "wells fargo", "citibank",
]

# Domains that legitimately mention their own brand — don't flag impersonation
BRAND_OWN_DOMAINS = {
    "paypal.com", "amazon.com", "apple.com", "microsoft.com",
    "facebook.com", "instagram.com", "netflix.com",
}


def analyze_content(html: str, base_url: str) -> dict:
    features = {}
    soup     = BeautifulSoup(html, "html.parser")

    # ── Forms & password fields ─────────────────────────────────
    forms           = soup.find_all("form")
    password_fields = soup.find_all("input", {"type": "password"})
    features["form_count"]           = len(forms)
    features["password_field_count"] = len(password_fields)
    features["has_login_form"]       = len(password_fields) > 0

    # ── Hidden elements — only count deeply hidden ones ─────────
    # Legitimate sites use display:none for menus/modals — cap contribution
    hidden = soup.find_all(
        style=re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden")
    )
    # Cap at 5 so large sites don't get over-penalised
    features["hidden_element_count"] = min(len(hidden), 5)

    # ── External scripts — capped, legitimate sites load many ───
    ext_scripts = [
        s["src"] for s in soup.find_all("script", src=True)
        if s.get("src", "").startswith("http")
    ]
    # Cap at 3 to prevent over-scoring legitimate CDN-heavy sites
    features["external_script_count"] = min(len(ext_scripts), 3)

    # ── Iframes ─────────────────────────────────────────────────
    iframes = soup.find_all("iframe")
    features["iframe_count"] = len(iframes)
    features["has_iframe"]   = len(iframes) > 0

    # ── Inline JS analysis ──────────────────────────────────────
    inline_js = " ".join(s.get_text() for s in soup.find_all("script", src=False))

    # JS redirect: only flag aggressive patterns, not normal navigation
    # window.location.href = "..." used by legit sites for nav — ignore simple assigns
    features["has_js_redirect"] = bool(
        re.search(
            r"window\.location\s*=\s*[\"']http|"
            r"document\.location\s*=\s*[\"']http|"
            r"location\.replace\s*\([\"']http",
            inline_js
        )
    )

    # Obfuscated JS — strong signal, keep as-is
    features["has_obfuscated_js"] = bool(
        re.search(r"eval\s*\(|unescape\s*\(|String\.fromCharCode", inline_js)
    )

    # ── Favicon (external from a different domain) ───────────────
    favicons = soup.find_all("link", rel=lambda r: r and "icon" in r)
    if favicons:
        href = favicons[0].get("href", "")
        features["favicon_is_external"] = (
            href.startswith("http") and base_url not in href
        )
    else:
        features["favicon_is_external"] = False

    # ── Urgency / phishing language ─────────────────────────────
    text          = soup.get_text(separator=" ").lower()
    found_urgency = [p for p in URGENCY_PHRASES if p in text]
    features["urgency_word_count"] = len(found_urgency)
    features["urgency_words"]      = found_urgency

    # ── Brand impersonation ──────────────────────────────────────
    # Only flag if a brand name appears BUT the URL is not the brand's own domain
    from urllib.parse import urlparse
    parsed_host = urlparse(base_url).hostname or ""
    is_own_domain = any(own in parsed_host for own in BRAND_OWN_DOMAINS)

    if not is_own_domain:
        features["brand_impersonation"] = any(b in text for b in BRAND_KEYWORDS)
    else:
        features["brand_impersonation"] = False

    return features

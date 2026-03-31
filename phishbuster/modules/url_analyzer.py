import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "bank", "confirm", "password", "signin", "webscr",
    "free", "lucky", "service", "ebayisapi", "authenticate",
    "paypal", "suspended", "unusual", "validate", "recover"
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "rb.gy", "shorturl.at", "is.gd", "buff.ly", "adf.ly"
]


def analyze_url(url: str) -> dict:
    parsed   = urlparse(url)
    hostname = parsed.hostname or ""
    path     = parsed.path or ""
    full     = url.lower()

    features = {}
    features["url_length"]               = len(url)
    features["is_long_url"]              = len(url) > 75
    features["has_ip_address"]           = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname))
    features["uses_https"]               = parsed.scheme == "https"
    features["has_at_symbol"]            = "@" in url
    features["hyphen_count"]             = hostname.count("-")
    features["dot_count"]                = hostname.count(".")
    features["subdomain_count"]          = max(0, hostname.count(".") - 1)
    features["suspicious_keyword_count"] = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in full)
    features["suspicious_keywords"]      = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full]
    features["is_shortened"]             = any(s in hostname for s in URL_SHORTENERS)
    features["has_double_slash"]         = "//" in path
    features["has_hex_encoding"]         = bool(re.search(r"%[0-9a-fA-F]{2}", url))
    features["has_port"]                 = bool(parsed.port)
    features["path_length"]              = len(path)
    features["query_length"]             = len(parsed.query or "")

    return features

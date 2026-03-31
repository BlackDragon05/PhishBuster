import requests

TIMEOUT = 5


def check_blacklists(url: str) -> dict:
    results = {
        "google_safe_browsing":  False,
        "phishtank_is_phishing": False,
        "blacklisted":           False,
    }

    # ── PhishTank (free, no key required for basic lookup) ────
    try:
        r = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={"url": url, "format": "json"},
            timeout=TIMEOUT,
            headers={"User-Agent": "PhishBuster/1.0"}
        )
        if r.status_code == 200:
            data     = r.json()
            in_db    = data.get("results", {}).get("in_database", False)
            verified = data.get("results", {}).get("verified", False)
            results["phishtank_is_phishing"] = bool(in_db and verified)
    except Exception:
        pass  # API down or timeout — skip silently

    results["blacklisted"] = results["phishtank_is_phishing"]
    return results

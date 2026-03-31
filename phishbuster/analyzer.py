import asyncio
from phishbuster.modules.url_analyzer      import analyze_url
from phishbuster.modules.domain_analyzer   import analyze_domain
from phishbuster.modules.content_analyzer  import analyze_content
from phishbuster.modules.blacklist_checker import check_blacklists
from phishbuster.modules.ml_predictor      import predict_phishing
from phishbuster.scoring.risk_engine       import compute_score
from phishbuster.utils.safe_fetch          import safe_fetch
from urllib.parse import urlparse


def _normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


async def analyze_url_full(
    url: str,
    fetch_content: bool = True,
    use_ml: bool = True,
    timeout: int = 10
) -> dict:
    url      = _normalize_url(url)
    parsed   = urlparse(url)
    hostname = parsed.hostname or ""

    features = {}

    # Run URL analysis, domain analysis, and blacklist check concurrently
    url_feats, domain_feats, blacklist_feats = await asyncio.gather(
        asyncio.to_thread(analyze_url, url),
        asyncio.to_thread(analyze_domain, hostname),
        asyncio.to_thread(check_blacklists, url),
    )

    features.update(url_feats)
    features.update(domain_feats)
    features.update(blacklist_feats)

    # Content analysis (optional — requires HTTP fetch)
    if fetch_content:
        html = await safe_fetch(url, timeout=timeout)
        if html:
            content_feats = analyze_content(html, url)
            features.update(content_feats)

    # ML prediction
    if use_ml:
        features["ml_phishing_probability"] = predict_phishing(features)

    # Score
    result = compute_score(features)
    result["url"]      = url
    result["features"] = features

    return result

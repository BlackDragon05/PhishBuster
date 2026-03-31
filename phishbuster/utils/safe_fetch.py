import httpx

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

MAX_CONTENT_BYTES = 5 * 1024 * 1024  # 5 MB limit — don't download huge pages


async def safe_fetch(url: str, timeout: int = 10) -> str | None:
    """
    Fetches a URL safely:
    - Follows redirects
    - Enforces timeout
    - Does NOT execute JavaScript
    - Caps response size at 5 MB
    - Returns raw HTML string or None on failure
    """
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=timeout,
            headers=HEADERS,
            verify=False,            # allow self-signed certs (analysis only)
            max_redirects=5
        ) as client:
            async with client.stream("GET", url) as r:
                if r.status_code != 200:
                    return None
                content_type = r.headers.get("content-type", "")
                if "text/html" not in content_type and "text/plain" not in content_type:
                    return None

                chunks = []
                total  = 0
                async for chunk in r.aiter_bytes(chunk_size=8192):
                    total += len(chunk)
                    if total > MAX_CONTENT_BYTES:
                        break
                    chunks.append(chunk)

                raw = b"".join(chunks)
                return raw.decode("utf-8", errors="replace")

    except Exception:
        return None

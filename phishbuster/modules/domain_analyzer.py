import whois
import ssl
import socket
from datetime import datetime, timezone

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# Well-known domains — skip WHOIS entirely, never flag as newly registered
TRUSTED_DOMAINS = {
    "google.com", "github.com", "wikipedia.org", "youtube.com",
    "facebook.com", "twitter.com", "x.com", "amazon.com",
    "microsoft.com", "apple.com", "linkedin.com", "reddit.com",
    "instagram.com", "netflix.com", "stackoverflow.com",
    "cloudflare.com", "yahoo.com", "bing.com", "live.com",
    "outlook.com", "office.com", "adobe.com", "dropbox.com",
}


def analyze_domain(hostname: str) -> dict:
    features = {}

    if not hostname:
        features["domain_is_new"]   = False
        features["ssl_valid"]       = False
        features["dns_resolves"]    = False
        features["ip_count"]        = 0
        features["domain_age_days"] = None
        features["registrar"]       = "unknown"
        return features

    # WHOIS
    if hostname in TRUSTED_DOMAINS:
        features["domain_age_days"] = 9999
        features["domain_is_new"]   = False
        features["registrar"]       = "trusted-domain"
    else:
        try:
            w       = whois.whois(hostname)
            created = w.creation_date
            if isinstance(created, list):
                created = created[0]

            if created:
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - created).days
            else:
                age_days = None

            features["domain_age_days"] = age_days
            features["domain_is_new"]   = (age_days is not None and age_days < 30)
            features["registrar"]       = str(w.registrar)[:50] if w.registrar else "unknown"
        except Exception:
            # WHOIS timeout — do NOT treat as new domain (was causing false positives)
            features["domain_age_days"] = None
            features["domain_is_new"]   = False
            features["registrar"]       = "unknown"

    # SSL
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
        features["ssl_valid"] = True
    except Exception:
        features["ssl_valid"] = False

    # DNS
    if DNS_AVAILABLE:
        try:
            answers = dns.resolver.resolve(hostname, "A")
            features["dns_resolves"] = True
            features["ip_count"]     = len(list(answers))
        except Exception:
            features["dns_resolves"] = False
            features["ip_count"]     = 0
    else:
        try:
            socket.gethostbyname(hostname)
            features["dns_resolves"] = True
            features["ip_count"]     = 1
        except Exception:
            features["dns_resolves"] = False
            features["ip_count"]     = 0

    return features

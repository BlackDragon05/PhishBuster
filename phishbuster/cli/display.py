from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich import box
from datetime import datetime

console = Console()

VERDICT_STYLE = {
    "Safe":       ("green",  "✅ SAFE",       "bright_green"),
    "Suspicious": ("yellow", "⚠️  SUSPICIOUS", "yellow"),
    "Phishing":   ("red",    "🚨 PHISHING",   "bright_red"),
}


def print_banner():
    banner = Text()
    banner.append("\n")
    banner.append("  ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗\n", style="bold bright_red")
    banner.append("  ██╔══██╗██║  ██║██║██╔════╝██║  ██║\n", style="bold red")
    banner.append("  ██████╔╝███████║██║███████╗███████║\n",  style="bold yellow")
    banner.append("  ██╔═══╝ ██╔══██║██║╚════██║██╔══██║\n", style="bold yellow")
    banner.append("  ██║     ██║  ██║██║███████║██║  ██║\n", style="bold green")
    banner.append("  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝\n", style="bold bright_green")
    banner.append("\n")
    banner.append("  ██████╗ ██╗   ██╗███████╗████████╗███████╗██████╗ \n",  style="bold cyan")
    banner.append("  ██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗\n", style="bold cyan")
    banner.append("  ██████╔╝██║   ██║███████╗   ██║   █████╗  ██████╔╝\n", style="bold bright_cyan")
    banner.append("  ██╔══██╗██║   ██║╚════██║   ██║   ██╔══╝  ██╔══██╗\n", style="bold bright_cyan")
    banner.append("  ██████╔╝╚██████╔╝███████║   ██║   ███████╗██║  ██║\n", style="bold blue")
    banner.append("  ╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝\n", style="bold blue")
    banner.append("\n")
    banner.append("  Phishing Website Detection Tool", style="bold white")
    banner.append("  v1.0.0\n", style="dim white")
    banner.append("  Developed by: ", style="dim white")
    banner.append("Anand", style="bold cyan")
    banner.append(" & ", style="dim white")
    banner.append("Vikrant Yadav\n", style="bold cyan")
    banner.append("  GitHub: ", style="dim white")
    banner.append("github.com/BlackDragon05/PhishBuster\n", style="dim cyan")
    banner.append("  ─────────────────────────────────────────────\n", style="dim")
    banner.append(f"  Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", style="dim")

    console.print(banner)


def print_result(result: dict, compact: bool = False):
    verdict  = result.get("verdict", "Suspicious")
    score    = result.get("score", 0)
    url      = result.get("url", "")
    triggered= result.get("triggered", [])
    features = result.get("features", {})
    color, label, rich_color = VERDICT_STYLE.get(verdict, VERDICT_STYLE["Suspicious"])

    if compact:
        bar   = _score_bar(score, color)
        console.print(f"  [{rich_color}]{label}[/{rich_color}]  Score: [{color}]{score}/10[/{color}]  {bar}")
        return

    console.print()

    # ── Verdict Panel ─────────────────────────────────────────
    verdict_text = Text(justify="center")
    verdict_text.append(f"\n  {label}\n", style=f"bold {rich_color}")
    verdict_text.append(f"\n  Risk Score: ", style="white")
    verdict_text.append(f"{score} / 10  ", style=f"bold {rich_color}")
    verdict_text.append(_score_bar(score, color))
    verdict_text.append(f"\n\n  {url}\n", style="dim cyan")

    console.print(Panel(
        verdict_text,
        title="[bold white]PhishBuster Result[/bold white]",
        border_style=rich_color,
        box=box.DOUBLE_EDGE,
        padding=(0, 2)
    ))

    # ── Feature Table ──────────────────────────────────────────
    table = Table(
        title="Detection Details",
        box=box.SIMPLE_HEAD,
        header_style="bold white",
        show_lines=False,
        padding=(0, 1)
    )
    table.add_column("Module",   style="dim",         width=20)
    table.add_column("Check",    style="white",        width=30)
    table.add_column("Value",    justify="right",      width=16)
    table.add_column("Status",   justify="center",     width=10)

    f = features

    def row(module, check, val, risky: bool | None = None):
        if risky is True:
            status = "[red]⚠ Risk[/red]"
        elif risky is False:
            status = "[green]✓ OK[/green]"
        else:
            status = "[dim]—[/dim]"
        table.add_row(module, check, str(val), status)

    # URL
    row("URL",    "Length",            f.get("url_length", "—"),        f.get("is_long_url", False))
    row("URL",    "HTTPS",             "Yes" if f.get("uses_https") else "No", not f.get("uses_https", True))
    row("URL",    "Has IP address",    "Yes" if f.get("has_ip_address") else "No", f.get("has_ip_address", False))
    row("URL",    "@ symbol",          "Yes" if f.get("has_at_symbol")  else "No", f.get("has_at_symbol", False))
    row("URL",    "Subdomains",        f.get("subdomain_count", 0),     f.get("subdomain_count", 0) > 2)
    row("URL",    "Suspicious keywords",f.get("suspicious_keyword_count", 0), f.get("suspicious_keyword_count", 0) > 0)
    row("URL",    "URL shortener",     "Yes" if f.get("is_shortened")   else "No", f.get("is_shortened", False))
    row("URL",    "Hex encoding",      "Yes" if f.get("has_hex_encoding") else "No", f.get("has_hex_encoding", False))

    # Domain
    age = f.get("domain_age_days")
    row("Domain", "Age (days)",        age if age is not None else "Unknown", f.get("domain_is_new", False))
    row("Domain", "SSL valid",         "Yes" if f.get("ssl_valid") else "No",  not f.get("ssl_valid", True))
    row("Domain", "DNS resolves",      "Yes" if f.get("dns_resolves") else "No", not f.get("dns_resolves", True))
    row("Domain", "Registrar",         str(f.get("registrar", "Unknown"))[:28], None)

    # Content
    if "form_count" in f:
        row("Content", "Login form",      "Yes" if f.get("has_login_form") else "No", f.get("has_login_form", False))
        row("Content", "Hidden elements", f.get("hidden_element_count", 0),  f.get("hidden_element_count", 0) > 3)
        row("Content", "External scripts",f.get("external_script_count", 0), f.get("external_script_count", 0) > 5)
        row("Content", "Iframes",         f.get("iframe_count", 0),          f.get("has_iframe", False))
        row("Content", "JS redirect",     "Yes" if f.get("has_js_redirect") else "No", f.get("has_js_redirect", False))
        row("Content", "Obfuscated JS",   "Yes" if f.get("has_obfuscated_js") else "No", f.get("has_obfuscated_js", False))
        row("Content", "Urgency language",f.get("urgency_word_count", 0),    f.get("urgency_word_count", 0) > 0)
        row("Content", "External favicon","Yes" if f.get("favicon_is_external") else "No", f.get("favicon_is_external", False))

    # Blacklist
    row("Blacklist", "PhishTank",       "HIT" if f.get("phishtank_is_phishing") else "Clean",
        f.get("phishtank_is_phishing", False))
    row("Blacklist", "Blacklisted",     "Yes" if f.get("blacklisted") else "No",
        f.get("blacklisted", False))

    # ML
    ml_prob = f.get("ml_phishing_probability")
    if ml_prob is not None:
        row("ML Model", "Phishing probability", f"{ml_prob:.1%}", ml_prob > 0.5)

    console.print(table)

    # ── Triggered Rules ────────────────────────────────────────
    if triggered:
        console.print(Panel(
            "\n".join(f"  [red]•[/red] {t}" for t in triggered),
            title="[bold red]Triggered Rules[/bold red]",
            border_style="red",
            box=box.ROUNDED,
            padding=(0, 1)
        ))

    # ── Keywords ───────────────────────────────────────────────
    kw = f.get("suspicious_keywords", [])
    if kw:
        console.print(f"\n  [yellow]Suspicious keywords found:[/yellow] {', '.join(kw)}")

    uw = f.get("urgency_words", [])
    if uw:
        console.print(f"  [yellow]Urgency phrases found:[/yellow] {', '.join(uw)}")

    console.print()


def print_batch_summary(results: list):
    safe       = sum(1 for r in results if r.get("verdict") == "Safe")
    suspicious = sum(1 for r in results if r.get("verdict") == "Suspicious")
    phishing   = sum(1 for r in results if r.get("verdict") == "Phishing")

    summary = Table(
        title="Batch Scan Summary",
        box=box.DOUBLE_EDGE,
        header_style="bold white",
        padding=(0, 2)
    )
    summary.add_column("Verdict",  style="bold", width=14)
    summary.add_column("Count",    justify="center", width=10)
    summary.add_column("URLs",     width=40)

    safe_urls = [r["url"] for r in results if r.get("verdict") == "Safe"]
    susp_urls = [r["url"] for r in results if r.get("verdict") == "Suspicious"]
    phsh_urls = [r["url"] for r in results if r.get("verdict") == "Phishing"]

    summary.add_row("[green]✅ Safe[/green]",       str(safe),       "\n".join(safe_urls[:3]) + ("..." if len(safe_urls) > 3 else ""))
    summary.add_row("[yellow]⚠ Suspicious[/yellow]",str(suspicious), "\n".join(susp_urls[:3]) + ("..." if len(susp_urls) > 3 else ""))
    summary.add_row("[red]🚨 Phishing[/red]",       str(phishing),   "\n".join(phsh_urls[:3]) + ("..." if len(phsh_urls) > 3 else ""))

    console.print()
    console.print(summary)
    console.print(f"\n  Total scanned: [white bold]{len(results)}[/white bold] URLs\n")


def _score_bar(score: float, color: str) -> str:
    filled = int(score)
    empty  = 10 - filled
    return f"[{color}]{'█' * filled}[/{color}][dim]{'░' * empty}[/dim]"

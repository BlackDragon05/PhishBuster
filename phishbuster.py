#!/usr/bin/env python3
"""
██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██████╗ ██╗   ██╗███████╗████████╗███████╗██████╗
██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗
██████╔╝███████║██║███████╗███████║██████╔╝██║   ██║███████╗   ██║   █████╗  ██████╔╝
██╔═══╝ ██╔══██║██║╚════██║██╔══██║██╔══██╗██║   ██║╚════██║   ██║   ██╔══╝  ██╔══██╗
██║     ██║  ██║██║███████║██║  ██║██████╔╝╚██████╔╝███████║   ██║   ███████╗██║  ██║
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

PhishBuster v1.0 — Phishing Website Detection Tool
Developed by: Anand (BlackDragon05) & Vikrant Yadav
GitHub: https://github.com/BlackDragon05/PhishBuster
"""

import sys
import asyncio
import argparse
import json
from datetime import datetime

from phishbuster.cli.display import (
    print_banner,
    print_result,
    print_batch_summary,
    console
)
from phishbuster.analyzer import analyze_url_full


def parse_args():
    parser = argparse.ArgumentParser(
        prog="phishbuster",
        description="PhishBuster — Phishing Website Detection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python phishbuster.py -u https://example.com
  python phishbuster.py -u http://suspicious-login.xyz --json
  python phishbuster.py -f urls.txt --output results.json
  python phishbuster.py -u https://site.com --no-content
        """
    )

    parser.add_argument(
        "-u", "--url",
        help="Single URL to analyze"
    )
    parser.add_argument(
        "-f", "--file",
        help="Text file with one URL per line (batch mode)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON instead of formatted display"
    )
    parser.add_argument(
        "--output",
        help="Save results to a JSON file"
    )
    parser.add_argument(
        "--no-content",
        action="store_true",
        help="Skip webpage content analysis (faster)"
    )
    parser.add_argument(
        "--no-ml",
        action="store_true",
        help="Skip ML model prediction"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP timeout in seconds (default: 10)"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="PhishBuster v1.0.0"
    )

    return parser.parse_args()


async def run_single(url: str, args) -> dict:
    result = await analyze_url_full(
        url,
        fetch_content=not args.no_content,
        use_ml=not args.no_ml,
        timeout=args.timeout
    )
    return result


async def run_batch(filepath: str, args) -> list:
    try:
        with open(filepath, "r") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        console.print(f"[red]Error:[/red] File not found: {filepath}")
        sys.exit(1)

    if not urls:
        console.print("[yellow]Warning:[/yellow] No URLs found in file.")
        sys.exit(0)

    console.print(f"\n[bold]Found [cyan]{len(urls)}[/cyan] URLs to analyze...[/bold]\n")
    results = []

    for i, url in enumerate(urls, 1):
        console.print(f"[dim]({i}/{len(urls)})[/dim] Analyzing: [cyan]{url}[/cyan]")
        result = await analyze_url_full(
            url,
            fetch_content=not args.no_content,
            use_ml=not args.no_ml,
            timeout=args.timeout
        )
        results.append(result)
        print_result(result, compact=True)

    return results


async def main():
    args = parse_args()

    # No args — show help
    if not args.url and not args.file:
        print_banner()
        console.print("[yellow]Usage:[/yellow] python phishbuster.py -u <URL>  or  -f <file.txt>\n")
        console.print("Run [cyan]python phishbuster.py --help[/cyan] for full options.\n")
        sys.exit(0)

    print_banner()

    # --- Single URL ---
    if args.url:
        result = await run_single(args.url, args)

        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            print_result(result)

        if args.output:
            with open(args.output, "w") as f:
                json.dump(result, f, indent=2, default=str)
            console.print(f"\n[green]✓[/green] Result saved to [cyan]{args.output}[/cyan]")

        # Exit code based on verdict
        exit_codes = {"Safe": 0, "Suspicious": 1, "Phishing": 2}
        sys.exit(exit_codes.get(result.get("verdict", "Suspicious"), 1))

    # --- Batch mode ---
    if args.file:
        results = await run_batch(args.file, args)
        print_batch_summary(results)

        if args.output:
            output = {
                "scan_time": datetime.now().isoformat(),
                "total":     len(results),
                "results":   results
            }
            with open(args.output, "w") as f:
                json.dump(output, f, indent=2, default=str)
            console.print(f"\n[green]✓[/green] All results saved to [cyan]{args.output}[/cyan]")


if __name__ == "__main__":
    asyncio.run(main())

"""Command-line interface for WAYBACKRECON."""
from __future__ import annotations

import argparse
import html
import json
import sys
from typing import Sequence

from . import TOOL_NAME, TOOL_VERSION
from .core import ReconResult, analyze, severity_rank, SEVERITY_ORDER

_SEV_COLORS = {
    "critical": "#7c1f1f",
    "high": "#b3261e",
    "medium": "#c77700",
    "low": "#2f6f3e",
    "info": "#3a5a8c",
}


def _read_input(path: str) -> list[str]:
    if path == "-":
        return sys.stdin.read().splitlines()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read().splitlines()


def _render_table(result: ReconResult) -> str:
    out: list[str] = []
    s = result.severity_counts()
    out.append(f"WAYBACKRECON {TOOL_VERSION}")
    out.append("=" * 60)
    out.append(f"URLs scanned : {result.total_urls}  (unique: {result.unique_urls})")
    out.append(f"Hosts        : {len(result.hosts)}  Params: {len(result.params)}")
    if result.extensions:
        top = ", ".join(f"{k}:{v}" for k, v in list(result.extensions.items())[:8])
        out.append(f"Extensions   : {top}")
    out.append(
        "Severity     : "
        + "  ".join(f"{name}={s[name]}" for name in reversed(SEVERITY_ORDER))
    )
    out.append("-" * 60)
    if not result.findings:
        out.append("No findings.")
    else:
        out.append(f"{'SEVERITY':<9} {'CATEGORY':<18} URL")
        for f in result.findings:
            url = f.url if len(f.url) <= 90 else f.url[:87] + "..."
            out.append(f"{f.severity:<9} {f.category:<18} {url}")
    if result.errors:
        out.append("-" * 60)
        out.append(f"Errors: {len(result.errors)}")
        for e in result.errors[:10]:
            out.append(f"  ! {e}")
    return "\n".join(out)


def _render_html(result: ReconResult) -> str:
    s = result.severity_counts()
    esc = html.escape
    rows = []
    for f in result.findings:
        color = _SEV_COLORS.get(f.severity, "#555")
        rows.append(
            "<tr>"
            f'<td><span class="sev" style="background:{color}">{esc(f.severity)}</span></td>'
            f"<td>{esc(f.category)}</td>"
            f'<td class="url">{esc(f.url)}</td>'
            f"<td>{esc(f.detail)}</td>"
            f"<td>{esc(f.timestamp)}</td>"
            "</tr>"
        )
    findings_rows = "\n".join(rows) or '<tr><td colspan="5">No findings.</td></tr>'

    sev_cards = "".join(
        f'<div class="card" style="border-top:4px solid {_SEV_COLORS[name]}">'
        f'<div class="num">{s[name]}</div><div class="lbl">{name}</div></div>'
        for name in reversed(SEVERITY_ORDER)
    )
    ext_rows = "".join(
        f"<tr><td>{esc(k)}</td><td>{v}</td></tr>" for k, v in list(result.extensions.items())[:15]
    ) or '<tr><td colspan="2">none</td></tr>'

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{TOOL_NAME} report</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; background:#0f1419; color:#e6e6e6; }}
  header {{ background:#1a2230; padding:20px 28px; border-bottom:1px solid #2a3344; }}
  h1 {{ margin:0; font-size:20px; letter-spacing:1px; }}
  .meta {{ color:#8aa; font-size:13px; margin-top:4px; }}
  .wrap {{ padding:24px 28px; }}
  .cards {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:24px; }}
  .card {{ background:#1a2230; border-radius:8px; padding:14px 20px; min-width:80px; text-align:center; }}
  .card .num {{ font-size:26px; font-weight:700; }}
  .card .lbl {{ font-size:12px; text-transform:uppercase; color:#8aa; }}
  table {{ border-collapse:collapse; width:100%; background:#1a2230; border-radius:8px; overflow:hidden; margin-bottom:24px; }}
  th, td {{ text-align:left; padding:9px 12px; border-bottom:1px solid #2a3344; font-size:13px; vertical-align:top; }}
  th {{ background:#222d3d; text-transform:uppercase; font-size:11px; letter-spacing:.5px; color:#9ab; }}
  td.url {{ font-family:ui-monospace, Menlo, monospace; word-break:break-all; max-width:520px; }}
  .sev {{ color:#fff; padding:2px 8px; border-radius:10px; font-size:11px; text-transform:uppercase; font-weight:600; }}
  h2 {{ font-size:15px; color:#9ab; margin:24px 0 10px; }}
  .small {{ width:auto; max-width:320px; }}
</style></head>
<body>
<header>
  <h1>{TOOL_NAME.upper()} &mdash; historical attack surface</h1>
  <div class="meta">v{TOOL_VERSION} &bull; {result.total_urls} URLs scanned ({result.unique_urls} unique) &bull;
    {len(result.hosts)} hosts &bull; {len(result.params)} params &bull; {len(result.findings)} findings</div>
</header>
<div class="wrap">
  <div class="cards">{sev_cards}</div>
  <h2>Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Category</th><th>URL</th><th>Detail</th><th>Timestamp</th></tr></thead>
    <tbody>
{findings_rows}
    </tbody>
  </table>
  <h2>Top extensions</h2>
  <table class="small"><thead><tr><th>Ext</th><th>Count</th></tr></thead><tbody>{ext_rows}</tbody></table>
</div>
</body></html>"""


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Mine archived URLs/params/endpoints from a Wayback/CDX export (defensive triage).",
    )
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Analyze a CDX/URL-list file for attack surface")
    scan.add_argument("input", help="Path to CDX export or URL list ('-' for stdin)")
    scan.add_argument("--format", choices=["table", "json", "html"], default="table")
    scan.add_argument("--min-severity", choices=SEVERITY_ORDER, default="info",
                      help="Only report findings at or above this severity")
    scan.add_argument("-o", "--output", help="Write report to file instead of stdout")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 2

    try:
        lines = _read_input(args.input)
    except OSError as exc:
        print(f"error: cannot read input: {exc}", file=sys.stderr)
        return 2

    result = analyze(lines, min_severity=args.min_severity)

    if args.format == "json":
        report = json.dumps(result.as_dict(), indent=2)
    elif args.format == "html":
        report = _render_html(result)
    else:
        report = _render_table(result)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(report)
            print(f"wrote {args.format} report to {args.output}", file=sys.stderr)
        except OSError as exc:
            print(f"error: cannot write output: {exc}", file=sys.stderr)
            return 2
    else:
        print(report)

    # Non-zero exit when actionable findings exist or parse errors occurred.
    if result.errors:
        return 2
    if any(severity_rank(f.severity) >= severity_rank("medium") for f in result.findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Command-line interface; all inputs are local and all outputs deterministic."""

from __future__ import annotations

import argparse
import sqlite3
import sys
from datetime import date, timedelta

from .backtest import run_backtest
from .ingest import parse_findings_csv
from .insights import compute_insights
from .models import BacktestConfig, VulnprioError
from .report import (build_analysis_report, render_analysis_html, render_analysis_markdown,
                     render_triage_csv, render_triage_markdown, to_json)
from .storage import build_database, connect
from .triage import run_triage


def _date(value):
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid date: {value} (expected YYYY-MM-DD)") from None


def _parser():
    parser = argparse.ArgumentParser(prog="vulnprio", description="Offline vulnerability prioritization analytics")
    parser.add_argument("--version", action="store_true")
    commands = parser.add_subparsers(dest="command")
    build = commands.add_parser("build", help="build a SQLite database from local feeds")
    build.add_argument("--db", required=True)
    build.add_argument("--nvd", nargs="+", required=True)
    build.add_argument("--kev", required=True)
    build.add_argument("--epss", nargs="+", required=True)
    build.add_argument("--force", action="store_true")
    build.add_argument("--output")
    analyze = commands.add_parser("analyze", help="backtest prioritization strategies")
    analyze.add_argument("--db", required=True)
    analyze.add_argument("--date", type=_date, action="append")
    analyze.add_argument("--lookback-days", type=int, default=730)
    analyze.add_argument("--horizon-days", type=int, default=365)
    analyze.add_argument("--epss-threshold", type=float, default=0.1)
    analyze.add_argument("--bootstrap", type=int, default=1000)
    analyze.add_argument("--seed", type=int, default=42)
    analyze.add_argument("--confidence", type=float, default=0.95)
    analyze.add_argument("--format", choices=("json", "markdown", "html"), default="json")
    analyze.add_argument("--output")
    triage = commands.add_parser("triage", help="prioritize an organization's findings")
    triage.add_argument("--db", required=True)
    triage.add_argument("--findings", required=True)
    triage.add_argument("--as-of", type=_date)
    triage.add_argument("--format", choices=("csv", "json", "markdown"), default="csv")
    triage.add_argument("--output")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 2)
    if args.version:
        print("vulnpriority-analytics 1.0.0")
        return 0
    if args.command is None:
        parser.print_help(sys.stderr)
        return 2
    conn = None
    try:
        if args.command == "build":
            rendered = to_json(build_database(args.db, args.nvd, args.kev, args.epss, force=args.force))
        elif args.command == "analyze":
            if args.lookback_days < 1:
                raise VulnprioError("--lookback-days must be >= 1")
            if args.horizon_days < 1:
                raise VulnprioError("--horizon-days must be >= 1")
            if not 0 < args.epss_threshold <= 1:
                raise VulnprioError("--epss-threshold must be > 0 and <= 1")
            if args.bootstrap < 1:
                raise VulnprioError("--bootstrap must be >= 1")
            if not 0 < args.confidence < 1:
                raise VulnprioError("--confidence must be > 0 and < 1")
            config = BacktestConfig(args.lookback_days, args.horizon_days, args.epss_threshold,
                                    args.bootstrap, args.seed, args.confidence)
            conn = connect(args.db)
            backtest = run_backtest(conn, args.date, config)
            decisions = [date.fromisoformat(d) for d in backtest["decision_dates"]]
            insights = compute_insights(conn, min(decisions), max(decisions) + timedelta(days=args.horizon_days))
            report = build_analysis_report(conn, backtest, insights)
            rendered = {"json": to_json, "markdown": render_analysis_markdown,
                        "html": render_analysis_html}[args.format](report)
        else:
            conn = connect(args.db)
            findings, skipped = parse_findings_csv(args.findings)
            result = run_triage(conn, findings, args.as_of, rows_skipped=skipped)
            rendered = {"csv": render_triage_csv, "json": to_json,
                        "markdown": render_triage_markdown}[args.format](result)
        if args.output:
            with open(args.output, "w", encoding="utf-8", newline="") as fh:
                fh.write(rendered)
        else:
            sys.stdout.write(rendered)
        return 0
    except (VulnprioError, OSError, sqlite3.Error, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        if conn is not None:
            conn.close()

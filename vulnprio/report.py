"""Deterministic text reports and accessible, self-contained HTML charts."""

from __future__ import annotations

import csv
import html
import io
import json

from .models import REASON_TEXT, TIERS
from .storage import load_summary

_LIMITATIONS = (
    "CVSS scores reflect the download date and may include later revisions.",
    "KEV is an incomplete, US-government-centred record of known exploitation; addition dates are not first exploitation dates.",
    "The population is limited to the lookback window and CVEs with both CVSS and EPSS data.",
    "CVSS ranking ties use an arbitrary but deterministic CVE identifier order.",
)


def to_json(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def build_analysis_report(conn, backtest, insights) -> dict:
    return {"schema_version": 1, "tool": "vulnpriority-analytics", "version": "1.0.0",
            "data": load_summary(conn), "backtest": backtest, "insights": insights}


def _pct(value):
    return "n/a" if value is None else f"{value * 100:.2f}%"


def _lift(value):
    return "n/a" if value is None else f"{value:.2f}x"


def _text(value):
    return "n/a" if value is None else str(value)


def _md(value):
    return _text(value).replace("|", "\\|")


def _escape(value):
    return html.escape(_text(value))


def _sections(report):
    """Shared report content keeps the Markdown and HTML tables consistent."""
    data, bt, insights = report["data"], report["backtest"], report["insights"]
    data_rows = [(key, data[key]) for key in (
        "cves", "cves_rejected", "cves_without_cvss", "nvd_files", "nvd_items_skipped",
        "nvd_duplicates", "kev_entries", "kev_rows_skipped", "kev_as_of")]
    config = bt["config"]
    sections = [("Data", [
        ("table", ("Measure", "Value"), data_rows),
        ("table", ("EPSS snapshot", "Model version", "Rows", "Rows skipped"),
         [(s["snapshot_date"], s["model_version"], s["rows"], s["rows_skipped"]) for s in data["epss_snapshots"]]),
        ("p", f"Lookback: {config['lookback_days']} days; outcome horizon: {config['horizon_days']} days; "
         f"EPSS threshold: {_pct(config['epss_threshold'])}."),
    ])]
    pooled = bt["pooled"]
    sections.append(("Pooled results", [
        ("p", f"Population instances: {pooled['population']}; positives: {pooled['positives']}; "
         f"base rate: {_pct(pooled['base_rate'])}."),
        ("table", ("Strategy", "Flagged", "Effort", "Coverage", "Efficiency", "Lift"),
         [(m["strategy"], m["flagged"], _pct(m["effort"]), _pct(m["coverage"]),
           _pct(m["efficiency"]), _lift(m["lift"])) for m in pooled["strategies"]]),
    ]))
    bootstrap = bt["bootstrap"]
    if bootstrap is None:
        statistical = "Not enough positives for a bootstrap."
    else:
        statistical = (
            f"EPSS_EFFORT_MATCHED versus CVSS_CRITICAL: coverage difference "
            f"{_pct(bootstrap['point_estimate'])}; {_pct(bootstrap['confidence'])} confidence interval "
            f"[{_pct(bootstrap['ci_low'])}, {_pct(bootstrap['ci_high'])}]. "
            f"Paired bootstrap with {bootstrap['positives']} positive instances and "
            f"{bootstrap['iterations']} iterations (seed {bootstrap['seed']}); "
            f"significant: {'yes' if bootstrap['significant'] else 'no'}."
        )
    sections.append(("Statistical comparison", [("p", statistical)]))
    date_blocks = [("table", ("Decision date", "Window end", "N", "P", "Base rate", "No CVSS", "No EPSS",
                              "Known exploited", "Positives without CVSS"),
                    [(d["decision_date"], d["window_end"], d["population"], d["positives"], _pct(d["base_rate"]),
                      d["excluded_no_cvss"], d["excluded_no_epss"], d["excluded_known_exploited"],
                      d["positives_without_cvss"]) for d in bt["per_date"]])]
    for d in bt["per_date"]:
        date_blocks.extend([
            ("h3", d["decision_date"]),
            ("p", f"EPSS model: {_text(d['epss_model_version'])}."),
            ("table", ("Strategy", "Flagged", "Effort", "Coverage", "Efficiency", "Lift"),
             [(m["strategy"], m["flagged"], _pct(m["effort"]), _pct(m["coverage"]),
               _pct(m["efficiency"]), _lift(m["lift"])) for m in d["strategies"]]),
        ])
    sections.append(("Per decision date", date_blocks))
    curve = bt["effort_curve"]
    sections.append(("Effort curve", [
        ("p", "Coverage at each effort level, pooling positive counts across decision dates."),
        ("table", ("Effort", "EPSS coverage", "CVSS coverage"),
         [(f"{level}%", _pct(e), _pct(c)) for level, e, c in
          zip(curve["levels_pct"], curve["EPSS"], curve["CVSS"])]),
    ]))
    lag = insights["lag_days"]
    sections.append(("Exploitation insights", [
        ("p", f"KEV window: {insights['window']['start']} through {insights['window']['end']} (inclusive). "
         f"Entries: {insights['kev_entries']}; linked to NVD: {insights['with_nvd']}; "
         f"ransomware-linked: {insights['ransomware']['count']} ({_pct(insights['ransomware']['share'])})."),
        ("p", f"Publication-to-KEV lag: median {_text(lag['median'])} days, mean {_text(lag['mean'])} days. "
         f"Among scored entries, below critical: {_pct(insights['below_critical_share'])}; "
         f"below high: {_pct(insights['below_high_share'])}."),
        ("h3", "Lag buckets"),
        ("table", ("Lag (days)", "Count", "Share"),
         [(b["label"], b["count"], _pct(b["share"])) for b in lag["buckets"]]),
        ("h3", "CVSS bands"),
        ("table", ("Band", "Count", "Share"),
         [(b["band"], b["count"], _pct(b["share"])) for b in insights["cvss_bands"]]),
        ("h3", "Top vendors"),
        ("table", ("Vendor", "Count", "Ransomware"),
         [(v["vendor"], v["count"], v["ransomware"]) for v in insights["top_vendors"]]),
        ("h3", "Top CWEs"),
        ("table", ("CWE", "Count"), [(c["cwe"], c["count"]) for c in insights["top_cwes"]]),
    ]))
    sections.append(("Limitations", [("bullets", _LIMITATIONS)]))
    return sections


def _markdown_table(headers, rows):
    lines = ["| " + " | ".join(map(_md, headers)) + " |",
             "| " + " | ".join("---" for _ in headers) + " |"]
    lines.extend("| " + " | ".join(map(_md, row)) + " |" for row in rows)
    return "\n".join(lines)


def render_analysis_markdown(report) -> str:
    parts = ["# Vulnerability Prioritization Report"]
    for name, blocks in _sections(report):
        parts.append("## " + name)
        for kind, *content in blocks:
            if kind == "table":
                parts.append(_markdown_table(*content))
            elif kind == "h3":
                parts.append("### " + str(content[0]))
            elif kind == "bullets":
                parts.append("\n".join("- " + value for value in content[0]))
            else:
                parts.append(str(content[0]))
    return "\n\n".join(parts) + "\n"


def _html_table(headers, rows):
    return ("<div class=\"table-wrap\"><table><thead><tr>"
            + "".join("<th>" + _escape(h) + "</th>" for h in headers)
            + "</tr></thead><tbody>"
            + "".join("<tr>" + "".join("<td>" + _escape(cell) + "</td>" for cell in row) + "</tr>" for row in rows)
            + "</tbody></table></div>")


def _bar_chart(title, labels, values):
    height = 50 + 42 * len(labels)
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" role="img" viewBox="0 0 800 {height}">',
             "<title>" + _escape(title) + "</title>"]
    for i, (label, value) in enumerate(zip(labels, values)):
        y = 25.0 + 42.0 * i
        width = 350.0 * (value if value is not None else 0.0)
        parts.extend([
            f'<text x="8.00" y="{y + 17:.2f}">{_escape(label)}</text>',
            f'<rect x="290.00" y="{y:.2f}" width="{width:.2f}" height="24.00" fill="#2563eb"/>',
            f'<text x="{650.0:.2f}" y="{y + 17:.2f}">{_escape(_pct(value))}</text>',
        ])
    parts.append("</svg>")
    return "".join(parts)


def _curve_chart(curve):
    parts = ['<svg xmlns="http://www.w3.org/2000/svg" role="img" viewBox="0 0 800 340">',
             "<title>Effort versus exploitation coverage</title>",
             '<path d="M 60.00 20.00 V 280.00 H 760.00" fill="none" stroke="#64748b"/>',
             '<text x="330.00" y="330.00">Effort (%)</text>',
             '<text x="60.00" y="15.00">Coverage (%)</text>']
    for pct in (0, 20, 40, 60, 80, 100):
        x, y = 60.0 + 7.0 * pct, 280.0 - 2.6 * pct
        parts.extend([f'<text x="{x:.2f}" y="300.00">{pct}</text>',
                      f'<text x="20.00" y="{y:.2f}">{pct}</text>'])
    for i, (name, color) in enumerate((("EPSS", "#2563eb"), ("CVSS", "#d97706"))):
        points = " ".join(f"{60 + 7 * pct:.2f},{280 - 260 * value:.2f}" for pct, value in
                          zip(curve["levels_pct"], curve[name]) if value is not None)
        parts.extend([f'<polyline points="{points}" fill="none" stroke="{color}" stroke-width="3.00"/>',
                      f'<text x="{580 + i * 90:.2f}" y="25.00" fill="{color}">{_escape(name)}</text>'])
    parts.append("</svg>")
    return "".join(parts)


def render_analysis_html(report) -> str:
    pooled = report["backtest"]["pooled"]["strategies"]
    buckets = report["insights"]["lag_days"]["buckets"]
    charts = {
        "Pooled results": _bar_chart("Pooled exploitation coverage per strategy",
                                     [m["strategy"] for m in pooled], [m["coverage"] for m in pooled]),
        "Effort curve": _curve_chart(report["backtest"]["effort_curve"]),
        "Exploitation insights": _bar_chart("Publication-to-KEV lag distribution",
                                            [b["label"] for b in buckets], [b["share"] for b in buckets]),
    }
    parts = ['<!DOCTYPE html>', '<html lang="en">', '<head>', '<meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width, initial-scale=1">',
             '<title>Vulnerability Prioritization Report</title>',
             '<style>body{font:16px/1.6 system-ui,sans-serif;color:#172033;background:#f4f7fb;margin:0}'
             'main{max-width:1120px;margin:auto;padding:32px}h1{line-height:1.2}h2{color:#173a72}'
             'section{background:white;border:1px solid #dce3ef;border-radius:10px;padding:24px;margin:24px 0}'
             'table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:9px;'
             'border-bottom:1px solid #dce3ef}th{background:#edf3fc}.table-wrap{overflow-x:auto;margin:16px 0}'
             'svg{display:block;width:100%;height:auto;margin:20px 0}svg text{font:14px system-ui,sans-serif}'
             '</style>', '</head>', '<body><main>', '<h1>Vulnerability Prioritization Report</h1>']
    for name, blocks in _sections(report):
        parts.append("<section><h2>" + _escape(name) + "</h2>")
        if name in charts:
            parts.append(charts[name])
        for kind, *content in blocks:
            if kind == "table":
                parts.append(_html_table(*content))
            elif kind == "bullets":
                parts.append("<ul>" + "".join("<li>" + _escape(value) + "</li>" for value in content[0]) + "</ul>")
            else:
                tag = "h3" if kind == "h3" else "p"
                parts.append("<" + tag + ">" + _escape(content[0]) + "</" + tag + ">")
        parts.append("</section>")
    parts.extend(["</main></body>", "</html>"])
    return "\n".join(parts) + "\n"


def render_triage_csv(result) -> str:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(("rank", "tier", "asset_id", "cve_id", "kev", "ransomware", "epss", "cvss",
                     "asset_criticality", "internet_facing", "reasons"))
    for item in result["items"]:
        writer.writerow((item["rank"], item["tier"], item["asset_id"], item["cve_id"],
                         "yes" if item["kev"] else "no", "yes" if item["ransomware"] else "no",
                         f"{item['epss']:.6f}" if item["epss"] is not None else "",
                         f"{item['cvss']:.1f}" if item["cvss"] is not None else "",
                         item["asset_criticality"], "yes" if item["internet_facing"] else "no",
                         ";".join(item["reasons"])))
    return stream.getvalue()


def render_triage_markdown(result) -> str:
    rows = []
    for item in result["items"]:
        rows.append((item["rank"], item["tier"], item["asset_id"], item["cve_id"],
                     f"{item['epss']:.6f}" if item["epss"] is not None else "n/a",
                     f"{item['cvss']:.1f}" if item["cvss"] is not None else "n/a",
                     "; ".join(REASON_TEXT[code] for code in item["reasons"]) or "-"))
    return "\n\n".join([
        "# Remediation Plan",
        _markdown_table(("Tier", "Findings"), [(tier, result["summary"]["tiers"][tier]) for tier in TIERS]),
        _markdown_table(("Rank", "Tier", "Asset", "CVE", "EPSS", "CVSS", "Why"), rows),
    ]) + "\n"

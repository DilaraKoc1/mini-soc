"""Dashboard: render the findings as a standalone HTML page.

Everything from the logs is escaped on the way in: account names are strings
an attacker chose, and the browser would otherwise run them as markup.
"""

import html
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

DASHBOARD_FILE = (Path(__file__).resolve().parent.parent
                  / "data" / "dashboard.html")

# Defined here rather than imported from detect, the same way detect defines
# it rather than importing from collect: a renderer that reaches into the
# detection module for one integer is coupled to it for no gain.
FAILED_LOGON = 4625

# How many accounts the card lists. One place, because the card's title says
# how many of the total it is showing and the two must not drift apart.
ACCOUNT_LIMIT = 5

# The pipeline scores 1 to 5. SOC consoles name their levels instead, and a
# reader who has seen one expects those words rather than a bare number.
SEVERITY_NAMES = {
    5: "Critical",
    4: "High",
    3: "Medium",
    2: "Low",
    1: "Informational",
}

# The columns of the collapsed row, and the widths that keep them aligned
# down the list. Shared by the header, so both use one definition.
COLUMNS = ["", "Severity", "Title", "Source", "Target", "Attempts",
           "First seen", "Technique"]
GRID = ("18px 100px minmax(220px, 2fr) 130px 130px 80px 150px "
        "minmax(170px, 1fr)")

STYLE = """
:root {
  --bg: #1b1a19; --panel: #252423; --line: #3b3a39;
  --text: #f3f2f1; --dim: #a19f9d;
  --critical: #a4262c; --high: #d13438; --medium: #ca5010;
  --low: #986f0b; --informational: #605e5c;
  /* Volume is not severity. The chart gets a colour of its own so that a
     tall bar does not read as a bad one. */
  --volume: #4f9cf9;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 24px; background: var(--bg); color: var(--text);
  font: 14px/1.5 "Segoe UI", system-ui, sans-serif;
}
h1 { font-size: 20px; font-weight: 600; margin: 0 0 4px; }
.window { color: var(--dim); font-size: 13px; margin-bottom: 24px; }
.tiles { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 24px; }
.tile {
  background: var(--panel); border: 1px solid var(--line);
  border-left: 3px solid var(--line); border-radius: 2px;
  padding: 12px 16px; min-width: 120px;
}
.tile .n { font-size: 26px; font-weight: 600; }
.tile .k { color: var(--dim); font-size: 12px; text-transform: uppercase;
           letter-spacing: .4px; }
.badge {
  display: inline-block; padding: 1px 8px; border-radius: 2px;
  font-size: 12px; font-weight: 600; color: #fff;
}
.panel {
  background: var(--panel); border: 1px solid var(--line);
  border-radius: 2px; padding: 12px 16px 8px; margin-bottom: 24px;
}
.panel .k { color: var(--dim); font-size: 12px; text-transform: uppercase;
            letter-spacing: .4px; margin-bottom: 8px; }
.cards { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 24px; }
.cards > .panel { flex: 1 1 340px; margin-bottom: 0; }
/* Both carry a bottom margin for when they stand on their own. Inside a
   card the card's padding already provides it. */
.panel .tiles { margin-bottom: 12px; }
.panel .mix { margin-bottom: 0; }
.bar { display: grid; grid-template-columns: 130px 1fr 36px; gap: 8px;
       align-items: center; padding: 4px 0; }
.bar .track { background: var(--line); height: 8px; border-radius: 2px; }
.bar .fill { background: var(--volume); height: 8px; border-radius: 2px; }
.bar .n { text-align: right; color: var(--dim); font-size: 12px; }
.tactic { padding: 8px 0; border-top: 1px solid var(--line); }
.tactic:first-child { border-top: none; padding-top: 0; }
.tactic .name { font-weight: 600; margin-bottom: 4px; }
.chart { width: 100%; height: auto; display: block; }
.chart text { fill: var(--dim); font-size: 11px; }
.chart .value { fill: var(--text); }
.mix { display: flex; height: 6px; border-radius: 3px; overflow: hidden;
       margin-bottom: 24px; }

/* Eight columns is more than a narrow window holds, so the list scrolls
   sideways rather than wrapping every title one character at a time. */
.list { overflow-x: auto; }
.headings, summary {
  display: grid; grid-template-columns: GRID_TEMPLATE;
  gap: 12px; align-items: center; min-width: 980px;
}
.headings {
  padding: 8px 16px; border-bottom: 1px solid var(--line);
  color: var(--dim); font-size: 12px; font-weight: 600;
  text-transform: uppercase; letter-spacing: .4px;
  /* The rows below sit inside a bordered box. Without the same two pixels
     here, every column is offset against its own heading. */
  border-left: 1px solid transparent; border-right: 1px solid transparent;
}
details {
  background: var(--panel); border: 1px solid var(--line);
  border-radius: 2px; margin-top: 4px;
}
summary { padding: 12px 16px; cursor: pointer; list-style: none; }
summary::-webkit-details-marker { display: none; }
.caret { color: var(--dim); display: inline-block; transition: transform .15s; }
details[open] .caret { transform: rotate(90deg); }
.detail { padding: 4px 16px 16px 46px; }
.row { display: flex; gap: 12px; padding: 6px 0;
       border-top: 1px solid var(--line); }
.row .label {
  color: var(--dim); font-size: 12px; text-transform: uppercase;
  letter-spacing: .4px; min-width: 150px; padding-top: 2px; flex: none;
}
.chip {
  display: inline-block; padding: 1px 8px; margin: 0 4px 4px 0;
  border: 1px solid var(--line); border-radius: 10px; font-size: 12px;
}
.chip.priv { border-color: var(--high); color: #f5a3a5; }
ul { margin: 0; padding-left: 18px; }
code { color: var(--dim); font-size: 12px; }
""".replace("GRID_TEMPLATE", GRID)


def severity_name(score):
    """The console-style name for a numeric score."""
    return SEVERITY_NAMES.get(score, str(score))


def severity_badge(score):
    """A severity badge coloured the way a SOC console colours it."""
    name = severity_name(score)
    return (f'<span class="badge" style="background: var(--{name.lower()})">'
            f"{html.escape(name)}</span>")


def chips(values, privileged=(), counts=None):
    """Entity chips. Privileged accounts are marked, and a count is appended
    where there is more than one: nine accounts touched once each is a sweep,
    one of them touched fifteen times is not.
    """
    out = []
    for value in values:
        css = "chip priv" if value in privileged else "chip"
        body = html.escape(str(value))
        count = (counts or {}).get(value)
        if count and count > 1:
            body += f" &times;{count}"
        out.append(f'<span class="{css}">{body}</span>')
    return "".join(out) or '<span class="chip">none</span>'


def named_counts(names, counts):
    """Pair each code's display name with how often that code appeared."""
    return {names[code]: count for code, count in counts.items()}


def when(timestamp):
    """An ISO timestamp with the date and the seconds a reader needs."""
    return html.escape(timestamp.replace("T", " ")[:19])


def target_of(finding):
    """One account name, or how many were swept."""
    return finding["target_user"] or f"{finding['distinct_accounts']} accounts"


def tiles(findings):
    """Total plus one count per severity level that actually occurs."""
    cells = [f'<div class="tile"><div class="n">{len(findings)}</div>'
             f'<div class="k">Findings</div></div>']
    for score in sorted(SEVERITY_NAMES, reverse=True):
        count = sum(1 for f in findings if f["severity"] == score)
        if not count:
            continue
        name = severity_name(score)
        cells.append(
            f'<div class="tile" style="border-left-color: var(--{name.lower()})">'
            f'<div class="n">{count}</div>'
            f'<div class="k">{html.escape(name)}</div></div>')
    return f'<div class="tiles">{"".join(cells)}</div>'


def severity_mix(findings):
    """One bar whose segments are proportional to the severity counts.

    The tiles above already give the numbers. This gives the shape, which is
    the thing you read without counting.
    """
    if not findings:
        return ""
    segments = []
    for score in sorted(SEVERITY_NAMES, reverse=True):
        count = sum(1 for f in findings if f["severity"] == score)
        if not count:
            continue
        name = severity_name(score)
        share = 100 * count / len(findings)
        segments.append(
            f'<div style="width: {share:.1f}%; '
            f'background: var(--{name.lower()})" '
            f'title="{html.escape(name)}: {count}"></div>')
    return f'<div class="mix">{"".join(segments)}</div>'


def failures_per_hour(events):
    """Failed logons bucketed by hour, with the empty hours kept.

    Dropping the quiet hours would pull the bars together and hide the thing
    the chart exists to show, which is that the failures arrive in bursts.
    """
    stamps = [datetime.fromisoformat(e["timestamp"]).replace(
                  minute=0, second=0, microsecond=0)
              for e in events if e["event_id"] == FAILED_LOGON]
    if not stamps:
        return []

    # Stepping over real datetimes rather than a range of hour numbers.
    # Counting from a sliced timestamp worked until the events crossed
    # midnight, where the first hour is 23 and the last is 01 and the range
    # between them is empty: the chart went blank without saying so.
    counts = Counter(stamps)
    hour, last = min(stamps), max(stamps)
    buckets = []
    while hour <= last:
        buckets.append((hour.strftime("%H:%M"), counts.get(hour, 0)))
        hour += timedelta(hours=1)
    return buckets


def timeline(events):
    """Failed logons over time, as an inline bar chart.

    Hand-drawn rectangles rather than a charting library: the project has no
    dependencies, and a bar chart is a rectangle per bucket.
    """
    buckets = failures_per_hour(events)
    if not buckets:
        return ""

    width, height = 900, 150
    top, bottom = 20, 24
    plot = height - top - bottom
    slot = width / len(buckets)
    tallest = max(count for _, count in buckets)

    parts = []
    for i, (label, count) in enumerate(buckets):
        bar = plot * count / tallest if tallest else 0
        x = i * slot + slot * 0.15
        parts.append(
            f'<rect x="{x:.1f}" y="{top + plot - bar:.1f}" '
            f'width="{slot * 0.7:.1f}" height="{bar:.1f}" '
            f'fill="var(--volume)"/>')
        if count:
            parts.append(
                f'<text class="value" x="{i * slot + slot / 2:.1f}" '
                f'y="{top + plot - bar - 5:.1f}" text-anchor="middle">'
                f"{count}</text>")
        parts.append(
            f'<text x="{i * slot + slot / 2:.1f}" y="{height - 8}" '
            f'text-anchor="middle">{html.escape(label)}</text>')

    return (f'<svg class="chart" viewBox="0 0 {width} {height}" '
            f'role="img" aria-label="Failed logons per hour">'
            f'{"".join(parts)}</svg>')


def panel(title, body):
    """A titled card. A SOC console groups its widgets into these."""
    return (f'<div class="panel"><div class="k">{html.escape(title)}</div>'
            f"{body}</div>")


def tactics(findings):
    """Findings grouped by MITRE tactic, with the techniques under each.

    The tactic is what the adversary wanted, the technique is how they went
    about it. Showing both together is what stops "Discovery" from reading as
    a truncated "Account Discovery".
    """
    rows = []
    for tactic in sorted({f["mitre_tactic"] for f in findings}):
        matching = [f for f in findings if f["mitre_tactic"] == tactic]
        marks = chips(f"{i} {n}" for i, n in
                      sorted({(f["mitre_id"], f["mitre_technique"])
                              for f in matching}))
        rows.append(
            f'<div class="tactic"><div class="name">{html.escape(tactic)}'
            f" ({len(matching)})</div>{marks}</div>")
    return "".join(rows) or "none"


def account_total(events):
    """How many distinct accounts were targeted at all.

    The card shows a handful. A truncated list that does not say it is
    truncated reads as the whole picture.
    """
    return len({event["target_user"] for event in events
                if event["event_id"] == FAILED_LOGON})


def top_accounts(events, limit=ACCOUNT_LIMIT):
    """The most-targeted accounts, counted from the events.

    Counted from the events rather than summed across the findings. Findings
    overlap on purpose, administrator appears in two of them, and summing
    their target_users would claim 44 attempts where the logs hold 31.
    """
    counts = Counter(event["target_user"] for event in events
                     if event["event_id"] == FAILED_LOGON)
    if not counts:
        return "none"
    top = counts.most_common(limit)
    most = top[0][1]
    return "".join(
        f'<div class="bar"><div>{html.escape(str(name))}</div>'
        f'<div class="track"><div class="fill" '
        f'style="width: {100 * count / most:.0f}%"></div></div>'
        f'<div class="n">{count}</div></div>'
        for name, count in top)


def column_headings():
    """Column labels, on the same grid as the rows below them."""
    cells = "".join(f"<div>{html.escape(c)}</div>" for c in COLUMNS)
    return f'<div class="headings">{cells}</div>'


def row(label, value):
    """One labelled line inside an opened finding."""
    return (f'<div class="row"><div class="label">{html.escape(label)}</div>'
            f"<div>{value}</div></div>")


def entry(finding):
    """One finding: the collapsed row, and everything else behind it."""
    reasons = "".join(f"<li>{html.escape(r)}</li>"
                      for r in finding["severity_reasons"])
    summary = (
        '<span class="caret">&#9656;</span>'
        f'<div>{severity_badge(finding["severity"])}</div>'
        f'<div>{html.escape(finding["title"])}</div>'
        f'<div><code>{html.escape(finding["source_ip"])}</code></div>'
        f"<div>{html.escape(str(target_of(finding)))}</div>"
        f'<div>{finding["attempts"]}</div>'
        f"<div>{when(finding['first_seen'])}</div>"
        f'<div>{html.escape(finding["mitre_id"])} '
        f'{html.escape(finding["mitre_technique"])}</div>')
    return (
        f"<details><summary>{summary}</summary>"
        '<div class="detail">'
        + row("Why this severity",
              f"<ul>{reasons}</ul>" if reasons else "no weights fired")
        # Repeated from the row above on purpose: that column scrolls out of
        # sight on a narrow window, and a tactic on its own reads as a
        # truncated technique.
        + row("MITRE technique", f'{html.escape(finding["mitre_id"])} '
                                 f'{html.escape(finding["mitre_technique"])}')
        + row("MITRE tactic", chips([finding["mitre_tactic"]]))
        + row("Source", chips([finding["source_ip"], finding["ip_scope"]]))
        + row("Hosts", chips(finding["hosts"]))
        + row("Accounts targeted",
              chips(finding["target_users"], finding["privileged_targets"],
                    finding["target_users"]))
        + row("Logon types",
              chips(finding["logon_type_names"].values(),
                    counts=named_counts(finding["logon_type_names"],
                                        finding["logon_types"])))
        + row("Failure reasons",
              chips(finding["status_code_names"].values(),
                    counts=named_counts(finding["status_code_names"],
                                        finding["status_codes"])))
        + row("Window", f"{when(finding['first_seen'])} - "
                        f"{when(finding['last_seen'])} "
                        f'({finding["duration_seconds"]}s)')
        + row("Finding id", f'<code>{html.escape(finding["finding_id"])}</code>')
        + "</div></details>")


def render(findings, events=()):
    """The whole page as one string.

    Events are optional because the findings alone make a usable page. The
    chart needs them: a finding only exists where something was detected, so
    findings cannot show a quiet hour.
    """
    if findings:
        first = min(f["first_seen"] for f in findings)
        last = max(f["last_seen"] for f in findings)
        window = f"Data window {when(first)} to {when(last)}"
        listing = (f'<div class="list">{column_headings()}'
                   f'{"".join(entry(f) for f in findings)}</div>')
        total = account_total(events)
        shown = min(ACCOUNT_LIMIT, total)
        accounts = f"Top targeted accounts ({shown} of {total})"
        cards = (f'<div class="cards">'
                 f'{panel("MITRE ATT&CK", tactics(findings))}'
                 f"{panel(accounts, top_accounts(events))}"
                 f"</div>")
    else:
        window = "No findings"
        listing = cards = ""

    chart = timeline(events)
    body = (panel("Incidents", tiles(findings) + severity_mix(findings))
            + (panel("Failed logons per hour", chart) if chart else "")
            + cards + listing)

    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            f"<title>Mini SOC</title><style>{STYLE}</style></head><body>"
            "<h1>Mini SOC</h1>"
            f'<div class="window">{window}</div>'
            f"{body}</body></html>")


def write(findings, events=(), path=DASHBOARD_FILE):
    """Write the page and return where it went."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(findings, events), encoding="utf-8")
    return path

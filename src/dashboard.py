"""Dashboard: render the findings as a standalone HTML page."""

import html
from pathlib import Path

DASHBOARD_FILE = (Path(__file__).resolve().parent.parent
                  / "data" / "dashboard.html")

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
.pill {
  display: inline-block; padding: 1px 8px; border-radius: 2px;
  font-size: 12px; font-weight: 600; color: #fff;
}

/* Eight columns is more than a narrow window holds, so the list scrolls
   sideways rather than wrapping every title one character at a time. */
.list { overflow-x: auto; }
.head, summary {
  display: grid; grid-template-columns: GRID_TEMPLATE;
  gap: 12px; align-items: center; min-width: 980px;
}
.head {
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


def pill(score):
    """A severity badge coloured the way a SOC console colours it."""
    name = severity_name(score)
    return (f'<span class="pill" style="background: var(--{name.lower()})">'
            f"{html.escape(name)}</span>")


def chips(values, privileged=()):
    """Entity chips. Privileged accounts are marked rather than just listed."""
    out = []
    for value in values:
        css = "chip priv" if value in privileged else "chip"
        out.append(f'<span class="{css}">{html.escape(str(value))}</span>')
    return "".join(out) or '<span class="chip">none</span>'


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


def head():
    """Column labels, on the same grid as the rows below them."""
    cells = "".join(f"<div>{html.escape(c)}</div>" for c in COLUMNS)
    return f'<div class="head">{cells}</div>'


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
        f'<div>{pill(finding["severity"])}</div>'
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
        + row("MITRE tactic",
              f'<span class="chip">{html.escape(finding["mitre_tactic"])}</span>')
        + row("Source", f'<span class="chip">{html.escape(finding["source_ip"])}</span>'
                        f'<span class="chip">{html.escape(finding["ip_scope"])}</span>')
        + row("Hosts", chips(finding["hosts"]))
        + row("Accounts targeted",
              chips(finding["target_users"], finding["privileged_targets"]))
        + row("Logon types", chips(finding["logon_type_names"].values()))
        + row("Failure reasons", chips(finding["status_code_names"].values()))
        + row("Window", f"{when(finding['first_seen'])} &rarr; "
                        f"{when(finding['last_seen'])} "
                        f'({finding["duration_seconds"]}s)')
        + row("Finding id", f'<code>{html.escape(finding["finding_id"])}</code>')
        + "</div></details>")


def render(findings):
    """The whole page as one string."""
    if findings:
        first = min(f["first_seen"] for f in findings)
        last = max(f["last_seen"] for f in findings)
        window = f"Data window {when(first)} to {when(last)}"
        listing = (f'<div class="list">{head()}'
                   f'{"".join(entry(f) for f in findings)}</div>')
    else:
        window = "No findings"
        listing = ""

    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            f"<title>Mini SOC</title><style>{STYLE}</style></head><body>"
            "<h1>Mini SOC</h1>"
            f'<div class="window">{window}</div>'
            f"{tiles(findings)}{listing}</body></html>")


def write(findings, path=DASHBOARD_FILE):
    """Write the page and return where it went."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(findings), encoding="utf-8")
    return path

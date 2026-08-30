"""Run the pipeline: collect -> detect -> enrich -> assess -> dashboard."""

import textwrap

import agent
import collect
import dashboard
import detect
import enrich


def pipeline():
    """Load events, detect, enrich. Returns findings.
    Sorted by severity, then by attempts.
    """
    events = collect.load()
    findings = [enrich.enrich(finding) for finding in detect.run(events)]
    return sorted(findings,
                  key=lambda finding: (finding["severity"], finding["attempts"]),
                  reverse=True)


def target_account(finding):
    """What the attack was aimed at: one account, or how many were swept."""
    return finding["target_user"] or f"{finding['distinct_accounts']} accounts"


def main():
    findings = pipeline()
    if not findings:
        print("No findings found.")
    for finding in findings:
        # flush: stdout is block-buffered off a terminal, so without it this
        # line would sit in the buffer through the model call below.
        print(f"[{finding['severity']}] {finding['rule']:<12}"
              f" {finding['source_ip']:<16}"
              f" {target_account(finding):<14}"
              f" {finding['attempts']} attempts"
              f" over {finding['duration_seconds']} seconds", flush=True)
        for reason in finding["severity_reasons"]:
            print(f"     - {reason}", flush=True)
        print()
        print(textwrap.indent(agent.assess(finding), "     "))
        print()

    print(f"Dashboard: {dashboard.write(findings)}")


if __name__ == "__main__":
    main()
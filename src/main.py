"""Run the pipeline: collect -> detect -> enrich, and print the outcome."""

import collect
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
        return
    for finding in findings:
        print(f"[{finding['severity']}] {finding['rule']:<12} {finding['source_ip']:<16}"
              f" {target_account(finding):<14} {finding['attempts']} attempts"
              f" over {finding['duration_seconds']} seconds")
        for reason in finding["severity_reasons"]:
            print(f"     - {reason}")

if __name__ == "__main__":
    main()
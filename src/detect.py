"""Detect: turn individual events into findings.

Windows does not record "a brute force attack". It writes one 4625 event
per failed attempt. The number of attempts only exists once something
counts them, and that counting is the detection.
"""

import hashlib
from collections import Counter
from datetime import datetime, timedelta

# Windows event ID for a failed logon.
FAILED_LOGON = 4625

# The failure code that says the account name itself was not found.
NO_SUCH_USER = "0xC0000064"

# Rule 1: many attempts against one account.
BURST_WINDOW = timedelta(minutes=5)
BURST_THRESHOLD = 5

# Rule 2: one source touching many accounts. Fewer attempts per account by
# nature, so the threshold counts distinct accounts, not attempts.
SWEEP_WINDOW = timedelta(minutes=10)
SWEEP_THRESHOLD = 4

RULES = {
    "brute_force": {
        "title": "Repeated failed logons against a single account",
        "mitre_id": "T1110",
        "mitre_technique": "Brute Force",
        "mitre_tactic": "Credential Access",
    },
    "enumeration": {
        "title": "Failed logons against account names that do not exist",
        "mitre_id": "T1087",
        "mitre_technique": "Account Discovery",
        "mitre_tactic": "Discovery",
    },
    "spraying": {
        "title": "One password tried against many existing accounts",
        "mitre_id": "T1110.003",
        "mitre_technique": "Password Spraying",
        "mitre_tactic": "Credential Access",
    },
}


def event_time(event):
    """An event's timestamp as a datetime."""
    return datetime.fromisoformat(event["timestamp"])


def failures(events):
    """Failed logons only, oldest first."""
    failed = [e for e in events if e["event_id"] == FAILED_LOGON]
    return sorted(failed, key=event_time)


def finding_id(*parts):
    """Content-based id, so the same cluster keeps its id across runs."""
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:8]


def densest_window(events, window):
    """Index range of the densest cluster of events within `window`.

    Sliding rather than fixed blocks: an attack running from 12:04 to 12:06
    would be split across two fixed five-minute blocks and might reach the
    threshold in neither. A sliding window has no boundaries.

    Assumes `events` is already sorted by time.
    """
    best_start, best_end, best_size = 0, 0, 0
    start = 0
    for end in range(len(events)):
        while event_time(events[end]) - event_time(events[start]) > window:
            start += 1
        size = end - start + 1
        if size > best_size:
            best_start, best_end, best_size = start, end + 1, size
    return best_start, best_end


def widest_spread(events, window):
    """The window holding the most distinct accounts."""
    best_start, best_end, most_accounts = 0, 0, 0
    for start in range(len(events)):
        start_time = event_time(events[start])
        end = start
        while (end < len(events)
               and event_time(events[end]) - start_time <= window):
            end += 1
        distinct_accounts = len({e["target_user"] for e in events[start:end]})
        if distinct_accounts > most_accounts:
            best_start, best_end, most_accounts = start, end, distinct_accounts
    return best_start, best_end, most_accounts


def build(cluster, rule, source_ip, target_user):
    """Turn a cluster of events into a finding."""
    times = [event_time(e) for e in cluster]
    target_users = Counter(e["target_user"] for e in cluster)

    logon_types = Counter(str(e["logon_type"]) for e in cluster)
    status_codes = Counter(str(e["status_code"]) for e in cluster)

    return {
        "finding_id": finding_id(rule, source_ip, target_user,
                                 times[0].isoformat()),
        "rule": rule,
        "title": RULES[rule]["title"],
        "mitre_id": RULES[rule]["mitre_id"],
        "mitre_technique": RULES[rule]["mitre_technique"],
        "mitre_tactic": RULES[rule]["mitre_tactic"],
        "source_ip": source_ip,
        "target_user": target_user,      # None for a sweep because it has many
        "target_users": dict(target_users),
        "attempts": len(cluster),
        "distinct_accounts": len(target_users),
        "first_seen": times[0].isoformat(),
        "last_seen": times[-1].isoformat(),
        "duration_seconds": int((times[-1] - times[0]).total_seconds()),
        "hosts": sorted({e["host"] for e in cluster}),
        "logon_types": dict(logon_types),
        "status_codes": dict(status_codes),
    }


def detect_brute_force(events):
    """Rule 1: BURST_THRESHOLD+ failures from one source against one account
    inside BURST_WINDOW."""
    groups = {}
    for e in failures(events):
        groups.setdefault((e["source_ip"], e["target_user"]), []).append(e)

    findings = []
    for (source_ip, user), group in groups.items():
        # Every qualifying burst, not only the densest one: two attacks from
        # the same source hours apart would otherwise be reported as the
        # larger of the two alone.
        while len(group) >= BURST_THRESHOLD:
            start, end = densest_window(group, BURST_WINDOW)
            if end - start < BURST_THRESHOLD:
                break
            burst = group[start:end]
            findings.append(build(burst, "brute_force", source_ip, user))
            group = group[:start] + group[end:]
    return findings


def sweep_technique(cluster):
    """Which technique a sweep is, decided by the failure codes.

    A spray works from a list of accounts the attacker believes are real, so
    it cannot produce a "no such user" failure. One is enough: if names were
    guessed it is enumeration, otherwise spraying.
    """
    names_were_guessed = any(event["status_code"] == NO_SUCH_USER
                             for event in cluster)
    return "enumeration" if names_were_guessed else "spraying"


def detect_account_sweep(events):
    """Rule 2: one source failing against SWEEP_THRESHOLD+ distinct accounts
    inside SWEEP_WINDOW. The failure codes decide which technique it was."""
    groups = {}
    for event in failures(events):
        groups.setdefault(event["source_ip"], []).append(event)

    findings = []
    for source_ip, group in groups.items():
        start, end, accounts = widest_spread(group, SWEEP_WINDOW)
        if accounts >= SWEEP_THRESHOLD:
            spread = group[start:end]
            technique = sweep_technique(spread)
            findings.append(build(spread, technique, source_ip, None))
    return findings


def run(events):
    """Apply both rules.

    An event can appear in two findings: the same burst is evidence of two
    different techniques, and they carry different MITRE IDs and different responses.
    """
    return detect_brute_force(events) + detect_account_sweep(events)

"""Collect: produce the raw authentication events the pipeline reads."""

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

EVENTS_FILE = Path(__file__).resolve().parent.parent / "data" / "events.json"

# Fixed start time and seed, so the dataset is identical on every run.
START = datetime(2026, 3, 12, 8, 0, 0)
SEED = 42

SUCCESSFUL_LOGON = 4624
FAILED_LOGON = 4625

WRONG_PASSWORD = "0xC000006A"   # the account exists, the password was wrong
NO_SUCH_USER = "0xC0000064"     # the account does not exist

# Paired by position; only the typo events below rely on that pairing.
STAFF = ["owilliams", "mschmidt", "jbauer", "aweber"]
WORKSTATIONS = ["192.168.56.20", "192.168.56.21",
                "192.168.56.22", "192.168.56.23"]


def event(when, event_id, source_ip, target_user, logon_type,
          status_code=None, host="WIN-DC-01"):
    """One authentication event."""
    return {
        "timestamp": when.isoformat(),
        "event_id": event_id,
        "source_ip": source_ip,
        "target_user": target_user,
        "logon_type": logon_type,
        "status_code": status_code,
        "host": host,
    }


def generate():
    """Build the demo dataset."""
    rng = random.Random(SEED)
    events = []

    # 1. Background noise: people logging in successfully through the day.
    for i in range(10):
        events.append(event(
            START + timedelta(minutes=37 * i),
            SUCCESSFUL_LOGON, rng.choice(WORKSTATIONS), rng.choice(STAFF), 3,
        ))

    # 2. Typos: one isolated failure per workstation. Same event ID and same
    #    failure code as the attack below, so filtering on event type alone
    #    cannot separate them. Only density per source can.
    for i, (ip, user) in enumerate(zip(WORKSTATIONS, STAFF)):
        events.append(event(
            START + timedelta(hours=1, minutes=13 * i),
            FAILED_LOGON, ip, user, 2, WRONG_PASSWORD,
        ))

    # 3. Internal brute force: 17 attempts against one account in 76 seconds.
    burst_start = START + timedelta(hours=4)
    for i in range(17):
        events.append(event(
            burst_start + timedelta(seconds=i * 4.75),
            FAILED_LOGON, "192.168.56.12", "administrator", 3, WRONG_PASSWORD,
        ))

    # 4. Two more attempts from the same source against the same account,
    #    hours either side of the burst. They belong to the same group but
    #    sit outside the window, so a parser that groups without correlating
    #    reports 19 where the correct answer is 17.
    for offset in (timedelta(hours=-3), timedelta(hours=3)):
        events.append(event(
            burst_start + offset,
            FAILED_LOGON, "192.168.56.12", "administrator", 3, WRONG_PASSWORD,
        ))

    # 5. Account enumeration from the same host: eight names that do not
    #    exist, twice each. Every attempt lands in a group of two, far below
    #    the brute-force threshold. Rule 1 reports none of it; rule 2 exists
    #    because of it.
    #
    #    Wide rather than deep: lockout counters run per account, so an
    #    operator tries every name once before repeating any.
    unknown_accounts = ["admin", "svc_sql", "backup", "test",
                        "helpdesk", "scanner", "ftpuser", "webadmin"]
    enum_start = burst_start + timedelta(minutes=8)
    for sweep in range(2):
        for i, name in enumerate(unknown_accounts):
            events.append(event(
                enum_start + timedelta(seconds=sweep * 120 + i * 18),
                FAILED_LOGON, "192.168.56.12", name, 3, NO_SUCH_USER,
            ))

    # 6. External RDP brute force from a public address.
    external_start = START + timedelta(hours=6, minutes=40)
    for i in range(12):
        events.append(event(
            external_start + timedelta(seconds=i * 5),
            FAILED_LOGON, "45.155.205.233", "administrator", 10,
            WRONG_PASSWORD, host="WIN-CLIENT-01",
        ))

    events.sort(key=lambda e: e["timestamp"])
    return events


def write(events, path=EVENTS_FILE):
    """Write JSON Lines - one event per line."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")


def load(path=EVENTS_FILE):
    """Read the event file, generating it first if it is not there yet."""
    if not path.exists():
        write(generate(), path)
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


if __name__ == "__main__":
    events = generate()
    write(events)
    print(f"{len(events)} events written to {EVENTS_FILE}")

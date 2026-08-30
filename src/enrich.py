"""Enrich: attach the context that is not in the log line itself."""

import ipaddress

# What Windows means by each logon type.
LOGON_TYPES = {
    "2": "Interactive (local console session)",
    "3": "Network (remote credentials, protocol not recorded)",
    "10": "RemoteInteractive (RDP desktop session)",
}

# Why a 4625 failed. The difference between them matters: one says the
# attacker already knows the account name, the other says they are still
# looking for one.
STATUS_CODES = {
    "0xC000006A": "wrong password, the account exists",
    "0xC0000064": "the account does not exist",
}

# Privileged accounts. A real deployment would resolve this against AD
# group membership instead of a name list.
PRIVILEGED = {"administrator", "admin", "root", "sa"}

# HIGH_VOLUME+ attempts in one cluster alone is aggravating.
HIGH_VOLUME = 15


def ip_scope(ip):
    """private, public, or invalid."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    return "private" if address.is_private else "public"


def is_privileged(user):
    """Whether an account has privileged rights."""
    name = str(user).strip().lower()
    return name in PRIVILEGED


def severity(finding):
    """Rate a finding from 1 (low) to 5 (critical), with its reasons."""
    score = 1
    reasons = []

    if finding["ip_scope"] == "public":
        score += 2
        reasons.append("the source is a public address")

    if "10" in finding["logon_types"]:
        score += 1
        reasons.append("logon type 10: an RDP desktop session was attempted")

    if finding["privileged_targets"]:
        score += 1
        reasons.append("a privileged account name was targeted")

    if finding["attempts"] >= HIGH_VOLUME:
        score += 1
        reasons.append(f"{finding['attempts']} attempts is high volume")

    return min(score, 5), reasons


def enrich(finding):
    """Attach context. Returns a new dict."""
    enriched = dict(finding)
    source_ip = enriched["source_ip"]

    enriched["ip_scope"] = ip_scope(source_ip)
    enriched["logon_type_names"] = {
        code: LOGON_TYPES.get(code, f"unrecognised logon type {code}")
        for code in enriched["logon_types"]
    }
    # An unrecognised code is reported as unrecognised rather than guessed
    # at, so an unusual failure reason yields a weaker finding, not a
    # wrong one.
    enriched["status_code_names"] = {
        code: STATUS_CODES.get(code, "unrecognised failure reason")
        for code in enriched["status_codes"]
    }
    enriched["privileged_targets"] = sorted(
        account for account in enriched["target_users"]
        if is_privileged(account)
    )
    enriched["severity"], enriched["severity_reasons"] = severity(enriched)
    return enriched

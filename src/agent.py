"""Ask a local model to triage a finding."""

import json
import urllib.request

import prompts

URL = "http://localhost:11434/api/chat"
MODEL = "qwen2.5:32b"

# Zero rather than a parameter. Two runs over the same finding must
# produce the same reports.
TEMPERATURE = 0

# Waiting forever is the default, so this is what turns a hung Ollama
# into an error.
TIMEOUT = 120


def ask(system, user):
    """Send a system and a user message, return the reply text.

    Knows nothing about findings. The rules travel in the system message and
    the data in the user message.
    """
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        # Without this, Ollama answers with one JSON object per token.
        "stream": False,
        "options": {"temperature": TEMPERATURE},
    }
    request = urllib.request.Request(
        URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return json.loads(response.read())["message"]["content"]


def assess(finding):
    """Ask the model to triage one enriched finding."""
    evidence = json.dumps(finding, indent=2)
    return ask(prompts.SYSTEM, f"<finding>\n{evidence}\n</finding>")
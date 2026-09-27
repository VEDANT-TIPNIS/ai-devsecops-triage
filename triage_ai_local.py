"""
AI-Assisted DevSecOps Vulnerability Triage -- FREE / LOCAL version
--------------------------------------------------------------------
Reads a raw OWASP ZAP scan report (JSON) and sends the findings to a
LOCAL AI model running in Ollama (free, open-source, no API key, no
internet call at inference time). Produces a prioritized,
developer-ready triage report.

Prerequisites (all free):
    1. Docker installed
    2. Run:  docker compose up -d
    3. Pull a small free model once:
           docker exec -it ollama ollama pull llama3.2:1b
       (a ~1.3GB one-time download, then everything runs offline)

Usage:
    python triage_ai_local.py sample_zap_report.json
"""

import json
import sys
from datetime import datetime, timezone

import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.2:1b"  # small, fast, free -- swap for phi3, mistral, etc.


def load_zap_report(path):
    with open(path, "r") as f:
        data = json.load(f)
    alerts = []
    for site in data.get("site", []):
        alerts.extend(site.get("alerts", []))
    return alerts


def build_prompt(alerts):
    findings_text = json.dumps(alerts, indent=2)
    return f"""You are a security triage assistant embedded in a CI/CD pipeline.
Below is a list of raw findings from an OWASP ZAP scan (JSON). For each finding,
return an object with these exact keys:
- "alert": the alert name
- "priority": one of CRITICAL, HIGH, MEDIUM, LOW (based on real-world exploitability)
- "impact": one short plain-English sentence on real-world impact
- "remediation": one short concrete fix
- "block_build": true or false (true only for CRITICAL/HIGH)

Return ONLY a JSON array. No preamble, no markdown fences, no explanation text.

Findings:
{findings_text}
"""


def call_ollama(prompt):
    response = requests.post(
        OLLAMA_URL,
        json={"model": MODEL, "prompt": prompt, "stream": False, "format": "json"},
        timeout=120,
    )
    response.raise_for_status()
    raw_text = response.json()["response"].strip()
    raw_text = raw_text.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    return json.loads(raw_text)


def render_markdown(triaged, source_file):
    lines = []
    lines.append("# AI-Triaged Security Report (generated locally, free)")
    lines.append(f"\nSource scan: `{source_file}`  ")
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  ")
    lines.append(f"Triage engine: {MODEL} (local, via Ollama -- no API key, no cost)\n")

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    triaged_sorted = sorted(triaged, key=lambda x: order.get(x.get("priority", "LOW"), 4))

    blockers = [t for t in triaged_sorted if t.get("block_build")]
    lines.append(f"**Pipeline decision:** {'BUILD BLOCKED' if blockers else 'BUILD ALLOWED'} "
                 f"({len(blockers)} blocking issue(s) found)\n")

    lines.append("| Priority | Alert | Impact | Remediation | Blocks Build? |")
    lines.append("|---|---|---|---|---|")
    for t in triaged_sorted:
        lines.append(
            f"| {t.get('priority','?')} | {t.get('alert','?')} | {t.get('impact','')} | "
            f"{t.get('remediation','')} | {'Yes' if t.get('block_build') else 'No'} |"
        )

    return "\n".join(lines)


def main():
    if len(sys.argv) != 2:
        print("Usage: python triage_ai_local.py <zap_report.json>")
        sys.exit(1)

    source_file = sys.argv[1]
    alerts = load_zap_report(source_file)
    print(f"Loaded {len(alerts)} raw findings from {source_file}")

    prompt = build_prompt(alerts)
    print(f"Sending findings to local Ollama model ({MODEL})...")
    triaged = call_ollama(prompt)

    report = render_markdown(triaged, source_file)
    out_path = "ai_triage_report.md"
    with open(out_path, "w") as f:
        f.write(report)

    print(f"Done. Report written to {out_path}")

    if any(t.get("block_build") for t in triaged):
        sys.exit(1)  # non-zero exit fails the Jenkins stage automatically


if __name__ == "__main__":
    main()

"""
AI-Assisted DevSecOps Vulnerability Triage -- FREE / LOCAL version
--------------------------------------------------------------------
Reads a raw OWASP ZAP scan report (JSON) and sends each finding, ONE AT
A TIME, to a LOCAL AI model running in Ollama (free, open-source, no
API key, no internet call at inference time). Produces a prioritized,
developer-ready triage report.

Small local models are unreliable at processing a whole list in one
shot, so we call the model once per finding instead -- this is slower
but far more reliable, and makes for a clearer demo (you can watch it
triage each finding one by one).

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
import time
from datetime import datetime, timezone

import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "phi3"  # small, free, local -- noticeably better instruction-following than 1b models


def load_zap_report(path):
    with open(path, "r") as f:
        data = json.load(f)
    alerts = []
    for site in data.get("site", []):
        alerts.extend(site.get("alerts", []))
    return alerts


def build_prompt(alert):
    finding_text = json.dumps(alert, indent=2)
    return f"""You are a security triage assistant embedded in a CI/CD pipeline.
Below is ONE raw finding from an OWASP ZAP scan (JSON). Judge it on its OWN
merits -- do not just copy the "riskdesc" field from the input.

Return a SINGLE JSON object (not an array) with these exact keys:
- "alert": the alert name
- "priority": one of CRITICAL, HIGH, MEDIUM, LOW. Use this guide:
    CRITICAL = remote code execution, auth bypass, SQL injection, or similar
    HIGH = XSS, sensitive data exposure, broken access control
    MEDIUM = missing security headers, misconfiguration with limited impact
    LOW = informational, best-practice, or purely cosmetic issues
- "impact": ONE new plain-English sentence written by you explaining the
  real-world risk. Do not copy words like "Low (Medium)" from the input.
- "remediation": one short concrete fix
- "block_build": true ONLY if priority is CRITICAL or HIGH. Most findings
  should be MEDIUM or LOW and should NOT block the build.

Return ONLY the JSON object. No preamble, no markdown fences, no explanation text.

Finding:
{finding_text}
"""


def call_ollama_for_finding(alert, index, total, max_retries=2):
    prompt = build_prompt(alert)
    print(f"  [{index}/{total}] triaging: {alert.get('alert', 'unknown')} ...")

    last_error = None
    for attempt in range(1, max_retries + 2):  # e.g. 1 initial try + 2 retries
        try:
            response = requests.post(
                OLLAMA_URL,
                json={"model": MODEL, "prompt": prompt, "stream": False, "format": "json"},
                timeout=180,
            )
            response.raise_for_status()
            raw_text = response.json()["response"].strip()
            raw_text = raw_text.removeprefix("```json").removeprefix("```").removesuffix("```").strip()

            try:
                parsed = json.loads(raw_text)
            except json.JSONDecodeError:
                print(f"    -> invalid JSON, using fallback values. Raw: {raw_text[:200]}")
                parsed = {}

            if isinstance(parsed, list) and parsed:
                parsed = parsed[0]
            if not isinstance(parsed, dict):
                parsed = {}

            return {
                "alert": parsed.get("alert", alert.get("alert", "Unknown finding")),
                "priority": parsed.get("priority", "MEDIUM"),
                "impact": parsed.get("impact", alert.get("desc", "")[:150]),
                "remediation": parsed.get("remediation", alert.get("solution", "")[:150]),
                "block_build": parsed.get("block_build", alert.get("riskcode") == "3"),
            }

        except requests.exceptions.RequestException as e:
            last_error = e
            print(f"    -> Ollama request failed (attempt {attempt}): {e}")
            if attempt <= max_retries:
                wait = 10 * attempt
                print(f"    -> retrying in {wait}s...")
                time.sleep(wait)

    # All retries exhausted -- don't crash the whole run over one bad finding.
    # Fall back to ZAP's own risk data so the report still stays complete.
    print(f"    -> giving up on this finding after {max_retries + 1} attempts, using ZAP's own data as fallback.")
    return {
        "alert": alert.get("alert", "Unknown finding"),
        "priority": "HIGH" if alert.get("riskcode") in ("3", "2") else "LOW",
        "impact": f"[AI unavailable after retries: {last_error}] {alert.get('desc', '')[:150]}",
        "remediation": alert.get("solution", "")[:150],
        "block_build": alert.get("riskcode") == "3",
    }


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
    print(f"Sending findings to local Ollama model ({MODEL}), one at a time...")

    triaged = [
        call_ollama_for_finding(alert, i + 1, len(alerts))
        for i, alert in enumerate(alerts)
    ]

    report = render_markdown(triaged, source_file)
    out_path = "ai_triage_report.md"
    with open(out_path, "w") as f:
        f.write(report)

    print(f"Done. Report written to {out_path}")

    if any(t.get("block_build") for t in triaged):
        sys.exit(1)  # non-zero exit fails the Jenkins stage automatically


if __name__ == "__main__":
    main()
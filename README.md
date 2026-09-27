# AI-Assisted Vulnerability Triage in a DevSecOps Pipeline (100% Free)

**Assignment:** Demonstration of DevOps concepts using AI Tools (20 marks)

Everything here is free and runs locally: no API keys, no paid tiers, no
signups. The "AI tool" is **Ollama**, an open-source engine that runs
small LLMs (like Llama 3.2) on your own machine inside Docker.

## 1. The DevOps concept being demonstrated

In a DevSecOps CI/CD pipeline, a security scan (OWASP ZAP) runs
automatically on every build. The problem: raw scanner output is long
and noisy, and someone still has to manually read it, judge severity,
and decide whether the build should be blocked. That manual step slows
down the pipeline and breaks automation.

This project removes that manual step by having a **local AI model**
read the scan output, prioritize findings, suggest fixes, and decide
pass/fail for the build automatically -- demonstrating **AI-optimized
DevOps operations** end to end.

## 2. The stack

- **GitHub** -- hosts the project; Jenkins pulls from it (`checkout scm`)
- **Docker** -- runs two containers:
  - `juice-shop` -- the deliberately-vulnerable target app being scanned
  - `ollama` -- the free local AI engine that does the triage
- **Jenkins** -- orchestrates the pipeline: checkout -> spin up containers
  -> run ZAP scan -> AI triage -> publish report, all in one `Jenkinsfile`

```
GitHub repo
   |
   v
Jenkins pipeline
   |-- docker compose up  (Juice Shop + Ollama)
   |-- ZAP scan (Docker)  -->  zap_report.json
   |-- triage_ai_local.py -->  sends findings to local Ollama model
   |-- ai_triage_report.md -->  prioritized report + build pass/fail
```

## 3. Files in this project

- `docker-compose.yml` -- starts Juice Shop + Ollama
- `sample_zap_report.json` -- example raw ZAP output (use this if you
  don't want to run a live scan during your demo)
- `triage_ai_local.py` -- sends findings to the local Ollama model,
  writes `ai_triage_report.md`, and exits non-zero if anything critical
  is found (this is what lets Jenkins auto-fail the build)
- `Jenkinsfile` -- the full pipeline definition
- `sample_output_ai_triage_report.md` -- a pre-generated example report,
  in case you want something to show without running anything live
- `requirements.txt` -- just `requests`, nothing paid

## 4. How to run it yourself (all free)

```bash
# 1. Start the target app + local AI engine
docker compose up -d

# 2. Pull a small free model (one-time, ~1.3GB download, then fully offline)
docker exec -it ollama ollama pull llama3.2:1b

# 3. Run the triage script against the sample report
pip install -r requirements.txt
python triage_ai_local.py sample_zap_report.json

# Output: ai_triage_report.md
```

To wire it into Jenkins: push this repo to GitHub, create a Jenkins
Pipeline job pointing at it (Jenkins will pick up the `Jenkinsfile`
automatically), and run the build. Jenkins needs Docker available on
its agent.

## 5. Before / After (the slide you want)

| | Manual triage | AI-assisted triage (this project) |
|---|---|---|
| Input | Raw ZAP JSON/HTML report | Same raw report |
| Time to prioritize 6 findings | ~10-15 min of manual reading | Seconds |
| Consistency | Varies by reviewer | Same criteria every run |
| Output | List of findings, no fix guidance | Prioritized table + concrete fix + build pass/fail |
| Fits in CI/CD? | No -- manual step breaks automation | Yes -- script exit code gates the Jenkins stage |
| Cost | N/A | $0 -- fully local, no API key |

## 6. Mapping to the rubric

- **DevOps concept from syllabus:** CI/CD pipeline security gating /
  shift-left security, using GitHub + Docker + Jenkins.
- **AI tool used for optimization:** a local open-source LLM (via
  Ollama) automates triage, prioritization, and remediation drafting --
  work that would otherwise need a human security engineer.
- **Better system performance:** faster feedback loop, consistent
  prioritization, and the pipeline can now auto-block risky builds
  instead of waiting on a human reviewer -- with zero recurring cost.

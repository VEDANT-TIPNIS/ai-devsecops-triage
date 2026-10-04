# AI-Assisted Vulnerability Triage in a DevSecOps Pipeline

**Assignment:** Demonstration of DevOps concepts using AI tools

Everything is free and runs locally: no API keys, no paid services.
The AI tool is **Ollama** running the open-source **phi3** model natively
on my Mac.

## 1. The problem

A CI/CD pipeline can run a security scan on every build, but the raw
scanner output is long and noisy. Someone still has to read it, judge how
serious each finding is, and decide whether the release should be stopped.
That manual step slows the pipeline down.

## 2. What this project does

An AI model reads each scan finding, rates its severity, explains the risk
in plain English, suggests a fix, and decides whether it should block the
build. Jenkins then acts on that decision automatically (a "security gate").

GitHub repo
|
v
Jenkins pipeline
|-- docker compose up (OWASP Juice Shop, the test target)
|-- OWASP ZAP baseline scan (Docker) -> zap_report.json
|-- triage_ai_local.py -> local Ollama (phi3), one finding at a time
|-- ai_triage_report.md -> archived as a build artifact
|-- security gate -> build fails if any finding is CRITICAL/HIGH


## 3. Stack

- **GitHub**: hosts the code; Jenkins checks it out each build
- **Jenkins** (installed natively): runs the pipeline defined in `Jenkinsfile`
- **Docker**: runs Juice Shop (deliberately vulnerable app) and the ZAP scanner
- **Ollama + phi3** (installed natively on the Mac, *not* in Docker): the
  local AI engine. Running it natively rather than in Docker lets it use
  the Apple GPU, which made inference much faster than in a container.

## 4. Files

- `Jenkinsfile`: the main pipeline (fast passive scan, used for the live demo)
- `docker-compose.yml`: starts Juice Shop
- `triage_ai_local.py`: sends each finding to Ollama, writes the report,
  exits non-zero if anything is blocking. Uses temperature 0 for repeatable
  results, and retries if Ollama returns an error
- `requirements.txt`: just `requests`

## 5. Setup (Mac)

```bash
brew install ollama
brew services start ollama
ollama pull phi3

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

```

Then create a Jenkins Pipeline job ("Pipeline script from SCM", this repo,
Script Path `Jenkinsfile`) and click Build Now. The report appears under
Build Artifacts as `ai_triage_report.md`.

## 6. Results and honest limitations

- The live scan uses `zap-baseline.py`, a **passive** scan. It finds
  configuration issues (missing headers, caching), not exploitable bugs such
  as SQL injection, so a live run correctly comes back LOW/MEDIUM and the
  build passes. `sample_zap_report.json` is used to show the CRITICAL path.
- An active scan (`zap-full-scan.py`) was also tried against the live Juice
  Shop app. It still came back with only LOW/MEDIUM findings, because Juice
  Shop's vulnerabilities are deliberately hidden behind custom app logic
  rather than generic reflected patterns — a known limitation of automated
  scanners against this specific target, not a flaw in the triage logic.
- Small local models can vary between runs on borderline cases. Temperature 0
  reduces this but does not remove it. A 1B model was tried first and was
  unreliable (over-flagged almost everything as CRITICAL), so phi3 is used.

## 7. Manual vs AI-assisted triage

| | Manual triage | AI-assisted triage |
|---|---|---|
| Who decides severity | A security engineer reading the report | The local AI model |
| Consistency | Varies by reviewer | Same prompt and settings every run |
| Output | Findings list | Severity, plain-English impact, fix, and pass/fail |
| Fits in CI/CD | Manual step breaks automation | Runs as a pipeline stage |
| Cost | Engineer time | Free (local, no API) |
| Time | Depends on reviewer (estimate, not measured) | A few minutes on an M2 Mac (see Jenkins stage view) |

## 8. Mapping to the rubric

- **DevOps concept:** CI/CD with a security gate (DevSecOps, shift-left)
- **AI tool optimizing DevOps:** a local LLM automates triage, prioritisation
  and remediation drafting inside the pipeline
- **Better system performance:** faster, consistent decisions and automatic
  build blocking, at zero recurring cost
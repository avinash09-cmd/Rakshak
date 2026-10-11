# Rakshak: LLM-Assisted SOC Alert Triage

Rakshak summarizes SOC alerts, maps them to MITRE ATT&CK, and recommends a severity, **without
trusting the LLM**. Alert fields are attacker-controlled text, so the model is treated as an untrusted
advisor behind several independent defenses, and an analyst makes every final call.

**Stack:** Python 3.10+, FastAPI, SQLAlchemy + MySQL 8, MITRE ATT&CK STIX, Docker Compose, and your choice of LLM: free local (Ollama), free-tier APIs, or Claude.

![Alert queue](docs/screenshots/01-queue.png)

## Choose your model: free options first

Rakshak works with **no paid API**. Pick one provider in `.env` (`LLM_PROVIDER=...`):

| Provider | Cost | Needs | Notes |
|---|---|---|---|
| `ollama` (default) | **Free** | ~4 GB RAM, ~2 GB disk | Open-source model runs locally in Docker. No account, and alert data never leaves your machine. |
| `mock` | **Free** | nothing | No real LLM: simple keyword "model" so the whole pipeline and UI still work. Good for demos and tests. |
| `openai_compat` | Free tiers exist | API key | Any OpenAI-compatible endpoint, e.g. Groq or Gemini free tiers. Check their current limits and data-use terms before sending real alerts. |
| `anthropic` | Paid (pay per token) | API key | Claude. Optional. |

**Heads-up on quality:** a small local model (default `llama3.2:3b`) is less accurate than Claude and may
return malformed JSON or weaker ATT&CK mappings. The pipeline is built for this: bad output is rejected, invented
technique IDs are dropped, the severity floor holds, and anything unusable fails safe to at least *medium*. On a
CPU, expect roughly 10 to 60 seconds per alert. Use `OLLAMA_MODEL` to try a larger model if you have the hardware.

## Quick start (Docker, free)

```bash
cp .env.example .env                     # defaults to the free local model
docker compose --profile free up --build
```

1. The first run downloads the ATT&CK data and the model (~2 GB). The `ollama-pull` service exits when it finishes.
2. Wait for `Uvicorn running on http://0.0.0.0:8000` in the logs.
3. Open **http://localhost:8000** (analyst UI) or **http://localhost:8000/docs** (API docs).

If you triage an alert before the model has finished downloading, it **fails safe** (recommended severity at
least *medium*, with the error shown). Wait for `ollama-pull` to exit, then submit it again.

**No model download at all?** Set `LLM_PROVIDER=mock` in `.env` and run `docker compose up --build`.

| Command | What it does |
|---|---|
| `docker compose --profile free up --build` | App + MySQL + local free model |
| `docker compose up --build` | App + MySQL only (use with `mock`, `openai_compat` or `anthropic`) |
| `docker compose --profile test run --rm test` | Run the 25 tests |
| `docker compose --profile eval run --rm eval` | Run the evaluation with your chosen provider |
| `docker compose down -v` | Stop and delete the database and model volumes |

Change the default MySQL passwords in `.env` for anything beyond local use. Use `--profile free` on every
`up`/`run` command in a session where you want the local model.

## Features

### 1. Triage with verified ATT&CK mapping
Each alert gets a summary, rationale, severity recommendation, and ATT&CK techniques. Every technique
ID is checked against the official STIX dataset, so only real techniques reach the analyst.
The raw alert is always shown separately and labeled untrusted.

![Triage detail](docs/screenshots/02-triage-detail.png)

### 2. Rule-based severity floor the LLM cannot lower
Deterministic rules (credential dumping, ransomware precursors, encoded PowerShell, threat-intel hits,
asset criticality, ...) set a minimum severity. The final recommendation is `max(rule floor, LLM)`.
Below, a subtle "red-team exercise" note talked the (simulated) model into answering *low* on an LSASS
dump against a critical asset. The floor kept it **critical**.

![Floor overrides LLM](docs/screenshots/03-floor-overrides-llm.png)

### 3. Prompt-injection pre-filter
Untrusted fields are scanned (Unicode-normalized, zero-width characters stripped, base64 decoded) before
any model sees them. On a high-confidence hit the **LLM is skipped entirely**, the alert is flagged,
and it goes to an analyst at no less than medium severity.

![Injection blocked](docs/screenshots/04-injection-blocked.png)

### 4. Hallucinated techniques are dropped
Here the (simulated) model returned a real technique and an invented one (`T9999`). The invented ID is
dropped with a visible reason instead of silently passing through.

![Hallucinated technique dropped](docs/screenshots/05-hallucinated-technique-dropped.png)

### 5. Human-in-the-loop review gate
Analysts accept, override, or mark a false positive. Going **below the rule floor** is refused unless the
analyst explicitly approves it and writes a justification.

![Review gate](docs/screenshots/06-review-gate-blocks-lowering.png)

### 6. Full audit trail
Every step (ingest, pre-filter, LLM output, technique verification, severity computation, analyst decision)
is recorded in an append-only audit log, with the raw model output stored for later review.

![Reviewed alert with audit log](docs/screenshots/07-reviewed-with-audit-log.png)

> The screenshots come from `scripts/capture_screenshots.py`, which uses an offline demo client. The
> "fooled by red-team note" and "hallucinated technique" model behaviors in screenshots 3 and 5 are
> **simulated** to demonstrate the defenses. They are not measurements of Claude.

## Pipeline

```
POST /alerts
   |
   v
[1 Injection pre-filter] --high-confidence hit--> skip LLM (fail safe, route to analyst)
   |
   v
[2 Isolated prompt]  alert JSON in <untrusted_alert>, '<' '>' escaped, no tools given to the model
   |
   v
[3 Strict schema]    pydantic, extra keys rejected, 1 retry, else fail safe (>= medium)
   |
   v
[Output guard]       model text that repeats flagged alert content is redacted
   |
   v
[4 STIX verifier]    technique IDs checked against the official ATT&CK bundle
   |
   v
[5 Severity floor]   final = max(rule floor, LLM)
   |
   v
[6 Analyst review]   going below the floor needs explicit approval + notes
   |
   v
[7 Audit log]        append-only, stored in MySQL
```

## API

| Method | Path | Purpose |
|---|---|---|
| POST | `/alerts` | Ingest + triage an alert |
| GET | `/alerts?status=` | Queue |
| GET | `/alerts/{id}` | Alert, triage result, reviews |
| POST | `/alerts/{id}/review` | Analyst decision |
| GET | `/alerts/{id}/audit` | Full audit trail |
| GET | `/healthz` | Health + loaded ATT&CK technique count |

```bash
curl -X POST localhost:8000/alerts -H 'content-type: application/json' -d '{
  "source":"edr","rule_name":"Suspicious PowerShell","host":"WS-014",
  "command_line":"powershell.exe -nop -w hidden -enc SQBFAFgA"}'
```

## Running without Docker

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python scripts/fetch_stix.py
export STIX_PATH=data/enterprise-attack.json DATABASE_URL=sqlite:///./rakshak.db
uvicorn app.main:create_app --factory --reload
python -m pytest
```

## Evaluation

```bash
docker compose --profile free --profile eval run --rm eval     # evaluates your chosen provider
```
`eval/build_dataset.py` generates 250 labeled synthetic alerts (100 clean, 150 adversarial across 12
injection styles). Metric definitions are in `eval/run_eval.py`.

**Read this before quoting any number:**
- With `LLM_PROVIDER=mock` the eval uses a keyword stub that ignores injected text, so injection results are
  meaningless. Run it with a real model (Ollama, a free-tier API, or Claude).
- Results depend on the model: report which model produced your numbers.
- The dataset is **synthetic and template-generated**, and includes 3 deliberately subtle payload styles
  the pre-filter cannot catch. Extend it with hand-labeled alerts and payloads you didn't write while
  tuning the filter, and report numbers from *that* run.

## Known limitations
- Pre-filter misses homoglyphs, letter-spacing, and trigger-word-free (semantic) injections. Later layers
  and the analyst are the backstop.
- No authentication on the API/UI yet. Add SSO/RBAC before exposing it.
- No schema migrations (add Alembic); tables are created with `create_all` on startup.
- Severity-floor rules are a small illustrative set. Tune them to your environment.

## Project layout
```
app/guards/     prefilter.py  attack.py (STIX)  severity.py (floor)
app/triage/     prompt.py  llm.py  service.py (pipeline)
app/templates/  analyst UI          eval/   dataset + scoring
tests/          25 tests            docs/screenshots/  README images
```

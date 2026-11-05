# Threat modeling with STRIDE + MAESTRO and a pluggable decision model

Status: DRAFT example. It is not connected to any gate.

Motto: **Repeatable, Defendable, Reusable.**
Rule: **The decision model judges, code decides, a human signs off.**

## What this is
- A runner that reads a system model (YAML) and asks narrow, typed questions about each element.
- STRIDE questions apply to each element. MAESTRO layer questions apply to AI elements (agents, tools, models).
- A **decision model** answers each question. Code converts the answers to findings, severity, and mitigations.
- A human reviewer confirms or dismisses each finding. Only the risk owner accepts a risk.

## Decision model interface
The decision model is pluggable. It gives typed answers only:

| Type | Answer | Code rule |
|---|---|---|
| `yes_no` | probability p (0-1) that the answer is yes | p ≥ 0.70 yes, p ≤ 0.30 no, else unsure → human review |
| `pick_one` | one allowed key + confidence (0-1) | key must be allowed, confidence ≥ 0.60, else human review |
| `score` | value 0-1 + confidence (0-1) | confidence ≥ 0.60, else human review |

You can use a small fine-tuned classifier, an LLM with a strict JSON schema, or a hosted typed-judgment service.
Write a thin adapter that maps your service to the request/response shape in `threatmodel.py` (section "decision model adapter").
An offline stub adapter (`stub_transport`) is included for tests and demos.

Errors, timeouts, and malformed answers fail closed to human review. They never clear a finding.

## Files
- `WORKFLOW.md`: process, roles, thresholds, scoring rules, diagram.
- `SYSTEM-MODEL-GUIDE.md`: how to write a system model YAML.
- `CALIBRATION-LESSON.md`: the severity-inflation lesson and how we fixed it.
- `system-model.schema.yaml`: input contract. `examples/example-fastapi-agent.yaml`: hypothetical example.
- `questions/stride.yaml`, `questions/maestro.yaml`: question sets, mitigation catalog, public sources.
- `threatmodel.py`: runner. `tests/`: offline tests. `tests/fixtures/baseline-audit.jsonl`: recorded answers for the hypothetical example (for replay tests).

## Run
```bash
python3 -m venv .venv && .venv/bin/pip install pyyaml pytest
.venv/bin/python -m pytest -q tests                                   # offline, no network
.venv/bin/python threatmodel.py examples/example-fastapi-agent.yaml --validate-only
.venv/bin/python threatmodel.py examples/example-fastapi-agent.yaml --out out           # DRY RUN (default)
.venv/bin/python threatmodel.py examples/example-fastapi-agent.yaml --out out --live --adapter stub   # offline mock
# Real decision model (after approval). Put the key in the environment. Do not print it.
#   env: DECISION_MODEL_API_KEY, DECISION_MODEL_ENDPOINT (or --endpoint)
.venv/bin/python threatmodel.py examples/example-fastapi-agent.yaml --out out --live --adapter http
```
Replay (no network): `--replay <prior audit.jsonl>` re-scores recorded answers with the current questions and rules.

Exit codes: 0 clean or dry run, 1 findings or review items, 2 input error.
Outputs: `findings.json`, `findings.md`, `audit.jsonl`, `requests.jsonl`, `risk_proposals.jsonl` (proposals only, `R-TBD`).

## Safety
- Requests contain only allowlisted fields. Secret-shaped text is replaced with `[REDACTED:<pattern>]`.
- The system model holds secret **key names** only, never values.
- Before a live run, read `requests.jsonl` from a dry run.

## License and disclaimer
Code: MIT (see `LICENSE`). Personal views, not my employer's. The example system is hypothetical.

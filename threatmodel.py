#!/usr/bin/env python3
"""STRIDE + MAESTRO threat-model runner with a pluggable decision model.

The decision model judges, code decides. The decision model is advisory only; every uncertain/failed/invalid
answer fails CLOSED into the human review queue. Default mode is --dry-run
(prints masked requests, sends nothing). Live mode needs --live and env
DECISION_MODEL_API_KEY (value never printed or logged). Use --adapter stub for
an offline mock decision model.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import re
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Callable

import yaml

DEFAULT_ENDPOINT = "https://decision-model.example.invalid/v1/decide"  # placeholder: set --endpoint
KEY_ENV = "DECISION_MODEL_API_KEY"
DEFAULT_MODEL = "decision-model"
TIMEOUT_S = 30
MAX_RESP_BYTES = 1_000_000

# ---- thresholds (code-owned) -------------------------------------------------
YES_THRESHOLD = 0.7
NO_THRESHOLD = 0.3
MIN_CONFIDENCE = 0.6  # choice/score

# ---- enums -------------------------------------------------------------------
ELEMENT_TYPES = {"process", "data_store", "data_flow", "external_entity", "agent", "tool", "model"}
AI_TYPES = {"agent", "tool", "model"}
EXPOSURE = {"host_only": 1, "lan": 2, "internet": 3}
IMPACT = {"public": 1, "internal": 2, "pii": 3, "credentials": 4}
AUTONOMY = {"read_only", "suggests", "acts_with_approval", "acts_autonomously"}
SEVERITIES = ("info", "low", "medium", "high", "critical")
# Outcome statuses (code-owned enum)
CONFIRMED = "confirmed_finding"       # description affirmatively shows the weakness
GAP = "documentation_gap"             # control simply not mentioned -> info, never a risk proposal
INFORMATIONAL = "informational"       # context fact that a code rule did not escalate
REVIEW = "needs_human_review"         # the decision model uncertain / error / invalid (fail closed)
NOT_ASKED = "not_asked"               # replay: no recorded answer maps to this v2 question (-> review queue)
STATUSES = {CONFIRMED, GAP, INFORMATIONAL, REVIEW, NOT_ASKED}
KINDS = {"control", "weakness", "context"}
CONTROL_CHOICES = ("present", "absent_stated", "not_mentioned")
TLS_PROTOCOLS = {"https", "tls", "mtls", "ssh", "grpcs", "wss", "sftp"}
PLAIN_PROTOCOLS = {"http", "tcp", "plain", "ws", "ftp", "telnet", "grpc"}
# Trust order of boundary zones (higher = more trusted)
ZONE_TRUST = {"internet": 0, "third_party": 1, "lan": 2, "container": 3, "host": 4}

# STRIDE-per-element (Microsoft). Code-enforced applicability.
STRIDE_PER_ELEMENT = {
    "external_entity": {"Spoofing", "Repudiation"},
    "process": {"Spoofing", "Tampering", "Repudiation", "Information Disclosure",
                "Denial of Service", "Elevation of Privilege"},
    "agent": {"Spoofing", "Tampering", "Repudiation", "Information Disclosure",
              "Denial of Service", "Elevation of Privilege"},
    "tool": {"Spoofing", "Tampering", "Repudiation", "Information Disclosure",
             "Denial of Service", "Elevation of Privilege"},
    "model": {"Tampering", "Information Disclosure", "Denial of Service"},
    "data_store": {"Tampering", "Repudiation", "Information Disclosure", "Denial of Service",
                   "Elevation of Privilege"},
    "data_flow": {"Spoofing", "Tampering", "Information Disclosure", "Denial of Service"},
}

# ---- masking -----------------------------------------------------------------
# Only these element fields are ever sent to the decision model. Everything else is dropped.
SENT_FIELDS = ("id", "type", "name", "description", "exposure", "data_classification",
               "controls", "secret_refs", "protocol", "crosses_boundary", "autonomy",
               "untrusted_inputs", "source", "destination", "tools", "model", "boundary")

SECRET_PATTERNS = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)")),
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("openai_style_key", re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-+/=]{8,}")),
    ("url_credentials", re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)[^\s/:@]+:[^\s/@]+@")),
    ("assignment", re.compile(r"(?i)\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_KEY)[A-Z0-9_]*)\s*[:=]\s*['\"]?[^\s'\",]{4,}")),
    ("high_entropy", re.compile(r"\b[A-Za-z0-9+/_\-]{32,}={0,2}\b")),
]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def mask_text(text: str) -> tuple[str, list[str]]:
    """Replace secret-shaped substrings with [REDACTED:<pattern>]. Returns (text, hit pattern names)."""
    hits: list[str] = []
    for name, rx in SECRET_PATTERNS:
        def repl(m: re.Match, name=name) -> str:
            if name == "high_entropy" and _entropy(m.group(0)) < 3.5:
                return m.group(0)
            hits.append(name)
            if name == "assignment":
                return f"{m.group(1)}=[REDACTED:{name}]"
            if name == "url_credentials":
                return f"{m.group(1)}[REDACTED:{name}]@"
            return f"[REDACTED:{name}]"
        text = rx.sub(repl, text)
    return text, hits


def mask_value(v: Any, hits: list[str]) -> Any:
    if isinstance(v, str):
        out, h = mask_text(v)
        hits.extend(h)
        return out
    if isinstance(v, list):
        return [mask_value(x, hits) for x in v]
    if isinstance(v, bool) or v is None or isinstance(v, (int, float)):
        return v
    if isinstance(v, dict):
        return {k: mask_value(x, hits) for k, x in v.items()}
    return mask_value(str(v), hits)


def masked_state(element: dict, model: dict) -> tuple[dict, list[str]]:
    hits: list[str] = []
    el = {k: mask_value(element[k], hits) for k in SENT_FIELDS if k in element}
    # secret_refs must be KEY NAMES; anything else is dropped (never forwarded).
    if "secret_refs" in el:
        el["secret_refs"] = [s for s in el["secret_refs"]
                             if isinstance(s, str) and re.fullmatch(r"[A-Z][A-Z0-9_]*", s)]
    names = {e["id"]: e.get("name", e["id"]) for e in model["elements"]}
    for ref in ("source", "destination", "model"):
        if ref in el and el[ref] in names:
            el[ref] = names[el[ref]]
    if "tools" in el:
        el["tools"] = [names.get(t, t) for t in el["tools"]]
    state = {"system": mask_value(model["system"].get("name", ""), hits), "element": el}
    return state, hits

# ---- loading & validation ----------------------------------------------------

class ModelError(ValueError):
    pass


def load_yaml(path: Path) -> Any:
    raw = path.read_bytes()
    if len(raw) > 2_000_000:
        raise ModelError(f"{path}: too large")
    return yaml.safe_load(raw)


def validate_model(m: dict) -> None:
    if not isinstance(m, dict) or m.get("schemaVersion") != 1:
        raise ModelError("schemaVersion must be 1")
    ids = set()
    for e in m.get("elements") or []:
        for f in ("id", "type", "name", "description"):
            if not isinstance(e.get(f), str) or not e[f]:
                raise ModelError(f"element missing {f}: {e.get('id')}")
        if e["type"] not in ELEMENT_TYPES:
            raise ModelError(f"bad type {e['type']} on {e['id']}")
        if e["id"] in ids:
            raise ModelError(f"duplicate id {e['id']}")
        ids.add(e["id"])
        if e.get("exposure", "lan") not in EXPOSURE:
            raise ModelError(f"bad exposure on {e['id']}")
        if e.get("data_classification", "internal") not in IMPACT:
            raise ModelError(f"bad data_classification on {e['id']}")
        if "autonomy" in e and e["autonomy"] not in AUTONOMY:
            raise ModelError(f"bad autonomy on {e['id']}")
    if not ids:
        raise ModelError("no elements")
    allowed = set(SENT_FIELDS)
    bids = {b.get("id") for b in m.get("trust_boundaries") or []}
    for b in m.get("trust_boundaries") or []:
        if b.get("zone") not in {"internet", "lan", "host", "container", "third_party"}:
            raise ModelError(f"bad zone on boundary {b.get('id')}")
    for e in m["elements"]:
        extra = set(e) - allowed
        if extra:
            raise ModelError(f"unknown fields on {e['id']}: {sorted(extra)}")
        if not re.fullmatch(r"[a-z0-9_-]+", e["id"]):
            raise ModelError(f"bad id {e['id']}")
        if "boundary" in e and e["boundary"] not in bids:
            raise ModelError(f"unknown boundary on {e['id']}")
        for r in e.get("secret_refs", []):
            if not isinstance(r, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]*", r):
                raise ModelError(f"secret_refs on {e['id']} must be KEY NAMES only")
        refs = [e.get("source"), e.get("destination"), e.get("model"), *e.get("tools", [])]
        for r in refs:
            if r is not None and r not in ids:
                raise ModelError(f"{e['id']} references unknown element {r}")
        if e["type"] == "data_flow" and not (e.get("source") and e.get("destination")):
            raise ModelError(f"data_flow {e['id']} needs source and destination")


def validate_questions(qs: dict) -> None:
    seen = set()
    for q in qs["questions"]:
        if q["id"] in seen:
            raise ModelError(f"duplicate question id {q['id']}")
        seen.add(q["id"])
        if q["type"] not in {"yes_no", "pick_one", "score"}:
            raise ModelError(f"unsupported type {q['type']}")
        if not set(q["applies_to"]) <= ELEMENT_TYPES:
            raise ModelError(f"bad applies_to on {q['id']}")
        if q.get("kind") not in KINDS:
            raise ModelError(f"question {q['id']} needs kind in {sorted(KINDS)}")
        if q["kind"] == "control" and set(q["criteria"]) != set(CONTROL_CHOICES):
            raise ModelError(f"control question {q['id']} must use choices {CONTROL_CHOICES}")
        if q["kind"] == "weakness" and q["type"] != "yes_no":
            raise ModelError(f"weakness question {q['id']} must be yes_no")
        if q["mitigation"]["id"] not in FAMILY:
            raise ModelError(f"mitigation {q['mitigation']['id']} has no family/severity entry")
        if not q.get("sources") or not q.get("mitigation", {}).get("id"):
            raise ModelError(f"question {q['id']} needs sources and mitigation")


def is_ai_related(e: dict, by_id: dict) -> bool:
    if e["type"] in AI_TYPES:
        return True
    if e["type"] == "data_flow":
        return any(by_id.get(e.get(k), {}).get("type") in AI_TYPES for k in ("source", "destination"))
    return False


def applicable(e: dict, q: dict, framework: str, by_id: dict) -> bool:
    if e["type"] not in q["applies_to"]:
        return False
    if q["id"] == "S.authn_present" and e["type"] == "data_flow":  # R-FLOW-AUTHN (v2.1)
        return bool(e.get("crosses_boundary"))
    if framework == "STRIDE":
        return q["category"] in STRIDE_PER_ELEMENT[e["type"]]
    return is_ai_related(e, by_id)

# ---- decision model adapter (the ONLY place that knows the wire shape) -------
# Interface: a Transport is any callable(request) -> response.
#   request  {model, state, questions: {name: {type, instructions, criteria}}}
#     type is one of: yes_no (answer probability 0-1 that the answer is yes),
#                     pick_one (answer one criteria key + confidence 0-1),
#                     score (answer value 0-1 + confidence 0-1)
#   response {model, answers: {name: {type, yes_no|pick_one|score, confidence}}}
# Back it with any typed decision model: a small fine-tuned classifier, an LLM
# with a strict JSON schema, or a hosted typed-judgment service. Write a thin
# adapter that maps your service to this shape. Verify with one live probe.

def build_request(state: dict, questions: list[dict], model_name: str) -> dict:
    qmap = {}
    for q in questions:
        body = {"type": q["type"], "instructions": q["instructions"], "criteria": q["criteria"]}
        qmap[wire_name(q["id"])] = body
    return {"model": model_name, "state": state, "questions": qmap}


def wire_name(qid: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", qid)


Transport = Callable[[dict], dict]


def http_transport(endpoint: str) -> Transport:
    def send(req: dict) -> dict:
        key = os.environ.get(KEY_ENV)
        if not key:
            raise RuntimeError(f"env {KEY_ENV} not set")
        data = json.dumps(req).encode()
        r = urllib.request.Request(endpoint, data=data, method="POST", headers={
            "Content-Type": "application/json", "Authorization": f"Bearer {key}"})
        try:
            with urllib.request.urlopen(r, timeout=TIMEOUT_S) as resp:
                raw = resp.read(MAX_RESP_BYTES + 1)
        except urllib.error.HTTPError as ex:  # never echo headers (could hold auth)
            raise RuntimeError(f"decision model HTTP {ex.code}") from None
        if len(raw) > MAX_RESP_BYTES:
            raise RuntimeError("decision model response too large")
        return json.loads(raw, parse_constant=_reject_const)
    return send


def stub_transport(yes_p: float = 0.1, pick: str = "not_mentioned", conf: float = 0.9) -> Transport:
    """Offline mock decision model for tests and demos. Deterministic. No network."""
    def send(req: dict) -> dict:
        out = {}
        for name, q in req["questions"].items():
            if q["type"] == "yes_no":
                out[name] = {"type": "yes_no", "yes_no": yes_p}
            elif q["type"] == "pick_one":
                c = pick if pick in q["criteria"] else next(iter(q["criteria"]))
                out[name] = {"type": "pick_one", "pick_one": c, "confidence": conf}
            else:
                out[name] = {"type": "score", "score": 0.5, "confidence": conf}
        return {"model": "stub", "answers": out}
    return send


def _reject_const(c: str) -> Any:
    raise ValueError(f"non-finite JSON constant {c}")

# ---- answer interpretation: the decision model answer -> normalized FACT (no decisions here) --

def _num(x: Any) -> float | None:
    if isinstance(x, bool) or not isinstance(x, (int, float)) or not math.isfinite(x):
        return None
    return float(x)


def interpret(q: dict, ans: Any) -> tuple[str | None, str, float | None, str]:
    """Return (fact, answer_repr, confidence, reason). fact None => human review (fail closed).
    yes_no facts: 'yes'/'no'. choice facts: an allowed criteria key."""
    if not isinstance(ans, dict) or ans.get("type") != q["type"]:
        return None, repr(ans)[:80], None, "missing or wrong-type answer"
    if q["type"] == "yes_no":
        p = _num(ans.get("yes_no"))
        if p is None or not 0 <= p <= 1:
            return None, repr(ans.get("yes_no")), None, "enum/range check failed"
        if p >= YES_THRESHOLD:
            return "yes", "yes", p, "threshold"
        if p <= NO_THRESHOLD:
            return "no", "no", 1 - p, "threshold"
        return None, f"{p:.2f}", p, "yes_no in uncertain band"
    if q["type"] == "pick_one":
        c, conf = ans.get("pick_one"), _num(ans.get("confidence"))
        if c not in q["criteria"]:
            return None, repr(c)[:80], conf, "enum check failed: choice not in allowed values"
        if conf is None or not 0 <= conf <= 1 or conf < MIN_CONFIDENCE:
            return None, c, conf, "low or invalid confidence"
        return c, c, conf, "threshold"
    return None, "", None, "unsupported type"

# ---- code facts: model attributes that make a decision model question unnecessary -------

def code_fact(e: dict, q: dict) -> str | None:
    kind = q.get("code_fact")
    if kind == "protocol" and isinstance(e.get("protocol"), str):
        p = e["protocol"].strip().lower().split("/")[0]
        if p in TLS_PROTOCOLS:
            return "present"
        if p in PLAIN_PROTOCOLS:
            return "absent_stated"
    if kind == "autonomy" and e.get("autonomy") in AUTONOMY:
        return e["autonomy"]
    return None

# ---- outcome rules (code decides) --------------------------------------------

def zone_of(el: dict | None, model: dict) -> str | None:
    if not el:
        return None
    zones = {b["id"]: b["zone"] for b in model.get("trust_boundaries") or []}
    return zones.get(el.get("boundary"))


def flow_to_less_trusted(e: dict, model: dict, by_id: dict) -> bool:
    src, dst = by_id.get(e.get("source")), by_id.get(e.get("destination"))
    if dst and dst["type"] in {"model", "external_entity"}:
        return True
    zs, zd = zone_of(src, model), zone_of(dst, model)
    return zs is not None and zd is not None and ZONE_TRUST[zd] < ZONE_TRUST[zs]


def outcome(e: dict, q: dict, fact: str, facts: dict, model: dict, by_id: dict) -> tuple[str | None, str]:
    """(status or None=clear, rule id). facts = this element's other facts by question id."""
    kind = q["kind"]
    if kind == "control":
        if fact == "present":
            return None, "control-present"
        if fact == "absent_stated":
            return CONFIRMED, "control-absent-stated"
        if fact == "not_mentioned":
            return GAP, "control-not-mentioned"
        if fact == "absent_or_not_mentioned":  # v1 replay: cannot tell which -> conservative non-escalation
            return GAP, "replay-v1-no-cannot-split"
    if kind == "weakness":
        return (CONFIRMED, "weakness-stated") if fact == "yes" else (None, "weakness-not-shown")
    # context rules
    if q["id"] in {"I.sensitive_data_in_flow", "L2.pii_to_model"}:
        if fact != "yes":
            return None, "R-PII-FLOW:no-pii"
        tls = facts.get("T.transport_integrity")
        if tls == "absent_stated" or flow_to_less_trusted(e, model, by_id):
            return CONFIRMED, "R-PII-FLOW:pii+(plaintext|less-trusted|model)"
        return INFORMATIONAL, "R-PII-FLOW:pii-over-tls-to-trusted"
    if q["id"] == "L3.autonomy_level":
        if fact in {"acts_autonomously"} and e.get("tools"):
            return CONFIRMED, "R-AUTONOMY:tools-without-approval"
        return (INFORMATIONAL, "R-AUTONOMY:no-tools-or-approved") if fact != "read_only" else (None, "R-AUTONOMY:read-only")
    return INFORMATIONAL, "context-default"

# ---- severity: rubric then per-family cap ------------------------------------
# Root-cause family per mitigation id; dedupe + risk proposals group by (element, family).
FAMILY = {
    "M-AUTHN": "authn", "M-IDV": "authn",
    "M-VALIDATE": "input_validation", "M-PARAMQ": "input_validation",
    "M-TLS": "data_exposure", "M-MINIMIZE": "data_exposure", "M-PII-REDACT": "data_exposure",
    "M-AUDIT": "logging", "M-AGENT-TRACE": "logging",
    "M-ENC-REST": "at_rest",
    "M-RATELIMIT": "dos",
    "M-AUTHZ": "authz", "M-DELEGATED-AUTHZ": "authz", "M-LEASTPRIV": "authz", "M-TOOL-VALIDATE": "authz",
    "M-MODEL-PIN": "supply_chain",
    "M-PI-ISOLATE": "prompt_injection", "M-CODE-GUARD": "prompt_injection", "M-HITL": "prompt_injection",
    "M-OUTPUT-ENCODE": "output_handling",
    "M-ENDPOINT-LOCK": "model_endpoint",
    "M-ECOSYS-PIN": "ecosystem",
}


def _sensitive(e: dict) -> bool:
    return e.get("data_classification", "internal") in {"pii", "credentials"}


def _agent_drives(e: dict, model: dict) -> list[dict]:
    return [x for x in model["elements"] if x["type"] == "agent"
            and (x["id"] == e["id"] or e["id"] in x.get("tools", []))]


def raw_severity(e: dict, model: dict) -> str:
    """impact(data class) x exposure (+2 if an autonomous agent drives it)."""
    pts = IMPACT[e.get("data_classification", "internal")] * EXPOSURE[e.get("exposure", "lan")]
    if any(a.get("autonomy") == "acts_autonomously" for a in _agent_drives(e, model)):
        pts += 2
    return "low" if pts <= 2 else "medium" if pts <= 5 else "high" if pts <= 8 else "critical"


def severity_cap(e: dict, q: dict, facts: dict, model: dict, by_id: dict) -> str:
    """Max severity per mitigation / family. Documented in WORKFLOW.md (Severity table)."""
    mid = q["mitigation"]["id"]
    fam = FAMILY[mid]
    if fam == "logging":
        return "medium"
    if fam == "dos":
        no_auth = facts.get("S.authn_present") == "absent_stated"
        return "high" if e.get("exposure") == "internet" and no_auth else "medium"
    if fam == "authz":
        return "high" if _sensitive(e) else "medium"
    if fam == "data_exposure":
        if mid == "M-TLS":
            crosses = e.get("crosses_boundary") or flow_to_less_trusted(e, model, by_id)
            return "high" if _sensitive(e) and crosses else "medium"
        plaintext = facts.get("T.transport_integrity") == "absent_stated"
        return "high" if _sensitive(e) and plaintext else "medium"
    if fam == "prompt_injection":
        agents = _agent_drives(e, model)
        side = any(a.get("tools") and a.get("autonomy") in {"acts_autonomously", "acts_with_approval"} for a in agents)
        return "high" if side else "medium"
    if fam == "model_endpoint":
        return "high" if _sensitive(e) and e.get("exposure") in {"lan", "internet"} else "medium"
    if fam == "authn":
        if e.get("exposure") == "internet" and e.get("data_classification") == "credentials":
            return "critical"
        return "high"
    if fam == "input_validation":
        return "high"
    if fam == "output_handling":  # R-OUTPUT-SINK (v2.1)
        return "high" if output_sink_dangerous(e, model, by_id) else "medium"
    return "medium"  # supply_chain, at_rest, ecosystem


def output_sink_dangerous(e: dict, model: dict, by_id: dict) -> bool:
    """Model output reaches a dangerous sink, from existing attributes only:
    the agent has tools (output becomes tool args), or a data_flow from this agent/model
    goes to a tool, process, or data_store (rendered in a UI, executed, or used in queries)."""
    if e.get("tools"):
        return True
    ids = {e["id"]} | ({e["model"]} if e.get("model") else set())
    for f in model["elements"]:
        if f["type"] == "data_flow" and f.get("source") in ids and f.get("destination") != e["id"]:
            dst = by_id.get(f.get("destination"))
            if dst and dst["type"] in {"tool", "process", "data_store"}:
                return True
    return False


def final_severity(status: str, e: dict, q: dict, facts: dict, model: dict, by_id: dict) -> str:
    if status in {GAP, INFORMATIONAL}:
        sev = "info"
    else:
        raw, cap = raw_severity(e, model), severity_cap(e, q, facts, model, by_id)
        sev = SEVERITIES[min(SEVERITIES.index(raw), SEVERITIES.index(cap))]
    if sev not in SEVERITIES:  # enum check
        raise AssertionError("severity outside enum")
    return sev

# ---- replay: recorded answers -> facts (zero network) ------------------------

def load_replay(path: Path) -> dict:
    """Map (element, question_id) -> recorded row. Last row wins."""
    rows = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line, parse_constant=_reject_const)
            rows[(r["element"], r["question_id"])] = r
    return rows


def replay_fact(e: dict, q: dict, rows: dict) -> tuple[str | None, str, float | None, str, dict]:
    """Return (fact, answer_repr, conf, reason, provenance). fact 'not_asked' when nothing maps."""
    rf = q.get("replay_from") or {"id": q["id"], "map": {}}
    r = rows.get((e["id"], rf["id"]))
    if r is None or r.get("decision") == "dry_run":
        return "not_asked", "", None, f"not_asked: no recorded answer for {rf['id']}", {}
    prov = {"replayed_from": rf["id"], "v1_input_sha256": r.get("input_sha256"), "v1_model": r.get("model"),
            "v1_answer": r.get("answer"), "v1_confidence": r.get("confidence")}
    ans, conf = r.get("answer"), r.get("confidence")
    if ans in ("yes", "no"):
        mapped = rf["map"].get(ans)
        if mapped is None:
            return "not_asked", str(ans), conf, f"not_asked: v1 answer '{ans}' has no v2 mapping", prov
        return mapped, str(ans), conf, f"replay {rf['id']}={ans} -> {mapped}", prov
    if q["type"] == "pick_one" and ans in q["criteria"]:
        c = _num(conf)
        if c is None or c < MIN_CONFIDENCE:
            return None, str(ans), c, "replay: low confidence", prov
        return ans, str(ans), c, f"replay {rf['id']}={ans}", prov
    return None, str(ans), _num(conf), f"replay: v1 answer was review/uncertain ({ans})", prov

# ---- run ---------------------------------------------------------------------

def sha256_json(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def run(model: dict, qsets: list[dict], outdir: Path, transport: Transport | None,
        model_name: str = DEFAULT_MODEL, echo: Callable[[str], None] = print,
        replay: dict | None = None) -> dict:
    """transport=None and replay=None => dry run (no network). replay => re-score recorded answers, no network."""
    validate_model(model)
    for qs in qsets:
        validate_questions(qs)
    if transport is not None and replay is not None:
        raise ValueError("choose live or replay, not both")
    outdir.mkdir(parents=True, exist_ok=True)
    run_id = str(uuid.uuid4())
    mode = "replay" if replay is not None else "live" if transport is not None else "dry_run"
    by_id = {e["id"]: e for e in model["elements"]}
    qver = {qs_["framework"]: qs_.get("version") for qs_ in qsets}
    findings: list[dict] = []
    req_log = []
    with (outdir / "audit.jsonl").open("a", encoding="utf-8") as audit:
        for e in model["elements"]:
            qs = [(qs_["framework"], q) for qs_ in qsets for q in qs_["questions"]
                  if applicable(e, q, qs_["framework"], by_id)]
            if not qs:
                continue
            cfacts = {q["id"]: code_fact(e, q) for _, q in qs}
            ask = [q for _, q in qs if cfacts[q["id"]] is None]
            state, hits = masked_state(e, model)
            req = build_request(state, ask, model_name) if ask else None
            ihash = sha256_json(req) if req else None
            if req:
                req_log.append({"element": e["id"], "input_sha256": ihash, "redactions": hits, "request": req})
            if mode == "dry_run":
                if req:
                    echo(json.dumps({"element": e["id"], "input_sha256": ihash, "redactions": hits,
                                     "request": req}, indent=2))
                for fw, q in qs:
                    audit.write(json.dumps({"ts": now(), "run_id": run_id, "mode": mode, "element": e["id"],
                        "question_id": q["id"], "question_version": qver[fw], "framework": fw,
                        "input_sha256": ihash, "model": model_name, "answer": cfacts[q["id"]],
                        "confidence": None, "decision": "dry_run",
                        "code_fact": cfacts[q["id"]] is not None, "redactions": hits}) + "\n")
                continue
            answers, resp_model, err = {}, model_name, None
            if mode == "live" and req:
                try:
                    resp = transport(req)
                    answers = resp.get("answers") if isinstance(resp, dict) else None
                    resp_model = resp.get("model", "unknown") if isinstance(resp, dict) else "unknown"
                    if not isinstance(answers, dict):
                        raise ValueError("response has no answers object")
                except Exception as ex:  # fail closed
                    answers, resp_model, err = {}, "unavailable", f"{type(ex).__name__}: {str(ex)[:120]}"
            # pass 1: facts
            facts: dict[str, Any] = {}
            meta: dict[str, tuple] = {}
            for fw, q in qs:
                prov: dict = {}
                if cfacts[q["id"]] is not None:
                    fact, arepr, conf, reason = cfacts[q["id"]], cfacts[q["id"]], 1.0, f"code_fact:{q['code_fact']}"
                    qmodel = "code"
                elif mode == "replay":
                    fact, arepr, conf, reason, prov = replay_fact(e, q, replay)
                    qmodel = prov.get("v1_model", "none")
                elif err:
                    fact, arepr, conf, reason, qmodel = None, "", None, f"decision model error: {err}", resp_model
                else:
                    fact, arepr, conf, reason = interpret(q, answers.get(wire_name(q["id"])))
                    qmodel = resp_model
                facts[q["id"]] = fact
                meta[q["id"]] = (fw, arepr, conf, reason, qmodel, prov)
            # pass 2: outcomes (code decides; may combine facts + model attributes)
            for fw, q in qs:
                fact = facts[q["id"]]
                arepr, conf, reason, qmodel, prov = meta[q["id"]][1:]
                if fact == "not_asked":
                    status, rule = NOT_ASKED, "not_asked"
                elif fact is None:
                    status, rule = REVIEW, "fail-closed"
                else:
                    status, rule = outcome(e, q, fact, facts, model, by_id)
                assert status is None or status in STATUSES
                row = {"ts": now(), "run_id": run_id, "mode": mode, "element": e["id"],
                       "question_id": q["id"], "question_version": qver[fw], "framework": fw,
                       "input_sha256": ihash, "model": qmodel, "answer": arepr, "confidence": conf,
                       "fact": fact, "decision": status or "clear", "rule": rule, "reason": reason,
                       "redactions": hits}
                row.update(prov)
                audit.write(json.dumps(row) + "\n")
                if status is None:
                    continue
                findings.append({
                    "element": e["id"], "element_name": e["name"], "element_type": e["type"],
                    "framework": fw, "category": q["category"], "question_id": q["id"], "kind": q["kind"],
                    "status": status, "severity": final_severity(status, e, q, facts, model, by_id),
                    "family": FAMILY[q["mitigation"]["id"]],
                    "mitigation_id": q["mitigation"]["id"], "mitigation": q["mitigation"]["text"],
                    "sources": list(q["sources"]), "fact": fact, "dm_answer": arepr, "confidence": conf,
                    "rule": rule, "reason": reason, "input_sha256": ihash, "model": qmodel, **prov})
    findings.sort(key=lambda f: (-SEVERITIES.index(f["severity"]), STATUS_ORDER.index(f["status"]),
                                 f["element"], f["question_id"]))
    for i, f in enumerate(findings, 1):
        f["id"] = f"TM-{i:03d}"
    (outdir / "requests.jsonl").write_text("".join(json.dumps(r) + "\n" for r in req_log))
    result = {"run_id": run_id, "mode": mode, "dry_run": mode == "dry_run", "system": model["system"],
              "question_versions": qver,
              "thresholds": {"yes_threshold": YES_THRESHOLD, "no_threshold": NO_THRESHOLD, "min_confidence": MIN_CONFIDENCE},
              "findings": findings if mode != "dry_run" else []}
    if mode != "dry_run":
        result["risk_proposals"] = root_causes(findings)
        (outdir / "findings.json").write_text(json.dumps(result, indent=2))
        (outdir / "findings.md").write_text(render_md(result))
        (outdir / "risk_proposals.jsonl").write_text("".join(
            json.dumps(risk_event(rc, run_id)) + "\n" for rc in result["risk_proposals"]))
    return result


STATUS_ORDER = [CONFIRMED, REVIEW, NOT_ASKED, INFORMATIONAL, GAP]


def root_causes(findings: list[dict]) -> list[dict]:
    """Only CONFIRMED at high/critical; one per (element, family)."""
    groups: dict[tuple, dict] = {}
    for f in findings:
        if f["status"] != CONFIRMED or f["severity"] not in ("high", "critical"):
            continue
        k = (f["element"], f["family"])
        g = groups.setdefault(k, {"element": f["element"], "element_name": f["element_name"],
                                  "family": f["family"], "severity": f["severity"], "findings": [],
                                  "mitigations": {}, "sources": set(), "categories": set()})
        g["findings"].append(f["id"])
        g["mitigations"][f["mitigation_id"]] = f["mitigation"]
        g["sources"] |= set(f["sources"])
        g["categories"].add(f"{f['framework']} / {f['category']}")
        if SEVERITIES.index(f["severity"]) > SEVERITIES.index(g["severity"]):
            g["severity"] = f["severity"]
    out = []
    for g in groups.values():
        g["sources"], g["categories"] = sorted(g["sources"]), sorted(g["categories"])
        out.append(g)
    return sorted(out, key=lambda g: (-SEVERITIES.index(g["severity"]), g["element"], g["family"]))


def risk_event(rc: dict, run_id: str) -> dict:
    """PROPOSAL only. The security reviewer assigns a register ID; the risk owner approves acceptance. Never auto-applied."""
    return {"id": str(uuid.uuid4()), "ts": now(), "agent": "threatmodel-runner", "domain": "security",
            "type": "risk.opened", "schemaVersion": 1,
            "payload": {"risk_id": "R-TBD", "title": f"{rc['family']}: {rc['element_name']}",
                        "severity": rc["severity"], "element": rc["element"], "root_cause": rc["family"],
                        "categories": rc["categories"], "mitigations": rc["mitigations"],
                        "sources": rc["sources"], "status": "proposed"},
            "provenance": {"tool": "threatmodel.py", "run_id": run_id, "findings": rc["findings"]}}


def render_md(r: dict) -> str:
    lines = [f"# Threat model findings: {r['system'].get('name')}", "",
             f"- run_id: `{r['run_id']}` · mode: {r['mode']} · question versions: {r['question_versions']}",
             f"- example system: {bool(r['system'].get('example'))}",
             "- The decision model is advisory. confirmed_finding = description affirmatively shows the weakness;",
             "  documentation_gap = control not mentioned (info); needs_human_review / not_asked -> security reviewer.", "",
             "## Risk proposals (confirmed, high/critical, one per element + root cause)", ""]
    for rc in r.get("risk_proposals", []):
        lines.append(f"- **{rc['severity']}** `{rc['element']}` / {rc['family']}: "
                     + "; ".join(f"{k}" for k in rc["mitigations"]) + f" ({', '.join(rc['findings'])})")
    lines += ["", "## Findings", "",
              "| ID | Sev | Status | Element | Framework / category | Rule | Mitigation | Source |",
              "|---|---|---|---|---|---|---|---|"]
    for f in r["findings"]:
        lines.append(f"| {f['id']} | {f['severity']} | {f['status']} | {f['element_name']} (`{f['element']}`) | "
                     f"{f['framework']} / {f['category']} | {f['rule']} | {f['mitigation_id']}: {f['mitigation']} | {f['sources'][0]} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("model", type=Path)
    ap.add_argument("--questions", type=Path, nargs="+",
                    default=[here / "questions/stride.yaml", here / "questions/maestro.yaml"])
    ap.add_argument("--out", type=Path, default=Path("out"))
    ap.add_argument("--live", action="store_true", help="actually call the decision model (default is dry run)")
    ap.add_argument("--endpoint", default=os.environ.get("DECISION_MODEL_ENDPOINT", DEFAULT_ENDPOINT))
    ap.add_argument("--dm-model", default=DEFAULT_MODEL)
    ap.add_argument("--adapter", choices=["http", "stub"], default="http",
                    help="with --live: http = real endpoint, stub = offline mock")
    ap.add_argument("--replay", type=Path, metavar="AUDIT_JSONL",
                    help="re-score recorded answers from a prior audit.jsonl; no network")
    ap.add_argument("--validate-only", action="store_true",
                    help="validate model + question files, write nothing, send nothing")
    a = ap.parse_args(argv)
    try:
        model = load_yaml(a.model)
        qsets = [load_yaml(p) for p in a.questions]
        if a.validate_only:
            validate_model(model)
            for qs in qsets:
                validate_questions(qs)
            print(f"VALID: {a.model} ({len(model['elements'])} elements)")
            return 0
        if a.live and a.replay:
            raise ModelError("--live and --replay are mutually exclusive")
        rows = load_replay(a.replay) if a.replay else None
        r = run(model, qsets, a.out, ((stub_transport() if a.adapter == "stub" else http_transport(a.endpoint)) if a.live else None), a.dm_model, replay=rows)
    except (ModelError, yaml.YAMLError, OSError, KeyError, TypeError, ValueError) as ex:
        print(f"input error: {ex}", file=sys.stderr)
        return 2
    if a.live or a.replay:
        c = {s_: sum(f["status"] == s_ for f in r["findings"]) for s_ in STATUS_ORDER}
        print(f"mode={r['mode']} " + " ".join(f"{k}={v}" for k, v in c.items())
              + f" proposals={len(r['risk_proposals'])} out={a.out}")
        return 1 if c[CONFIRMED] or c[REVIEW] or c[NOT_ASKED] else 0
    print(f"DRY RUN: nothing sent. requests in {a.out}/requests.jsonl", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

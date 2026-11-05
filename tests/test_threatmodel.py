import json
import sys
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import threatmodel as tm  # noqa: E402

MODEL = tm.load_yaml(ROOT / "examples/example-fastapi-agent.yaml")
QS = [tm.load_yaml(ROOT / "questions/stride.yaml"), tm.load_yaml(ROOT / "questions/maestro.yaml")]
Q0 = {q["id"]: q for qs in QS for q in qs["questions"]}


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network used in test")
    monkeypatch.setattr(urllib.request, "urlopen", boom)


def all_answers(req, yes_no=0.1, choice="absent_stated", conf=0.9):
    out = {}
    for name, q in req["questions"].items():
        if q["type"] == "yes_no":
            out[name] = {"type": "yes_no", "yes_no": yes_no}
        else:
            c = choice if choice in q["criteria"] else next(iter(q["criteria"]))
            out[name] = {"type": "pick_one", "pick_one": c, "confidence": conf,
                         "probabilities": {}}
    return {"model": "stub-test", "answers": out, "usage": {"input_tokens": 1, "output_tokens": 1}}


def test_dry_run_sends_nothing_and_logs(tmp_path):
    printed = []
    r = tm.run(MODEL, QS, tmp_path, None, echo=printed.append)
    assert r["dry_run"] and r["findings"] == []
    assert printed and not (tmp_path / "findings.json").exists()
    rows = [json.loads(l) for l in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert rows and all(x["decision"] == "dry_run" and len(x["input_sha256"]) == 64 for x in rows)
    # MAESTRO only on AI-related elements
    assert not any(x["framework"] == "MAESTRO" and x["element"] in {"db", "user", "api", "f_user_api"} for x in rows)
    assert any(x["framework"] == "MAESTRO" and x["element"] == "f_agent_llm" for x in rows)


def test_cli_default_is_dry_run(tmp_path):
    assert tm.main([str(ROOT / "examples/example-fastapi-agent.yaml"), "--out", str(tmp_path)]) == 0
    assert (tmp_path / "requests.jsonl").exists()


def test_fail_closed_on_transport_error(tmp_path):
    def broken(req):
        raise ConnectionError("down")
    r = tm.run(MODEL, QS, tmp_path, broken)
    dm = [f for f in r["findings"] if f["model"] != "code"]
    assert dm and all(f["status"] == "needs_human_review" for f in dm)
    rows = [json.loads(l) for l in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert all(x["decision"] == "needs_human_review" for x in rows if x["model"] != "code")


def test_fail_closed_on_garbage_response(tmp_path):
    r = tm.run(MODEL, QS, tmp_path, lambda req: {"oops": 1})
    dm = [f for f in r["findings"] if f["model"] != "code"]
    assert dm and all(f["status"] == "needs_human_review" for f in dm)


def test_uncertain_yes_no_goes_to_review(tmp_path):
    r = tm.run(MODEL, QS, tmp_path, lambda req: all_answers(req, yes_no=0.5))
    qt = {q["id"]: q["type"] for qs in QS for q in qs["questions"]}
    yes_nos = [f for f in r["findings"] if qt[f["question_id"]] == "yes_no" and f["model"] != "code"]
    assert yes_nos and all(f["status"] == "needs_human_review" for f in yes_nos)


def test_low_confidence_choice_goes_to_review():
    q = Q0["S.authn_present"]
    d, *_ = tm.interpret(q, {"type": "pick_one", "pick_one": "present", "confidence": 0.4})
    assert d is None


@pytest.mark.parametrize("bad", [
    {"type": "pick_one", "pick_one": "banana", "confidence": 0.99},
    {"type": "yes_no", "yes_no": 0.9},
])
def test_enum_rejection(bad):
    q = next(q for qs in QS for q in qs["questions"] if q["id"] == "S.authn_present")
    d, _, _, reason = tm.interpret(q, bad)
    assert d is None


@pytest.mark.parametrize("val", [True, float("nan"), 1.5, -0.1, "0.9"])
def test_yes_no_range_and_type_checks(val):
    q = next(q for qs in QS for q in qs["questions"] if q["type"] == "yes_no")
    assert tm.interpret(q, {"type": "yes_no", "yes_no": val})[0] is None


def test_confident_answers_make_findings_with_rubric(tmp_path):
    r = tm.run(MODEL, QS, tmp_path, lambda req: all_answers(req, yes_no=0.05))
    assert r["findings"]
    for f in r["findings"]:
        assert f["severity"] in tm.SEVERITIES and f["sources"] and f["mitigation"]
    rc = [(p["element"], p["family"]) for p in r["risk_proposals"]]
    assert len(rc) == len(set(rc))  # one proposal per root cause
    assert (tmp_path / "findings.md").exists()
    for line in (tmp_path / "risk_proposals.jsonl").read_text().splitlines():
        ev = json.loads(line)
        assert ev["type"] == "risk.opened" and ev["payload"]["risk_id"] == "R-TBD"
        assert set(ev) == {"id", "ts", "agent", "domain", "type", "schemaVersion", "payload", "provenance"}


def test_no_secret_values_reach_decision_model(tmp_path):
    # Fixtures built at runtime so no secret-shaped literal sits in the repo (gitleaks-friendly).
    fake = {
        "gh": "ghp_" + "Z" * 36,
        "aws": "AKIA" + "Q" * 16,
        "sk": "sk-" + "x1" * 12,
        "assign": "DB_" + "PASSWORD=" + "hunter" + "2hunter2",
        "url": "postgres://app:" + "pw" * 5 + "@db:5432/x",
        "bearer": "Bearer " + "abcDEF123" * 3,
    }
    m = json.loads(json.dumps(MODEL))
    m["elements"][1]["description"] = " ".join(fake.values())
    assert fake["sk"] not in json.dumps(tm.masked_state(dict(m["elements"][1], secret_refs=["APP_SESSION_KEY", fake["sk"]]), m)[0])
    extra = dict(m["elements"][1], password=fake["assign"])  # unknown field: validator rejects, masker drops
    with pytest.raises(tm.ModelError):
        tm.validate_model(dict(m, elements=[extra]))
    assert fake["assign"] not in json.dumps(tm.masked_state(extra, m)[0])
    sent = []
    tm.run(m, QS, tmp_path, lambda req: (sent.append(json.dumps(req)), all_answers(req))[1])
    blob = "\n".join(sent) + (tmp_path / "audit.jsonl").read_text() + (tmp_path / "requests.jsonl").read_text()
    for v in fake.values():
        assert v not in blob
    for frag in ("Z" * 36, "Q" * 16, "hunter2hunter2", "pwpwpw", "abcDEF123abcDEF123"):
        assert frag not in blob
    assert "APP_SESSION_KEY" in blob and "[REDACTED:" in blob


def test_key_never_logged(tmp_path, monkeypatch):
    secret = "k" + "e" * 30
    monkeypatch.setenv(tm.KEY_ENV, secret)
    tm.run(MODEL, QS, tmp_path, lambda req: (_ for _ in ()).throw(RuntimeError("x")))
    for p in tmp_path.iterdir():
        assert secret not in p.read_text()


def test_validate_only_ok_and_writes_nothing(tmp_path, capsys):
    out = tmp_path / "out"
    assert tm.main([str(ROOT / "examples/example-fastapi-agent.yaml"), "--validate-only", "--out", str(out)]) == 0
    assert "VALID" in capsys.readouterr().out and not out.exists()


def test_validate_only_rejects_bad_model(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("schemaVersion: 1\nsystem: {name: x, owner: y}\nelements:\n  - {id: a, type: database, name: A, description: d}\n")
    assert tm.main([str(bad), "--validate-only"]) == 2


@pytest.mark.parametrize("patch", [
    {"secret_refs": ["not a key name"]},
    {"source": "ghost"},
    {"api_key": "x"},
    {"boundary": "nowhere"},
])
def test_validate_rejects_bad_refs(patch):
    m = json.loads(json.dumps(MODEL))
    m["elements"][1].update(patch)
    with pytest.raises(tm.ModelError):
        tm.validate_model(m)


# ---------------- v2 calibration rules ----------------
BY_ID = {e["id"]: e for e in MODEL["elements"]}
Q = {q["id"]: q for qs in QS for q in qs["questions"]}
BASELINE = ROOT / "tests/fixtures/baseline-audit.jsonl"  # recorded answers for the hypothetical example
needs_baseline = pytest.mark.skipif(not BASELINE.exists(), reason="baseline run not shipped in tarball")


def test_control_tristate_splits_confirmed_vs_gap():
    e, q = BY_ID["api"], Q["R.audit_logging"]
    assert tm.outcome(e, q, "present", {}, MODEL, BY_ID)[0] is None
    assert tm.outcome(e, q, "absent_stated", {}, MODEL, BY_ID)[0] == tm.CONFIRMED
    st, _ = tm.outcome(e, q, "not_mentioned", {}, MODEL, BY_ID)
    assert st == tm.GAP and tm.final_severity(st, e, q, {}, MODEL, BY_ID) == "info"


def test_gaps_never_become_proposals(tmp_path):
    r = tm.run(MODEL, QS, tmp_path, lambda req: all_answers(req, yes_no=0.05, choice="not_mentioned"))
    assert all(p for p in r["risk_proposals"])
    gap_ids = {f["id"] for f in r["findings"] if f["status"] == tm.GAP}
    assert gap_ids and not gap_ids & {i for p in r["risk_proposals"] for i in p["findings"]}


def test_pii_flow_rule_tls_to_trusted_is_informational():
    e, q = BY_ID["f_user_api"], Q["I.sensitive_data_in_flow"]
    facts = {"T.transport_integrity": tm.code_fact(e, Q["T.transport_integrity"])}
    assert facts["T.transport_integrity"] == "present"
    assert tm.outcome(e, q, "yes", facts, MODEL, BY_ID)[0] == tm.INFORMATIONAL


def test_pii_flow_rule_plain_http_to_model_is_confirmed_high():
    e, q = BY_ID["f_agent_llm"], Q["I.sensitive_data_in_flow"]
    facts = {"T.transport_integrity": tm.code_fact(e, Q["T.transport_integrity"])}
    assert facts["T.transport_integrity"] == "absent_stated"
    st, _ = tm.outcome(e, q, "yes", facts, MODEL, BY_ID)
    assert st == tm.CONFIRMED and tm.final_severity(st, e, q, facts, MODEL, BY_ID) == "high"


def test_pii_flow_rule_less_trusted_zone_even_with_tls():
    m = json.loads(json.dumps(MODEL))
    by = {e["id"]: e for e in m["elements"]}
    by["f_user_api"]["source"], by["f_user_api"]["destination"] = "api", "user"  # container -> internet
    assert tm.outcome(by["f_user_api"], Q["I.sensitive_data_in_flow"], "yes",
                      {"T.transport_integrity": "present"}, m, by)[0] == tm.CONFIRMED


def test_rate_limiting_applies_to_processes_only():
    assert Q["D.rate_limiting"]["applies_to"] == ["process"]
    assert not tm.applicable(BY_ID["f_agent_llm"], Q["D.rate_limiting"], "STRIDE", BY_ID)


def test_cap_logging_max_medium():
    e, q = BY_ID["api"], Q["R.audit_logging"]
    assert tm.raw_severity(e, MODEL) in {"high", "critical"}
    assert tm.final_severity(tm.CONFIRMED, e, q, {}, MODEL, BY_ID) == "medium"


def test_cap_rate_limit_medium_unless_internet_and_no_auth():
    e, q = BY_ID["api"], Q["D.rate_limiting"]
    assert tm.final_severity(tm.CONFIRMED, e, q, {"S.authn_present": "present"}, MODEL, BY_ID) == "medium"
    assert tm.final_severity(tm.CONFIRMED, e, q, {"S.authn_present": "absent_stated"}, MODEL, BY_ID) == "high"


def test_cap_bola_shared_credential_on_pii_can_be_high():
    e, q = BY_ID["lookup_order"], Q["L6.shared_service_credential"]
    assert tm.final_severity(tm.CONFIRMED, e, q, {}, MODEL, BY_ID) == "high"
    m = json.loads(json.dumps(MODEL)); by = {x["id"]: x for x in m["elements"]}
    by["lookup_order"]["data_classification"] = "internal"
    assert tm.final_severity(tm.CONFIRMED, by["lookup_order"], q, {}, m, by) == "medium"


def test_prompt_injection_with_side_effect_tool_is_high_else_medium():
    e, q = BY_ID["summarizer"], Q["L2.untrusted_text_in_prompt"]
    assert tm.final_severity(tm.CONFIRMED, e, q, {}, MODEL, BY_ID) == "high"
    m = json.loads(json.dumps(MODEL)); by = {x["id"]: x for x in m["elements"]}
    by["summarizer"]["tools"] = []
    assert tm.final_severity(tm.CONFIRMED, by["summarizer"], q, {}, m, by) == "medium"


def test_autonomy_rule_needs_tools():
    q = Q["L3.autonomy_level"]
    assert tm.code_fact(BY_ID["summarizer"], q) == "acts_autonomously"
    assert tm.outcome(BY_ID["summarizer"], q, "acts_autonomously", {}, MODEL, BY_ID)[0] == tm.CONFIRMED
    m = json.loads(json.dumps(MODEL)); by = {x["id"]: x for x in m["elements"]}
    by["summarizer"]["tools"] = []
    assert tm.outcome(by["summarizer"], q, "acts_autonomously", {}, m, by)[0] == tm.INFORMATIONAL


def test_severity_enum_and_proposals_only_confirmed_high(tmp_path):
    r = tm.run(MODEL, QS, tmp_path, lambda req: all_answers(req, yes_no=0.95))
    assert all(f["severity"] in tm.SEVERITIES and f["status"] in tm.STATUSES for f in r["findings"])
    fid = {f["id"]: f for f in r["findings"]}
    for p in r["risk_proposals"]:
        for i in p["findings"]:
            assert fid[i]["status"] == tm.CONFIRMED and fid[i]["severity"] in ("high", "critical")


@needs_baseline
def test_replay_no_network_and_sanity_targets(tmp_path):
    r = tm.run(MODEL, QS, tmp_path, None, replay=tm.load_replay(BASELINE))
    assert r["mode"] == "replay"
    conf = {(f["element"], f["question_id"]) for f in r["findings"] if f["status"] == tm.CONFIRMED}
    assert ("lookup_order", "L6.shared_service_credential") in conf
    assert ("f_agent_llm", "I.sensitive_data_in_flow") in conf
    assert ("summarizer", "L2.untrusted_text_in_prompt") in conf
    assert ("llm", "L1.model_unpinned") in conf
    assert not any(f["element"] == "f_user_api" and f["status"] == tm.CONFIRMED for f in r["findings"])
    props = {(p["element"], p["family"]) for p in r["risk_proposals"]}
    assert props == {("lookup_order", "authz"), ("f_agent_llm", "data_exposure"),
                     ("summarizer", "prompt_injection"), ("llm", "model_endpoint"),
                     ("summarizer", "output_handling")}  # v2.1 R-OUTPUT-SINK
    rows = [json.loads(l) for l in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert all(x["mode"] == "replay" and x["input_sha256"] for x in rows)


@needs_baseline
def test_replay_unmapped_question_is_not_asked(tmp_path):
    qs = json.loads(json.dumps(QS))
    qs[0]["questions"].append({**qs[0]["questions"][0], "id": "S.brand_new", "replay_from": None})
    r = tm.run(MODEL, qs, tmp_path, None, replay=tm.load_replay(BASELINE))
    na = [f for f in r["findings"] if f["question_id"] == "S.brand_new"]
    assert na and all(f["status"] == tm.NOT_ASKED for f in na)


@needs_baseline
def test_cli_replay(tmp_path):
    rc = tm.main([str(ROOT / "examples/example-fastapi-agent.yaml"), "--replay", str(BASELINE),
                  "--out", str(tmp_path)])
    assert rc == 1 and (tmp_path / "findings.md").exists()
    assert tm.main([str(ROOT / "examples/example-fastapi-agent.yaml"), "--replay", str(BASELINE),
                    "--live", "--out", str(tmp_path)]) == 2


# ---------------- v2.1 ----------------
def test_flow_authn_only_on_boundary_crossing_flows():
    q = Q["S.authn_present"]
    assert tm.applicable(BY_ID["f_agent_llm"], q, "STRIDE", BY_ID)
    m = json.loads(json.dumps(MODEL)); by = {x["id"]: x for x in m["elements"]}
    by["f_agent_llm"]["crosses_boundary"] = False
    assert not tm.applicable(by["f_agent_llm"], q, "STRIDE", by)
    e = BY_ID["f_agent_llm"]
    assert tm.outcome(e, q, "absent_stated", {}, MODEL, BY_ID)[0] == tm.CONFIRMED
    assert tm.outcome(e, q, "not_mentioned", {}, MODEL, BY_ID)[0] == tm.GAP


def test_output_handling_cap_medium_unless_dangerous_sink():
    q = Q["L3.output_rendered_unsafely"]
    assert tm.final_severity(tm.CONFIRMED, BY_ID["summarizer"], q, {}, MODEL, BY_ID) == "high"  # tools
    m = json.loads(json.dumps(MODEL)); by = {x["id"]: x for x in m["elements"]}
    by["summarizer"]["tools"] = []
    assert tm.final_severity(tm.CONFIRMED, by["summarizer"], q, {}, m, by) == "medium"
    m["elements"].append({"id": "f_out", "type": "data_flow", "name": "summary to db", "source": "summarizer",
                          "destination": "db", "protocol": "TCP"})
    by = {x["id"]: x for x in m["elements"]}
    assert tm.final_severity(tm.CONFIRMED, by["summarizer"], q, {}, m, by) == "high"


# ---------------- pluggable adapter ----------------
def test_stub_adapter_runs_offline_and_is_used_by_cli(tmp_path):
    r = tm.run(MODEL, QS, tmp_path, tm.stub_transport())
    assert r["mode"] != "dry_run" and r["findings"]
    assert all(f["status"] in tm.STATUSES for f in r["findings"])
    rc = tm.main([str(ROOT / "examples/example-fastapi-agent.yaml"), "--live", "--adapter", "stub",
                  "--out", str(tmp_path / "cli")])
    assert rc in (0, 1) and (tmp_path / "cli" / "findings.json").exists()


def test_stub_uncertain_yes_no_goes_to_human_review(tmp_path):
    r = tm.run(MODEL, QS, tmp_path, tm.stub_transport(yes_p=0.5))
    yn = [f for f in r["findings"] if Q0.get(f["question_id"], {}).get("type") == "yes_no" and f["model"] != "code"]
    assert yn and all(f["status"] == tm.REVIEW for f in yn)


def test_key_placeholder_name():
    assert tm.KEY_ENV == "DECISION_MODEL_API_KEY"

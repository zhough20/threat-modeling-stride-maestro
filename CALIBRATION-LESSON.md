# Calibration lesson: severity inflation

## What happened
The first version asked "is control X present?" as a yes/no question.
The decision model answered "no" when the description did not mention the control.
Code treated every "no" as a finding and applied the full severity rubric.
Result on the hypothetical example: most findings were high or critical, and almost every finding became a risk proposal.
Reviewers could not find the real risks in the noise.

## Why
1. **Absence of evidence was scored as evidence of absence.** "Not mentioned" is a documentation gap, not a weakness.
2. **One rubric for all families.** Missing logging got the same severity as broken authorization on personal data.
3. **Questions applied too widely.** For example, rate limiting was asked of data flows, and PII questions were asked of processes.

## Fix
1. Control questions use pick-one with three values: `present`, `absent_stated`, `not_mentioned`.
   - `absent_stated` → confirmed finding.
   - `not_mentioned` → documentation gap (info). It never becomes a risk proposal.
2. Severity = min(rubric, family cap). Each cap has a public source (see WORKFLOW.md).
3. Code rules combine facts with model attributes (for example, PII is a finding only on plain transport, to a model, or to a less-trusted zone).
4. Facts that the model already states (protocol, autonomy) are decided in code. The decision model is not asked.
5. Only confirmed findings at high or critical become risk proposals, one per element and root cause.

## How to check
- Replay recorded answers with the new rules (no network). Compare before and after counts.
- Keep a short list of "sanity targets": known real risks that must stay confirmed after calibration.
- A human reviews every changed finding before you accept the new rules.

## General rule
Ask the decision model narrow, observable facts. Let code decide severity. Treat silence as a gap, not a finding.

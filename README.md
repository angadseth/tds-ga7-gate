# TDS GA7 — release gate

The deterministic release-gate implementation from GA7, plus the workflow
evidence each student's submission points at.

`release_gate_test.py` exercises the rules directly; `gates/` holds the policy
modules. Every workflow under `.github/workflows/` runs that test and is scoped
with `paths:` to its own file, so adding one does not re-run the others.

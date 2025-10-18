# Arkkeeper Honesty & Integrity Review

This report compares claims in `README.md` with the current implementation under `src/ark/` and associated assets. Each discrepancy highlights where the documented behavior overstates the tool's capabilities today.

## Summary

* Only the SSH enumerator is implemented; the README advertises broad multi-service coverage, a full rule engine, and multiple output/reporting backends that are not present.
* The CLI exposes a small subset of the documented commands and lacks options such as `ark rules`, `ark explain`, `ark export`, or `ark scan --online`.
* Repository structure and automated testing coverage are far leaner than described.

## Detailed Findings

### 1. Scanner Coverage

*Claim*: Arkkeeper "inspects common credential locations" across SSH, AWS, Git, GitHub/GitLab, Azure, GCP, npm/PyPI, Docker, and shell history.【F:README.md†L56-L66】

*Reality*: The only implemented scanner is `scan_ssh()`; the CLI imports just the SSH module and leaves other scanners as a TODO.【F:src/ark/cli.py†L69-L88】【F:src/ark/enumerate/ssh.py†L1-L206】 No other enumerator modules exist under `src/ark/enumerate/` beyond `ssh.py`.

### 2. Rule Engine & Scoring

*Claim*: README describes a YAML-driven rule engine with scoring, referencing modules such as `rules/engine.py`, `rules/parser.py`, and `rules/scoring.py`, along with weighted severity calculations.【F:README.md†L103-L141】【F:README.md†L400-L407】

*Reality*: The `scan` command does not load or evaluate YAML rules; it directly appends hard-coded findings produced by the SSH enumerator. There are no `engine.py`, `parser.py`, or `scoring.py` modules in `src/ark/rules/`, and no scoring data is computed in the CLI output.【F:src/ark/cli.py†L69-L124】

### 3. Rotation Playbooks & Calendar Integration

*Claim*: README states that Arkkeeper generates detailed rotation playbooks per finding and can export calendar reminders, including examples of per-finding directories and rollback instructions.【F:README.md†L143-L193】【F:README.md†L244-L256】

*Reality*: `ark rotate` writes a generic `rotate.sh` script containing placeholder commands; it does not derive remediation steps from findings or create category-specific logic beyond simple string checks in the script template.【F:src/ark/cli.py†L164-L198】【F:src/ark/cli.py†L364-L436】 Calendar reminders are generated only if `arkkeeper_outputs/findings.json` exists and use a single summary per finding rather than the detailed scheduling options shown in the README.【F:src/ark/cli.py†L200-L319】

### 4. CLI Command Surface

*Claim*: README documents a rich CLI with commands such as `ark rules --list`, `ark explain`, `ark compare`, `ark export`, `ark config`, `ark clean`, and `ark audit` with advanced flags (`--online`, `--quick`, etc.).【F:README.md†L337-L366】

*Reality*: The implemented CLI defines only `init`, `scan`, `report`, `rotate`, `selftest`, and `remind`. None of the additional commands or flags exist, and `ark rotate` lacks `--severity`, `--all`, or similar options.【F:src/ark/cli.py†L19-L319】

### 5. Reporting Backends

*Claim*: README advertises an interactive HTML dashboard featuring heatmaps and sortable tables, along with JSON schema outputs and CSV support.【F:README.md†L195-L242】【F:README.md†L305-L308】

*Reality*: The HTML report generator is a simple Jinja2 template without interactive elements; CSV output is not implemented anywhere in the codebase, and the JSON structure emitted by `scan` lacks the schema fields listed in the README.【F:src/ark/cli.py†L320-L361】【F:src/ark/cli.py†L89-L124】

### 6. Repository Layout & Tests

*Claim*: README outlines a complex repository with numerous submodules (`config.py`, multi-provider enumerators, rotation providers, utilities) and extensive unit/integration/security tests.【F:README.md†L372-L423】【F:README.md†L311-L333】

*Reality*: The `src/ark/` package lacks the majority of those modules; only `cli.py`, `enumerate/ssh.py`, and empty package initializers exist. The `tests/` directory contains a single SSH-focused test file rather than the described suite.【F:src/ark/cli.py†L1-L436】【F:src/ark/enumerate/ssh.py†L1-L206】【F:tests/test_ssh.py†L1-L199】

## Recommendations

1. Update `README.md` to match the current feature set (primarily SSH scanning, basic reporting, and template rotation scripts), or
2. Implement the missing functionality before claiming support for additional services, rule evaluation, and reporting features.

Until one of these actions occurs, the README substantially overstates Arkkeeper's present capabilities.

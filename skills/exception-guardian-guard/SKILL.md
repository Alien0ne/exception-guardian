---
name: exception-guardian-guard
description: Draft Sigma detection rules for revoked exceptions' CVEs that SigmaHQ does not cover, then run exception-guardian guard to validate, convert to Splunk/Sentinel/Defender and write hunt briefs.
---

# Exception Guardian: guard

## When to use

After `find`, when `guard.json` lists CVEs under `missing_drafts`: SigmaHQ has no rule for them and no draft exists.
Only the CVEs behind the REVOKE are listed there (in KEV, EPSS at or above the line, or used in an attack path).
CVEs under `not_drafted` carry none of those signals (a monthly rollup plugin can cover 78 CVEs): do not draft
them; say how many were skipped and why. A CVE with nothing a log can show (a CPU side channel such as Spectre or
Meltdown, CVE-2017-5715/5753/5754) gets no draft. Record it in `<run>/drafts/not-loggable.json` as
`{"CVE-2017-5715": "CPU side channel: it reads memory through cache timing and writes no log"}`, one reason per CVE,
then rerun guard. Guard stops asking for a draft, attaches no generic web-shell rules, and the report says to patch
or mitigate instead. Use it only when nothing in any log could show the attack, never to skip hard work.

CVEs under `coverage_gaps` have SigmaHQ rules that leave a gap: no query for one of the SIEMs (the rule reads a
log source that SIEM has no table or field for), or no rule catches the CVE's attack samples. Draft one rule per
such CVE that closes the gap, usually the same behaviour on `process_creation` or another source every target has,
and rerun guard. One valid draft ends the ask; if no log source can close it, say which SIEM stays without a query.

`guard.json` is keyed by REVOKE rule id. Each value holds `rules` (each with `file`, `origin`, `title`, `url`,
`conversions` per SIEM and `tested`), `dropped`, `missing_drafts`, `no_valid_draft`, `not_drafted`, `not_loggable`,
`needs_samples` and `coverage_gaps`.

When an exception has CVEs no log can show, check its other CVEs (under `not_drafted`) too: an accept for CPU side
channels lists Spectre, Meltdown, MDS and L1TF together, and only the ones with signals were checked. Add each one
of the same kind to `not-loggable.json` with its own reason; `handoff-guard.md` lists them.

## Drafting rules

Write one rule per CVE to `<run>/drafts/<CVE>.yml` (extra rules as `<CVE>-<suffix>.yml`).

- **Detection only.** Describe behaviour to look for. No exploit code, payloads, or step-by-step exploitation.
- `status: experimental` and `author: Exception Guardian (drafted)`.
- At least one real advisory URL in `references` (vendor advisory, GHSA, NVD). Check it exists; never invent one.
- Prefer `logsource: {category: process_creation, product: <os>}`: it converts to every target. Add a webserver or
  proxy rule only as an extra; it often converts to Splunk only.
- Scope to the affected hosts' OS (see the hunt brief's host list) and the vulnerable service's processes.
- Fill in `falsepositives` with real benign causes. Add tags such as `attack.t1190` and `cve.YYYY-NNNNN`.
- See `samples/golden/drafts/` for reviewed examples.

## Then

Run `exception-guardian guard --run <run>`. A draft that fails validation is not written and is listed under
`dropped` with its errors: fix it and rerun, at most twice. Report per-target results honestly: a target marked
`unsupported` has no query; say so rather than hand-writing one. A conversion's `note` must be passed on: a
placeholder such as `%DC-MACHINE-NAME%` is widened to match any value unless the config sets it under
`placeholders:`, so tell the reader to set it there (never edit the bundled rule). A rule whose placeholder sits in
a filter gets the stand-in `SET_<name>`, which excludes nothing: its query also returns the events the filter was
meant to drop until the config sets it; a Sentinel query on the `SecurityEvent` table needs that table in their workspace.

## Sample logs for untested rules

A rule whose log source has no sample events, or no attack events for its CVEs, is listed under `needs_samples` in
`guard.json`, and guard writes a brief for its log source to `<run>/sample-briefs/<log>.md`. For each brief:

1. Read the brief only. It names the log, the CVEs and the field names, and leaves out the rule's logic on
   purpose: do not open the rule's `detection` block while writing samples, or the samples will be written to fit it.
2. Read the CVE's public write-up (vendor advisory, CISA, a research post) and write what a defender's log would hold
   after the exploit runs. Never a working payload or exploit code.
3. Save labelled events to the file the brief names (`<run>/samples/<log>.jsonl`) with the Write tool,
   one log at a time: one file per call, never one script that writes them all. Every attack event cites the write-up's URL in
   `_source`. Write at least as many benign events: ordinary activity on the same log. Fields hold what the log
   records; `_note` says what the log shows, never how to attack.
4. Rerun guard. Rejected events are listed in `handoff-guard.md` with the reason: fix them once and rerun.

Guard marks these events as agent-written, and the report says so under each score. When you report the scores,
say which came from agent-written samples. A rule that misses attacks you wrote from the write-up is a real
finding: report it, never rewrite the samples to make the rule pass.

Each written rule carries `tested` in `guard.json`: how many attack samples it caught and how many benign events it
fired on in the labelled sample logs. A drafted rule that misses its own CVE's attack samples needs another look
before you hand it on; a benign hit should match one of its `falsepositives` lines, or be added there. Say that the
sample logs are synthetic when you report these numbers.

# Variant 2 — One Brain + one Muscle (agent loop)

The current, actively used architecture. A SINGLE strong model (Brain) makes every
decision, writes every command/script, reads output, and concludes. MUSCLE is a dumb
executor: it runs tools/VMs and returns raw, structured slices — it never concludes.
Canonical think → act → observe loop over a compressed Ledger
(KNOWN / ASSUMED / RULED-OUT), with $0 code guards (budget, stall=2, stop-don't-guess).

**Status:** the active, proven design — tested and used in practice on
**FLARE-On 12 (challenges 1–8)**, **FLARE-On 13 (challenges 1–9)** and **CSS CTF 2026:
Return to Nexus** (University of Sydney Cyber Security Society — used to solve **all** of
the challenges). It costs more API tokens than variant 1 but needs little local compute.

See the [repo root README](../README.md) for full setup (dependencies, VM tooling, AI
models, `.env`, and configuring flag detection per CTF) and the complete tool catalog
(29 Muscle tools).

The `recall` corpus is 178 distilled technique notes (FLARE-On RE plus a CSS-CTF-2026 set, `source: distilled/cssctf`, notes 161–179 covering web/crypto/pwn/forensics/signal/blockchain/OSINT) under `knowledge/notes/` — see [root README → recall](../README.md#the-recall-knowledge-base).

Run (from this folder):
    python3 -m agent.run <path-to-file>          # e.g. ../challenges/ch4/ToxicMiner.exe
    MAX_STEPS=40 python3 -m agent.run <path>      # raise the per-run step budget
    python3 -m agent.run <path> --resume          # resume from the last state dump
    python3 -m agent.run <path> 2>&1 | tee ../run.log   # keep a log to compare runs

Shared secrets live at the repo root (../.env, ../.ssh_keys).

## Brain tiers (orchestrator.py)

Two models: `BRAIN_MODEL` (default) and `BRAIN_TOP_MODEL` (top). Only code switches them:

- `_handle_stall()` — 2 consecutive analysis stalls (no new KNOWN) → escalate
  default → top; at top → **stop**. After `PIN_TOP_AFTER_ESCALATIONS` (2) escalations the
  top model is **pinned** for the rest of the run.
- `_handle_tool_errors()` — 3 consecutive operational errors (path/host, Frida syntax,
  timeout, SSH drop, crash) → escalate to top only to **repair the call**; at top → stop.
  Does not count as an escalation and never pins.
- De-escalation (loop in `solve()`) — 5 consecutive progressed steps at top, not
  pinned → back to default.
- Each tier switch re-writes the prompt cache for the other model (~23.5k tokens).

Full table: [root README → Brain tiers](../README.md#brain-tiers--escalation--de-escalation).

## Measurement & prompt caching

- `agent/metrics.py` — observe-only per-step measurement; prints `=== METRICS ===` at the
  end of a run and writes `_metrics.json` (section sizes, tokens, Brain vs tool seconds,
  reusable cache head). Compare runs of the same challenge before/after a change.
- `CACHE_LEDGER=1` (default) — `Workspace.render_state_parts()` + `reasoner._ledger_blocks()`
  send ARTIFACTS + KNOWN as a cached prefix (one block per KNOWN fact, breakpoint on the
  last). State order is most-stable-first; ASSUMED is not cached (sliding window); KNOWN
  is evicted in batches of `KNOWN_EVICT_BATCH`. `CACHE_LEDGER=0` turns it off.
- `reasoner.estimate_call()` — 1.6 chars/token for state, 2.4 for the system prompt
  (measured; hex/disassembly tokenize badly).

Details and measured numbers: [root README → Cost & speed](../README.md#cost--speed-measurement-and-prompt-caching).

## run_cmd and grep's exit 1

`tools._grep_shape()` reads an empty exit-1 from a single grep pipeline as **NO MATCH**
(a measured negative in KNOWN, not a tool error) and flags a grep with no file operand.
`tools._cmd_label()` shows commands up to 110 chars and marks any cut outside the
backticks. Measured reason: ch4 run 2 escalated to Opus on three honest "no match"
greps, then wasted 4 steps "fixing" a quoting bug that was only the 55-char display cut.

## Where the VM tools live

The 16 VM-control tools (`run_cmd`, `run_script`, `read_file`, `win_windows`,
`win_screenshot`, `win_gui_run`, `win_frida`, `win_ui_tree`/`win_ui_click`/
`win_ui_type`/`win_key`/`win_ui_seq`, `linux_gui_run`, `linux_gdb`, `job_start`,
`job_poll`) are registered here as usual but delegate to the **`dualvm`** package
(the Muscle). Their `@tool` name/description/args are unchanged, so `catalog()` is
byte-identical. The remaining tools (`triage`, `peek`, `author_and_run`,
`check_flag`, `extract`, `extract_images`, `pe_overview`, `decompile`, `view_image`,
`pdf_pages`, `ghidra_script`, `recall`, `r2`) stay here — they are CTF-specific.

Adding a VM capability now means adding it in `dualvm` **and** exposing a thin adapter
tool here; update both READMEs per the project rule.


## Rule for contributors

Every new function, rule, env knob or dependency is documented in this README **and** the
root README in the same change.

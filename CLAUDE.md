# CLAUDE.md — ctf-brain

> Read this first. Authoritative, stable entry point for any AI working with this
> repo: the architecture, how to run it, the full tool catalog the Brain can use, the
> cost/prompt-caching design, and the hard rules. Prefer this one file over
> re-reading all of `agent/`.

## What this is

**The Brain.** An AI agent that solves CTF / reverse-engineering challenges (built on
FLARE-On). One strong model **decides everything**, writes every script, reads output,
and concludes. It drives two VMs through the **Muscle** — the separate `dualvm` package
(`dual-vm-ai-agent`), which this repo depends on.

- **Brain = this repo** (`variant2_brain_muscle/agent/`): orchestrator + reasoner,
  calls the model API, owns everything CTF-specific (flag detection, the Workspace,
  Ghidra / radare2 analysis, the `recall` knowledge base).
- **Muscle = `dualvm`** (separate repo): deterministic `$0` VM control. The 16 VM tools
  here are **thin adapters** over `dualvm`; their `@tool` name/description/args are
  unchanged so `catalog()` is byte-identical (prompt cache unaffected).

Architecture is "1 Brain + 1 Muscle" (`variant2_brain_muscle/`, active).
`variant1_multinode/` is the older cheap multi-role prototype (legacy).

## Run

```bash
cd variant2_brain_muscle
source ../.venv/bin/activate
python3 -m agent.run ../challenges/ch4/ToxicMiner.exe        # one challenge
MAX_STEPS=40 python3 -m agent.run <path>                     # raise the step budget
python3 -m agent.run <path> --resume                         # resume last state
python3 -m agent.run <path> 2>&1 | tee ../run.log            # log to compare runs
```

Needs `../.env` (API key + VM hosts) and `../.ssh_keys/` — both git-ignored.
`BRAIN_MODEL` (default tier) ↔ `BRAIN_TOP_MODEL` (top tier). Install the Muscle:
`pip install -e ../dual-vm-ai-agent` (or the pinned dependency in `requirements.txt`).

## Tool catalog (29) — the Brain's muscle

The Brain is shown each tool's `@tool` description in `agent/tools.py`; read
`tools.catalog()` for the exact text it sees. Grouped:

- **CTF-specific (defined here):** `triage`, `peek`, `author_and_run`, `check_flag`,
  `extract`, `extract_images`, `pe_overview`, `decompile`, `view_image`, `pdf_pages`,
  `ghidra_script`, `recall`, `r2`.
- **VM control (delegated to `dualvm`):** `run_cmd`, `run_script`, `read_file`,
  `win_windows`, `win_screenshot`, `win_gui_run`, `win_frida`, `win_ui_tree`,
  `win_ui_click`, `win_ui_type`, `win_key`, `win_ui_seq`, `linux_gui_run`,
  `linux_gdb`, `job_start`, `job_poll`. **Full usage of these lives in the Muscle's
  `CLAUDE.md` (the `dual-vm-ai-agent` repo).**

Every tool returns a `ToolResult` (`ok, summary, detail, known, flag, info, image,
waiting`); the adapters convert `dualvm`'s `VMResult` 1:1. Flag detection
(`FLAG_RES`) stays in the Brain and is injected into the Muscle once with
`dualvm.set_matcher(_find_flag)`.

## Cost & prompt caching (already built — measure, don't guess)

- `agent/metrics.py` is observe-only: prints `=== METRICS ===` and writes
  `_metrics.json` (per-section state sizes, real tokens, Brain-vs-tool seconds,
  reusable cache head). **Compare the same challenge before/after any change.**
- `CACHE_LEDGER=1` (default): `ARTIFACTS + KNOWN` go out as a **cached prefix** (one
  block per KNOWN fact, breakpoint on the last). State order is most-stable-first so
  the cached prefix stays byte-identical across steps; `ASSUMED` is not cached
  (sliding window); `KNOWN` evicts in batches of `KNOWN_EVICT_BATCH`.
- Each Brain-tier switch rewrites the other model's cache (~23.5k tokens) — so tier
  changes are code-gated and rare.
- `reasoner.estimate_call()` uses 1.6 chars/token for state, 2.4 for the system
  prompt (hex/disassembly tokenize badly).

## Hard rules

- **Secrets never committed.** `.env`, `.ssh_keys/`, `challenges/`, `*.log`,
  `_run_state.json`, `_metrics.json` are git-ignored.
- **Documentation rule:** every new function, rule, env knob, dependency or plugin is
  documented in the **root `README.md` AND** the relevant variant's `README.md` in the
  **same change**.
- **Stop, don't guess:** at the top tier with no progress, the run stops rather than
  guessing. Progress = a new KNOWN fact, not a re-read.
- **Solvers must print every value** (enforced in `author_and_run`).
- Don't disassemble/exec marshalled Python bytecode from a different Python version
  (segfault) — decode statically via `co_consts`.

## Map

`variant2_brain_muscle/agent/`: `run.py` (entry), `orchestrator.py` (the loop +
tier logic), `reasoner.py` (model calls, prompt assembly, caching), `workspace.py`
(Ledger/artifacts), `tools.py` (tool registry + CTF tools + VM-tool adapters),
`remote.py` (shim → `dualvm.remote`), `metrics.py`, `config.py`. Technique corpus:
`knowledge/notes/`. Full setup & numbers: `README.md` and
`variant2_brain_muscle/README.md`.

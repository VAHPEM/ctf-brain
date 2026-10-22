# dual-vm-ai-agent — an AI that operates a two-VM lab

> Repository: [`dual-vm-ai-agent`](https://github.com/VAHPEM/dual-vm-ai-agent)
> (formerly `ctf-reverse-engineering-agent`) · project name: **ctf-brain**

**An LLM agent that works *inside* two real virtual machines — a Kali Linux VM and a
Windows VM — the way a human analyst would.** Over SSH it runs shell commands and whole
scripts, moves files between the machines, launches GUI programs and actually *sees* them
(screenshots fed back to the model), clicks and types through Windows UI Automation,
attaches debuggers (Frida on Windows, gdb on Linux), and starts long jobs that it polls
later. A single strong LLM (the **Brain**) decides every action and writes every script; a
set of deterministic, zero-cost tools (the **Muscle**) carry those actions out on the VMs
and return raw output — they never interpret or conclude.

The workload this has been built, tuned and proven on is **CTF reverse engineering**
(unpacking, decompiling, debugging, emulating, defeating obfuscation — the kind of puzzle
found in [FLARE-On](https://flare-on.com/)). It has been tested and used in practice on:

- **FLARE-On 12** — solved challenges **1–8**
- **FLARE-On 13** — solved challenges **1–9**
- **CSS CTF 2026: Return to Nexus** (University of Sydney Cyber Security Society) — used to solve **all** of the challenges

> **Current scope, stated honestly.** The VM-control layer (`agent/remote.py` and the
> Muscle tools) is general-purpose — nothing in it is CTF-specific. The *loop* that drives
> it is not yet: today the only entry point takes **files** as input, and a run ends when a
> **flag** is found (or the step budget / stall guard stops it). A generic task mode and a
> way for other AI clients to use the two VMs directly are on the [roadmap](#roadmap).

> Research / education project. Operate it only on files you own or on published,
> authorized CTF puzzles, inside a private, network-isolated lab. Challenge binaries are
> **not** included in this repo.

---

## Table of contents

1. [What the AI can do on the two VMs](#what-the-ai-can-do-on-the-two-vms)
   - [How the AI reaches the VMs](#how-the-ai-reaches-the-vms)
   - [Safety model](#safety-model)
2. [The two variants](#the-two-variants)
3. [How it works](#how-it-works)
   - [variant2 — Brain + Muscle](#variant2--brain--muscle-active)
   - [Brain tiers — escalation & de-escalation](#brain-tiers--escalation--de-escalation)
   - [variant1 — multi-node pipeline](#variant1--multi-node-pipeline-legacy)
4. [The Muscle toolset](#the-muscle-toolset)
5. [The recall knowledge base](#the-recall-knowledge-base)
6. [Repository layout](#repository-layout)
7. [Getting started from zero](#getting-started-from-zero)
   - [Prerequisites](#1-prerequisites)
   - [Clone the repo](#2-clone-the-repo)
   - [Python dependencies](#3-python-dependencies)
   - [The analysis VMs (the Muscle)](#4-the-analysis-vms-the-muscle)
   - [AI models](#5-ai-models)
   - [The `.env` file (API keys & VM addresses)](#6-the-env-file-api-keys--vm-addresses)
   - [Flag detection per CTF](#7-flag-detection-per-ctf)
8. [Running it](#running-it)
9. [Cost & speed: measurement and prompt caching](#cost--speed-measurement-and-prompt-caching)
10. [Design principles](#design-principles)
11. [Roadmap](#roadmap)
12. [License & scope](#license--scope)

---

## What the AI can do on the two VMs

Every capability below is a Muscle tool the Brain calls by name with arguments it chooses.
The tool runs on the VM and returns raw output (text, exit code, new files, or an image the
model can look at).

| Capability | Kali Linux VM | Windows VM |
|---|---|---|
| **Run a shell command** (real timeout, exit code, new-file detection) | `run_cmd` | `run_cmd host=windows` (cmd.exe, tree-killing timeout) |
| **Run a whole script the AI wrote** | `run_script`, `author_and_run` (Python / bash) | `run_script host=windows`, `author_and_run host=windows` |
| **Read files / bytes** | `read_file`, `peek` | `read_file host=windows` — if the file is not on the host asked for, the other VM is tried |
| **Unpack / extract** | `extract`, `extract_images` (archives, WIM, PE resources) | `extract` (7-Zip on Windows for WIM) |
| **See the screen** | `linux_gui_run` — program under Xvfb + screenshot | `win_screenshot` (the real desktop), `win_windows` (window list) |
| **Run a GUI program and watch it** | `linux_gui_run` | `win_gui_run` — exit code, or window titles + screenshot if still up |
| **Drive a GUI** (list controls, click, type, keys, sequences) | — | `win_ui_tree`, `win_ui_click`, `win_ui_type`, `win_key`, `win_ui_seq` (UI Automation) |
| **Debug a live process** | `linux_gdb` — gdb-python script, ASLR off, under Xvfb | `win_frida` — Frida JS inside the process (hook, read/patch memory) |
| **Static binary analysis** | `pe_overview`, `decompile`, `ghidra_script` (headless Ghidra), `r2` (radare2), `triage` | — (the binary is analysed on Kali) |
| **Long-running work** | `job_start` / `job_poll` | `job_start host=windows` / `job_poll` |
| **Look at an image / PDF** | `view_image`, `pdf_pages` (rendered, then shown to the model) | (screenshots come back the same way) |

A typical run therefore crosses both machines: decompile on Kali, run the sample on
Windows, screenshot its window, click through its UI, hook the check routine with Frida,
pull a dumped buffer back, and finish the math in a Python script on Kali.

### How the AI reaches the VMs

All of it lives in `variant2_brain_muscle/agent/remote.py` (≈430 lines, `paramiko` only):

- **One pooled SSH connection per VM, key auth only.** The private key lives in the
  git-ignored `.ssh_keys/`; a dropped connection is detected and re-opened, and a command
  whose channel never opened is retried once.
- **Output is never lost on a timeout.** `ssh_exec()` drains the channel as bytes arrive,
  so a command that printed its answer and then hung still returns what it printed, marked
  as real output that arrived before the timeout.
- **Real timeouts on both OSes.** Kali commands run under `timeout -k` in their own process
  group (a forking solver leaves no orphans); Windows commands go through a small launcher
  (`win_run_bounded()`) that kills the whole process tree and reports exit code `124`.
- **File transfer over SFTP** (`upload`, `write_remote`, `read_bytes`) into a per-VM
  `samples/` working directory. Long output is spilled to a file on the VM and paged back
  instead of flooding the model's context.
- **Reaching the Windows desktop.** An SSH login on Windows lands in *session 0*, which has
  no interactive desktop: screenshots fail ("The handle is invalid") and a GUI program
  paints a window nobody can see (a modal dialog then blocks it until the timeout).
  `run_in_session1()` crosses over with a one-shot interactive scheduled task that runs as
  the logged-on user in *session 1* — the real desktop — and collects its output.
  `win_windows`, `win_screenshot`, `win_gui_run`, the `win_ui_*` tools and `win_frida` all
  use it.

### Safety model

Letting a model type into real machines needs guardrails that do not depend on the model
behaving:

- **Isolated lab.** The VMs are meant to be disposable analysis machines (snapshot them)
  on a private, host-only network. The agent only ever opens SSH to the two addresses in
  `.env`.
- **Command filter in code.** `tools._security_block()` checks every command and every
  script body *before* it reaches a VM and refuses changes to security/system
  configuration: Windows Defender and firewall settings, service control, registry
  writes, ACL/boot config, disk formatting/encryption; Linux firewall rules, disabling
  security services, account management, interactive root shells, `rm -rf /`. Installing
  tools and libraries on the analysis VM is allowed — that is ordinary analysis work.
- **Bounded everything.** Per-call timeouts, a per-run step budget (`MAX_STEPS`), an
  optional token budget (`MAX_RUN_TOKENS`), and a stall detector that **stops the run**
  rather than letting the model keep guessing.
- **No secrets in the repo.** `.env` (API keys, VM addresses) and `.ssh_keys/` are
  git-ignored and never printed.

---

## The two variants

A deliberate cost-vs-capability trade-off:

| | **variant2** — 1 Brain + 1 Muscle | **variant1** — multi-node pipeline |
|---|---|---|
| Idea | one strong **API** model decides everything | fixed LangGraph of cheap/**local** models per role (triage → planner → coder → executor → evaluator) |
| Token cost | higher (a capable model does every step) | **lower** — cheap/local models, few or no API tokens |
| Hardware | light locally (reasoning is in the cloud) | **needs a strong machine** so the local model (the "muscle") is actually capable |
| Status | **active & proven** — FLARE-On 12 (1–8), FLARE-On 13 (1–9) | the original idea; **not yet well-refined**, kept for A/B comparison |

**`variant2_brain_muscle/` is the active design.** `variant1_multinode/` came first — it
trades API tokens for local compute, so it is cheaper to run but only as good as the local
model your hardware can host, and it has not yet been polished to the same level. Their
workflows are described side by side below.

---

## How it works

The two variants take opposite approaches to the same loop. **variant2** (active) puts one
strong model in charge; **variant1** (legacy) splits the work across cheap local models.

### variant2 — Brain + Muscle (active)

```
                 think → act → observe  (loop over a compressed Ledger)
   ┌──────────┐   decides everything,   ┌───────────────────────────────┐
   │  BRAIN   │   writes every script   │            MUSCLE             │
   │ (1 LLM)  │ ──────────────────────► │  ~29 deterministic tools, $0   │
   │          │ ◄────────────────────── │  run commands, return RAW out  │
   └──────────┘   raw tool output       └───────────────────────────────┘
                                              │ SSH (key auth)
                                   ┌──────────┴───────────┐
                                   ▼                      ▼
                           Kali Linux VM           Windows VM
                        (radare2, Ghidra,        (Frida, UI automation,
                         gdb, Xvfb, …)            x64 emulation, …)
```

- **Brain** — one strong model decides the next action, authors any command/script, reads
  the output, and updates its state. It reasons over a compressed **Ledger** of `KNOWN`
  (measured facts) / `ASSUMED` (unverified) / `RULED-OUT` (with evidence).
- **Muscle** — a dumb, deterministic executor. Each tool runs a command or a VM action and
  returns a raw, structured slice of output. **It never draws conclusions** — that is the
  Brain's job. This keeps the expensive model focused on reasoning and the cheap,
  reproducible work in code.
- **Guardrails** (all in code, $0): a hard per-challenge step budget; a *stall* detector
  (two consecutive steps with no new `KNOWN` ⇒ escalate to the stronger model, then **stop
  rather than guess**); a tool-error budget; and anti-loop nudges that stop the Brain
  re-reading the same bytes instead of writing the solver.
- **Two tiers, one seam** — a default model does the bulk of the work; on repeated stalls
  the run escalates to a stronger *top* model, then de-escalates on progress (exact rules:
  [Brain tiers](#brain-tiers--escalation--de-escalation)). Dispatch is
  by model-name prefix (`claude-*` → Anthropic, `gpt-*`/`o*` → OpenAI). **The Claude path
  is what has been tested in practice; the OpenAI path is implemented but not yet exercised
  end-to-end** (see `variant2_brain_muscle/smoke_openai.py` for a standalone check).

### Brain tiers — escalation & de-escalation

variant2 runs two models: `BRAIN_MODEL` (the **default** tier, does the bulk of the work)
and `BRAIN_TOP_MODEL` (the **top** tier, stronger and more expensive). Only code moves the
run between them (`agent/orchestrator.py`) — the model never picks its own tier.

| Trigger | Where | Effect |
|---|---|---|
| `STALL_THRESHOLD` (2) consecutive **analysis stalls** — the tool worked but showed nothing new (< `INFO_MIN_CHARS` of never-seen text), or repeated / re-read the same data | `_handle_stall()` | default → **top**, `ws.escalations += 1`, and a "change the KIND of approach" nudge. Already at top → the run **stops** (stuck at top ⇒ stop, don't guess). |
| `PIN_TOP_AFTER_ESCALATIONS` (default 2) analysis escalations in one run | `_handle_stall()` | `ws.pinned_top = True`: the top model keeps the endgame and never de-escalates again (fixes the default↔top flip-flop measured on ch7/ch8). |
| `TOOL_ERROR_BUDGET` (3) consecutive **operational** errors — wrong path/host, Frida/JS syntax, timeout, SSH/SFTP drop, tool crash | `_handle_tool_errors()` | default → **top** only to *repair the call* ("fix the call, not the plan" nudge). Not counted as an escalation, never pins. Already at top → stop (the tool/target is broken). |
| The controller cannot form a valid JSON action even after in-step re-asks | `_acquire_action()` → `_handle_stall()` | escalates like a stall. |
| `DEESCALATE_AFTER` (5) consecutive **progressed** steps at top, not pinned | main loop of `solve()` | top → **default** (`.. 5 steps of real progress -> back to DEFAULT tier`). Two fresh stalls escalate again. |

Cost note: Anthropic's prompt cache is **per model**, so every tier switch pays one fresh
cache write of the system prompt (~23.5k tokens measured). A spurious escalation is the
single most expensive event in a run.

### variant1 — multi-node pipeline (legacy)

A fixed [LangGraph](https://github.com/langchain-ai/langgraph) state machine where each
role is a **separate node running a cheap/local model** (default `qwen2.5-coder:7b` via
ollama):

```
  ┌────────┐   ┌─────────┐   ┌───────┐   ┌──────────┐   ┌───────────┐
  │ triage │──►│ planner │──►│ coder │──►│ executor │──►│ evaluator │
  └────────┘   └─────────┘   └───────┘   └──────────┘   └─────┬─────┘
                    ▲             ▲            ▲              │
                    │             │  retry the code          │
                    │             └──────────────────────────┤
                    │        try another strategy            │
                    └────────────────────────────────────────┘
                         (loops until solved or budget spent)
```

- **triage** — survey the file (type, strings) on the Kali VM.
- **planner** — pick a strategy from a fixed menu; on a malformed reply it re-asks once,
  more strictly.
- **coder** — write the solver / command for the chosen strategy.
- **executor** — run it on the VM and capture the output.
- **evaluator** — scan for the flag, then route back to **coder** (fix the code) or
  **planner** (try another strategy) until the flag is found or the step budget is spent.

Each stage is one cheap model call, so a run costs far fewer tokens than variant2 — but
every stage is only as capable as the local model, which is why it needs strong hardware
and is less robust on hard challenges. Entry point: `variant1_multinode/graph_skeleton.py`
(see [Running it](#running-it)).

---

## The Muscle toolset

variant2 gives the Brain ~29 deterministic tools. All are $0 (no model calls), return raw
output, and never interpret.

**Recon / read**
- `triage` — first-look survey of an input (file type, sections, entropy, imports, strings).
- `peek` / `read_file` — read bytes / paged text of an artifact or a produced file.
- `run_cmd` — run one shell command on a VM (real timeout, exit code, new-file detection).
  grep's exit-status convention is honoured (`_grep_shape()` in `tools.py`): a single
  pipeline with a `grep`/`egrep`/`fgrep`/`zgrep`/`rg` stage that exits 1 with no output is
  a **`NO MATCH`** result — a measured negative recorded in KNOWN, not a tool error (two
  empty searches in a row still count as a stall, by design). A `grep` given **no file**
  (it would read an empty stdin) is reported as exactly that. Commands chained with
  `&&`/`||`/`;` keep exit 1 as a failure. In the ledger a long command is cut at 110
  chars with the cut marked *outside* the backticks (`_cmd_label()`), so a truncated
  command never looks like one with an unclosed quote.
- `run_script` — run a whole Python/bash script the Brain wrote, on a VM.

**Solve**
- `author_and_run` — the Brain writes a solver; it runs and is forced to print every value.
- `check_flag` — scan text (or the last output) for the flag pattern.
- `extract` / `extract_images` — unpack archives / WIM, pull images out of PE resources.

**Vision**
- `view_image` — let the Brain actually see an image.
- `pdf_pages` — render PDF pages to images.

**Binary reverse-engineering**
- `pe_overview` — Ghidra full auto-analysis once; lists every function + imports.
- `decompile` — Ghidra decompiled C for one function (by name or address).
- `ghidra_script` — the Brain writes a custom Ghidra Java pass and it runs headless.
- `r2` — radare2, with the shell-out traps removed (functions, xrefs, disasm, strings).
- `recall` — search distilled RE technique notes from past CTFs (see next section).

**Windows dynamic / GUI** (over a second SSH session to the Windows VM)
- `win_frida` — scriptable debugger: the Brain writes Frida JS that runs inside the live
  process (breakpoints, read/patch memory, hook functions, drive a GUI).
- `win_windows`, `win_screenshot`, `win_gui_run` — inspect/see/run GUI programs.
- `win_ui_tree`, `win_ui_click`, `win_ui_type`, `win_key`, `win_ui_seq` — drive a GUI via
  UI Automation (list controls, click, type, key, click sequences).

**Linux dynamic / GUI**
- `linux_gdb` — scriptable gdb-python debugger; runs the target with ASLR off (fixed PIE
  base) under Xvfb so GUI / GTK / webkit binaries actually start.
- `linux_gui_run` — run a Linux GUI program under Xvfb and screenshot it.

**Long-running jobs**
- `job_start` / `job_poll` — start a long analysis in the background and poll it, so a slow
  job doesn't block the loop.

---

## Split: Brain (ctf-brain) + Muscle (dual-vm-ai-agent)

The VM-control layer now lives in its own package, **`dual-vm-ai-agent`** (import
name `dualvm`). The two repos map onto the variant2 design:

- **`ctf-brain` = the Brain.** The orchestrator and reasoner — it decides everything,
  calls the model API, and owns everything CTF-specific (flag detection, the
  Workspace, Ghidra/r2 analysis, the recall knowledge base).
- **`dual-vm-ai-agent` = the Muscle.** Deterministic, `$0`, no model calls: it runs
  commands on the Kali + Windows VMs and returns raw output. It has no concept of a
  flag or a challenge.

The 16 VM tools (`run_cmd`, `run_script`, `read_file`, `win_*`, `linux_*`,
`job_*`) keep their exact `@tool` names, descriptions and argument schemas here — so
the catalog the Brain sees is byte-identical and the prompt cache is unaffected — but
their bodies are now thin adapters that call `dualvm` and convert the returned
`VMResult` back into a `ToolResult`.

**Dependency:** `requirements.txt` includes `dual-vm-ai-agent` (install editable for
development: `pip install -e ../dual-vm-ai-agent`). `agent/remote.py` is a shim that
points `DUALVM_ENV`/`DUALVM_SSH_KEY` at this repo's `.env` and `.ssh_keys/`, then
re-exports `dualvm.remote` (one SSH implementation, shared).

**Flag detection** is injected into the Muscle once at startup
(`agent/tools.py` calls `dualvm.set_matcher(_find_flag)`) — `FLAG_RES` still lives
here, in the Brain.


## The recall knowledge base

`recall` is the agent's **memory of how this *kind* of challenge is usually cracked** — a
corpus of short "situation → technique" notes distilled from many reverse-engineers' CTF
writeups (not challenge-specific solutions). It ships with 178 notes under
`variant2_brain_muscle/knowledge/notes/`, tagged by situation (e.g. `qt-gui`,
`debug-disassembly`, `malware-c2`, `pcap-network`, `vm-obfuscation`, `firmware-uefi`). Most are distilled from FLARE-On RE work (`source: distilled/flareon`); a CSS-CTF-2026 set (`source: distilled/cssctf`, notes 161–179) widens the corpus beyond pure RE to web (GraphQL/SSRF), crypto (GF(p)/keystream), pwn, forensics (debugfs/timestomp), signal (SSTV/AFSK, chirp matched-filter), blockchain, OSINT and no-oracle packed-checksum puzzles. When
the Brain is stuck or a target feels familiar, it queries `recall("qt crackme per-keystroke
accumulator")` and gets back the few most relevant notes — it still decides and acts itself.

**Adding your own notes.** `scripts/ingest_writeups.py` turns a folder of writeup Markdown
into `recall` notes, chunked by heading, into `knowledge/writeups/` (git-ignored to keep
the repo lean). Run it where the writeup repos are cloned:

```bash
git clone --depth 1 https://github.com/pawlos/allthingsreversed.io /tmp/wr/allthingsreversed.io
cd variant2_brain_muscle && python3 scripts/ingest_writeups.py
```

> If you benchmark on a specific challenge, **exclude or distill** writeups of that same
> challenge to avoid contamination — the script's header explains which sources to treat as
> notes vs. as a regression test corpus.

---

## Repository layout

```
ctf-brain/
├── variant2_brain_muscle/       # ACTIVE agent
│   ├── agent/
│   │   ├── run.py               # entry point: python3 -m agent.run <file>
│   │   ├── orchestrator.py      # the think→act→observe loop, budget & tier escalation
│   │   ├── reasoner.py          # model dispatch, prompt caching, token accounting
│   │   ├── workspace.py         # artifacts + the Ledger (KNOWN/ASSUMED/RULED-OUT), state render
│   │   ├── metrics.py           # per-step token/section/time measurement (observe only)
│   │   ├── tools.py             # the Muscle: every tool + flag detection (FLAG_RES)
│   │   ├── remote.py            # SSH/SFTP to the Kali & Windows VMs
│   │   └── config.py            # models, budgets, prompt facts, knobs
│   ├── prompts.py               # system prompt (lab/CTF context)
│   ├── ctf_playbook.py          # RE discipline the Brain reads
│   ├── knowledge/notes/         # distilled technique notes for `recall`
│   ├── scripts/ingest_writeups.py
│   └── technique_archive.md
├── variant1_multinode/          # legacy multi-role LangGraph prototype (local models)
│   └── graph_skeleton.py        # run: python3 graph_skeleton.py <file>
├── docker-x86/                  # x86 helper container
├── requirements.txt             # host (orchestrator) dependencies
├── requirements-vm.txt          # analysis-VM Python toolbox (install on Kali venv)
└── .env.example                 # copy to .env and fill in (never commit .env)
```

Not committed (see `.gitignore`): `.env`, `.ssh_keys/`, `challenges/`, VM `samples/`, run
logs (`*.log`), run state (`_run_state.json`, `_metrics.json`), `knowledge/writeups/`, and
other scratch.

---

## Getting started from zero

This section assumes you have never seen the repo before.

### 1. Prerequisites

- A **host machine** to run the orchestrator (macOS or Linux) with **Python 3.10+** and
  `git`. This machine does not need to be powerful for variant2 — the heavy reasoning is a
  cloud API call.
- **Two analysis VMs** the host can reach over SSH (a typical local setup uses a hypervisor
  on the same host, e.g. addresses like `192.168.64.5` / `192.168.64.10`):
  - a **Kali Linux VM** (Linux RE tooling), and
  - a **Windows VM** (for Windows binaries and GUI/Frida work).
  You can start with only Kali if you don't need Windows challenges.
- For **variant2**: an API key from Anthropic (and/or OpenAI).
- For **variant1** (or a local fallback): a machine strong enough to run a local LLM.

### 2. Clone the repo

```bash
git clone https://github.com/VAHPEM/dual-vm-ai-agent.git ctf-brain
cd ctf-brain
```

Cloning into a folder named `ctf-brain` keeps every path in this README (`ctf-brain/…`,
`/path/to/ctf-brain/requirements-vm.txt`) valid as written.

### 3. Python dependencies

Install on the **host** into a virtualenv:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

What they are for: `anthropic`, `openai` (Brain via API) · `paramiko` (SSH/SFTP to the VMs)
· `python-dotenv` (`.env` loading) · `py7zr` (7-zip archives) · `pillow`, `pymupdf` (image /
PDF handling for `view_image`, `pdf_pages`) · `ollama` (local-model client, variant1 /
fallback) · `langgraph` (variant1 only).

### 4. The analysis VMs (the Muscle)

The tools run **on the VMs**, not on the host, so the RE toolchain must be installed on
each VM. The agent probes what's available at startup and degrades gracefully if something
is missing — but the more you install, the more the Brain can do. You can start with only
Kali; the Windows VM is optional and only needed for Windows targets.

#### Kali VM — Linux targets

**System tools** (apt):

```bash
sudo apt update
sudo apt install -y \
    radare2 gdb binwalk binutils file p7zip-full \
    xvfb xdotool imagemagick \
    openjdk-21-jre-headless
```

- `radare2`, `gdb`, `binwalk`, `binutils` (`objdump`), `file`, `p7zip-full` (`7z`) —
  static RE, unpacking, archives.
- `xvfb` + `xdotool` + `imagemagick` — run and screenshot Linux GUIs, and back `linux_gdb`
  (GUI/webkit binaries start under a virtual display).
- `openjdk-21-jre-headless` — required to run Ghidra.

**Ghidra (headless)** — download a release, unzip, and put `analyzeHeadless` on the `PATH`
(the agent calls the bare command name):

```bash
# https://github.com/NationalSecurityAgency/ghidra/releases  (unzip anywhere)
echo 'export PATH="$HOME/ghidra/ghidra_11.4.2_PUBLIC/support:$PATH"' >> ~/.zshrc
source ~/.zshrc
analyzeHeadless        # should print usage, not "command not found"
```

**Python analysis venv** — the Brain's solver scripts import a large RE toolbox (capstone,
unicorn, angr, z3, pefile, lief, pwntools, pycryptodome, uncompyle6, scapy, capa, floss, …).
Create the venv at the path the agent expects and install [`requirements-vm.txt`](requirements-vm.txt):

```bash
python3 -m venv ~/ctf-venv
~/ctf-venv/bin/pip install -r /path/to/ctf-brain/requirements-vm.txt
```

The default interpreter is `~/ctf-venv/bin/python3`; if you put the venv elsewhere, set
`KALI_PYTHON` in `.env`.

**Optional — [pyghidra-mcp](https://github.com/clearbluejar/pyghidra-mcp)** (persistent
Ghidra server). *Installed on the reference Kali VM but **not wired into the agent**.* It
keeps one Ghidra JVM + project open, so a query costs ~0.3 s instead of ~2–5 s per
`analyzeHeadless` call. Measured on ch4: tools are only 21–26% of a run's wall time and
`decompile` ~2–5 s of it (the Brain is 74–79%), so it was **not worth integrating yet** —
revisit if metrics show many Ghidra calls per run. Install into its **own** venv with
Python 3.13 (JPype has no 3.14 wheel) and Ghidra's bundled `pyghidra` wheel:

```bash
python3.13 -m venv ~/pyghidra-venv
~/pyghidra-venv/bin/pip install --no-index \
    -f /usr/share/ghidra/Ghidra/Features/PyGhidra/pypkg/dist pyghidra
~/pyghidra-venv/bin/pip install pyghidra-mcp pyghidra-mcp-cli

export GHIDRA_INSTALL_DIR=/usr/share/ghidra
~/pyghidra-venv/bin/pyghidra-mcp --transport streamable-http \
    --project-path ~/ctf_work/pgm_proj --wait-for-analysis <binary>     # 127.0.0.1:8000
~/pyghidra-venv/bin/pyghidra-mcp-cli list binaries                     # in another shell
~/pyghidra-venv/bin/pyghidra-mcp-cli decompile --binary /<name> <function>
```

The first start downloads a 79 MB embedding model (`~/.cache/chroma`, semantic search).
The JVM stays resident — stop the server when idle on a small VM.

#### Windows VM — Windows targets (optional)

Needed only for Windows binaries / GUI challenges (the `win_*` tools). Install Python and
Frida; UI automation (`win_ui_*`) uses built-in PowerShell, so nothing else is required:

```powershell
pip install frida frida-tools
```

The agent invokes Python at
`C:\Users\<you>\AppData\Local\Programs\Python\Python3xx\python.exe` by default — set
`WIN_PYTHON_EXE` in `.env` to match your actual install path.

#### SSH access (the repo ships NO keys)

The repository contains **no credentials of any kind.** You generate your own key, keep the
**private** half in `.ssh_keys/` (which is git-ignored and is never committed or printed),
and install the **public** half on each VM:

```bash
ssh-keygen -t ed25519 -f .ssh_keys/ctf_orchestrator_ed25519 -N ""
ssh-copy-id -i .ssh_keys/ctf_orchestrator_ed25519.pub <user>@<kali-ip>
ssh-copy-id -i .ssh_keys/ctf_orchestrator_ed25519.pub <user>@<win-ip>   # only if using Windows
```

### 5. AI models

**variant2 (recommended) — cloud API, no local model needed.** Put an API key in `.env`
(next step) and set the model ids. Dispatch is by name prefix: a `claude-*` id routes to
Anthropic, a `gpt-*`/`o*` id routes to OpenAI. **Only the Claude path has been tested in
practice**; the OpenAI path is implemented but not yet run end-to-end (verify it in
isolation with `python3 smoke_openai.py` from `variant2_brain_muscle/`). You choose two
tiers:

```dotenv
BRAIN_MODEL=claude-sonnet-...        # default tier — does most steps
BRAIN_TOP_MODEL=claude-opus-...      # escalation tier — harder steps / stalls
```

**variant1 (or a local fallback) — a local model via [ollama](https://ollama.com).** Install
ollama on a strong machine, pull a code model, and run the server:

```bash
# on the machine that will host the model:
ollama pull qwen2.5-coder:7b          # the model variant1 uses by default
ollama serve                          # exposes http://<that-host>:11434
```

Point the agent at it with `OLLAMA_HOST=http://<that-host>:11434` when you run variant1.
(To change variant1's model, edit `MODEL` in `variant1_multinode/graph_skeleton.py`.) If
`BRAIN_MODEL` is unset, variant2 refuses to silently fall back to a local model unless you
opt in with `ALLOW_LOCAL_BRAIN=1`.

### 6. The `.env` file (API keys & VM addresses)

Copy the template and fill it in. `.env` lives at the **repo root** (next to
`variant2_brain_muscle/`) and is git-ignored — **never commit it.**

```bash
cp .env.example .env
$EDITOR .env
```

| Variable | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` | Brain via Claude API (`claude-*` models) |
| `OPENAI_API_KEY` | Brain via OpenAI API (`gpt-*` models) — optional |
| `BRAIN_MODEL` | default-tier model id |
| `BRAIN_TOP_MODEL` | escalation-tier model id |
| `KALI_HOST`, `KALI_USER` | Kali VM address and SSH user |
| `WIN_HOST`, `WIN_USER` | Windows VM address and SSH user |
| `KALI_PYTHON` | *(optional)* Kali venv interpreter — default `~/ctf-venv/bin/python3` |
| `WIN_PYTHON_EXE` | *(optional)* Windows `python.exe` full path |

Get an Anthropic key at <https://console.anthropic.com/> (an OpenAI key at
<https://platform.openai.com/>). Keep keys out of the code and out of git — the API key is
read only from `.env` at runtime.

### 7. Flag detection per CTF

The agent decides "solved" when a tool's output matches a **flag pattern**. Patterns live in
one place — the `FLAG_RES` list in `variant2_brain_muscle/agent/tools.py`:

```python
# FLARE-On flags are always <text>@flare-on.com
FLAG_RES = [
    re.compile(r"[A-Za-z0-9_.\-+]{4,}@flare-on\.com"),
]
```

**To target a different CTF, edit this list.** Examples:

```python
FLAG_RES = [
    re.compile(r"[A-Za-z0-9_.\-+]{4,}@flare-on\.com"),   # FLARE-On
    re.compile(r"flag\{[^}]{1,200}\}"),                  # generic flag{...}
    re.compile(r"CTF\{[^}]{1,200}\}"),                   # e.g. picoCTF-style
    re.compile(r"HTB\{[^}]{1,200}\}"),                   # Hack The Box
]
```

`_find_flag` returns the **first non-placeholder** match, so a decoy like `flag@flare-on.com`
or `flag{...}` template earlier in the output won't mask the real flag later. Obvious
placeholders (`flag`, `example`, `xxxx`, `____`, …) are rejected automatically via the
`_FLAG_PLACEHOLDERS` set — extend it if your CTF has its own template strings. Keep patterns
**specific** (a delimiter or domain), not a bare `\{.*\}`, so binary noise isn't mistaken for
a flag.

---

## Running it

**variant2** (from its folder):

```bash
cd variant2_brain_muscle
source ../.venv/bin/activate
python3 -m agent.run ../challenges/09_neonoutrun
```

- Input is a **file or a directory** (a directory's files are all ingested).
- Raise the step budget for a run: `MAX_STEPS=40 python3 -m agent.run <path>`
- Resume a previous run: `python3 -m agent.run <path> --resume [state.json]`
- On finish it prints the flag (or `not found`), a full token-usage breakdown and the
  `METRICS` block (see [Cost & speed](#cost--speed-measurement-and-prompt-caching)).
- Keep a log for later comparison: `python3 -m agent.run <path> 2>&1 | tee ../run.log`

**variant1** (cheaper, local model):

```bash
cd variant1_multinode
OLLAMA_HOST=http://<model-host>:11434 python3 graph_skeleton.py <path-to-file>
```

### Useful environment knobs (variant2)

| Variable | Default | Effect |
|---|---|---|
| `MAX_STEPS` | `20` | hard per-challenge step cap |
| `MAX_RUN_TOKENS` | `0` (off) | optional token budget |
| `SEED_RECALL` | — | pre-seed `recall` notes from the input's shape |
| `PIN_SMALL_FILES_MAX_CHARS` | `4000` | pin small input files into context to stop re-reads |
| `INSPECT_NUDGE_AFTER` | `5` | nudge toward writing a solver after N read-only steps |
| `ALLOW_LOCAL_BRAIN` | — | accept a local ollama Brain when `BRAIN_MODEL` is unset |
| `CACHE_LEDGER` | `1` (on) | cache the ARTIFACTS+KNOWN head of each step's prompt; `0` = off (A/B) |
| `CACHE_TTL` | empty (5 min) | TTL of the cached **system** prompt, e.g. `1h` (writes then cost 2×) |
| `PIN_TOP_AFTER_ESCALATIONS` | `2` | analysis escalations before the top model is pinned for the run |
| `METRICS_DUMP` | `_metrics.json` | where per-step measurements are written |
| `STATE_DUMP` | `_run_state.json` | ledger snapshot per step (used by `--resume`) |

(See `agent/config.py` for the full list.)

---

## Cost & speed: measurement and prompt caching

### Step-0 metrics (`agent/metrics.py`)

Every variant2 run ends with a `=== METRICS (step-0 measurement) ===` block and writes
per-step detail to `_metrics.json`. It only **observes** (a failure inside it is swallowed,
never breaks a run). Per step it records: the size of each section of the user message
(KNOWN / ASSUMED / observations / …), provider-reported tokens (uncached in, out, cache
read, cache write), Brain seconds vs tool seconds, and how much of the ARTIFACTS+KNOWN head
is reusable from the previous step. Use it **before and after** any optimisation.

Measured on FLARE-On 13 ch4 (20 steps): the Brain is **74–79% of wall time**, tools
21–26% (36 s of that is one `pe_overview`); the uncached per-step state is ~50%
observations, ~20% KNOWN, ~15% ASSUMED.

### What is cached (Anthropic `cache_control`, max 4 breakpoints)

1. the static system prompt (identity, discipline, playbook) — `CACHE_TTL`;
2. the run context (environment facts, tool catalog, seeded notes) — `CACHE_TTL`;
3. **the head of each step's user message**: ARTIFACTS + KNOWN (`CACHE_LEDGER`, plain
   5-minute TTL). `Workspace.render_state_parts()` returns `(head_pieces, tail)`, one text
   block per KNOWN fact, and `reasoner._ledger_blocks()` puts the breakpoint on the last
   one. KNOWN only grows at its end, so last step's breakpoint is still a block boundary
   and the API's ~20-block lookback finds that prefix: it is billed as a cache **read**
   (0.1×); only the new facts are written.

Rules that keep it working:

- **Most-stable first.** State order is ARTIFACTS → KNOWN → | ASSUMED → RULED OUT →
  observations → recent actions → stall nudge (the nudge used to be first).
- **ASSUMED is not cached** — it is a sliding window (newest `ASSUMED_CAP`), so its start
  changes every step.
- **Evict in batches.** Past `KNOWN_CAP` (70) the oldest unpinned facts are dropped
  `KNOWN_EVICT_BATCH` (15) extra at a time; one-per-step eviction would miss every step.
- The text the model reads is byte-identical to the plain-string prompt; only block
  boundaries differ. Non-Anthropic models get the plain string.

Measured (ch4, run 1 without → run 2 with): uncached input per state character
0.54 → 0.43 tokens (**~21% less**); per-step `cache_r` grows ~23.7k → ~25.5k while
`cache_w` is ~50–150 tokens per step.

### Token estimates (`MAX_RUN_TOKENS` guard)

Hex dumps and disassembly tokenize badly: **1.6–2.0 chars/token** measured for the
per-step state, ~2.5 for the system prompt + tool catalog (not the 3–4 of prose).
`reasoner.estimate_call()` uses `USER_CHARS_PER_TOKEN = 1.6` and
`SYSTEM_CHARS_PER_TOKEN = 2.4` so the budget guard over- rather than under-estimates.

### Measured and deferred

- **pyghidra-mcp** — saves ~2–4 s per Ghidra call ≈ 2% of a run (see the Kali section).
- **`output_config.effort`** — output is only ~400 tokens per call; little to save.
- **Lossy tool-output compressors** (e.g. Headroom) — rejected: a lost hex byte or address
  breaks an RE solve; the agent already trims observations reversibly (re-read with
  `peek`/`read_file`).

---

## Design principles

- **Measure, don't assume.** A conclusion is only `KNOWN` once a tool measured it;
  everything else is `ASSUMED` until verified.
- **Emptiness is a measurement.** Two cheap static looks at the same question coming back
  empty means the answer is built at runtime or the call is obfuscated — switch to dynamic
  analysis instead of repeating the search with a bigger regex.
- **Stop rather than guess.** At the top tier with no progress, the run stops for a human
  instead of emitting a plausible-looking wrong flag.
- **Change one thing at a time**, and verify each fix on a real run before the next —
  with `metrics.py` numbers from the same challenge before and after.
- **The Muscle never interprets.** Tools return raw output; conclusions are the Brain's.
- **Only code changes the tier.** Escalate on measured stalls / tool-error budget,
  de-escalate on measured progress, stop at the top instead of guessing.
- **Prompt order = most stable first**, so the cacheable prefix stays byte-identical.
- **Every new function, rule, knob or dependency goes into this README** and the README
  of the variant it belongs to, in the same change.

---

## Roadmap

Ordered, one step at a time, each measured on the CTF baseline before the next so the
proven workload does not regress:

1. **Generic task mode** — `python3 -m agent.run --task "<instruction>" [files…]`: the run
   ends when the Brain reports the task done *with evidence from a tool*, instead of when a
   flag regex matches. Touches `run.py`, the stop condition in `orchestrator.py` and a
   prompt branch; CTF mode stays the default.
2. **The two VMs as an MCP server** — expose the Muscle tools over the Model Context
   Protocol so any MCP client (Claude Desktop, Claude Code, …) can drive the Kali and
   Windows VMs directly, with the same command filter and timeouts, without going through
   the Brain loop.

---

## License & scope

For security research and education. The agent executes model-written commands on real
machines: run it only on disposable VMs in a private, network-isolated lab, and only
against files you are authorized to analyze (your own, or published CTF challenges
intended to be solved). Challenge binaries are **not** included in this repository.

# -*- coding: utf-8 -*-
"""Toolbox = an OPEN REGISTRY of typed, cheap, verifiable tools (the "muscle").
Each tool: fn(ws, **args) -> ToolResult. Add a capability by registering a new
tool here; the Orchestrator loop never changes.
"""


import re


import os


import ast


import json


import shlex


import base64


import struct


import time as _time


from dataclasses import dataclass, field


from . import remote


from . import reasoner
from dualvm import (shell as dvm_shell, windows as dvm_windows,
                    linux as dvm_linux, jobs as dvm_jobs)
import dualvm as _dualvm



# FLARE-On flags are always <text>@flare-on.com. The old generic `flag\{[^}]{0,200}\}`
# was REMOVED: it matched the solver's own echoed search pattern ("b'flag{'") plus
# binary noise up to a stray '}' byte -> a false SOLVED (run 1, ch4).
FLAG_RES = [
    re.compile(r"[A-Za-z0-9_.\-+]{4,}@flare-on\.com"),
]


# Commands that change SECURITY/SYSTEM config, never needed to solve a challenge (the
# official writeups never touch these) but seen once in practice: run 3 (ch4) had the
# Brain disable Windows Defender real-time protection + add a scan exclusion just to
# force a flagged sample to execute, instead of treating the AV block as information.
# Scope is deliberately narrow: EXECUTING the sample itself is still allowed.
# A word only counts as a COMMAND when it stands in command position: start of a
# line, right after a shell separator (; & |), or right after sudo/doas/xargs.
# Measured 2026-09-22: the old bare-word patterns blocked ordinary RE work -
# `cat /etc/passwd`, `grep -r 'useradd' extracted/`, `objdump ... | grep passwd`,
# `echo 'sc create' >> notes.txt`, and any solver whose COMMENT mentioned
# iptables - exactly the same failure mode as the `cipher` bug that killed the
# last 3 steps of the ch2 run. `(?!\s*=)` additionally spares python assignments
# (`iptables_rules = [...]`, `passwd = "..."`) at the start of a line.
_CMDPOS = r"(?:^|[\n;&|]\s*|\bsudo\s+|\bdoas\s+|\bxargs\s+)"


_BLOCKED_PATTERNS = [
    (r"\b-MpPreference\b", "Windows Defender config (Add/Set/Remove-MpPreference)"),
    (r"Disable-\w*(Protection|Defender|Realtime)", "disabling Windows security protection"),
    (r"netsh\s+advfirewall", "Windows firewall config"),
    (_CMDPOS + r"sc(\.exe)?\s+(stop|config|delete|create)\b", "Windows service control"),
    (_CMDPOS + r"reg(\.exe)?\s+(add|delete)\s", "Windows registry write"),
    (_CMDPOS + r"(bcdedit|takeown|icacls)\s", "Windows system/ACL config"),
    (r"\bcipher\.exe\b|\bcipher\s+/[a-zA-Z]", "Windows disk-encryption utility (cipher.exe)"),
    # Installing tools/libraries/interpreters on the analysis VM is ORDINARY RE work
    # and is allowed (granted 2026-09-22). Only an INTERACTIVE root shell stays
    # blocked: whatever gets typed into it never passes through this filter at all.
    (r"\bsudo\s+(su|-i|-s|bash|sh|zsh|dash|fish)\b", "interactive root shell (sudo su / sudo -i)"),
    (_CMDPOS + r"(iptables|ip6tables|nft|ufw)(?!\s*=)\s", "Linux firewall config"),
    (_CMDPOS + r"systemctl\s+(stop|disable|mask)\s+\S*(firewall|ufw|apparmor)",
     "disabling a host security service via systemctl"),
    (_CMDPOS + r"(useradd|userdel|usermod|chpasswd|passwd)(?!\s*=)\s", "Linux account management"),
    (r"\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+/(\s|$)", "recursive delete of filesystem root"),
    (_CMDPOS + r"(mkfs(\.\w+)?|diskpart)\b", "disk formatting/partitioning"),
    (r"^\s*format\s+[a-zA-Z]:", "Windows disk format"),
]


def _security_block(text):
    """Return a human reason if `text` (a run_cmd command or a run_script/solver body)
    touches security/system config, else None. Checked BEFORE anything reaches a VM."""
    for pat, why in _BLOCKED_PATTERNS:
        if re.search(pat, text or "", re.IGNORECASE | re.MULTILINE):
            return why
    return None


TOOLS = {}  # name -> {"fn", "desc", "args"}


def _clamp_page(length):
    """A paging tool must never hand back more than the Brain will actually be shown,
    or its own "next offset" becomes a lie (measured ch6, 2026-09-23: 12000 requested,
    3500 shown, 8500 silently skipped every page). Returns (length, note)."""
    from . import config
    n = int(length or SLICE)
    if n > config.PAGE_MAX:
        return config.PAGE_MAX, (f"  (asked for {n}, capped to {config.PAGE_MAX} - that "
                                 "is all one turn can show you; continue from the "
                                 "offset below)")
    return n, ""


# how much raw output a single tool call returns inline before it spills to a
# host file that the Brain pages through with read_file
SLICE = 4000


def tool(name, desc, args):
    def deco(fn):
        TOOLS[name] = {"fn": fn, "desc": desc, "args": args}
        return fn
    return deco


@dataclass
class ToolResult:
    ok: bool
    summary: str                       # short line -> ledger + history
    detail: str = ""                   # longer, optional
    known: list = field(default_factory=list)   # facts to add as KNOWN (only if the step made progress)
    flag: str = None
    info: str = None                   # text the Brain actually saw, for novelty accounting
                                       # (None -> detail, else the known facts)
    image: dict = None                 # {"media_type": "image/png", "data": <base64>} - a picture
                                       # for the Brain to SEE on its NEXT decide() call only
                                       # (orchestrator clears it after one use, single-shot)
    waiting: bool = False              # "this step is legitimately WAITING on work that is


                                       # still running" - neither progress nor a stall. Without
                                       # it, polling a long job looks identical to going in
                                       # circles: the output barely changes, so novelty is ~0,
                                       # so every poll increments the stall counter and two of
                                       # them escalate to the top tier and then end the run -
                                       # while the job it was waiting for was working fine.


def catalog():
    lines = []
    for n, t in TOOLS.items():
        lines.append(f'- {n}: {t["desc"]}  args={t["args"]}')
    return "\n".join(lines)


_SPILL_N = [0]


def _spill(host, text, stem="out"):
    """The ONE way a tool hands back output longer than it can show inline.

    Two failures this replaces, both measured on real runs:
      * EVERY large run_cmd/run_script spilled to the SAME `_cmd_out.txt`. The Brain
        noted "full output -> samples/_cmd_out.txt", ran another big command, then
        read that path back and silently got the OTHER command's output. ch6 run 2
        step 29 did exactly this: its own note says it was fetching the sed 869-1140
        output, and it read step 28's instead. No error, no warning, wrong data.
      * win_windows / win_gui_run / pdf_pages just did text[:SLICE] - everything past
        4000 characters was gone with no way to ask for it.

    Returns (inline_text, saved_path_or_None); the name is unique to THIS call.
    """
    # SLICE (4000) is the default PAGE size for peek/read_file; it is NOT the size of
    # what one turn can SHOW. That is config.OBS_CAP_NEWEST (12000). head + marker +
    # tail must stay under it, or render_state trims the result again on its way into
    # the prompt.
    if len(text) <= SLICE:
        return text, None                      # tiny: no host file needed
    from . import config as _cfg
    budget = max(int(getattr(_cfg, "OBS_CAP_NEWEST", 12000)) - 1900, SLICE)
    tail_n = 1200
    _SPILL_N[0] += 1
    name = f"_{stem}_{_SPILL_N[0]:03d}.txt"
    # ALWAYS persist output larger than one PAGE, so it can be paged back on a LATER
    # turn once the observation window has trimmed it. Regression measured 2026-09-23:
    # a version that "saved nothing when it fits the window" showed a 6000-char result
    # in full THIS turn but left no file, so the next turn (window trimmed to 1400) the
    # Brain had to RE-RUN the command to see it again. Callers that keep `saved` put the
    # path in their KNOWN line, so it survives in the ledger.
    saved = _save_to_host(host, name, text)
    if len(text) <= budget + tail_n:
        return text, saved                     # fits one turn: show whole, file kept
    host_arg = "" if host == "kali" else f', host="{host}"'
    if saved:
        where = (f'FULL output is {len(text)} chars; this is the head and tail. '
                 f'Read the rest with read_file(path="{name}"{host_arg})')
    else:
        where = f"{len(text)} chars total; saving the full copy FAILED, so the middle is lost"
    return text[:budget] + f"\n...[{where}]...\n" + text[-tail_n:], saved


# Placeholder / template local-parts that match the flag regex but are NOT a real flag.
# MEASURED ch5 catthief (2026-09-26): a WRONG solver output contained the literal
# "flag@flare-on.com" (the challenge's own format hint), _find_flag matched it, and the
# run declared [SOLVED] on a decoy - stopping a run that had not actually solved anything.
# FLARE-On real flags are long, distinctive leetspeak; none equal these generic words, so
# an EXACT (whole local-part) match is safe and never rejects a genuine flag.
_FLAG_PLACEHOLDERS = {
    "flag", "email", "name", "user", "username", "your", "youremail", "your_email",
    "yourname", "your_name", "example", "test", "sample", "someone", "somebody",
    "me", "you", "foo", "bar", "redacted", "placeholder", "yourflag", "your_flag",
}


_FLAG_PLACEHOLDER_RX = re.compile(r"^(?:x+|\.+|_+|-+|a+)$", re.I)  # xxxx@, ...., ____, aaaa@


def _is_placeholder_flag(match_str):
    """True if the matched `<local>@flare-on.com` is an obvious template/placeholder,
    not a real flag. Judged on the WHOLE local-part only (exact word or an all-filler
    run like xxxx), so a real flag that merely CONTAINS 'flag'/'me' as a substring
    (e.g. 'fl4g_g3t@...') is never rejected."""
    local = match_str.split("@", 1)[0]
    ll = local.lower()
    return ll in _FLAG_PLACEHOLDERS or bool(_FLAG_PLACEHOLDER_RX.match(local))


def _find_flag(text):
    # Return the FIRST match that is NOT a placeholder. Using finditer (not search) means
    # a decoy 'flag@flare-on.com' earlier in the text does not hide a real flag later in
    # the same blob; a text with ONLY placeholders yields None (correctly: not solved).
    for rx in FLAG_RES:
        for m in rx.finditer(text or ""):
            g = m.group(0)
            if not _is_placeholder_flag(g):
                return g
    return None


def _vm(r):
    """VMResult (dualvm) -> ToolResult (Brain). Trung truong nen anh xa 1-1."""
    return ToolResult(r.ok, r.summary, detail=r.detail, known=r.known,
                      flag=r.flag, info=r.info, image=r.image, waiting=r.waiting)


_dualvm.set_matcher(_find_flag)   # day cach nhan flag xuong Muscle mot lan


def _scratch_tok(name):
    """Turn an artifact NAME/path into a filesystem-safe token for a scratch filename on
    the VM: subdir separators and other odd chars -> '_'. An ingested folder keeps subdir
    names (e.g. "data/x.bin"), and a raw '/' in a derived filename (samples/_dump_data/x)
    would need a directory that write_remote does not create. Flat names are unchanged
    (dots/dashes kept)."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", name or "")


def _primary(ws, artifact=None):
    """artifact=None -> the first/only registered artifact (or None if there are none).
    artifact='<name>' -> that EXACT artifact, or None if it is not registered - NEVER
    silently substitutes a different one (run 5, ch4: pe_overview was asked for the
    header-fixed copy the Brain had just created on the VM, that name was not a
    registered artifact, and the old code silently fell back to the FIRST artifact -
    the original, still-corrupted file - and re-analyzed the wrong thing without
    saying so)."""
    if artifact is not None:
        return ws.artifacts.get(artifact)
    return next(iter(ws.artifacts.values())) if ws.artifacts else None


def _no_artifact_msg(ws, artifact, fallback):
    """A specific, actionable message when `artifact` was named but isn't registered -
    vs the generic `fallback` when no artifact was asked for at all."""
    if artifact and ws.artifacts:
        names = ", ".join(ws.artifacts.keys())
        return (f"no artifact named '{artifact}' - registered artifacts: {names}. "
                "A file made directly on the VM (run_cmd/run_script/author_and_run) is "
                "NOT auto-registered as an artifact; tools that take an `artifact` arg "
                "can only see files that arrived as input or via `extract`.")
    if artifact:
        return f"no artifact named '{artifact}' and none are registered yet"
    return fallback


def _save_to_host(host, name, data):
    """Persist a full (possibly large) output to samples/<name> on the VM via SFTP
    (write_remote), so the Brain can page it later with read_file. Best-effort.
    NOTE: this used to base64-encode `data` and pass it as a single shell command
    line via ssh_exec() for host="kali" (windows already used write_remote, since
    cmd.exe has no printf/base64). Measured 2026-09-22 (ch5 ntfsm run 7/8): a 403KB
    Ghidra function-list -> 537KB of base64 crammed into one exec_command() call
    overflows the SSH channel itself (paramiko raises EOFError, not a normal shell
    error) - silently swallowed by the except below, so pe_overview reported "full
    list -> inline above" as if nothing were wrong, when the full list was in fact
    NEVER saved anywhere and only the first SLICE chars were ever visible to the
    Brain. write_remote() (SFTP) has no such command-line-size limit and already
    proved reliable for windows - use it unconditionally for both hosts."""
    try:
        remote.write_remote(f"samples/{name}", data, host=host)
        return f"samples/{name}"
    except Exception:  # noqa: BLE001
        return None


_BIN_MARKERS = ("PE32", "ELF", "MS-DOS executable", "Mach-O")


_TRIAGE_IMPORT_CHARS = 2500      # the grouped import block; the full list goes to a file


_TRIAGE_NAMES_PER_LIB = 6


_TRIAGE_FACT_CHARS = 400


def _binary_survey(a, q):
    """Cheap structural survey of an executable with radare2 - MEASURED 2026-09-23 on
    ch8 (837KB PE): rabin2 -I 0.08s, sections+entropy 0.02s, libs 0.02s, imports 0.01s,
    versus 180s for a Ghidra pe_overview (which then failed). Until now triage showed the
    controller ONE line of `file` and 16 bytes of hex - strings were collected but never
    reached it - so there was nothing cheap to reason from before reaching for Ghidra.
    r2 was installed and listed in TOOLCHAIN_HINT, and was used 0 times across the ch6
    and ch8 logs. This returns raw tool output only: no interpretation, the grouping of
    imports by library is a deterministic count.

    Returns (detail_text, known_facts)."""
    import json as _json
    parts, facts = [], []
    info, _ = remote.ssh_exec(f"rabin2 -I {q} 2>/dev/null | head -40", read_timeout=30)
    if info.strip():
        parts.append("[rabin2 -I : binary info]\n" + info.rstrip())
        keep = ("arch", "bits", "bintype", "class", "compiler", "lang", "machine", "os",
                "stripped", "static", "canary", "nx", "pic", "signed", "subsys")
        kv = []
        for ln in info.splitlines():
            bits = ln.split(None, 1)
            if len(bits) == 2 and bits[0] in keep:
                kv.append(f"{bits[0]}={bits[1].strip()}")
        if kv:
            facts.append(f"{a.name}: rabin2 -I: " + ", ".join(kv))
    secs, _ = remote.ssh_exec(
        f"r2 -e bin.relocs.apply=true -qc 'iS entropy' {q} 2>/dev/null | head -45",
        read_timeout=30)
    if secs.strip():
        parts.append("[r2 iS entropy : sections, perms, entropy (8.0 = random)]\n"
                     + secs.rstrip())
        sl = []
        for ln in secs.splitlines():
            f = ln.split()
            # nth paddr size vaddr vsize perm flags entropy type name
            if len(f) >= 9 and f[0].isdigit():
                try:
                    sl.append(f"{f[-1]} {f[5]} ent={float(f[7]):.2f}")
                except ValueError:
                    sl.append(f"{f[-1]} {f[5]}")
        if sl:
            facts.append(f"{a.name}: sections: " + "; ".join(sl[:20]))
    libs, _ = remote.ssh_exec(f"rabin2 -l {q} 2>/dev/null | head -60", read_timeout=30)
    if libs.strip():
        parts.append("[rabin2 -l : linked libraries]\n" + libs.rstrip())
    raw, _ = remote.ssh_exec(f"rabin2 -ij {q} 2>/dev/null", read_timeout=40)
    try:
        j = _json.loads(raw) if raw.strip() else {}
        imps = j.get("imports", []) if isinstance(j, dict) else (j or [])
    except ValueError:
        imps = []
    if imps:
        groups = {}
        for it in imps:
            lib = (it.get("libname") or "(no library name)").strip() or "(no library name)"
            groups.setdefault(lib, []).append(it.get("name") or "?")
        full = "\n".join(f"{lib}\t{n}" for lib, ns in sorted(groups.items()) for n in ns)
        dump = f"_rabin2_imports_{_scratch_tok(a.name)}.txt"
        try:
            remote.write_remote(f"samples/{dump}", full + "\n", host="kali")
            where = f"full list ({len(imps)} lines, 'lib<TAB>name'): samples/{dump} on kali - grep it"
        except Exception as e:  # noqa: BLE001
            where = f"(could not save the full list: {e.__class__.__name__})"
        lines = [f"[rabin2 -i : {len(imps)} imports from {len(groups)} libraries, "
                 f"by count; {where}]"]
        used = 0
        for lib, ns in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            shown = ", ".join(ns[:_TRIAGE_NAMES_PER_LIB])
            more = f", +{len(ns) - _TRIAGE_NAMES_PER_LIB} more" if len(ns) > _TRIAGE_NAMES_PER_LIB else ""
            ln = f"  {lib} ({len(ns)}): {shown}{more}"
            if used + len(ln) > _TRIAGE_IMPORT_CHARS:
                lines.append(f"  ...(remaining libraries cut - see samples/{dump})")
                break
            lines.append(ln)
            used += len(ln)
        parts.append("\n".join(lines))
        facts.append(f"{a.name}: imports: {len(imps)} from " + ", ".join(
            f"{lib}({len(ns)})" for lib, ns in
            sorted(groups.items(), key=lambda kv: -len(kv[1]))[:12]))
    # --- embedded-runtime & big-binary guard (ch8 crux + ch9 neon_outrun lesson): both
    # were 15-21MB hosts whose real logic lived in an embedded VM (WASM / V8), where the
    # agent ground static tooling for dozens of steps instead of going dynamic. Cheap:
    # one wc -c beyond what we already read; raw signals only, no interpretation. ---
    _hl = (info + " " + libs).lower()
    _rt = []
    if "javascriptcore" in _hl or "libv8" in _hl:  _rt.append("V8/JS engine")
    if "webkit" in _hl or "tauri" in _hl:          _rt.append("Tauri/webkit webview")
    if "electron" in _hl:                          _rt.append("Electron")
    _sz, _ = remote.ssh_exec(f"wc -c < {q} 2>/dev/null", read_timeout=15)
    try:
        _nb = int(_sz.strip())
    except ValueError:
        _nb = 0
    if _rt or _nb >= 8 * 1024 * 1024:
        _h = []
        if _rt:
            _h.append("embedded runtime (" + ", ".join(sorted(set(_rt))) + "): the real "
                      "logic runs INSIDE that runtime, not in this host binary\'s static "
                      "code - go DYNAMIC early (linux_gdb / win_frida, or run the payload "
                      "in its own engine) and try replacing the script/input at the load "
                      "boundary to measure native functions as black boxes (recall: "
                      "embedded-runtime)")
        if _nb >= 8 * 1024 * 1024:
            _h.append(f"large binary (~{_nb // (1024*1024)}MB): Ghidra full-analysis "
                      "likely TIMES OUT - prefer targeted r2 (pdf/axt @ addr) or "
                      "ghidra_script on ONE function, or go dynamic, over pe_overview")
        _line = f"{a.name}: " + " | ".join(_h)
        parts.append("[triage guard]\n" + _line)
        facts.append(_line)

    # The ledger is re-sent UNCACHED on every step (it is the fresh user message), so a
    # long KNOWN line is paid ~60 times per run. Measured: an ELF's sections line came to
    # ~800 chars. The full text stays in the detail and in the saved file.
    facts = [f if len(f) <= _TRIAGE_FACT_CHARS else
             f[:_TRIAGE_FACT_CHARS] + " ...(cut; full output in the triage observation)"
             for f in facts]
    return "\n\n".join(parts), facts


def survey_inputs(ws):
    """Cheap startup survey of EVERY input artifact: upload each to the analysis VM and
    record its `file` type + size, so from step 1 the Brain sees the whole input
    LANDSCAPE (the binary, a pcap, a memory dump, a disk/firmware image) instead of only
    the first file's name. Multi-file bundles are the norm for real RE challenges;
    without this the Brain tended to triage only the first artifact and miss the pcap /
    dump. Best-effort per file: an upload or `file` failure is noted, never fatal. A
    very large image is not uploaded at startup (a later tool uploads it on demand).
    Returns a list of ledger facts."""
    facts = []
    # A target .exe left running by an EARLIER run (a GUI crackme win_frida/win_gui_run
    # did not kill) LOCKS its own file and every DLL it loaded on Windows, so the SFTP
    # upload below fails with OSError "Failure" (measured run 7, ch8 FlareAuthenticator
    # pid 804 - files persisted, but the error scared the run). Kill any process whose
    # image matches an artifact we are about to upload, best-effort, first. Windows only;
    # Kali does not lock a running file.
    for _exe in sorted({a.name.rsplit("/", 1)[-1] for a in ws.artifacts.values()
                        if a.name.lower().endswith(".exe")}):
        try:
            remote.ssh_exec(f'taskkill /F /T /IM "{_exe}"', host="windows", read_timeout=15)
        except Exception:  # noqa: BLE001 - nothing to kill / VM down is fine
            pass
    for a in list(ws.artifacts.values()):
        try:
            size = os.path.getsize(a.local_path)
        except OSError:
            facts.append(f"{a.name}: MISSING on disk ({a.local_path})")
            continue
        size_s = f"{size:,} B" if size < (1 << 20) else f"{size / (1 << 20):.1f} MB"
        if size > 150 * (1 << 20):        # big disk/firmware image: don't block startup
            facts.append(f"{a.name}: {size_s} (large - uploaded when a tool first touches it)")
            continue
        try:
            a.remote_path = remote.upload(a.local_path, a.name, host="kali")
            out, _ = remote.ssh_exec(f"file {shlex.quote(a.remote_path)}", read_timeout=20)
            ftype = out.split(":", 1)[1].strip() if ":" in out else out.strip()
        except Exception as e:  # noqa: BLE001 - a survey failure must not block the run
            facts.append(f"{a.name}: {size_s} - could not survey ({e.__class__.__name__})")
            continue
        # Also stage on the Windows VM (best-effort): FLARE-On is mostly Windows PE, and a
        # multi-file challenge run on Windows (an .exe next to its .dll / a data file it
        # opens) needs ALL siblings in samples/ on WINDOWS too, not just Kali - otherwise
        # the launch fails with "DLL not found" / can't find its data. triage does the
        # same dual upload for the file it touches; do it for every input up front.
        win = ""
        try:
            remote.upload(a.local_path, a.name, host="windows")
        except Exception as e:  # noqa: BLE001 - Windows VM may be down/optional
            win = f" [not on Windows VM: {e.__class__.__name__}]"
        facts.append(f"{a.name}: {ftype or 'unknown type'} ({size_s}){win}")
    return facts


@tool("triage",
      "Collect raw evidence on an artifact (upload to BOTH Kali and Windows VMs so "
      "it's ready for run_cmd/run_script/author_and_run on either host without a "
      "separate upload step, run file/xxd/strings on Kali, test if it reads as "
      "UTF-8 text). For an executable (PE/ELF/Mach-O) it also runs a sub-second "
      "radare2 survey and SHOWS it to you: rabin2 -I (arch, compiler, language, "
      "stripped, protections), every section with its permissions and entropy, the "
      "linked libraries, and the imports grouped by library (full list saved to a "
      "file you can grep). Records facts only; does NOT conclude anything - you "
      "interpret it. To actually READ text content, use `peek`.",
      {"artifact": "name of an artifact (optional; defaults to the first)"})
def triage(ws, artifact=None):
    a = _primary(ws, artifact)
    if not a:
        return ToolResult(False, _no_artifact_msg(ws, artifact, "no artifact to triage"))
    a.remote_path = remote.upload(a.local_path, a.name, host="kali")
    # also upload to Windows so run_cmd/run_script(host="windows") and a real EXE
    # launch have the file available - previously NOTHING ever put artifacts on the
    # Windows VM, so host="windows" silently assumed a file that was never there
    # (run 7, ch5 ntfsm: step 3 tried to run the artifact on Windows before any tool
    # had uploaded it, "not recognized as an internal or external command"). Best
    # effort: a Windows upload failure should not block triage on Kali, which is the
    # host every other muscle tool (Ghidra, etc.) actually depends on.
    win_ok = True
    win_err = ""
    try:
        remote.upload(a.local_path, a.name, host="windows")
    except Exception as e:  # noqa: BLE001 - surface infra errors to the ledger, don't crash triage
        win_ok = False
        win_err = str(e)
    q = shlex.quote(a.remote_path)
    file_out, _ = remote.ssh_exec(f"file {q}", read_timeout=20)
    hexd, _ = remote.ssh_exec(f"xxd -l 64 {q}", read_timeout=20)
    strings_out, _ = remote.ssh_exec(f"strings {q} | head -50", read_timeout=20)
    try:
        with open(a.local_path, "r", encoding="utf-8") as f:
            text = f.read()
        is_text = True
    except (UnicodeDecodeError, OSError):
        text, is_text = "", False
    a.notes.update(hex=hexd, strings=strings_out, file_out=file_out.strip(), text=text)
    facts = [
        f"{a.name}: `file` says: {file_out.strip()}",
        f"{a.name}: first bytes (xxd): {hexd.splitlines()[0] if hexd else '(none)'}",
        f"{a.name}: readable as UTF-8 text: {'yes (%d chars)' % len(text) if is_text else 'no (binary)'}",
    ]
    # What the controller SEES. Before 2026-09-23 triage returned no detail at all, so
    # the Brain's whole cheap-measurement budget was one `file` line and 16 hex bytes.
    shown = [f"[file]\n{file_out.strip()}", f"[xxd -l 64]\n{hexd.rstrip()}"]
    if not is_text and any(m in file_out for m in _BIN_MARKERS):
        try:
            survey, sfacts = _binary_survey(a, q)
        except Exception as e:  # noqa: BLE001 - a survey failure must not break triage
            survey, sfacts = f"[rabin2 survey failed: {e.__class__.__name__}: {e}]", []
        if survey:
            shown.insert(1, survey)          # decisive info first: observations taper with age
            facts.extend(sfacts)
    elif not is_text and strings_out.strip():
        shown.append("[strings | head -50]\n" + strings_out.rstrip()[:3000])
    triage_detail = "\n\n".join(shown)
    if win_ok:
        facts.append(f"{a.name}: also uploaded to the Windows VM (samples/{a.name}) - "
                     "ready for run_cmd/run_script(host='windows') without a separate step.")
        summ = f"triaged {a.name} (uploaded to kali+windows, file/xxd/strings/text)"
    else:
        facts.append(f"{a.name}: upload to the Windows VM FAILED ({win_err[:120]}) - it "
                     "is NOT available there; run_cmd/run_script(host='windows') on it "
                     "will fail until this is resolved.")
        summ = f"triaged {a.name} (uploaded to kali only, WINDOWS UPLOAD FAILED, file/xxd/strings/text)"
    return ToolResult(True, summ, detail=triage_detail, known=facts, info=triage_detail)


@tool("peek",
      "Read a slice of an artifact's TEXT content locally ($0, no VM). Pages "
      "through the file so you can see ALL of it without re-running cat/head/fold. "
      "Call again with a larger offset to read the next chunk.",
      {"artifact": "artifact to read (optional; default first)",
       "offset": "start char index (default 0)",
       "length": f"chars to return (default {SLICE})"})
def peek(ws, artifact=None, offset=0, length=SLICE):
    a = _primary(ws, artifact)
    if not a:
        # Measured twice (ch6 runs 2 and 3): the Brain calls peek on a file IT made on
        # the VM - challenge_disasm.txt, chat_log.json - because from its side "a file
        # I can read" is one idea, not two. The old answer was a lecture about the
        # artifact registry and a wasted step. If the name IS a file on the VM, just
        # read it and say which tool actually served it.
        if artifact:
            alt = read_file(ws, path=str(artifact), offset=offset, length=length)
            if alt.ok:
                alt.summary = (f"peek: '{artifact}' is not a registered artifact but IS "
                               f"a file on the Kali VM - served it with read_file. "
                               + alt.summary)
                return alt
        return ToolResult(False, _no_artifact_msg(ws, artifact, "no artifact to peek"))
    # A handoff doc pinned into the cached run context at start (orchestrator,
    # config.PIN_DOCS_MAX_CHARS): the Brain already has ALL of it on every step.
    # MEASURED ch8 run 15: FINDINGS.md was re-read 13 times in 60 steps (22% of the run).
    if a.name in getattr(ws, "pinned_docs", set()):
        return ToolResult(True, f"peek {a.name}: already in your context in full "
                                "(PRIOR NOTES block) - not re-read",
                          detail=f"[{a.name} is pinned WHOLE in your system context under "
                                 "'PRIOR NOTES' on every step. Read it there; act on it.]",
                          known=[f"{a.name} is pinned in context (no need to peek)"])
    text = a.notes.get("text")
    if not text:
        try:
            with open(a.local_path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
            a.notes["text"] = text
        except OSError as e:
            return ToolResult(False, f"cannot read {a.name}: {e}")
    offset = int(offset or 0)
    length, cap_note = _clamp_page(length)
    n = len(text)
    chunk = text[offset:offset + length]
    end = offset + len(chunk)
    # Units: peek pages in CHARACTERS, while the input survey and read_file report
    # BYTES. MEASURED ch8 runs 14-15: FINDINGS.md is 8052 bytes = 7036 chars (Vietnamese
    # UTF-8); the Brain saw "0..7036/7036", compared with the survey's 8052 B, decided
    # "bytes 7036-8052 are still unread" and spent 4 steps hunting a tail it had already
    # read. Say it explicitly.
    nbytes = len(text.encode("utf-8", errors="replace"))
    unit = "" if nbytes == n else f" chars (= {nbytes} bytes UTF-8)"
    hdr = f"[{a.name} chars {offset}..{end} of {n}{unit}]"
    flag = _find_flag(chunk)
    more = ("  END OF FILE - you have now seen up to the last character" + (
                f" (the {nbytes}-byte size elsewhere is the same file in bytes)"
                if unit else "")) if end >= n else f"  (more: peek offset={end})"
    more += cap_note
    return ToolResult(True, f"peek {a.name} {offset}..{end}/{n}{more}", detail=hdr + "\n" + chunk,
                      known=[f"read {a.name}[{offset}:{end}]"], flag=flag)


@tool("read_file",
      "Read a slice of a file that lives ON THE VM (e.g. a large decoded blob a "
      "solver saved). Pages a big file so you never lose data to truncation. "
      "Pair with author_and_run / run_cmd which save full output to a host file.",
      {"path": "path on the VM (relative to samples/ or absolute)",
       "offset": "start byte index (default 0)",
       "length": f"bytes to return (default {SLICE})",
       "host": "'kali' (default) or 'windows'. If the file is not there but IS on the other VM, it is served from there and the answer says so - you do not lose a step to guessing which box wrote it"})
def read_file(ws, path, offset=0, length=SLICE, host="kali"):
    return _vm(dvm_shell.read_file(path, offset=offset, length=length,
                                   host=host,
                                   pinned_docs=getattr(ws, "pinned_docs", ())))


@tool("author_and_run",
      "Ask the reasoner to WRITE a self-contained python solver for a goal (using "
      "the evidence gathered so far), then RUN it on a VM and return its output. "
      "Output longer than one turn is saved to a host file whose EXACT name is given "
      "in the answer (page it with read_file - do not guess the name). "
      "Auto-scans the output for a flag.",
      {"goal": "what the script must compute/achieve (be specific)",
       "artifact": "artifact to draw evidence from (optional)",
       "host": "'kali' (default) or 'windows'",
       "timeout": "seconds, default 20 - raise it for heavy work (a big extraction, "
                  "a graph search); the VM kills the script at this limit",
       "python": "ABSOLUTE path of the interpreter to run the solver with "
                 "(optional). Default is the preinstalled analysis venv - see the "
                 "ENVIRONMENT FACTS in the ledger for what is already importable "
                 "there. Use this ONLY when the task is version-locked to another "
                 "interpreter (e.g. marshalled 3.12 bytecode) AND you installed "
                 "that interpreter yourself; a library you pip-installed into a "
                 "DIFFERENT python is not importable here."})
def author_and_run(ws, goal, artifact=None, host="kali", timeout=20, python=None):
    a = _primary(ws, artifact)
    # Every other artifact-taking tool says so when the name is unknown; this one used
    # to fall through and write the solver with NO evidence at all (no strings, no hex,
    # no decompile) while still reporting ok=True on whatever that script printed.
    if artifact and not a and not ws.ghidra_cache.get(artifact):
        return ToolResult(False, _no_artifact_msg(
            ws, artifact, "no artifact to draw evidence from"))
    ev = []
    # Ghidra output for a target that is NOT a registered artifact (a header-fixed
    # copy the Brain made on the VM) lives in ws.ghidra_cache, not in a.notes - so
    # without this the script-writer was blind to exactly the decompiles that took
    # the most steps to obtain.
    _bare = ws.ghidra_cache.get(artifact) if artifact else None
    if _bare is None and not a and len(getattr(ws, "ghidra_cache", {})) == 1:
        _bare = next(iter(ws.ghidra_cache.values()))
    if _bare:
        if _bare.get("decompiled"):
            ev.append("GHIDRA PSEUDOCODE (most recent decompile):\n"
                      + _bare["decompiled"][:6000])
        bfns = _bare.get("decompiled_fns") or {}
        if bfns:
            big = max(bfns, key=lambda k: len(bfns[k]))
            ev.append(f"GHIDRA PSEUDOCODE (largest decompiled so far: {big}, "
                      f"{len(bfns[big])} chars):\n" + bfns[big][:6000])
    if a:
        if a.notes.get("text"):
            ev.append("SOURCE / TEXT:\n" + a.notes["text"][:12000])
        # Ghidra pseudocode: the MOST RECENT decompile (what the Brain is thinking
        # about right now) plus, if different, the LARGEST one decompiled so far -
        # otherwise a 498-char CRT wrapper decompiled last would crowd out the 10k-char
        # main() that actually holds the logic. Budget ~6000 chars each: a real main is
        # ~10k and the old single 6000-char cap cut it mid-function; CODER_MAX_OUTPUT_
        # TOKENS is 16384 now, so the script-writer has room to use both.
        fns = a.notes.get("decompiled_fns") or {}
        if a.notes.get("decompiled"):
            ev.append("GHIDRA PSEUDOCODE (most recent decompile):\n"
                      + a.notes["decompiled"][:6000])
        if fns:
            recent = list(fns)[-1]
            big = max(fns, key=lambda k: len(fns[k]))
            if big != recent:
                ev.append(f"GHIDRA PSEUDOCODE (largest decompiled so far: {big}, "
                          f"{len(fns[big])} chars):\n" + fns[big][:6000])
            others = [k for k in fns if k not in (recent, big)][-12:]
            if others:
                ev.append("OTHER FUNCTIONS ALREADY DECOMPILED (decompile one by name if "
                          "you need its body): " + ", ".join(others))
        if a.notes.get("strings"):
            ev.append("STRINGS:\n" + a.notes["strings"][:1500])
        if a.notes.get("hex"):
            ev.append("HEX(64):\n" + a.notes["hex"])
    ev.append("LEDGER:\n" + ws.ledger.render())
    tier = getattr(ws, "tier", "default")
    from . import config as _cfg
    evidence = "\n\n".join(ev)
    est = reasoner.estimate_call(len(evidence) + len(goal), len(reasoner.CODER_SYSTEM),
                                 _cfg.CODER_MAX_OUTPUT_TOKENS)
    fits, left = reasoner.budget_room(est)
    if not fits:
        # The most expensive call in the whole loop: never start it without room for
        # its worst case. (Budget is a HARD stop, so say so - not a hint to retry.)
        return ToolResult(False, f"author_and_run NOT started: writing a solver can bill "
                                 f"up to ~{est:,} tokens and only {max(left, 0):,} are "
                                 "left under MAX_RUN_TOKENS. Use a cheap tool (r2, "
                                 "run_cmd, read_file) or stop.")
    script = reasoner.author_script(goal, evidence, host=host, tier=tier)
    ws.last_script = script
    # Two failure shapes measured in the first successful real run (ch2, 2026-09-22),
    # both of which USED to reach the VM and come back as an unhelpful "produced NO
    # output" or a SyntaxError from the remote python:
    #   * the reply hit the output-token ceiling mid-statement (2 steps, 16384 output
    #     tokens burned each);
    #   * the model answered with PROSE ("Let's test the pipeline interactively
    #     first...") and extract_code, finding no fenced block, handed that straight
    #     to exploit.py.
    # Both are knowable here, for free, before any upload - and the message can say
    # what to do instead.
    if reasoner.last_call_truncated():
        return ToolResult(False,
            "the generated solver was CUT OFF at the output-token ceiling "
            f"({reasoner.config.CODER_MAX_OUTPUT_TOKENS} tokens) and was NOT run - a "
            "truncated script can only fail. Ask for LESS in one go: split this into "
            "two author_and_run calls, the first just extracting the data to a file "
            "with a print() confirming its size, the second loading that file and "
            "doing the analysis.")
    if not script.strip():
        return ToolResult(False, "the script writer returned nothing - restate the goal")
    try:
        ast.parse(script)
    except SyntaxError as e:
        head = " | ".join(script.strip().splitlines()[:2])[:160]
        return ToolResult(False,
            f"the generated solver is not valid python ({e.msg}, line {e.lineno}) and "
            f"was NOT run. It starts with: {head!r}. If that looks like prose rather "
            "than code, say in `goal` that the reply must be ONLY a python code block.")
    blocked = _security_block(script)
    if blocked:
        return ToolResult(False, f"blocked: the generated solver touches {blocked}, "
                                 "which is not permitted - it is never needed to solve "
                                 "a challenge; ask for a different approach in `goal`.")
    try:
        out = remote.run_script(script, host=host, timeout=int(timeout), python=python)
    except Exception as e:  # noqa: BLE001 - surface infra errors to the ledger
        return ToolResult(False, f"run failed: {e}")
    # peel the exit-code marker the runner appends (kali). stdout+stderr get
    # concatenated so the marker may not be last; take the LAST occurrence.
    rc = None
    ms = list(re.finditer(r"__RC=(\d+)", out))
    if ms:
        m = ms[-1]
        rc = int(m.group(1))
        out = (out[:m.start()] + out[m.end():]).strip()
    ws.last_output = out
    flag = _find_flag(out)
    n = len(out)
    # a solver that crashed/errored (non-zero exit) is a FAILED attempt even if it
    # printed a traceback - do not count it as progress, surface the error tail
    if rc not in (0, None) and not flag:
        if rc == 139:
            hint = ("segfault (139) - likely running/dis-assembling marshalled bytecode "
                    "compiled for a DIFFERENT python version. Decode the layers statically "
                    "or run under the matching interpreter; do not dis.dis foreign bytecode.")
        elif rc == 124:
            hint = ("TIMED OUT (killed after %ds) - it blocks on input()/network or loops. "
                    "Compute offline and print; do not run the challenge directly." % int(timeout))
        else:
            tail = out[-300:] if out else "(no stderr captured)"
            hint = f"exit {rc}. error tail: {tail}"
        # A failing solver's output is often the most informative thing in the run
        # (the traceback plus everything it printed before dying). Do not drop it.
        fail_detail, _ = _spill(host, out, "solver_fail")
        return ToolResult(False, "solver failed: " + hint, detail=fail_detail)
    if n == 0:
        if rc == 124:
            msg = ("solver TIMED OUT with no output (killed after %ds). It likely "
                   "blocks on input()/network or loops. Do NOT run the challenge "
                   "directly - author a solver that computes offline and prints." % int(timeout))
        elif rc:
            msg = f"solver exited {rc} with NO output/traceback - add prints or wrap in try/except."
        else:
            msg = "solver produced NO output (0 chars) - it never printed; add explicit print()."
        return ToolResult(False, "ran solver but " + msg)
    detail, saved = _spill(host, out, "solver_out")
    summ = f"ran solver on {host}; output {n} chars" + ("; FLAG found" if flag else "")
    known_fact = f"solver({goal[:40]}) -> {n} chars out"
    if saved:
        known_fact += f" (full -> {saved}, page with read_file)"
    return ToolResult(True, summ, detail=detail, known=[known_fact],
                      flag=flag)


@tool("check_flag",
      "Scan a piece of text (or the last solver output) for a flag pattern.",
      {"text": "text to scan (optional; defaults to last output)"})
def check_flag(ws, text=None):
    text = text if text is not None else getattr(ws, "last_output", "")
    flag = _find_flag(text)
    return ToolResult(bool(flag), "flag found" if flag else "no flag in text", flag=flag)


def _wrap_cmd(command, host, timeout=20):
    """Working dir + REAL timeout + exit-code marker.

    kali: the command runs inside `timeout -k 5 N bash -c '<command>'`. Two things
    this fixes, both measured 2026-09-22: (a) the `timeout` arg used to be a pure
    fiction - only paramiko's read_timeout existed, so a killed channel left the
    remote command RUNNING to completion (verified: `sleep 12; touch f` still
    created f after the channel died), which could clobber a later step's files and
    pile up heavy processes (Ghidra/angr) on the VM; (b) `bash -c` pins the shell,
    where before the command ran under the login shell (zsh here, despite the old
    comment claiming bash). timeout runs the child in its own process group and
    signals the whole group, so forked children die too. Exit 124 = timed out.
    windows: NOT built here any more - _run_and_wrap sends Windows commands through
    remote.win_run_bounded, which gives them the same real, tree-killing timeout."""
    if host == "windows":
        return ("cd /d samples 2>nul & " + command +
                " & if errorlevel 1 (echo __RC=1) else (echo __RC=0)")
    # Snapshot samples/ before and after, in the SAME shell, and report what changed.
    # Measured ch6 run 2 (2026-09-23): a hand-written run_script wrote 57262 bytes to
    # samples/dump2.txt and printed only "wrote 57262". The Brain had no way to learn
    # the filename, guessed "disasm.txt", read_file said it did not exist - second
    # stall, run dead. The step that did the real work was also scored a stall,
    # because 11 characters of output is below INFO_MIN_CHARS. One shell snapshot
    # fixes both: the Brain learns where its output went, and producing a file now
    # counts as the progress it plainly is.
    snap = "find . -maxdepth 1 -type f -printf '%f\\t%s\\n' 2>/dev/null | sort"
    inner = (
        "cd samples 2>/dev/null\n"
        "set -o pipefail\n"
        f"{snap} > /tmp/_pre.$$ 2>/dev/null\n"
        + command + "\n"
        "__rc=$?\n"
        f"{snap} > /tmp/_post.$$ 2>/dev/null\n"
        "comm -13 /tmp/_pre.$$ /tmp/_post.$$ 2>/dev/null | head -15 | "
        "sed 's/^/__NEWFILE__ /'\n"
        "rm -f /tmp/_pre.$$ /tmp/_post.$$\n"
        "exit $__rc"
    )
    return f"timeout -k 5 {int(timeout)} bash -c {shlex.quote(inner)}; echo __RC=$?"


_NEWFILE_RE = re.compile(r"^__NEWFILE__ (.+?)\t(\d+)$", re.M)


def _peel_newfiles(text):
    """Split the `__NEWFILE__ name\tsize` lines the wrapper appends off `text`.
    Returns (clean_text, [(name, size), ...])."""
    found = [(m.group(1), int(m.group(2))) for m in _NEWFILE_RE.finditer(text or "")]
    return (_NEWFILE_RE.sub("", text or "").rstrip(), found)


def _peel_rc(text):
    """Split the trailing __RC=<n> marker off `text` -> (clean_text, rc or None)."""
    ms = list(re.finditer(r"__RC=(\d+)", text))
    if not ms:
        return text, None
    m = ms[-1]
    return (text[:m.start()] + text[m.end():]).strip(), int(m.group(1))


# grep's exit-status convention: 0 = matched, 1 = searched and found NOTHING, 2 = error.
# MEASURED ch4 run 2 (2026-09-27): every "no match" came back as a FAILED run_cmd
# ("exit 1, 0 chars"), so (a) three honest negative searches spent the tool-error budget
# and escalated the Brain to Opus at step 6, and (b) with the command cut at 55 chars
# in the ledger (`...grep -i '@flare-on.com` -> exit 1) the Brain concluded its quoting
# was broken and burned steps 17-20 re-running a search that had already answered.
_GREP_CMDS = {"grep", "egrep", "fgrep", "zgrep", "rg"}


_GREP_ARG_OPTS = {"-e", "-f", "-m", "-A", "-B", "-C", "--regexp", "--file",
                  "--max-count", "--context", "--after-context", "--before-context"}


_REDIR_OPS = {">", ">>", "<", ">&", "<&", "&>", "&>>", "<<", "<<<", ">|"}


def _grep_shape(command):
    """How grep's exit 1 should be read for a one-line KALI command:
      'pipeline' - ONE pipeline (no && || ; &) with a grep-family stage, so with
                   `set -o pipefail` an empty exit-1 result means "no match";
      'no_file'  - that grep is the FIRST stage and has no file operand (and no -r),
                   so it searched an EMPTY stdin - a call error, not a negative result;
      None       - anything else (lists, subshells, unparsable): keep exit 1 a failure."""
    if "\n" in command or "$(" in command or "`" in command:
        return None
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        toks = list(lex)
    except ValueError:
        return None
    if any(t in ("&&", "||", ";", "&", ";;", "(", ")") for t in toks):
        return None
    stages, cur = [], []
    for t in toks:
        if t in ("|", "|&"):
            stages.append(cur)
            cur = []
        else:
            cur.append(t)
    stages.append(cur)
    for i, st in enumerate(stages):
        words, skip = [], False
        for j, w in enumerate(st):              # drop redirections (2>/dev/null ...)
            if skip:
                skip = False
                continue
            if w in _REDIR_OPS:
                skip = True
                continue
            if w.isdigit() and j + 1 < len(st) and st[j + 1] in _REDIR_OPS:
                continue
            words.append(w)
        while words and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[0]):
            words.pop(0)                         # VAR=x grep ...
        if not words or os.path.basename(words[0]) not in _GREP_CMDS:
            continue
        cmd, args = os.path.basename(words[0]), words[1:]
        if i > 0 or cmd == "rg":                 # piped input, or rg (searches cwd)
            return "pipeline"
        pat_from_opt, recursive, operands, k, opts_done = False, False, [], 0, False
        while k < len(args):
            a = args[k]
            k += 1
            if opts_done or a == "-" or not a.startswith("-"):
                operands.append(a)
            elif a == "--":
                opts_done = True
            elif a.startswith("--"):             # long option
                name = a.split("=", 1)[0]
                if name in ("--regexp", "--file"):
                    pat_from_opt = True
                if name in ("--recursive", "--dereference-recursive"):
                    recursive = True
                if name in _GREP_ARG_OPTS and "=" not in a:
                    k += 1                       # its value is the next word
            else:                                # short cluster, e.g. -rni or -e PAT
                for ci, ch in enumerate(a[1:]):
                    if ch in "rR":
                        recursive = True
                    if ch in "efmABC":
                        pat_from_opt = pat_from_opt or ch in "ef"
                        if ci == len(a) - 2:     # value not attached -> next word
                            k += 1
                        break
        files = operands if pat_from_opt else operands[1:]
        return "pipeline" if (files or recursive) else "no_file"
    return None


def _run_and_wrap(command, host, timeout, label, grep_shape=None):
    """Shared tail for run_cmd/run_script: exec + spill-to-host + rc/timeout detection +
    flag scan. `label` is what shows up in the ledger (the command text, or a script
    description) so the two tools can phrase their summary differently. `grep_shape`
    (run_cmd only, see _grep_shape) lets an empty exit-1 grep be read as NO MATCH."""
    if host == "windows":
        # real tree-killing timeout + the true exit code (see remote.win_run_bounded)
        out, err = remote.win_run_bounded(command, timeout)
    else:
        out, err = remote.ssh_exec(
            _wrap_cmd(command, host, timeout), host=host, read_timeout=int(timeout) + 25
        )
    combined = (out + ("\n" + err if err.strip() else "")).strip()
    channel_dead = "(TIMEOUT after" in combined
    combined, rc = _peel_rc(combined)
    combined, newfiles = _peel_newfiles(combined)
    # rc 124 = GNU timeout fired on the VM (the real, reliable signal); the
    # "(TIMEOUT after" marker only means paramiko stopped reading the channel.
    timed_out = channel_dead or rc == 124
    # 141 = SIGPIPE: `... | head` closing the pipe early is the NORMAL way to take the
    # first N lines, not a failure. Measured ch6 step 21: a `find | head` surfaced 3666
    # characters of genuinely new information and was still scored a stall because of
    # this exit code, which pushed the run into an escalation it did not need.
    if rc == 141 and combined.strip():
        rc = 0
    no_match = no_file = False
    if not timed_out and rc == 1 and not combined.strip():
        if grep_shape == "pipeline":
            rc, no_match = 0, True           # searched, found nothing: a measurement
        elif grep_shape == "no_file":
            no_file = True
    n = len(combined)
    sl, saved = _spill(host, combined, "cmd_out")
    if newfiles:
        sl += ("\nFILES WRITTEN OR CHANGED in samples/ by this command: "
               + "; ".join(f"{fn} ({fsz} bytes)" for fn, fsz in newfiles[:8])
               + '. Read one with read_file(path="<name>").')
    flag = _find_flag(combined)
    failed = timed_out or rc != 0
    why = (f"TIMEOUT (killed after {int(timeout)}s on the VM - pass a larger "
           f"`timeout` if the work is genuinely long, e.g. an install or Ghidra), "
           if timed_out else
           "exit 1 because grep was given NO FILE to search - it read an empty stdin. "
           "Add the file name (cwd is samples/), e.g. `grep -n PATTERN <file>`; "
           if no_file else
           "shell aborted before finishing (syntax error?), " if rc is None else
           f"exit {rc}, " if failed else "")
    known_fact = f"{label} -> {sl[:180]}"
    if no_match:
        # A negative result is a MEASURED fact ("this pattern is not in that data").
        # No `info`: it adds no new text, so repeating searches that come back empty
        # still reaches the stall threshold (design rule: two empty static looks ->
        # change the KIND of approach) instead of the tool-error budget.
        known_fact = (f"{label} -> NO MATCH (grep exit 1 = the search ran and found "
                      "nothing; this is a result, not an error)")
    if newfiles:
        known_fact += " | wrote " + ", ".join(f"samples/{fn} ({fsz}B)"
                                              for fn, fsz in newfiles[:8])
    if saved:
        known_fact += f" (full -> {saved}, page with read_file)"
    if no_match:
        return ToolResult(True, f"ran on {host}: {label} -> NO MATCH (grep exit 1: "
                                "searched, found nothing)", detail="", known=[known_fact],
                          info="")
    return ToolResult(
        not failed,
        f"ran on {host}: {label} -> {why}{n} chars" + ("; FLAG" if flag else ""),
        detail=sl,
        known=[] if failed else [known_fact],
        flag=flag,
        info=sl,
    )


@tool("run_cmd",
      "Run an arbitrary ONE-LINE shell command on a VM, in the samples/ working dir, "
      "and return its raw output. Large output is saved to a file NAMED IN THE REPLY "
      "(each call gets its own - page it with read_file) so nothing is lost. Use this "
      "to drive ANY CLI tool: "
      "qpdf, pdfimages, binwalk, objdump, nm, xxd, readelf, tshark, etc. YOU author "
      "the exact command; muscle just runs it and returns output verbatim. "
      "host='kali' = bash; host='windows' = cmd.exe (use dir/type/certutil/where, "
      "NOT ls/cat/grep; chain with & or &&). For anything MULTI-LINE or that needs "
      "nested quotes (a PowerShell one-liner, a python -c with quotes inside), use "
      "run_script instead - quoting through bash->ssh->cmd->powershell breaks easily. "
      "You MAY install what an analysis needs - but read the ENVIRONMENT FACTS "
      "entry in the ledger FIRST: it lists what is already importable, and gives "
      "the exact pip that installs into the interpreter your solvers actually run "
      "under (a bare `pip install` fails here with PEP 668, and --user / "
      "--break-system-packages land where the solver cannot see them). Installs are "
      "slow - pass a large `timeout`. Commands that change security config (antivirus, firewall, "
      "services, registry, ACLs) or that are destructive (mkfs, rm -rf /, user "
      "management) are REFUSED before reaching the VM - if you hit that, the "
      "sample/tool itself is the obstacle, work around it differently, do not try "
      "to disable the protection.",
      {"command": "the exact shell command to run",
       "host": "'kali' (default) or 'windows'",
       "timeout": "seconds, default 20"})
def run_cmd(ws, command, host="kali", timeout=20):
    return _vm(dvm_shell.run_cmd(command=command, host=host, timeout=timeout))


@tool("run_script",
      "Write a MULTI-LINE script to a file on the VM via SFTP and run it - use this "
      "whenever a command needs newlines or nested quotes (a PowerShell block, a "
      "python heredoc, a multi-step bash script) instead of fighting run_cmd's single "
      "shell line. No shell-quoting hazard: the script body is written to a file "
      "as-is, only the (quote-free) invocation goes through the shell. Same output "
      "handling and security restrictions as run_cmd.",
      {"script": "the full script body (not a single command)",
       "host": "'kali' (default) or 'windows'",
       "kind": "'bash' or 'python3' (kali, default 'bash'); 'powershell' or 'cmd' "
               "(windows, default 'powershell')",
       "timeout": "seconds, default 20 - raise it for an install or any long job; "
                  "the VM kills the script at this limit",
       "python": "ABSOLUTE path of the interpreter for kind='python3' (optional; "
                 "default = the preinstalled analysis venv, see ENVIRONMENT FACTS)"})
def run_script(ws, script, host="kali", kind=None, timeout=20, python=None):
    return _vm(dvm_shell.run_script(script=script, host=host, kind=kind, timeout=timeout, python=python))


_WIN_7Z_CACHE = [None]


def _win_7z():
    """Absolute path to 7z.exe on the Windows VM, cached. FLARE-On's Windows box ships
    7-Zip under Program Files but not on PATH (measured: `where 7z` returns nothing)."""
    if _WIN_7Z_CACHE[0] is not None:
        return _WIN_7Z_CACHE[0]
    cand = r"C:\Program Files\7-Zip\7z.exe"
    try:
        o, _ = remote.ssh_exec(f'if exist "{cand}" (echo __Y__) else (where 7z)',
                               host="windows", read_timeout=20)
    except Exception:  # noqa: BLE001
        _WIN_7Z_CACHE[0] = ""
        return ""
    if "__Y__" in (o or ""):
        _WIN_7Z_CACHE[0] = cand
    else:
        line = ""
        for l in (o or "").splitlines():
            if l.strip().lower().endswith("7z.exe"):
                line = l.strip()
                break
        _WIN_7Z_CACHE[0] = line
    return _WIN_7Z_CACHE[0]


def _extract_wim(ws, a, password=None):
    """Extract a .wim on the VMs with 7z and register every member as an artifact.

    Kali does the authoritative unpack (its output is downloaded to the host so the
    files become real artifacts you can peek/triage); 7z on Kali writes each NTFS
    alternate data stream as a separate 'name:stream' file, which we keep. Windows
    ALSO unpacks with `-sns`, so the members sit on the Windows VM WITH their ADS as
    genuine streams - ready for win_frida/win_gui_run without any further copy.
    """
    # WIM on Kali (upload if the survey didn't already).
    if not a.remote_path:
        try:
            a.remote_path = remote.upload(a.local_path, a.name, host="kali")
        except Exception as e:  # noqa: BLE001
            return ToolResult(False, f"extract(WIM): could not upload {a.name} to Kali: "
                                     f"{e.__class__.__name__}: {e}")
    wim_rel = a.remote_path.split("samples/", 1)[-1]
    reldir = _scratch_tok(a.name) + "_extracted"
    pw = f" -p{shlex.quote(password)}" if password else ""
    # --- Kali unpack (authoritative) ---
    kcmd = (f"cd samples && rm -rf {shlex.quote(reldir)} && "
            f"7z x -y{pw} -o{shlex.quote(reldir)} {shlex.quote(wim_rel)} 2>&1; "
            "echo __RC=$?")
    try:
        ko, _ = remote.ssh_exec(kcmd, host="kali", read_timeout=120)
    except Exception as e:  # noqa: BLE001
        return ToolResult(False, f"extract(WIM): 7z on Kali failed: "
                                 f"{e.__class__.__name__}: {e}")
    krc = "__RC=0" in ko
    if not krc:
        hint = (" (password may be wrong)" if password else
                " (if it is password-protected, pass password=...)")
        tail = " ".join(ko.split())[-300:]
        return ToolResult(False, f"extract(WIM): 7z on Kali did not succeed{hint}: {tail}")
    # --- Windows unpack (best-effort, -sns keeps ADS) ---
    win_note = ""
    sevenz = _win_7z()
    if sevenz:
        try:
            remote.upload(a.local_path, a.name, host="windows")
        except Exception:  # noqa: BLE001
            pass
        wsamp = remote.win_samples()
        wcmd = (f'cd /d "{wsamp}" & rmdir /s /q "{reldir}" 2>nul & '
                f'"{sevenz}" x -y{pw} -sns -o"{reldir}" "{wim_rel}"')
        try:
            wo, _ = remote.ssh_exec(wcmd, host="windows", read_timeout=120)
            if "Everything is Ok" in (wo or ""):
                win_note = (f" Members also unpacked on the Windows VM at "
                            f"samples/{reldir} WITH their NTFS ADS preserved (-sns) - "
                            "run them there directly.")
            else:
                win_note = (" (Windows -sns unpack did not confirm 'Everything is Ok'; "
                            "win_frida/win_gui_run will auto-copy from Kali if needed.)")
        except Exception as e:  # noqa: BLE001
            win_note = f" (Windows unpack skipped: {e.__class__.__name__})"
    else:
        win_note = (" (7z not found on the Windows VM; win_frida/win_gui_run will "
                    "auto-copy members from Kali, ADS included, on demand.)")
    # --- list Kali output, download each to the host, register as artifacts ---
    try:
        lo, _ = remote.ssh_exec(f'find "samples/{reldir}" -type f', host="kali",
                                read_timeout=30)
    except Exception as e:  # noqa: BLE001
        return ToolResult(False, f"extract(WIM): could not list extracted files: "
                                 f"{e.__class__.__name__}: {e}")
    kfiles = [l.strip() for l in (lo or "").splitlines()
              if l.strip().startswith(f"samples/{reldir}/")]
    if not kfiles:
        return ToolResult(False, f"extract(WIM): {a.name} unpacked but produced no files")
    host_root = a.local_path + "_extracted"
    new, ads = [], 0
    for kf in kfiles:
        name = kf[len("samples/"):]                 # reldir/inner/path[:stream]
        inner = name[len(reldir) + 1:]              # inner/path[:stream]
        # ':' is legal on ext4/APFS but fragile; keep the host file colon-free and
        # register the artifact under its TRUE name so a later upload recreates the ADS.
        host_inner = inner.replace(":", "__ADS__")
        host_path = os.path.join(host_root, host_inner)
        try:
            data = remote.read_bytes(kf, host="kali")
        except Exception:  # noqa: BLE001
            continue
        if len(data) > 150 * (1 << 20):
            continue
        try:
            os.makedirs(os.path.dirname(host_path), exist_ok=True)
            with open(host_path, "wb") as fh:
                fh.write(data)
        except OSError:
            continue
        reg = ws.add_artifact(host_path, name=name)
        new.append(reg)
        if ":" in inner.rsplit("/", 1)[-1]:
            ads += 1
    if not new:
        return ToolResult(False, f"extract(WIM): {a.name} unpacked but nothing could be "
                                 "downloaded from Kali")
    summ = (f"extracted {a.name} (WIM): {len(new)} file(s) registered"
            + (f", {ads} NTFS ADS stream(s) kept as 'name:stream' artifacts" if ads else ""))
    known = [f"{a.name} (WIM) extracted -> {', '.join(new[:12])}"
             + (f" (+{len(new) - 12} more)" if len(new) > 12 else "") + "." + win_note]
    if ads:
        known.append("ADS note: a 'file:stream' artifact IS the alternate data stream; "
                     "peek/read_file it directly. On Windows the same members carry the "
                     "stream inline (extracted with 7z -sns).")
    return ToolResult(True, summ, detail=(win_note.strip() or None), known=known,
                      info="\n".join(known))


@tool("extract",
      "Unpack an archive/container (zip/jar/tar/7z/WIM) into the workspace and register "
      "each resulting file as a NEW artifact you can then triage. Use for bundled "
      "challenges or nested payloads.",
      {"artifact": "name of the archive artifact (optional; default first)",
       "password": "archive password if needed (optional)"})
def extract(ws, artifact=None, password=None):
    import zipfile, tarfile
    a = _primary(ws, artifact)
    if not a:
        return ToolResult(False, _no_artifact_msg(ws, artifact, "no artifact to extract"))
    # Decide the archive TYPE before touching the disk. MEASURED 2026-09-26: extract()
    # on a PDF made an empty "<file>_extracted/" next to the challenge input before
    # answering "unrecognized archive type". 7z is also recognised by its magic now,
    # not only by the .7z extension (FLARE-On ships password-protected 7z).
    try:
        with open(a.local_path, "rb") as _f:
            _magic = _f.read(6)
    except OSError as e:
        return ToolResult(False, f"extract failed: cannot read {a.name}: {e}")
    is_wim = _magic.startswith(b"MSWIM") or a.local_path.lower().endswith(".wim")
    if is_wim:
        # WIM is not a stdlib archive and, crucially, carries NTFS alternate data
        # streams that a plain unpack loses. Handle it on the VMs with 7z instead:
        # Kali for the file bodies (ADS land as separate 'name:stream' files there),
        # Windows with -sns so the ADS survive as real streams for a later run.
        return _extract_wim(ws, a, password)
    is_zip = zipfile.is_zipfile(a.local_path)
    is_tar = (not is_zip) and tarfile.is_tarfile(a.local_path)
    is_7z = _magic == b"7z\xbc\xaf\x27\x1c" or a.local_path.lower().endswith(".7z")
    if not (is_zip or is_tar or is_7z):
        return ToolResult(False, f"{a.name}: unrecognized archive type")
    dest = a.local_path + "_extracted"
    existed = os.path.isdir(dest)
    os.makedirs(dest, exist_ok=True)

    def _drop_empty_dest():
        # Remove a dest dir WE created for an extraction that failed/yielded nothing.
        # Measured 2026-09-26: a wrong 7z password leaves a partial (garbage) member
        # behind, so a plain rmdir is not enough - and a half-written file would later
        # look like real extracted content. Never touches a dir that existed before.
        if not existed:
            import shutil
            shutil.rmtree(dest, ignore_errors=True)
    try:
        if is_zip:
            with zipfile.ZipFile(a.local_path) as z:
                z.extractall(dest, pwd=password.encode() if password else None)
        elif is_tar:
            with tarfile.open(a.local_path) as t:
                # filter="data" refuses absolute/../ member paths (tar-slip). Python
                # 3.14 makes this the default (PEP 706) and the host venv IS 3.14,
                # so this is belt-and-braces - but the extraction happens on the
                # HOST with attacker-authored CTF archives, so never rely on the
                # interpreter version for it.
                try:
                    t.extractall(dest, filter="data")
                except TypeError:      # python < 3.12 has no `filter=`
                    t.extractall(dest)
        else:   # is_7z
            import py7zr
            with py7zr.SevenZipFile(a.local_path, "r", password=password) as z:
                z.extractall(dest)
    except Exception as e:  # noqa: BLE001
        _drop_empty_dest()
        # py7zr with NO password raises a raw coder-list repr (hundreds of chars, no
        # word "password" in it - measured 2026-09-26), so say it plainly instead.
        hint = ""
        if is_7z or is_zip:
            hint = (" (if the archive is password-protected: the password given may be "
                    "WRONG)" if password else
                    " (if the archive is password-protected: NO password was given - "
                    "call extract again with password=...)")
        return ToolResult(False, f"extract failed: {e.__class__.__name__}: "
                                 f"{str(e)[:200]}{hint}")
    new = []
    for root, _, files in os.walk(dest):
        for f in files:
            new.append(ws.add_artifact(os.path.join(root, f)))
    if not new:
        _drop_empty_dest()
        return ToolResult(False, f"{a.name}: archive empty")
    return ToolResult(True, f"extracted {a.name}: {len(new)} file(s) registered",
                      known=[f"{a.name} extracted -> {', '.join(new[:12])}"])


# --- image extraction (P2): read pictures out of a PE's .rsrc resource section ---------
# Pure stdlib PE parsing ($0, deterministic, local - no VM round-trip to find/assemble
# the images). Only converting a raw BMP/ICO to PNG (so the Brain's vision API, which
# accepts png/jpeg/gif/webp but not bmp/ico, can view it) touches Kali, via the
# ImageMagick `convert` already installed there - measured present 2026-09-22.

_IMG_MAGIC = [
    (b"\xff\xd8\xff", "jpg"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"GIF8", "gif"),
]


_RT_NAMES = {1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING",
             9: "ACCELERATOR", 10: "RCDATA", 12: "GROUP_CURSOR", 14: "GROUP_ICON",
             16: "VERSION", 24: "MANIFEST"}


def _pe_resources(data):
    """Walk a PE's .rsrc TYPE->NAME->LANG directory tree, stdlib struct only.
    Returns [(type_id, name_id, blob), ...] for every leaf, or None if `data` is not
    a PE / has no .rsrc. Trusts only e_lfanew - tolerant of a corrupted MZ signature
    (ch4's own -150 sample has byte 0 mutated by the challenge itself)."""
    try:
        e = struct.unpack_from("<I", data, 0x3c)[0]
        if data[e:e + 4] != b"PE\x00\x00":
            return None
        nsec = struct.unpack_from("<H", data, e + 6)[0]
        osz = struct.unpack_from("<H", data, e + 20)[0]
        opt = e + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        sec = opt + osz
        secs = []
        for i in range(nsec):
            o = sec + i * 40
            vs, va, rs, rp = struct.unpack_from("<IIII", data, o + 8)
            secs.append((va, vs, rp, rs))

        def r2o(rva):
            for va, vs, rp, rs in secs:
                if va <= rva < va + max(vs, rs):
                    return rva - va + rp
            return None

        ddoff = opt + (96 if magic == 0x10b else 112)
        rrva, _rsz = struct.unpack_from("<II", data, ddoff + 2 * 8)   # dir entry 2 = resource
        if not rrva:
            return None
        rbase = r2o(rrva)
        if rbase is None:
            return None

        def dirents(off):
            nn, ni = struct.unpack_from("<HH", data, off + 12)
            return [struct.unpack_from("<II", data, off + 16 + i * 8) for i in range(nn + ni)]

        out = []
        for t_nm, t_dv in dirents(rbase):
            if not (t_dv & 0x80000000):
                continue
            for n_nm, n_dv in dirents(rbase + (t_dv & 0x7fffffff)):
                if not (n_dv & 0x80000000):
                    continue
                for _l_nm, l_dv in dirents(rbase + (n_dv & 0x7fffffff)):
                    if l_dv & 0x80000000:
                        continue  # deeper than LANG level - not a normal PE, skip
                    l_off = rbase + l_dv
                    data_rva, size, _cp, _rsv = struct.unpack_from("<IIII", data, l_off)
                    data_off = r2o(data_rva)
                    if data_off is None or size <= 0:
                        continue
                    out.append((t_nm, n_nm, bytes(data[data_off:data_off + size])))
        return out
    except (struct.error, IndexError):
        return None


def _wrap_bmp(blob):
    """A PE RT_BITMAP resource is a BITMAPINFOHEADER + palette + pixels with NO
    14-byte BITMAPFILEHEADER (that header only exists in standalone .bmp FILES) -
    prepend one, computed from the real palette size, so the result is valid."""
    if len(blob) < 40:
        return None
    try:
        bi_size = struct.unpack_from("<I", blob, 0)[0]
        bit_count = struct.unpack_from("<H", blob, 14)[0]
        clr_used = struct.unpack_from("<I", blob, 32)[0]
        palette = clr_used if clr_used else (1 << bit_count if bit_count <= 8 else 0)
        off_bits = 14 + bi_size + palette * 4
        bf_size = 14 + len(blob)
        return b"BM" + struct.pack("<IHHI", bf_size, 0, 0, off_bits) + blob
    except struct.error:
        return None


def _make_ico(group_blob, icons_by_id):
    """Win32 splits an icon across an RT_GROUP_ICON (directory) + separate RT_ICON
    (image) resources; a standalone .ico FILE needs them merged into one blob."""
    if len(group_blob) < 6:
        return None
    try:
        reserved, itype, count = struct.unpack_from("<HHH", group_blob, 0)
        if count == 0 or count > 64:
            return None
        entries, images = [], []
        offset = 6 + 16 * count
        for i in range(count):
            eo = 6 + 14 * i
            if eo + 14 > len(group_blob):
                return None
            w, h, colors, resv, planes, bitcount, _bytesinres, nid = struct.unpack_from(
                "<BBBBHHIH", group_blob, eo)
            img = icons_by_id.get(nid)
            if img is None:
                return None
            entries.append(struct.pack("<BBBBHHII", w, h, colors, resv, planes, bitcount,
                                       len(img), offset))
            images.append(img)
            offset += len(img)
        header = struct.pack("<HHH", reserved, itype, count)
        return header + b"".join(entries) + b"".join(images)
    except struct.error:
        return None


@tool("extract_images",
      "Scan an artifact's PE (.exe/.dll) resource section for embedded pictures "
      "(icons, bitmaps, raw JPEG/PNG/GIF blobs) and save each as a real image file "
      "locally under <artifact>_images/. Records ONLY metadata (name/kind/size) - no "
      "interpretation, you still need view_image to SEE one. A PE with no image-shaped "
      "resources (e.g. only VERSION/MANIFEST/STRING) is a valid, informative result: it "
      "means any picture the challenge shows is drawn/loaded at RUNTIME, not embedded.",
      {"artifact": "artifact to scan (optional; default first)"})
def extract_images(ws, artifact=None):
    a = _primary(ws, artifact)
    if not a:
        return ToolResult(False, _no_artifact_msg(ws, artifact, "no artifact to scan"))
    try:
        with open(a.local_path, "rb") as f:
            data = f.read()
    except OSError as e:
        return ToolResult(False, f"cannot read {a.name}: {e}")
    leaves = _pe_resources(data)
    if leaves is None:
        return ToolResult(False, f"{a.name}: not a PE, or no .rsrc resource section found")

    icons_by_id = {n: b for t, n, b in leaves if t == 3}
    group_blobs = [b for t, _n, b in leaves if t == 14]

    outdir = _images_dir(a)

    def stash(label, kind, blob):
        return _safe_write(os.path.join(outdir, f"{label}.{kind}"), blob)

    saved = []          # (filename, kind, size)
    todo_convert = []   # local paths (bmp/ico) still needing -> png

    for t_id, n_id, blob in leaves:
        kind = next((k for m, k in _IMG_MAGIC if blob.startswith(m)), None)
        if kind:
            fn = stash(f"t{t_id}_n{n_id}", kind, blob)
            if fn:
                saved.append((os.path.basename(fn), kind, len(blob)))
        elif t_id == 2 and blob[:2] != b"BM":
            bmp = _wrap_bmp(blob)
            if bmp:
                fn = stash(f"t2_n{n_id}", "bmp", bmp)
                if fn:
                    saved.append((os.path.basename(fn), "bmp(raw)", len(bmp)))
                    todo_convert.append(fn)

    for gi, gb in enumerate(group_blobs):
        ico = _make_ico(gb, icons_by_id)
        if ico:
            fn = stash(f"group{gi}", "ico", ico)
            if fn:
                saved.append((os.path.basename(fn), "ico(raw)", len(ico)))
                todo_convert.append(fn)

    if not saved:
        types = sorted({_RT_NAMES.get(t, t) for t, _n, _b in leaves})
        return ToolResult(True, f"{a.name}: .rsrc parsed OK, 0 image-shaped resources "
                                f"among {len(leaves)} resource(s) (types present: {types}) "
                                "- any picture the app shows is drawn/loaded at runtime, "
                                "not embedded as a static resource",
                          known=[f"{a.name}: .rsrc has {len(leaves)} resource(s), types "
                                 f"{types}, none are images"])

    converted, failed = 0, 0
    for raw_fn in todo_convert:
        base = os.path.basename(raw_fn)
        try:
            remote.upload(raw_fn, base, host="kali")
            q = shlex.quote(f"samples/{base}")
            remote.ssh_exec(f"convert {q} {q}.png", host="kali", read_timeout=20)
            png = remote.read_bytes(f"samples/{base}.png", host="kali")
            png_fn = raw_fn.rsplit(".", 1)[0] + ".png"
            with open(png_fn, "wb") as f:
                f.write(png)
            saved.append((os.path.basename(png_fn), "png", len(png)))
            converted += 1
        except Exception as e:  # noqa: BLE001 - surface as a normal failed conversion, don't crash the tool
            saved.append((base, f"convert_failed({e.__class__.__name__})", 0))
            failed += 1

    a.notes["images_dir"] = outdir
    lines = [f"{n} ({k}, {sz}B)" for n, k, sz in saved]
    tail = f"; {converted} converted to png" + (f", {failed} conversion failed" if failed else "")
    return ToolResult(True, f"{a.name}: found {len(saved)} image resource(s) in {outdir}{tail}",
                      known=[f"{a.name} images: " + "; ".join(lines)])


# --- Ghidra headless decompiler (P2): pe_overview (full analysis, once) + decompile ------
# Ghidra's println() inside a headless postScript gets wrapped by its own logger:
#   single-line call  -> "INFO  DumpInfo.java> <line> (GhidraScript)  "
#   multi-line call   -> prefix ONCE before the block, " (GhidraScript)" ONCE after it,
#                        every line IN BETWEEN passed through raw (measured directly,
#                        2026-09-22, by decompiling a real function and reading the log).
# For BULK output (the function list) this script writes straight to a FILE instead of
# println/stdout: measured 2026-09-22 that Ghidra's own async console logger silently
# DROPS lines under a rapid println burst (1271 calls -> only 1055 survived, ~17% lost) -
# a real file write has no such loss. Single low-volume println calls (the decompiled
# function's pseudocode) were verified complete.
_GHIDRA_SCRIPT_SRC = '// Ghidra headless post-script (muscle-side, no interpretation - just structured dump).\n// Modes:\n//   overview <outPath>   -> write function list (name/entry/size/thunk/external) +\n//                            imports DIRECTLY TO A FILE (not println/stdout - measured\n//                            2026-09-22: println()\'d bulk output (1271 lines) silently\n//                            DROPPED ~17% of lines under Ghidra\'s async console logger;\n//                            a real file write has no such loss).\n//   function <ident>     -> decompiled pseudocode of ONE function, via println (a single\n//                            multi-line call - not bursty, verified complete/lossless).\n// <ident> for "function" mode is either an exact Ghidra function name (e.g. FUN_004a8eb0)\n// or a bare/0x-prefixed hex address (e.g. 4a8eb0, 0x4a8eb0) - resolved by name first, then\n// as an address (exact entry point, else the function containing that address).\nimport ghidra.app.script.GhidraScript;\nimport ghidra.app.decompiler.DecompInterface;\nimport ghidra.app.decompiler.DecompileResults;\nimport ghidra.program.model.listing.Function;\nimport ghidra.program.model.listing.FunctionIterator;\nimport ghidra.program.model.address.Address;\nimport ghidra.program.model.symbol.ExternalManager;\nimport ghidra.program.model.symbol.SymbolIterator;\nimport ghidra.program.model.symbol.Symbol;\nimport ghidra.util.task.ConsoleTaskMonitor;\nimport java.io.File;\nimport java.io.FileWriter;\nimport java.io.PrintWriter;\n\npublic class DumpInfo extends GhidraScript {\n\n    @Override\n    public void run() throws Exception {\n        String[] args = getScriptArgs();\n        if (args.length < 1) {\n            println("ERR: need a mode arg (overview|function)");\n            return;\n        }\n        String mode = args[0];\n        if (mode.equals("overview")) {\n            if (args.length < 2) {\n                println("ERR: overview mode needs an output file path arg");\n                return;\n            }\n            doOverview(args[1]);\n        } else if (mode.equals("function")) {\n            if (args.length < 2) {\n                println("ERR: function mode needs a name/address arg");\n                return;\n            }\n            doFunction(args[1]);\n        } else {\n            println("ERR: unknown mode " + mode);\n        }\n    }\n\n    private void doOverview(String outPath) throws Exception {\n        PrintWriter pw = new PrintWriter(new FileWriter(new File(outPath)));\n        try {\n            // FUNCTION_COUNT used to print getFunctionCount(), which also counts EXTERNAL\n            // (imported) functions, while the FUNC list below iterates internal ones only -\n            // measured 2026-09-26 (UnholyDragon, MZ-fixed): header 1271 vs 1055 FUNC lines.\n            // Count both explicitly so the header matches the list.\n            int nInt = 0;\n            FunctionIterator cit = currentProgram.getFunctionManager().getFunctions(true);\n            while (cit.hasNext()) { cit.next(); nInt++; }\n            int nExt = 0;\n            FunctionIterator xit = currentProgram.getFunctionManager().getExternalFunctions();\n            while (xit.hasNext()) { xit.next(); nExt++; }\n            pw.println("FUNCTION_COUNT=" + nInt + " internal (= the FUNC lines below) + " + nExt\n                    + " external/imported (see IMPORTS); Ghidra getFunctionCount()="\n                    + currentProgram.getFunctionManager().getFunctionCount());\n            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);\n            int n = 0;\n            while (it.hasNext() && n < 20000) {\n                Function f = it.next();\n                pw.println("FUNC " + f.getEntryPoint().toString() + " " + f.getName()\n                        + " " + f.getBody().getNumAddresses()\n                        + " thunk=" + f.isThunk() + " external=" + f.isExternal());\n                n++;\n            }\n            pw.println("=== IMPORTS ===");\n            ExternalManager em = currentProgram.getExternalManager();\n            for (String libName : em.getExternalLibraryNames()) {\n                pw.println("LIB " + libName);\n            }\n            SymbolIterator sit = currentProgram.getSymbolTable().getExternalSymbols();\n            int m = 0;\n            while (sit.hasNext() && m < 5000) {\n                Symbol s = sit.next();\n                pw.println("IMPORT " + s.getName());\n                m++;\n            }\n            pw.flush();\n            println("===OVERVIEW-DONE=== wrote " + n + " functions to " + outPath);\n        } finally {\n            pw.close();\n        }\n    }\n\n    private Address parseAddr(String ident) {\n        String hex = ident;\n        if (hex.length() > 4 && hex.substring(0, 4).equalsIgnoreCase("FUN_")) {\n            hex = hex.substring(4);\n        }\n        if (hex.length() > 2 && hex.substring(0, 2).equalsIgnoreCase("0x")) {\n            hex = hex.substring(2);\n        }\n        try {\n            return currentProgram.getAddressFactory().getAddress(hex);\n        } catch (Exception e) {\n            return null;\n        }\n    }\n\n    private Function resolveFunction(String ident) {\n        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {\n            if (f.getName().equals(ident)) {\n                return f;\n            }\n        }\n        Address addr = parseAddr(ident);\n        try {\n            if (addr != null) {\n                Function f = getFunctionAt(addr);\n                if (f != null) {\n                    return f;\n                }\n                f = currentProgram.getFunctionManager().getFunctionContaining(addr);\n                if (f != null) {\n                    return f;\n                }\n            }\n        } catch (Exception e) {\n            // not a parseable address either - fall through to not-found\n        }\n        return null;\n    }\n\n    private void doFunction(String ident) throws Exception {\n        Function f = resolveFunction(ident);\n        boolean forced = false;\n        if (f == null) {\n            Address addr = parseAddr(ident);\n            if (addr != null && currentProgram.getMemory().contains(addr)) {\n                try {\n                    disassemble(addr);\n                    Function nf = createFunction(addr, null);\n                    if (nf == null) {\n                        nf = currentProgram.getFunctionManager().getFunctionContaining(addr);\n                    }\n                    if (nf != null) {\n                        f = nf;\n                        forced = true;\n                    }\n                } catch (Exception e) {\n                    // force-create failed - fall through to the not-found path\n                }\n            }\n        }\n        println("===FUNCTION-START===");\n        if (f == null) {\n            println("ERROR: function not found: " + ident);\n            println("(no function here and the address is unmapped or could not be disassembled into a function)");\n            println("===FUNCTION-END===");\n            return;\n        }\n        println("NAME=" + f.getName());\n        println("ENTRY=" + f.getEntryPoint().toString());\n        if (forced) {\n            println("FORCED_CREATE=yes (Ghidra had no function at this address; disassembled and created one, then decompiled it)");\n        }\n        DecompInterface decomp = new DecompInterface();\n        decomp.openProgram(currentProgram);\n        DecompileResults res = decomp.decompileFunction(f, 60, new ConsoleTaskMonitor());\n        if (res != null && res.decompileCompleted()) {\n            println(res.getDecompiledFunction().getC());\n        } else {\n            println("ERROR: decompile failed: " + (res != null ? res.getErrorMessage() : "null result"));\n        }\n        decomp.dispose();\n        println("===FUNCTION-END===");\n    }\n}\n'


_GHIDRA_PROJ = "_ghidra"


_GHIDRA_PROJ_NAME = "ctfbrain"


_GHIDRA_PREFIX_RE = re.compile(r"^INFO\s+DumpInfo\.java>\s?")


_GHIDRA_SUFFIX_RE = re.compile(r"\s*\(GhidraScript\)\s*$")


def _unwrap_ghidra_log(text, script="DumpInfo.java"):
    """Strip analyzeHeadless' own log decoration ("INFO  X.java> ... (GhidraScript)")
    so the Brain sees the script's real output. The prefix carries the SCRIPT's name,
    so it cannot be hardcoded to DumpInfo once ghidra_script exists."""
    pre = re.compile(r"^INFO\s+" + re.escape(script) + r">\s?")
    out = []
    for ln in (text or "").splitlines():
        ln = pre.sub("", ln)
        ln = _GHIDRA_SUFFIX_RE.sub("", ln)
        out.append(ln)
    return "\n".join(out)


_JAVAC_DIAG_RE = re.compile(
    r"\.java:\d+:|\b(?:cannot be resolved|cannot find symbol|incompatible types|"
    r"error:|compilation failed)\b", re.I)


def _java_diagnostics(console, limit=1400):
    """The part of an analyzeHeadless log that says WHAT is wrong with the Java.

    MEASURED ch8 run 1 step 44: the compile-failure branch returned console[-1800:],
    i.e. the TAIL - which on a failed script is the GhidraScriptLoadException /
    ClassNotFoundException stack trace (10 frames of Felix/OSGi internals). The javac
    diagnostics that name the offending line sit EARLIER in the log, so the Brain was
    handed 1800 characters of noise, no cause, and then re-sent that whole stack trace
    inside the ledger on every later step. javac writes the message, then the source
    line, then a caret, then any `symbol:`/`location:` lines - so a diagnostic without
    its next few lines is only half of it; keep them.
    """
    lines = (console or "").splitlines()
    keep, out = 0, []
    for ln in lines:
        if ln.lstrip().startswith("at ") or "Exception:" in ln:
            keep = 0                       # a Java stack frame explains nothing
            continue
        if _JAVAC_DIAG_RE.search(ln):
            out.append(ln.rstrip())
            keep = 3
        elif keep and ln.strip():
            out.append(ln.rstrip())
            keep -= 1
        else:
            keep = 0
    seen, uniq = set(), []
    for ln in out:
        if ln.strip() and ln not in seen:
            seen.add(ln)
            uniq.append(ln)
    return "\n".join(uniq)[:limit]


def _ghidra_samples_dir():
    return f"/home/{remote.KALI_USER}/samples"


def _ghidra_script_dir():
    """NOT samples/. remote._ensure_self_symlink creates samples/samples -> . there,
    and while GNU find ignores it, Ghidra's -scriptPath walker FOLLOWS it: measured
    2026-09-23, analyzeHeadless emitted hundreds of
    "skipping /home/vahpem/samples/samples/samples/.../CountFns.java" lines before
    finding the real one. Harmless-looking, but it was slowing down every pe_overview
    and decompile call as well. A dedicated directory has no such loop."""
    return f"/home/{remote.KALI_USER}/ghidra_scripts"


def _ghidra_custom_dir():
    """Separate dir for the Brain's custom ghidra_script passes, so a custom script that
    fails to compile can never poison pe_overview/decompile (which run DumpInfo.java from
    _ghidra_script_dir). MEASURED ch7 run 1 s33/s49: a stale FindStr.java in the shared
    scriptPath made Ghidra choke and decompile timed out at 50s."""
    return f"/home/{remote.KALI_USER}/ghidra_scripts_custom"


def _ensure_ghidra_script_dir():
    remote.ssh_exec(f"mkdir -p {shlex.quote(_ghidra_script_dir())}", host="kali",
                    read_timeout=15)


def _run_ghidra(script_args, extra_flags, timeout, script="DumpInfo.java", scriptpath=None):
    """Shared plumbing: invoke analyzeHeadless on Kali, unwrap the log, return raw text.

    `script` is the .java file in samples/ to run as -postScript; it defaults to the
    built-in DumpInfo.java that pe_overview/decompile use, and ghidra_script passes the
    name of whatever the Brain just wrote."""
    if scriptpath is None:
        scriptpath = _ghidra_script_dir()
    flags = " ".join(extra_flags)
    args = " ".join(shlex.quote(a) for a in script_args)
    to = int(timeout)
    # `timeout -k 10 N` around analyzeHeadless. MEASURED ch9 run (2026-09-27, steps
    # 18/27/32): a 20MB stripped Rust/V8 binary blows past the deadline; before this,
    # only paramiko's read_timeout fired, so the JVM kept running on the VM and held
    # ctfbrain.lock - the NEXT pe_overview then died with LockException, and the Brain
    # spent steps 28-33 (a stall + tool-error escalation) hunting the orphan by hand.
    # A real timeout kills the JVM (and its process group, -k = SIGKILL after grace),
    # so the lock is released and the next call is clean. analyzeHeadless itself removes
    # a lock left by a killed run of a PRIOR step, but only once nothing holds it; the
    # explicit `rm -f` of a lock with no live owner covers the case where a previous
    # session's JVM was killed uncleanly. `fuser -s` = "is anything using the lock?" -
    # we only remove it when the answer is no, never yanking a lock out from under a
    # legitimately running analysis.
    lock = f"{_GHIDRA_PROJ}/{_GHIDRA_PROJ_NAME}.lock"
    inner = (
        "cd samples 2>/dev/null; "
        f"if [ -e {shlex.quote(lock)} ] && command -v fuser >/dev/null 2>&1 "
        f"&& ! fuser -s {shlex.quote(lock)} 2>/dev/null; "
        f"then rm -f {shlex.quote(lock)} {shlex.quote(lock + '~')}; fi; "
        f"timeout -k 10 {to} analyzeHeadless {_GHIDRA_PROJ} {_GHIDRA_PROJ_NAME} {flags} "
        f"-postScript {shlex.quote(script)} {args} "
        f"-scriptPath {shlex.quote(scriptpath)} 2>&1; "
        "echo __GHIDRA_RC=$?"
    )
    cmd = f"bash -c {shlex.quote(inner)}"
    out, err = remote.ssh_exec(cmd, host="kali", read_timeout=to + 25)
    combined = (out + err).strip()
    # rc 124 = the deadline fired. Surface it as a clear line the callers already scan
    # for ("did not finish"), instead of a truncated JVM log tail that looks like a
    # crash and invites a blind retry with the same too-short timeout.
    mrc = re.search(r"__GHIDRA_RC=(\d+)\s*$", combined)
    if mrc:
        rc = int(mrc.group(1))
        combined = combined[:mrc.start()].rstrip()
        if rc == 124:
            combined += (f"\n__GHIDRA_TIMEOUT__ analyzeHeadless was killed after {to}s "
                         "on the VM (the project lock was released). This binary is too "
                         "big for full auto-analysis in that budget - pass a larger "
                         "`timeout`, or skip pe_overview/decompile and use r2 "
                         "(`aaa` with a big timeout, or targeted `pdf`/`axt`) instead.")
    return _unwrap_ghidra_log(combined, script)


def _ghidra_target(ws, artifact):
    """Resolve what pe_overview/decompile should operate on. Two paths:
    (a) a REGISTERED artifact (uploads it if not yet on Kali) - prog is derived from
        its remote_path, cache state lives in a.notes (as before this fix);
    (b) a BARE filename that already exists under samples/ on Kali but was never a
        registered artifact - e.g. a header-fixed copy the Brain wrote there with
        run_script (run 4 and run 5, ch4, both independently needed exactly this and
        had no way to do it - pe_overview/decompile could only ever see the ORIGINAL
        input file). Cache state lives in ws.ghidra_cache[artifact].
    Returns (prog, cache_dict, error_result) - error_result is a ToolResult to return
    immediately when neither path resolves, else None."""
    a = _primary(ws, artifact)
    if a:
        if not a.remote_path:
            a.remote_path = remote.upload(a.local_path, a.name, host="kali")
        # samples-relative path (e.g. "data/x.bin" for a subdir file, "chall.exe" for
        # a root file): correct for `-import`, which runs with cwd=samples. `-process`
        # and scratch filenames derive the program NAME/token from it separately.
        return a.remote_path.split("samples/", 1)[-1], a.notes, None
    if artifact:
        out, _ = remote.ssh_exec(
            f"test -f samples/{shlex.quote(artifact)} && echo YES || echo NO",
            host="kali", read_timeout=15)
        if "YES" in out:
            return artifact, ws.ghidra_cache.setdefault(artifact, {}), None
        msg = _no_artifact_msg(ws, artifact, "no artifact to analyze")
        return None, None, ToolResult(False, msg + " It also isn't a file under "
                                      "samples/ on the VM (checked directly).")
    return None, None, ToolResult(False, _no_artifact_msg(ws, artifact, "no artifact to analyze"))


@tool("pe_overview",
      "Run Ghidra's full auto-analysis on a PE artifact ONCE (~1 minute the first "
      "time - $0, deterministic, no interpretation) and list every function's "
      "name/address/size plus imports. Call this BEFORE `decompile` - decompile needs "
      "the analyzed project this creates. Cached after the first call (near-instant on "
      "repeat). Large function lists are saved to a host file (page with read_file); "
      "this returns a slice inline plus the total count.",
      {"artifact": "a registered artifact name, OR a bare filename that already exists "
                   "under samples/ on the VM (e.g. one you made with run_script) even if "
                   "it was never a registered artifact (optional; default first artifact)",
       "timeout": "seconds, default 180 (first run only; cached calls are instant)"})
def pe_overview(ws, artifact=None, timeout=180):
    prog, cache, err = _ghidra_target(ws, artifact)
    if err:
        return err
    ptok = _scratch_tok(prog)          # '/'-free token for scratch filenames
    if cache.get("ghidra_overview"):
        text = cache["ghidra_overview"]
        n_funcs = cache.get("ghidra_nfuncs", "?")
        cached_detail, _ = _spill("kali", text, f"overview_{re.sub(r'[^A-Za-z0-9]', '_', prog)}")
        where = f"full list -> samples/_ghidra_funcs_{ptok}.txt (page it with read_file)"
        return ToolResult(True, f"{prog}: Ghidra overview (cached, {n_funcs} functions)",
                          detail=cached_detail + f"\n[{where}]",
                          known=[f"{prog}: Ghidra overview available (cached, "
                                 f"{n_funcs} functions; {where})"])
    _ensure_ghidra_script_dir()
    remote.write_remote("ghidra_scripts/DumpInfo.java", _GHIDRA_SCRIPT_SRC, host="kali")
    remote.ssh_exec(f"mkdir -p samples/{_GHIDRA_PROJ}", host="kali", read_timeout=15)
    out_name = f"_ghidra_funcs_{ptok}.txt"
    # ONE path for both the write and the read-back. REGRESSION measured 2026-09-23
    # (ch8 run 1, steps 7+8): when the Ghidra *script* directory moved out of samples/
    # (symlink-recursion fix), out_abs was built from _ghidra_script_dir() too, so Ghidra
    # WROTE ~/ghidra_scripts/_ghidra_funcs_X.txt while this code READ samples/... - a
    # successful 180s analysis (113KB, 2041 functions, file verified on disk) was thrown
    # away and reported as a failure, twice. The output belongs in samples/ (where
    # read_file and run_cmd look); only the .java has to live outside it.
    out_abs = f"{_ghidra_samples_dir()}/{out_name}"
    combined = _run_ghidra(["overview", out_abs],
                           [f"-import {shlex.quote(prog)} -overwrite"], timeout)
    if "===OVERVIEW-DONE===" not in combined:
        tail = combined[-1500:]
        return ToolResult(False, f"pe_overview: Ghidra ran but did not report finishing "
                                 f"the overview (analysis may have failed) - tail: {tail}")
    try:
        text = remote.read_bytes(out_abs, host="kali").decode("utf-8", "replace")
    except IOError as e:
        # Measure the failure instead of just naming it: say where the file was supposed
        # to be and what is actually there, so the next step is not a blind retry.
        seen, _ = remote.ssh_exec(
            f"ls -la {shlex.quote(out_abs)} 2>&1; "
            f"find /home/{remote.KALI_USER} -maxdepth 3 -name {shlex.quote(out_name)} "
            f"-newer {shlex.quote(_ghidra_samples_dir())}/{shlex.quote(prog)} 2>/dev/null "
            "| head -5", host="kali", read_timeout=20)
        return ToolResult(False, f"pe_overview: Ghidra reported done (it printed "
                                 f"OVERVIEW-DONE) but its output {out_abs} could not be "
                                 f"read back ({e}). Measured on the VM just now:\n"
                                 f"{seen.strip()[:600]}\nIf the file exists elsewhere, "
                                 "read it there with read_file - do NOT re-run the "
                                 "analysis, it already succeeded.")
    n_funcs = len(re.findall(r"^FUNC ", text, re.M))
    # Header now states internal + external explicitly (see DumpInfo.java). Put the
    # external count in the summary too, so "N functions" and FUNCTION_COUNT agree.
    m = re.search(r"^FUNCTION_COUNT=(\d+) internal .*?\+ (\d+) external", text, re.M)
    if m:
        n_int, n_ext = int(m.group(1)), int(m.group(2))
        cap = "" if n_funcs >= n_int else f", list CAPPED at {n_funcs} of {n_int}"
        n_funcs = f"{n_funcs} internal (+{n_ext} external/imported{cap})"
    cache["ghidra_overview"] = text
    cache["ghidra_program"] = prog
    cache["ghidra_nfuncs"] = n_funcs
    # ONE advertised path, and it is the file GHIDRA ITSELF wrote (out_name), which is
    # on disk by definition - we just read it. The old code copied the text to a SECOND
    # name and then told the Brain "full list -> inline above" whenever that copy
    # failed, while `detail` was in fact cut to 4000 chars: the Brain was told a
    # 113KB/2041-function list was complete at 40 functions.
    detail, _ = _spill("kali", text, f"overview_{re.sub(r'[^A-Za-z0-9]', '_', prog)}")
    where = f"full list -> samples/{out_name} (page it with read_file)"
    return ToolResult(True, f"{prog}: Ghidra analyzed, {n_funcs} function(s) found",
                      detail=detail + f"\n[{where}]",
                      known=[f"{prog}: Ghidra overview - {n_funcs} functions ({where})"])


@tool("decompile",
      "Decompile ONE function to labeled C-like pseudocode via Ghidra (fast, ~3s, "
      "reuses the analysis pe_overview already did - call pe_overview on this artifact "
      "first). `function` is a Ghidra name from pe_overview's list (e.g. "
      "'FUN_004a8eb0') or a bare/0x hex address (e.g. '4a8eb0', '0x4a8eb0'). If Ghidra "
      "has NO function at that address it now force-disassembles and creates one there "
      "(look for FORCED_CREATE=yes) - so a mid-function or unmapped address returns "
      "pseudocode instead of 'function not found'; no need to fall back to r2 af+pdf.",
      {"function": "Ghidra function name or hex address",
       "artifact": "same artifact/filename you passed to pe_overview (optional; default first)",
       "timeout": "seconds, default 30"})
def decompile(ws, function, artifact=None, timeout=30):
    prog, cache, err = _ghidra_target(ws, artifact)
    if err:
        return err
    # NO pre-flight refusal. Until 2026-09-23 this returned "call pe_overview first"
    # whenever ITS OWN cache key was missing - but the Ghidra project is shared, and
    # ghidra_script(analyze=true) imports and analyzes the program just as well.
    # MEASURED ch8 run 1 step 11: pe_overview had failed for an unrelated reason while
    # ghidra_script had a fully analyzed 2041-function project sitting there, and
    # decompile still refused - a stall, and the Brain wrote off the tool as "broken"
    # for the rest of the run. Ask GHIDRA whether the program is in the project
    # instead of asking our own bookkeeping.
    combined = _run_ghidra(["function", function], [f"-process {shlex.quote(os.path.basename(prog))} -noanalysis"], timeout)
    m = re.search(r"===FUNCTION-START===\n(.*?)\n===FUNCTION-END===", combined, re.DOTALL)
    if not m:
        tail = combined[-1500:]
        low = combined.lower()
        if "cannot find" in low or "not found in project" in low or "no program" in low:
            return ToolResult(False, f"decompile: '{prog}' is not in the Ghidra project "
                                     "yet, so there is nothing to decompile. Run "
                                     "pe_overview on it (or ghidra_script(..., "
                                     "analyze=true), which also imports and analyzes it) "
                                     f"and then call decompile again. Ghidra said:\n{tail[-500:]}")
        return ToolResult(False, f"decompile: no function block found - tail: {tail}")
    text = m.group(1).strip("\n")
    if text.startswith("ERROR:"):
        return ToolResult(False, f"decompile: {text}")
    # An ADDRESS inside a function resolves to that whole function - so decompile("0x..")
    # and decompile("FUN_..") of the same function return byte-identical pseudocode.
    # MEASURED ch8 run 2 (steps 32,41,45,53,55): the Brain re-fetched FUN_140012e50's
    # 5685 chars FIVE times under different arg strings; each aged out of the observation
    # window so absorb() scored it ~5000 "novel" chars = PROGRESS, hiding a pure loop.
    # If the RESOLVED function (Ghidra's NAME= line) already produced this exact text,
    # hand back a short pointer instead of the same 5685 chars, and let it score as the
    # non-progress it is.
    resolved = None
    mrn = re.search(r"^NAME=(\S+)", text)
    if mrn:
        resolved = mrn.group(1)
        prev = (cache.get("decompiled_fns") or {}).get(resolved)
        if prev == text:
            # Dedup ANY repeat of the same resolved function - whether asked by name or
            # by an address inside it. MEASURED ch8 run 2: the loop was mostly
            # decompile("FUN_140012e50") BY NAME (s32,41,53,55), so guarding this on
            # "arg differs from resolved name" (an earlier version did) missed exactly
            # the case it was written for. A repeat is a repeat; return a short pointer
            # and let it score as the non-progress it is.
            is_addr = str(function) != resolved
            if is_addr:
                detail = (f"[{function} is an address INSIDE {resolved}; you have its "
                          f"full pseudocode already.]\nFor the raw INSTRUCTIONS at "
                          f"{function} (an indirect jump/call the decompiler folds "
                          f"away), use r2: pd 30 @ {function}.")
            else:
                detail = (f"[You already decompiled {resolved} ({len(text)} chars) this "
                          "run - its pseudocode is unchanged. Re-read your earlier "
                          "decompile, or act on it; decompiling it again yields the "
                          "same text.]")
            return ToolResult(True,
                f"decompile({function}): already have {resolved} "
                f"({len(text)} chars) - not re-fetching it.",
                detail=detail,
                known=[f"decompile({function}) -> {resolved} (already have it)"])
    flag = _find_flag(text)
    n = len(text)
    safe_fn = re.sub(r"[^A-Za-z0-9_]", "_", function)
    # One path for BOTH the cut and the marker. Before 2026-09-23 the marker was added
    # only `if saved`, so when _save_to_host failed (it swallows every exception and
    # returns None) a 20000-char function arrived as 4000 chars, ok=True, with nothing
    # saying it had been cut - and author_and_run then fed that half function to the
    # script-writer as evidence.
    detail, saved = _spill("kali", text, f"decompile_{safe_fn}")
    if saved is None and n > len(detail):
        detail += (f"\n...[this pseudocode is {n} chars and could NOT be saved to the "
                   "VM - what you see above is all of it that survived. Re-run "
                   "decompile, or use ghidra_script to write it to a file yourself.]")
    # Store the pseudocode so author_and_run can hand it to the script-writer as
    # EVIDENCE. Until 2026-09-22 nothing ever wrote this key while author_and_run
    # read it (a.notes.get("decompiled")), so every generated solver was written
    # WITHOUT the decompiled code - the script-writer saw only text/strings/hex plus
    # the ledger. (The controller/decide() side was fine: it gets res.detail via
    # ws.observe().) `cache` is a.notes for a registered artifact, so the reader
    # finds it there; ws.ghidra_cache[name] for a bare VM filename.
    cache.setdefault("ghidra_program", prog)   # decompile just proved it is in the project
    cache["decompiled"] = f"// decompile({function})  [{n} chars]\n{text}"
    fns_store = cache.setdefault("decompiled_fns", {})
    fns_store[str(function)] = text
    if resolved and resolved != str(function):
        fns_store[resolved] = text           # so a later decompile(<addr in this fn>) dedups
    known_fact = f"decompile({function}) -> {n} chars pseudocode"
    if saved:
        known_fact += f" (full -> {saved}, page with read_file)"
    return ToolResult(True, f"decompiled {function} ({n} chars)" + ("; FLAG" if flag else ""),
                      detail=detail, known=[known_fact],
                      flag=flag)


# --- $0 environment probe (run once at solve() start) -----------------------------
# "Đo lường thay vì giả định": the static INSTALL hint used to ASSERT things about the
# VM and got them wrong (it claimed `pip install X` works; it does not - PEP 668). One
# SSH round-trip measures the truth instead, and the result is seeded into the ledger
# as a PINNED fact so the Brain sees it on every single step.
_PROBE_MODULES = [
    "angr", "capstone", "unicorn", "z3", "pefile", "lief", "pwn", "elftools",
    "xdis", "uncompyle6", "decompyle3", "dis",
    "Crypto", "Cryptodome", "cryptography", "yara",
    "numpy", "PIL", "requests", "scapy", "frida",
    "fitz", "zxingcpp", "r2pipe", "dnfile", "dncil", "oletools", "olefile",
    "capa", "floss", "minidump", "macholib",
]


_PROBE_SRC = """
import sys, os, importlib.util as iu, shutil
def has(m):
    try:
        return iu.find_spec(m) is not None
    except Exception:
        return False
mods = %r
import platform as _plat
print("ARCH|" + _plat.machine())
print("PY|" + sys.executable + "|" + sys.version.split()[0])
print("PIP|" + os.path.join(os.path.dirname(sys.executable), "pip"))
print("MODS|" + ",".join(m for m in mods if has(m)))
print("SITE|system_site=%%s user_site=%%s" %% (
    os.path.exists(os.path.join(sys.prefix, "pyvenv.cfg")) and
    ("include-system-site-packages = true" in
     open(os.path.join(sys.prefix, "pyvenv.cfg")).read()),
    __import__("site").ENABLE_USER_SITE))
vbin = os.path.dirname(sys.executable)
abs_tools = []
for n in ["floss", "capa", "pydisasm", "uncompyle6", "decompyle3", "ROPgadget",
          "checksec"]:
    q = os.path.join(vbin, n)
    if os.path.exists(q):
        abs_tools.append(q)
home = os.path.expanduser("~")
for q in [os.path.join(home, "tools", "pycdc", "pycdc"),
          os.path.join(home, "tools", "pycdc", "pycdas"),
          os.path.join(home, "tools", "jadx", "bin", "jadx"),
          os.path.join(home, "tools", "pyinstxtractor.py"),
          os.path.join(home, "tools", "capa-rules"),
          os.path.join(home, "tools", "capa-src", "sigs")]:
    if os.path.exists(q):
        abs_tools.append(q)
print("ABS|" + " ".join(abs_tools))
print("BIN|" + " ".join(t for t in
      ["analyzeHeadless", "radare2", "rabin2", "binwalk", "tshark", "convert",
       "qpdf", "7z", "upx", "gdb", "objdump", "strings", "uv", "curl",
       "Xvfb", "xvfb-run", "xdotool", "import", "mutool", "wine", "tesseract",
       "node", "chromium", "firefox-esr"]
      if shutil.which(t)))
""" % (_PROBE_MODULES,)


def probe_environment(host="kali"):
    """Return one dense, MEASURED fact line about the analysis VM (or a fallback
    string if the VM cannot be reached). Never raises."""
    from . import config
    try:
        remote.write_remote("samples/_probe_env.py", _PROBE_SRC, host=host)
        out, err = remote.ssh_exec(
            f"cd samples 2>/dev/null; {shlex.quote(remote.KALI_PYTHON)} _probe_env.py 2>&1; "
            "echo \"PATH|$PATH\"; "
            "(sudo -n true 2>/dev/null && echo 'SUDO|passwordless') "
            "|| echo 'SUDO|needs a password (no TTY here, so sudo/apt lines always fail)'",
            host=host, read_timeout=45)
        text = (out or "") + (err or "")
        f = {}
        for ln in text.splitlines():
            k, sep, v = ln.partition("|")
            if sep:
                f[k.strip()] = v.strip()
        if "PY" not in f:
            return config.ENV_FACTS_FALLBACK + f" (probe output: {text[:200]!r})"
        exe, _, ver = f["PY"].partition("|")
        pip = f.get("PIP", "?")
        vbin_hint = os.path.dirname(pip) if "/" in pip else "<venv>/bin"
        return (
            "ENVIRONMENT FACTS (measured on the analysis VM at the start of THIS run "
            "- trust these over any assumption):\n"
            f"  * solver interpreter = {exe} (Python {ver}). author_and_run and "
            "run_script(kind='python3') use exactly this unless you pass `python=`.\n"
            f"  * ALREADY IMPORTABLE by it (do NOT install these again): {f.get('MODS','(none found)')}\n"
            f"  * isolation: {f.get('SITE','?')} -> a library installed anywhere ELSE "
            "is NOT importable by the solver.\n"
            f"  * to add a library the solver can import: `{pip} install <name>` "
            "(a bare `pip install` hits PEP 668 and fails).\n"
            f"  * CLI tools on PATH: {f.get('BIN','?')}\n"
            + (f"  * NOT on PATH, call by ABSOLUTE path: {f.get('ABS')}\n"
               if f.get("ABS") else "")
            + (f"  * capa needs BOTH its rules and its signatures: `{vbin_hint}/capa "
               "-r ~/tools/capa-rules -s ~/tools/capa-src/sigs <file>`. The capa on "
               "PATH (/usr/local/bin/capa) is BROKEN - measured 2026-09-22, it "
               "tracebacks even on --version; use the venv one above.\n"
               if "capa-rules" in (f.get("ABS") or "") else "")
            + (f"  * THIS VM's CPU IS {f['ARCH']}, and FLARE-On binaries are x86-64. "
               "Measured 2026-09-23: there is no x86-64 loader or libc on this Kali "
               "(/lib64/ld-linux-x86-64.so.2 is absent; qemu-x86_64 alone cannot "
               "substitute), so an x86-64 Linux ELF CANNOT BE RUN here - only analysed "
               "statically. The Windows VM is ARM64 too, but Windows-on-ARM emulates "
               "x86-64, so an x86-64 .exe DOES run there (run_cmd/run_script/"
               "win_gui_run with host='windows'). Plan dynamic analysis around that "
               "split rather than discovering it by failing.\n"
               if "aarch64" in (f.get("ARCH") or "") or "arm" in (f.get("ARCH") or "").lower()
               else f"  * this VM's CPU is {f.get('ARCH','?')}\n")
            + f"  * sudo: {f.get('SUDO','?')}\n"
            + f"  * PATH = {f.get('PATH','?')}  (note: no ~/.local/bin and no "
              "venv/bin here - call those by full path)"
        )
    except Exception as e:  # noqa: BLE001 - a probe failure must never abort a run
        return config.ENV_FACTS_FALLBACK + f" (probe error: {e.__class__.__name__}: {e})"


# --- Seeing things: images, PDFs, and real GUIs -----------------------------------
# Claude resizes anything whose long edge exceeds ~1568px, and a full-screen capture
# costs ~1.1-1.6k input tokens either way, so shrink BEFORE sending: cheaper and no
# quality lost to a server-side resize we don't control.
IMAGE_MAX_EDGE = 1568


IMAGE_MAX_BYTES = 4_000_000


_VIEWABLE = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
             "gif": "image/gif", "webp": "image/webp"}


_CONVERTIBLE = {"bmp", "ico", "tif", "tiff", "ppm", "pgm", "pnm", "tga", "dib"}


def _images_dir(a):
    """Where derived pictures go. Next to the artifact when that is writable (handy
    for a human poking at the files), otherwise a scratch dir - a challenge folder can
    be read-only, on a synced/mounted volume that refuses unlink, or already hold a
    file from an earlier run that the writer wants to replace. Measured 2026-09-22:
    pymupdf's save() unlinks an existing target first, and on a mount that forbids
    unlink that raised out of the tool and killed the whole step."""
    cand = a.local_path + "_images"
    try:
        os.makedirs(cand, exist_ok=True)
        probe = os.path.join(cand, ".w")
        with open(probe, "w") as f:
            f.write("x")
        os.remove(probe)
        return cand
    except OSError:
        import tempfile
        alt = os.path.join(tempfile.gettempdir(), "ctfbrain_images",
                           re.sub(r"[^A-Za-z0-9_.-]", "_", a.name))
        os.makedirs(alt, exist_ok=True)
        return alt


def _safe_write(path, data):
    """Write bytes, replacing a stale file even where unlink is awkward. Returns the
    path written, or None (never raises - one unwritable file must not kill a tool)."""
    try:
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass
        with open(path, "wb") as f:
            f.write(data)
        return path
    except OSError:
        return None


def _prepare_image(raw, ext):
    """(media_type, base64, note) or (None, None, reason). Converts and downscales
    with Pillow when the HOST has it; falls back to ImageMagick on Kali; and finally
    to sending the bytes untouched when the format is already viewable."""
    ext = (ext or "").lower().lstrip(".")
    note = ""
    try:
        import io
        from PIL import Image
        im = Image.open(io.BytesIO(raw))
        w, h = im.size
        changed = False
        if max(w, h) > IMAGE_MAX_EDGE:
            sc = IMAGE_MAX_EDGE / float(max(w, h))
            im = im.resize((max(1, int(w * sc)), max(1, int(h * sc))), Image.LANCZOS)
            note = f" (downscaled {w}x{h} -> {im.size[0]}x{im.size[1]})"
            changed = True
        if ext not in _VIEWABLE or changed:
            buf = io.BytesIO()
            im.convert("RGBA" if im.mode in ("RGBA", "LA", "P") else "RGB").save(buf, "PNG")
            return "image/png", base64.b64encode(buf.getvalue()).decode(), note or " (converted to png)"
        return _VIEWABLE[ext], base64.b64encode(raw).decode(), f" ({w}x{h})"
    except ImportError:
        pass
    except Exception as e:  # noqa: BLE001 - a corrupt/odd image is a normal result
        return None, None, f"could not decode as an image ({e.__class__.__name__}: {e})"
    # no Pillow on the host: ImageMagick on Kali can still convert
    if ext in _CONVERTIBLE:
        try:
            remote.write_remote("samples/_viewconv_in", raw, host="kali")
            remote.ssh_exec("cd samples && convert _viewconv_in -resize "
                            f"{IMAGE_MAX_EDGE}x{IMAGE_MAX_EDGE}\\> _viewconv_out.png",
                            host="kali", read_timeout=40)
            png = remote.read_bytes("samples/_viewconv_out.png", host="kali")
            return "image/png", base64.b64encode(png).decode(), " (converted on Kali)"
        except Exception as e:  # noqa: BLE001
            return None, None, f"format .{ext} needs conversion and it failed ({e})"
    if ext in _VIEWABLE:
        if len(raw) > IMAGE_MAX_BYTES:
            return None, None, f"{len(raw)} bytes is over the {IMAGE_MAX_BYTES}-byte cap"
        return _VIEWABLE[ext], base64.b64encode(raw).decode(), " (sent as-is)"
    return None, None, f"format .{ext} is not viewable"


def _fetch_image_bytes(ws, path, artifact, host):
    """(raw_bytes, ext, where) or raises ValueError with an actionable message."""
    if host in ("kali", "windows"):
        if not path:
            raise ValueError("host='%s' needs `path` (a file on that VM)" % host)
        p = path if re.match(r"^([A-Za-z]:|[\\/])", path) else f"samples/{path}"
        try:
            return remote.read_bytes(p, host=host), path.rsplit(".", 1)[-1], f"{host}:{p}"
        except IOError:
            raise ValueError(f"{p} does not exist on {host}")
    a = _primary(ws, artifact)
    cands = []
    outdir = a.notes.get("images_dir") if a else None
    if outdir and path:
        cands.append(os.path.join(outdir, os.path.basename(path)))
    if path:
        cands += [path, os.path.join(os.getcwd(), path)]
        for art in ws.artifacts.values():
            d = art.notes.get("images_dir")
            if d:
                cands.append(os.path.join(d, os.path.basename(path)))
    if not path and a:
        cands.append(a.local_path)          # view the artifact itself (a .png challenge)
    for c in cands:
        if c and os.path.isfile(c):
            with open(c, "rb") as f:
                return f.read(), c.rsplit(".", 1)[-1], c
    have = []
    for art in ws.artifacts.values():
        d = art.notes.get("images_dir")
        if d and os.path.isdir(d):
            have += [f"{art.name}:{n}" for n in sorted(os.listdir(d))[:20]]
    raise ValueError(
        f"no image found for path={path!r} artifact={artifact!r} host={host!r}. "
        + (f"Extracted images available: {', '.join(have)}. " if have else
           "No images have been extracted yet (try extract_images / pdf_pages). ")
        + "For a file that lives on a VM pass host='kali' or host='windows' with its path.")


@tool("view_image",
      "SEE a picture - attached to your VERY NEXT turn (this call returns text only; "
      "the image appears on the next decide() and is then cleared, so describe what "
      "you saw in that turn's 'note'). Works on ANY image, not just extracted ones: a "
      "file extracted by extract_images/pdf_pages, an image artifact given as the "
      "challenge input (call with no args), a local path, or a file sitting on a VM "
      "(pass host='kali'/'windows' + its path) - e.g. a screenshot, a PNG a solver "
      "just wrote, a rendered PDF page. bmp/ico/tiff are converted automatically and "
      "big images are downscaled before sending.",
      {"path": "image file name or path (optional; omit to view the artifact itself)",
       "artifact": "artifact it belongs to (optional; default first)",
       "host": "'local' (default), 'kali' or 'windows' - where the file lives"})
def view_image(ws, path=None, artifact=None, host="local"):
    try:
        raw, ext, where = _fetch_image_bytes(ws, path, artifact, host)
    except ValueError as e:
        return ToolResult(False, str(e))
    media, b64, note = _prepare_image(raw, ext)
    if not media:
        return ToolResult(False, f"{where}: {note}")
    return ToolResult(True, f"showing {where}{note} on your next turn",
                      known=[f"viewed image {where}{note}"],
                      image={"media_type": media, "data": b64})


@tool("pdf_pages",
      "Turn a PDF into things you can actually look at and read: renders each page to "
      "a PNG, pulls out every embedded image, and extracts the page text - all $0 and "
      "local. Use view_image afterwards to SEE a page or an extracted image. Good "
      "first move on any PDF challenge, where the visible page and the file's internal "
      "objects are often telling different stories.",
      {"artifact": "PDF artifact (optional; default first)",
       "pages": "how many pages to render, from the first (default 5)",
       "zoom": "render scale, 1.0 = 72dpi (default 2.0)"})
def pdf_pages(ws, artifact=None, pages=5, zoom=2.0):
    a = _primary(ws, artifact)
    if not a:
        return ToolResult(False, _no_artifact_msg(ws, artifact, "no artifact"))
    try:
        import pymupdf  # noqa: F401
    except ImportError:
        try:
            import fitz as pymupdf  # noqa: F401
        except ImportError:
            return ToolResult(False, "pdf_pages needs pymupdf on the HOST "
                                     "(pip install pymupdf in the orchestrator venv)")
    try:   # CTF PDFs are deliberately malformed; MuPDF's recovery warnings on stderr
        pymupdf.TOOLS.mupdf_display_errors(False)   # would otherwise flood the run log
    except Exception:  # noqa: BLE001
        pass
    outdir = _images_dir(a)
    try:
        doc = pymupdf.open(a.local_path)
    except Exception as e:  # noqa: BLE001
        return ToolResult(False, f"{a.name}: not a readable PDF ({e})")
    facts, saved, texts = [], [], []
    n_pages = doc.page_count
    failed = 0
    for i in range(min(int(pages), n_pages)):
        try:
            pg = doc.load_page(i)
            png = pg.get_pixmap(matrix=pymupdf.Matrix(float(zoom), float(zoom))).tobytes("png")
            if _safe_write(os.path.join(outdir, f"page{i+1}.png"), png):
                saved.append(f"page{i+1}.png")
            else:
                failed += 1
            t = (pg.get_text() or "").strip()
            if t:
                texts.append(f"[page {i+1} text]\n{t[:1500]}")
        except Exception as e:  # noqa: BLE001 - a broken page is normal in CTF PDFs
            failed += 1
            texts.append(f"[page {i+1}] could not be rendered: "
                         f"{e.__class__.__name__}: {e} - which is itself evidence "
                         "about how the file is malformed")
    n_img = 0
    for i in range(n_pages):
        for xref, *_ in doc.load_page(i).get_images(full=True):
            try:
                d = doc.extract_image(xref)
            except Exception:  # noqa: BLE001
                continue
            fn = os.path.join(outdir, f"p{i+1}_img{xref}.{d['ext']}")
            if _safe_write(fn, d["image"]):
                saved.append(os.path.basename(fn))
                n_img += 1
    a.notes["images_dir"] = outdir
    doc.close()
    if not saved and not texts:
        return ToolResult(False, f"{a.name}: PDF opened ({n_pages} page(s)) but nothing "
                                 "could be rendered or extracted from it")
    facts.append(f"{a.name}: PDF with {n_pages} page(s); rendered "
                 f"{min(int(pages), n_pages) - failed} page(s) to PNG"
                 + (f" ({failed} page(s) failed to render)" if failed else "")
                 + f", extracted {n_img} embedded image(s)"
                 + (f" -> {', '.join(saved[:16])} in {outdir} (view one with view_image)"
                    if saved else " - nothing written"))
    all_text = "\n\n".join(texts)
    detail, _ = _spill("kali", all_text, "pdf_text")
    detail = detail or "(no extractable text on the rendered pages)"
    flag = _find_flag(detail)
    return ToolResult(True, f"{a.name}: {n_pages} page(s), {len(saved)} image file(s) written",
                      detail=detail, known=facts, flag=flag)


@tool("win_windows",
      "List the windows currently open on the Windows VM's REAL desktop (interactive "
      "session), as TEXT: process name, window title, and - via UI Automation - the "
      "class and control type of every top-level window, including message boxes and "
      "error dialogs. This is the CHEAP way to see what a GUI program is showing; try "
      "it BEFORE win_screenshot, since a picture costs ~1.5k tokens and a dialog's "
      "title plus text is usually the whole answer. Pass `match` to dump all readable "
      "text inside one window (substring of its title or class).",
      {"match": "substring of a window title/class to dump the inner text of (optional)",
       "timeout": "seconds, default 40"})
def win_windows(ws, match=None, timeout=40):
    return _vm(dvm_windows.win_windows(match=match, timeout=timeout))


@tool("win_screenshot",
      "Take a picture of the Windows VM's REAL desktop (interactive session) and "
      "attach it to your NEXT turn so you can SEE it. Use when win_windows' text is "
      "not enough - a drawn image, a custom-rendered widget, a game, a CAPTCHA-like "
      "puzzle, anything whose meaning is visual. Costs ~1.5k tokens per look, so "
      "prefer win_windows first and say what you saw in that turn's 'note'.",
      {"timeout": "seconds, default 40"})
def win_screenshot(ws, timeout=40):
    return _vm(dvm_windows.win_screenshot(timeout=timeout))


@tool("win_gui_run",
      "Run a program on the Windows VM's REAL desktop (interactive session), wait, "
      "then report what happened: exit code if it finished, or - if it is still up - "
      "its window title, every top-level window on screen, and a screenshot attached "
      "to your NEXT turn. THIS is how you 'just run it and read the error dialog'. "
      "Running a GUI program through run_cmd/run_script instead puts it on the "
      "invisible service desktop where you cannot see it AND a modal dialog blocks "
      "until the timeout kills it, which looks like 'produced no output'.",
      {"program": "program to run - a bare filename resolves inside samples/ (e.g. "
                  "'ntfsm.exe'), or give an absolute path",
       "args": "command-line arguments (optional)",
       "wait": "seconds to let it run before looking (default 6)",
       "kill": "true (default) to close it afterwards; false to leave it running so a "
               "later win_windows/win_screenshot can look again. NOTE: many modern "
               "programs are thin launchers that exit at once while the real window "
               "belongs to a DIFFERENT process - so judge by the window list, not by "
               "EXITED/EXITCODE, and kill by process name if you need it gone",
       "screenshot": "true (default) to also attach a picture",
       "timeout": "seconds, default 60"})
def win_gui_run(ws, program, args="", wait=6, kill=True, screenshot=True, timeout=60):
    return _vm(dvm_windows.win_gui_run(program=program, args=args, wait=wait, kill=kill, screenshot=screenshot, timeout=timeout))


@tool("linux_gui_run",
      "Run a GUI program on KALI under a virtual X display (Xvfb) and photograph the "
      "result - Kali is headless, so without this a GUI binary there just fails with "
      "'cannot open display'. Returns the window titles it found plus a screenshot "
      "attached to your NEXT turn.",
      {"command": "the command to launch (runs in samples/, e.g. './chal' or 'wine x.exe')",
       "wait": "seconds to let it draw before capturing (default 5)",
       "screen": "virtual screen size, default '1280x800x24'",
       "timeout": "seconds, default 60"})
def linux_gui_run(ws, command, wait=5, screen="1280x800x24", timeout=60):
    return _vm(dvm_linux.linux_gui_run(command=command, wait=wait, screen=screen, timeout=timeout))


@tool("linux_gdb",
      "SCRIPTABLE DEBUGGER on the Kali VM (the Linux twin of win_frida). You write a "
      "gdb-PYTHON script; it runs the target under gdb with ASLR OFF and whatever your "
      "script log()s / prints comes back as raw lines. This is how you break, read a "
      "register or memory, dump a decrypted buffer, patch bytes, or drive a function - "
      "on a Linux ELF, without a GUI debugger. Runs under Xvfb by default so a GUI / "
      "GTK / webkit binary actually starts (set gui=false for a pure console target). "
      "PIE BASE IS FIXED at 0x555555554000 (ASLR disabled), so an RVA from r2/objdump "
      "maps straight to a live address - use the ready-made at(rva) helper, no leak "
      "needed. READY-MADE (all injected, just call them): log(*a) print one raw line; "
      "rd(addr,n)/wr(addr,data) read/write inferior memory (wr = patch bytes or swap a "
      "buffer in place); u64/u32/f64(addr); reg('rsi'); cstr(addr) read a C string; "
      "at(rva)=base+rva; base(); hook(rva_or_'*addr'_or_'sym', fn) breaks and calls "
      "fn(bp) then CONTINUES (fn returns True to stop) - an int arg is an RVA, a str is "
      "a gdb location; starti()/cont()/run(). ORDER for an RVA hook: starti() FIRST "
      "(loads the program so the base is known), THEN hook(rva, fn), THEN cont(). A "
      "string-location hook (a symbol or '*0xabsolute') may be set before run(). A "
      "breakpoint's fn runs WHILE stopped, so read "
      "registers/memory there. To capture a value only valid at that PC, read it inside "
      "fn - e.g. hook(0x61834d, lambda b: log('len', reg('rdx'), cstr(reg('rsi')))). To "
      "replace data the program is about to use, wr() it inside the hook (e.g. overwrite "
      "a just-decrypted script buffer, then adjust the length register). log() a "
      "SUMMARY, not one line per loop iteration (huge output is truncated). Your script "
      "and its breakpoints live ONLY for this one call. Webkit forks helper processes; "
      "gdb stays on the parent automatically. If the target never reaches your "
      "breakpoint, that PC is on a path your input doesn't take - hook an earlier / "
      "always-run address, or read the value where it IS live.",
      {"script": "the gdb-python to run (required). Uses the injected helpers above; "
                 "set hooks then call run().",
       "program": "program to debug - bare filename resolves under samples/ on Kali "
                  "(e.g. 'neon_outrun'), or an absolute path (required)",
       "args": "command-line arguments for the target (string or list; optional)",
       "gui": "true (default) runs under Xvfb so a GUI/webkit app can start; false skips "
              "Xvfb for a console-only target",
       "screen": "Xvfb virtual screen, default '1280x800x24'",
       "max_lines": "cap on output lines returned (default 800)",
       "timeout": "seconds, default 120 (the whole gdb run is killed after this)"})
def linux_gdb(ws, script, program=None, args="", gui=True, screen="1280x800x24",
              max_lines=800, timeout=120):
    prog, _cache, err = _ghidra_target(ws, program)
    if err:
        return err
    return _vm(dvm_linux.linux_gdb(prog, script, args=args, gui=gui,
                                   screen=screen, max_lines=max_lines,
                                   timeout=timeout))


# One line, so a JS_ERROR line number is exactly 1 more than the Brain's own line;
# _fix_js_lines() puts it back before the Brain ever sees it. Gives every script
# hex(p,n) - because readByteArray inside a send() payload is silently dropped -
# plus at(mod,off) for "the address Ghidra showed me".
_FRIDA_PRELUDE_TMPL = (
    "function hex(p,n){var u=new Uint8Array(ptr(p).readByteArray(n));var o='';"
    "for(var i=0;i<u.length;i++){o+=('0'+u[i].toString(16)).slice(-2);}return o;} "
    "function at(m,o){return Process.getModuleByName(m).base.add(o);} "
    "function mod(m){return Process.getModuleByName(m);} "
    # exp(dll, ...parts): resolve an export by SUBSTRING match on its (mangled) name -
    # so you hook `exp('Qt6Widgets.dll','QLineEdit','setText')` instead of guessing the
    # exact C++ decoration (which was the repeated JS_ERROR on ch8). Returns the address
    # or null.
    "function exp(m){var a=[].slice.call(arguments,1);var es=Process.getModuleByName(m).enumerateExports();"
    "for(var i=0;i<es.length;i++){var n=es[i].name.toLowerCase();var ok=true;"
    "for(var j=0;j<a.length;j++){if(n.indexOf((''+a[j]).toLowerCase())<0){ok=false;break;}}"
    "if(ok)return es[i].address;}return null;} "
    # key(vk) / click(x,y): DRIVE the GUI from inside THIS call so a hooked handler
    # actually fires (hooks die when the call returns). Needs desktop=true so the window
    # is real. VK digits '0'-'9' = 0x30-0x39; get x,y from a win_ui_tree rect (centre of
    # the button). One press/click with your hook installed catches the handler.
    "var _NF={};function _nf(n,r,a){if(!_NF[n]){_NF[n]=new NativeFunction(Module.getGlobalExportByName(n),r,a);}return _NF[n];} "
    "function key(vk){var f=_nf('keybd_event','void',['uint8','uint8','uint32','pointer']);f(vk,0,0,ptr(0));Thread.sleep(0.03);f(vk,0,2,ptr(0));} "
    "function click(x,y){_nf('SetCursorPos','int',['int','int'])(x,y);var m=_nf('mouse_event','void',['uint32','uint32','uint32','uint32','pointer']);m(2,0,0,0,ptr(0));Thread.sleep(0.03);m(4,0,0,0,ptr(0));} "
    "var LOG_PATH='__LOGPATH__';var _LF=null;"
    "function log(s){try{if(!_LF){_LF=new File(LOG_PATH,'a');}_LF.write(''+s+'\\n');"
    "_LF.flush();}catch(e){send({log_failed:''+e,path:LOG_PATH});}}\n"
)


# _fix_js_lines must shift by however many lines the prelude really adds - hardcoding
# "1" would silently mis-number every JS error the day someone adds a second line.
_PRELUDE_LINES = _FRIDA_PRELUDE_TMPL.count("\n")


def _fix_js_lines(text):
    """Report the Brain's OWN line numbers: subtract the lines the prelude added."""
    def shift(m):
        try:
            return m.group(1) + str(int(m.group(2)) - _PRELUDE_LINES) + m.group(3)
        except Exception:  # noqa: BLE001
            return m.group(0)
    text = re.sub(r"(JS_ERROR line )(\d+)(:)", shift, text or "")
    # the raw stack frames carry the same off-by-one; leaving them un-shifted makes
    # the Brain doubt the corrected number right above them
    return re.sub(r"(/script\d*\.js:)(\d+)(\b)", shift, text)


@tool("win_frida",
      "SCRIPTABLE DEBUGGER on the Windows VM. You write a Frida JavaScript snippet; it "
      "runs INSIDE the target process and whatever it send()s comes back to you as raw "
      "lines. This is how you set a breakpoint, read a function's arguments, dump "
      "decrypted memory, patch a check, or log a loop - without any GUI debugger. "
      "Verified working on x86-64 PEs (they run under this ARM64 VM's x64 emulator). "
      "API is Frida 17, which REMOVED several names you may remember: use "
      "Module.getGlobalExportByName('CreateFileW') (NOT Module.findExportByName), and "
      "Process.getModuleByName('thing.exe') -> .base / .size / .getExportByName(n) "
      "(NOT Module.getBaseAddress). For a C++/mangled export DON'T guess the decorated "
      "name - use the ready-made exp('Qt6Widgets.dll','QLineEdit','setText') which "
      "enumerates exports and matches ALL the substrings you give, returning the "
      "address (this was the repeated JS_ERROR on Qt). Core moves: "
      "Interceptor.attach(addr, {onEnter(args){send({a0:args[0].toString()})}, "
      "onLeave(r){send({ret:r.toInt32()})}}); "
      "Interceptor.replace(addr, new NativeCallback(...)); "
      "p.readByteArray(n) / p.readUtf8String() / p.readPointer() / p.writeByteArray([..]); "
      "Memory.scanSync(m.base, m.size, '48 8b ?? ??'). RAW BYTES: a readByteArray ArrayBuffer put INSIDE a send() payload is silently dropped and arrives as {} - use the ready-made hex(ptr, n) helper instead (also at(module, offset) and mod(name)), or pass the buffer as send()'s SECOND argument. To break at an address you found "
      "in Ghidra: Process.getModuleByName('x.exe').base.add(ghidra_addr - image_base) "
      "(typical 64-bit PE image base is 0x140000000). To CAPTURE A REGISTER at that address, "
      "read it INSIDE onEnter and send it as a STRING (a NativePointer/UInt64 put raw into "
      "send() arrives wrong): Interceptor.attach(mod('x.exe').base.add(rva),{onEnter(a){"
      "send({rax:this.context.rax.toString(16),rcx:this.context.rcx.toString(16)});}}) - do "
      "NOT send only at attach time, the value exists only when the hook FIRES. If a hook "
      "installs but never fires on your input, that address is on a branch your input does "
      "not reach (e.g. a compare AFTER a control-flow-flattening dispatch): hook the FUNCTION "
      "ENTRY or an always-run address, or emulate the function offline instead. "
      "send() a SUMMARY, not one message "
      "per loop iteration - thousands of lines get dropped. "
      "LIFETIME - READ THIS BEFORE HOOKING: your script is UNLOADED the moment this "
      "call returns, so every Interceptor.attach dies with it. kill=false keeps the "
      "PROCESS alive, NOT your hooks: a later win_ui_seq/win_ui_click or a second "
      "win_frida will NOT hit them (measured ch8 run 1 - 12 steps were spent "
      "rediscovering this). So the code you want to observe must be triggered INSIDE "
      "THIS SAME CALL. For a GUI app set desktop=true and use the ready-made "
      "key(vk) (press a keyboard key; digit '1'=0x31) or click(x,y) (click a point - "
      "take x,y from the centre of a win_ui_tree button rect): install your hook, "
      "then key()/click() ONCE so the handler fires inside this call. E.g. to find a "
      "Qt onNumberClicked handler: Interceptor.attach(exp('Qt6Widgets.dll','QLineEdit',"
      "'setText'),{onEnter(a){send({caller:this.returnAddress.sub(mod('x.exe').base)})}}); "
      "then make the app fire that handler by passing drive='1,2,3,OK' (see the drive "
      "arg): the tool clicks those GUI buttons by UIA InvokePattern WHILE your hooks are "
      "live, so the handler runs inside this call and your send()/log() capture it - a "
      "separate win_ui_seq afterwards cannot, the hooks are gone. You can also call the "
      "target function yourself with new NativeFunction(addr, ...). "
      "LOGGING: a ready-made log(x) writes one line to samples/_frida_log.txt on the "
      "Windows VM (absolute path already baked in - a relative path in your own "
      "File() resolves against the TARGET's working directory and fails). That file "
      "is deleted before your script runs and read back to you afterwards, so it "
      "survives this call even though your hooks do not; use it for high-volume "
      "output and send() for the summary.",
      {"script": "the Frida JavaScript to run inside the target (required)",
       "program": "program to spawn - bare filename resolves inside samples/ "
                  "(e.g. 'ntfsm.exe'), or an absolute path. Omit if using pid",
       "args": "command-line arguments for the spawned program (string or list)",
       "pid": "attach to an ALREADY-RUNNING process id instead of spawning (optional)",
       "wait": "seconds to let the target run with your hooks in place (default 8)",
       "kill": "true (default) kills the target afterwards; false leaves the PROCESS "
               "running so a later win_frida(pid=...)/win_ui_tree can carry on with it - "
               "but NOT your hooks, which are unloaded when this call returns",
       "desktop": "false (default) runs the target on the invisible service desktop, "
                  "which is fine for console programs. Set true for a GUI program so "
                  "its window really appears and you can click it with win_ui_click",
       "max_lines": "cap on send() lines returned (default 800)",
       "timeout": "seconds, default 90",
       "drive": "GUI buttons to click by name/AutomationId WHILE the hooks are live, e.g. '1,2,3,OK' or a char string '123OK' (comma-list or single chars). Forces desktop=true. Use this to fire a hooked GUI handler inside this same call",
       "drive_window": "restrict the UIA search to windows whose title/class contains this (optional; default: all top windows)",
       "drive_pause": "ms between drive clicks (default 250)",
       "drive_after": "seconds to wait after the last drive click (default 2)",
       "launch": "a .bat launcher (e.g. 'run.bat') that starts a GUI app which "
                 "crashes if spawned directly - ONE call runs it, finds the real "
                 ".exe process it started, attaches, hooks and (with drive=) clicks "
                 "it. Prefer this for launcher-based GUI targets over win_gui_run + "
                 "win_frida(pid=)",
       "launch_wait": "seconds to wait after launching before resolving the pid (default 5)"})
def win_frida(ws, script, program=None, args="", pid=None, wait=8, kill=True,
              desktop=False, max_lines=800, timeout=90,
              drive=None, drive_window=None, drive_pause=250, drive_after=2,
              launch=None, launch_wait=5):
    _bat_text, _bat_names = "", [a.name for a in ws.artifacts.values()]
    if launch:
        _lb = str(launch).replace(chr(34), "").replace(chr(39), "")
        _a = ws.artifacts.get(_lb) or next(
            (x for x in ws.artifacts.values()
             if x.name.lower() == _lb.lower()), None)
        if _a:
            try:
                _bat_text = open(_a.local_path, "r", errors="replace").read()
            except Exception:
                _bat_text = ""
    return _vm(dvm_windows.win_frida(script, program=program, args=args,
        pid=pid, wait=wait, kill=kill, desktop=desktop, max_lines=max_lines,
        timeout=timeout, drive=drive, drive_window=drive_window,
        drive_pause=drive_pause, drive_after=drive_after, launch=launch,
        launch_wait=launch_wait, bat_text=_bat_text, bat_names=_bat_names))


@tool("win_ui_tree",
      "List every control on the Windows desktop's live GUI, with the handle you need "
      "to act on it. Two layers, both reported: UIA lines (UI Automation - control "
      "type, AutomationId, Name, the control's CURRENT VALUE as val='...', and which "
      "PATTERNS it supports: Invoke = clickable, Value = its text can be read and set) "
      "and W32 lines (the raw Win32 control tree - hwnd, control id, window class, "
      "current text, rectangle). WHICH LAYER SEES ANYTHING DEPENDS ON THE TOOLKIT, and "
      "both cases are MEASURED on this VM: an ordinary WinForms/Win32 dialog exposes "
      "NOTHING useful through UIA (generic Panes, empty pattern list) so there the W32 "
      "lines are the real answer and you target by hwnd/text/class; a Qt application is "
      "the exact reverse - Win32 child enumeration returns ZERO controls because Qt "
      "paints its widgets inside one single HWND, while UIA lists every widget, so "
      "there you target by `target` (AutomationId or Name) and read state from val=. "
      "Do not decide the layer in advance: run this and use whichever layer came back "
      "non-empty. Qt widgets often have an EMPTY name and id - then val= and the rect "
      "are what identify them, and win_ui_click takes raw x/y from that rect. Run this "
      "BEFORE win_ui_click/win_ui_type/win_ui_seq. Much cheaper and more precise than a "
      "screenshot; use win_screenshot only when the meaning is visual.",
      {"match": "only dump windows whose title or class contains this (optional)",
       "limit": "max controls per layer, default 250",
       "timeout": "seconds, default 45"})
def win_ui_tree(ws, match=None, limit=250, timeout=45):
    return _vm(dvm_windows.win_ui_tree(match=match, limit=limit, timeout=timeout))


@tool("win_ui_click",
      "CLICK a control on the Windows desktop. Four ways to say which, tried in this "
      "order: `hwnd` (copy it straight from a W32 line of win_ui_tree - the most "
      "reliable), `target` matched against UIA AutomationId/Name, `target` matched "
      "against a Win32 control's text/id/class, or raw `x`/`y` screen coordinates for a "
      "custom-painted UI that exposes no controls at all. A button is pressed with its "
      "UIA Invoke pattern when it has one, otherwise with BM_CLICK, otherwise with a "
      "real mouse click at the centre of its rectangle - and the reply says WHICH of "
      "those happened. It then lists the desktop again so you can see what the click "
      "did (a title or label that changed is your proof it landed).",
      {"hwnd": "window handle from a W32 line, e.g. '0x000A1B2C' (most reliable)",
       "target": "AutomationId / Name / Win32 control text or class to match",
       "window": "restrict the search to windows whose title/class contains this",
       "x": "screen X to click instead of naming a control (needs y)",
       "y": "screen Y to click instead of naming a control (needs x)",
       "after": "seconds to wait after clicking before looking, default 1",
       "timeout": "seconds, default 45"})
def win_ui_click(ws, hwnd=None, target=None, window=None, x=None, y=None, after=1,
                 timeout=45):
    return _vm(dvm_windows.win_ui_click(hwnd=hwnd, target=target, window=window, x=x, y=y, after=after, timeout=timeout))


@tool("win_ui_type",
      "TYPE text into the Windows GUI. Say where with `hwnd` (from a W32 line of "
      "win_ui_tree - the text is written straight into that control with WM_SETTEXT, "
      "which works even when the control refuses keystrokes), or with `target` (tried "
      "as a UIA Value pattern first, then as a Win32 control), or with neither, in "
      "which case the keystrokes go to whatever currently has focus. Set `enter=true` "
      "to press Enter afterwards - that is usually what submits a form, and WM_SETTEXT "
      "alone does NOT tell the program anything changed, so a form filled by hwnd "
      "normally still needs a win_ui_click on its button. For key presses rather than "
      "text set sendkeys=true and use SendKeys notation ({TAB}, {ENTER}, {F5}, ^a).",
      {"text": "the text to type (required)",
       "hwnd": "window handle of the control to write into, e.g. '0x000A1B2C'",
       "target": "AutomationId / Name / Win32 text or class of the control",
       "window": "restrict the control search to windows matching this",
       "enter": "true to press Enter afterwards (default false)",
       "sendkeys": "true if `text` is already SendKeys notation and must NOT be escaped",
       "after": "seconds to wait afterwards before looking, default 1",
       "timeout": "seconds, default 45"})
def win_ui_type(ws, text, hwnd=None, target=None, window=None, enter=False,
                sendkeys=False, after=1, timeout=45):
    return _vm(dvm_windows.win_ui_type(text=text, hwnd=hwnd, target=target, window=window, enter=enter, sendkeys=sendkeys, after=after, timeout=timeout))


@tool("win_key",
      "Send raw KEYSTROKES to the Windows GUI - to the foreground window, or to a "
      "window you name. This is the tool for a MODAL DIALOG: a Qt/Win32 message box "
      "closes on {ENTER} (its default button) or {ESC}, without your having to find the "
      "button at all. MEASURED ch8 run 2: nine steps in a row were lost trying to "
      "locate and click the OK button of a 'Wrong Password' box that {ENTER} would have "
      "dismissed at once. Also use it for keyboard-driven UIs (Tab between fields, "
      "arrow keys, shortcuts). `keys` is SendKeys notation: plain text types "
      "literally; {ENTER} {ESC} {TAB} {F1}..{F12} {UP}/{DOWN}/{LEFT}/{RIGHT} {BACKSPACE} "
      "{DEL} {HOME} {END}; ^ = Ctrl, % = Alt, + = Shift (e.g. ^a = Ctrl+A). Repeat with "
      "{TAB 3}. Reads the window list back afterwards so you see what changed.",
      {"keys": "SendKeys string, e.g. '{ENTER}' or '{ESC}' or '{TAB}{TAB}{ENTER}' (required)",
       "window": "bring the window whose title/class matches this to the front first, "
                 "then send the keys (optional; default: send to the current foreground "
                 "window, which for a just-opened modal dialog is the dialog)",
       "after": "seconds to wait afterwards before reading the window list, default 1",
       "timeout": "seconds, default 45"})
def win_key(ws, keys, window=None, after=1, timeout=45):
    return _vm(dvm_windows.win_key(keys=keys, window=window, after=after, timeout=timeout))


@tool("win_ui_seq",
      "Press a WHOLE SEQUENCE of GUI buttons in ONE step, then read the window back. "
      "This is the tool for a keypad, a PIN pad or any dialog whose answer is dozens of "
      "presses: win_ui_click costs one step each, so entering a 25-digit code would eat "
      "the entire step budget. `clicks` names the buttons in order - either "
      "comma-separated ('1,2,3,DEL,OK') or, when every button's name is a single "
      "character, as a bare string ('12345' presses 1 then 2 then 3 then 4 then 5). Use "
      "the comma form for any multi-character name. Each name is matched against UIA "
      "AutomationId first, then Name, and pressed with its Invoke pattern; every press "
      "is reported PRESSED or FAILED so a wrong name cannot pass silently. Afterwards "
      "the window's controls are dumped exactly as win_ui_tree does, INCLUDING each "
      "control's current val= - so you SEE what the sequence produced without paying "
      "for a screenshot. Run win_ui_tree once first to learn the button names. UIA-only: "
      "for a WinForms/Win32 dialog whose controls live on the W32 layer, use "
      "win_ui_click with an hwnd instead.",
      {"clicks": "buttons to press in order: '1,2,3,OK' or '12345' (required)",
       "window": "restrict to windows whose title/class contains this (optional)",
       "pause": "milliseconds between presses, default 250",
       "after": "seconds to wait after the last press before reading, default 2",
       "limit": "max UIA lines in the dump afterwards, default 250",
       "timeout": "seconds, default 120"})
def win_ui_seq(ws, clicks, window=None, pause=250, after=2, limit=250, timeout=120):
    return _vm(dvm_windows.win_ui_seq(clicks=clicks, window=window, pause=pause, after=after, limit=limit, timeout=timeout))


@tool("job_start",
      "Start work in the BACKGROUND and get control back immediately. Use this the "
      "moment a job will not fit in a normal tool call: unpacking and analysing "
      "thousands of files, brute-forcing a keyspace, a long emulation. Give it either "
      "`command` (a shell line) or `script` (Python source, uploaded and run unbuffered "
      "- same deal as author_and_run: PRINT everything you want to see). It returns at "
      "once with the pid; the job keeps running after this call ends, writing stdout and "
      "stderr to its own log. Check on it with job_poll(name). Pick a short `name` you "
      "will remember - it is how you address the job later.",
      {"name": "short id for this job, letters/digits/_-. only (e.g. 'unpack_all')",
       "command": "shell line to run in samples/ (either this or `script`)",
       "script": "Python source to upload and run in samples/ (either this or `command`)",
       "host": "'kali' (default) or 'windows'",
       "python": "interpreter for `script` (optional; defaults to the venv python)"})
def job_start(ws, name, command=None, script=None, host="kali", python=None):
    return _vm(dvm_jobs.job_start(name, command=command, script=script,
                                  host=host, python=python,
                                  truncated=reasoner.last_call_truncated()))


@tool("job_poll",
      "Check on a background job started with job_start: is it still running, did it "
      "exit and with what code, how big its log has grown, and the last chunk of that "
      "log. Pass `grep` to get only the matching lines instead of the tail - that is "
      "how you watch a 200MB log without reading it. Pass `stop=true` to kill a job you "
      "no longer need. Call this with no `name` to list every job on the host.",
      {"name": "the job's name (omit to list all jobs on the host)",
       "tail": "how many lines from the end of the log, default 40",
       "grep": "return only log lines matching this (a plain string or regex)",
       "stop": "true to kill the job",
       "host": "'kali' (default) or 'windows'"})
def job_poll(ws, name=None, tail=40, grep=None, stop=False, host="kali"):
    return _vm(dvm_jobs.job_poll(name=name, tail=tail, grep=grep, stop=stop, host=host))


# --- Ghidra: the Brain's own analysis passes ----------------------------------------
# decompile() answers "show me this function". It cannot answer "walk every function,
# find the opaque predicates, patch them out and decompile again" - and that shape of
# question is what an obfuscated binary needs. DumpInfo.java hardcodes two modes; this
# tool lets the Brain write its own script against the same headless Ghidra.
# The println() loss measured 2026-09-22 (1271 lines emitted, ~17% silently dropped by
# Ghidra's async console logger) is why args[0] is ALWAYS an output file path: bulk
# output goes there and is read back over SFTP, where nothing is dropped.

_GHIDRA_CLASS_RE = re.compile(r"public\s+class\s+([A-Za-z_][A-Za-z0-9_]*)\s+extends\s+GhidraScript")


@tool("ghidra_script",
      "Run YOUR OWN Ghidra script (Java) against the analysed program - the escape "
      "hatch for anything pe_overview/decompile cannot express: walk every function and "
      "score it, find and patch junk/opaque-predicate blocks then decompile the result, "
      "follow cross-references, read initialised data, rename things, emit a call graph. "
      "Rules that matter: (1) the class MUST be `public class Name extends GhidraScript` "
      "and the tool names the file after it, (2) BULK OUTPUT GOES TO A FILE - "
      "getScriptArgs()[0] is a path prepared for you; open a PrintWriter on it and the "
      "tool reads it back in full, because Ghidra's console DROPS lines under load "
      "(measured: ~17% of 1271 println'd lines vanished), (3) use println() only for a "
      "few status lines. Your own args follow at [1], [2]... Skeleton: "
      "`import ghidra.app.script.GhidraScript; import ghidra.program.model.listing.*; "
      "import java.io.*; public class Scan extends GhidraScript { public void run() "
      "throws Exception { PrintWriter w = new PrintWriter(new FileWriter(new "
      "File(getScriptArgs()[0]))); for (Function f : "
      "currentProgram.getFunctionManager().getFunctions(true)) { w.println(f.getName() + "
      "\" \" + f.getEntryPoint()); } w.close(); println(\"DONE\"); } }`. Run pe_overview "
      "once first so the program is in the project.",
      {"java": "the full Java source of your GhidraScript (required)",
       "artifact": "which program to run against - a registered artifact, or a bare "
                   "filename already under samples/ on the VM (default: the first artifact)",
       "args": "extra arguments for your script; they arrive at getScriptArgs()[1] "
               "onwards (a string, split on spaces, or a list)",
       "analyze": "false (default) reuses the existing analysed project - fast, and what "
                  "you want. true re-imports and re-analyses the binary from scratch "
                  "(minutes); needed only if you changed the file on disk",
       "timeout": "seconds, default 300"})
def ghidra_script(ws, java, artifact=None, args="", analyze=False, timeout=300):
    if not (java or "").strip():
        return ToolResult(False, "ghidra_script: `java` is empty")
    if reasoner.last_call_truncated():
        return ToolResult(False, "ghidra_script: the source you just wrote was CUT OFF "
                                 "mid-generation, so it is incomplete - not running it. "
                                 "Write a shorter script.")
    m = _GHIDRA_CLASS_RE.search(java)
    if not m:
        return ToolResult(False, "ghidra_script: could not find `public class <Name> "
                                 "extends GhidraScript` in that source - Ghidra requires "
                                 "it, and the file must be named after the class")
    cls = m.group(1)
    prog, cache, err = _ghidra_target(ws, artifact)
    if err:
        return err
    if isinstance(args, str):
        extra = shlex.split(args) if args.strip() else []
    else:
        extra = [str(a) for a in (args or [])]

    out_name = f"_gs_{cls}.txt"
    out_abs = f"{_ghidra_samples_dir()}/{out_name}"
    try:
        remote.ssh_exec(f"mkdir -p {shlex.quote(_ghidra_custom_dir())}; "
                        f"rm -f {shlex.quote(_ghidra_custom_dir())}/*.java", host="kali",
                        read_timeout=15)
        remote.write_remote(f"ghidra_scripts_custom/{cls}.java", java, host="kali")
        remote.ssh_exec(f"rm -f samples/{shlex.quote(out_name)}", host="kali",
                        read_timeout=15)
    except Exception as e:  # noqa: BLE001
        return ToolResult(False, f"ghidra_script: could not upload {cls}.java: {e}")

    flags = ([f"-import {shlex.quote(prog)} -overwrite"] if analyze
             else [f"-process {shlex.quote(os.path.basename(prog))} -noanalysis"])
    try:
        console = _run_ghidra([out_abs] + extra, flags, timeout, script=f"{cls}.java",
                              scriptpath=_ghidra_custom_dir())
    except Exception as e:  # noqa: BLE001
        return ToolResult(False, f"ghidra_script failed: {e.__class__.__name__}: {e}")

    lowered = console.lower()
    # The POSITIVE signal first. Measured 2026-09-23: a keyword sweep for
    # "error"+"compil" fired on a run that had actually succeeded (the word appears
    # elsewhere in a normal headless log), and reported a compile failure for a script
    # whose output was sitting right there. Ghidra names the script it ran, so ask that.
    ran = re.search(r"INFO\s+SCRIPT:\s*\S*" + re.escape(cls) + r"\.java", console) is not None
    if not ran:
        if "cannot find" in lowered and "-process" in lowered:
            return ToolResult(False, f"ghidra_script: '{prog}' is not in the Ghidra "
                                     "project yet - run pe_overview first (or pass "
                                     "analyze=true)")
        if re.search(r"\.java:\d+:\s*error", console) or "cannot be resolved" in lowered \
                or "compilation failed" in lowered or "classnotfoundexception" in lowered \
                or "ghidrascriptloadexception" in lowered:
            diag = _java_diagnostics(console)
            body = (diag if diag else
                    "(no javac diagnostic line in the log. Tail:\n" + console[-700:] + ")")
            return ToolResult(False, "ghidra_script: your Java did not COMPILE, so Ghidra "
                                     f"could not load class {cls}. THE COMPILER SAID:\n"
                                     + body + "\nFix those lines and send the script "
                                     "again (the Java stack trace in the log is only "
                                     "Ghidra failing to load the class afterwards - it "
                                     "names no cause).")
        return ToolResult(False, f"ghidra_script: Ghidra never reported running "
                                 f"{cls}.java. Tail of the log:\n" + console[-1200:])

    file_text = ""
    read_err = ""
    try:
        file_text = remote.read_bytes(f"samples/{out_name}",
                                      host="kali").decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001 - say WHICH failure this was
        file_text, read_err = "", f"{e.__class__.__name__}: {e}"

    if read_err and not file_text.strip():
        # The script RAN (checked above). Losing its output to an SFTP error is a
        # plumbing failure, not "your script wrote nothing" - and reporting it as the
        # latter made the Brain rewrite a script that had already worked.
        return ToolResult(False, f"ghidra_script: {cls} ran, but samples/{out_name} "
                                 f"could not be read back ({read_err}). The file may "
                                 "well be there - try read_file(path=\"" + out_name +
                                 "\") before rewriting anything.")
    if not file_text.strip() and not console.strip():
        return ToolResult(False, "ghidra_script: the script produced NO output at all - "
                                 "neither the args[0] file nor the console. Did run() "
                                 "actually write and close the PrintWriter?")

    body = ""
    if file_text.strip():
        body += (f"=== output file ({len(file_text)} chars, "
                 f"samples/{out_name} - page it with read_file) ===\n{file_text}\n")
    if console.strip():
        body += "=== Ghidra console (status lines only - bulk output is lossy here) ===\n" \
                + console
    detail, _ = _spill("kali", body, f"gs_{cls}")
    nlines = len(file_text.splitlines())
    return ToolResult(True,
                      f"ghidra_script {cls} on {prog}: {nlines} line(s) in the output file"
                      + ("" if file_text.strip() else " (EMPTY - console only)"),
                      detail=detail, info=detail,
                      known=[f"ghidra_script {cls}({prog}) -> {(file_text or console)[:400]}"],
                      flag=_find_flag(body))


# =================================================================================
# recall - TIER-2 memory: a $0, deterministic, IN-PROCESS search over a corpus of
# distilled RE technique notes (knowledge/notes/*.md). Nothing here runs on a VM and
# nothing calls a model: the Brain writes the query (that is the reasoning), the tool
# just returns the few most relevant notes RAW, like every other muscle tool. This is
# how the agent carries a large body of experience WITHOUT paying for it in the
# every-step prompt - tier 1 (config.STATIC_FACTS) stays small; the rest is recalled
# on demand when a situation feels familiar.
_KNOWLEDGE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "knowledge")


_NOTES_CACHE = [None]   # list of {tags, body, source, path}; loaded once


_STOP = set("the a an of to in is are and or for with on at by it its this that be as "
            "you your they them then than when where which who whom into from not no if "
            "only can may might will would use used using via per each any all some one "
            "two more most other such do does done have has had was were been being".split())


def _tok(s):
    return [w for w in re.findall(r"[a-z0-9_]+", (s or "").lower())
            if len(w) > 1 and w not in _STOP]


def _recall_scored(q):
    """tf-idf score every note against the token list q; [(score, note)] with score>0,
    unsorted. Shared by the recall tool and the run-start seeder."""
    import math
    notes, df = _load_notes()
    N = len(notes) or 1
    out = []
    for nt in notes:
        tf = {}
        for w in nt["toks"]:
            tf[w] = tf.get(w, 0) + 1
        sc = 0.0
        for w in set(q):
            if w in tf:
                idf = math.log(1 + N / (1 + df.get(w, 0)))
                sc += (tf[w] / (tf[w] + 1.5)) * idf     # saturating tf * idf
        if sc > 0:
            out.append((sc, nt))
    return out


# Words that describe EVERY sample (file(1) boilerplate, runtime DLLs, our own dump
# names) and so match notes at random. MEASURED 2026-09-25: an unfiltered survey query
# for ch8 ranked "Polyglot DOS-PE", "Registry hive" and "Repair corrupt PE" above the
# Qt notes, purely on 'dos'/'file'/'windows'/'executable'. Only DISTINCTIVE words
# (framework, language, container, protocol) are allowed to drive the seed.
_SEED_GENERIC = set("""
ascii text file files executable for ms windows dos batch console pe pe32 elf data
dll x86 x64 bit bits lsb msb version intel amd arm with without line lines terminators
crlf utf unicode stripped dynamically statically linked interpreter shared object
sections section run bat exe bin sys msvcp vcruntime api ucrtbase kernel user gdi
advapi ntdll qwindows msvcrt libc libgcc libstdc lib sh gnu linux sysv relocatable type
unknown mb large readme txt md findings analysis decompile ghidra funcs solver out cmd
challenge chall chal sample samples flag enc input output test main program app
could not survey missing disk uploaded when tool first touches it on vm kb
""".split())


# Spelling variants file(1)/filenames use vs the words the notes use.
_SEED_ALIAS = {"pcapng": "pcap", "mono": "net", "pyc": "python", "apk": "android",
               "dex": "android", "wasm": "webassembly", "js": "javascript",
               "qt5core": "qt", "qt6core": "qt", "vbaproject": "vba"}


SEED_MIN_SCORE = 1.5   # per note, AFTER generic words are filtered (measured: a lone


                       # distinctive word like 'pcap' scores ~1.7; filtered noise < 1)
_SEED_SHORT_OK = {"qt", "go", "js", "py", "vm", "ui"}   # 2-letter words that ARE signal


def seed_recall(ws, facts, k=6):
    """Run-start memory seed. Builds a query from the DISTINCTIVE words of the input
    survey (file names + file(1) types), and returns a text block of the best-matching
    technique notes, or "" when nothing distinctive matched (a bare 'challenge.exe'
    carries no signal - the Brain must recall itself after triage).
    WHY: measured over ch6-ch8 + ch7 logs, recall was called 0-2 times per run and ONLY
    after a stall - i.e. after the steps its notes would have saved were already spent
    (ch8 run 14: 6 win_frida attempts before any note was consulted, while the
    'Qt / GUI crackme' notes describe exactly that target's shape)."""
    words = []
    # our own dumps (_analysis/_decompile_FUN_..., _r2_pd_...) are not input SHAPE:
    # their names are addresses and tool names, pure noise for the query
    srcs = [n for n in ws.artifacts.keys()
            if not n.startswith("_analysis/") and not n.rsplit("/", 1)[-1].startswith("_")]
    srcs += [f for f in (facts or []) if not str(f).startswith("_analysis/")]
    for f in srcs:
        for t in re.findall(r"[A-Za-z][A-Za-z0-9]+", str(f)):
            t = t.lower()
            t = _SEED_ALIAS.get(t, t)
            if any(c.isdigit() for c in t):
                t = re.sub(r"\d+", "", t)          # Qt6Core -> qtcore, msvcp140 -> msvcp
            pieces = [t[:2], t[2:]] if t.startswith("qt") and len(t) > 2 else [t]
            for piece in pieces:
                ok = len(piece) >= 3 or piece in _SEED_SHORT_OK
                if ok and piece not in _SEED_GENERIC and piece not in words:
                    words.append(piece)
    q = _tok(" ".join(words))
    if not q:
        return "", ""
    scored = [x for x in _recall_scored(q) if x[0] >= SEED_MIN_SCORE]
    if not scored:
        return " ".join(words), ""
    scored.sort(key=lambda x: -x[0])
    parts = [f"- ({nt['tags']}) {nt['body']}" for _, nt in scored[:k]]
    return " ".join(words), "\n".join(parts)


def _load_notes():
    if _NOTES_CACHE[0] is not None:
        return _NOTES_CACHE[0]
    from . import config as _cfg
    _exclude = [x for x in getattr(_cfg, "RECALL_EXCLUDE", []) if x]
    notes = []
    paths = []
    for root, _dirs, files in os.walk(_KNOWLEDGE_DIR):
        for fn in files:
            if fn.endswith(".md"):
                paths.append(os.path.join(root, fn))
    for full in sorted(paths):
        fn = os.path.relpath(full, _KNOWLEDGE_DIR)
        try:
            txt = open(full, encoding="utf-8").read()
        except OSError:
            continue
        tags, source = "", "?"
        m = re.match(r"^---\n(.*?)\n---\n(.*)$", txt, re.S)
        if m:
            meta, bodytext = m.group(1), m.group(2).strip()
            for line in meta.splitlines():
                if line.startswith("tags:"):
                    tags = line[5:].strip()
                elif line.startswith("source:"):
                    source = line[7:].strip()
        else:
            bodytext = txt.strip()
        src_low = source.lower()
        if any(x in src_low for x in _exclude):
            continue                      # benchmark-honesty: hide the current target's writeup
        notes.append({"tags": tags, "body": bodytext, "source": source, "file": fn,
                      "toks": _tok(tags + " " + tags + " " + bodytext)})  # tags counted twice
    # document frequency for a light idf
    from collections import Counter
    df = Counter()
    for nt in notes:
        for w in set(nt["toks"]):
            df[w] += 1
    _NOTES_CACHE[0] = (notes, df)
    return _NOTES_CACHE[0]


@tool("recall",
      "Search the agent's MEMORY of distilled reverse-engineering technique notes (past "
      "CTF/FLARE-On experience) and get back the few most relevant ones. $0, instant, no "
      "VM. Use it when a situation feels familiar or you are stuck and want to know how "
      "this KIND of thing is usually cracked - e.g. recall(\"qt crackme 25 boxes "
      "per-keystroke accumulator\"), recall(\"packed upx unpack\"), recall(\"pyinstaller "
      "pyc decompile\"), recall(\"obfuscated control flow flattening indirect call\"), "
      "recall(\"aes sbox hand-rolled\"). Query with the SITUATION in plain keywords - the "
      "binary's shape, the toolkit, the obfuscation, the crypto - not the flag. It "
      "returns notes (situation -> technique), not a solution: you still decide and act.",
      {"query": "situation in keywords (required)",
       "k": "how many notes to return (default 3, max 8)"})
def recall(ws, query, k=3):
    import math
    q = _tok(query)
    if not q:
        return ToolResult(False, "recall: give a keyword query, e.g. "
                                 'recall("qt crackme keypad accumulator")')
    try:
        k = max(1, min(int(k or 3), 8))
    except (TypeError, ValueError):
        k = 3
    notes, df = _load_notes()
    if not notes:
        return ToolResult(False, "recall: the knowledge corpus is empty "
                                 "(knowledge/notes/ has no notes yet).")
    N = len(notes)
    scored = _recall_scored(q)
    if not scored:
        return ToolResult(True, f"recall('{query[:50]}'): no matching note - this "
                                "situation is not in memory yet; reason it out.",
                          detail="(no note matched; the corpus has "
                                 f"{N} notes but none share a keyword with the query)")
    scored.sort(key=lambda x: -x[0])
    top = scored[:k]
    parts = []
    for i, (sc, nt) in enumerate(top, 1):
        parts.append(f"[{i}] ({nt['tags']})  <{nt['source']}>\n{nt['body']}")
    detail = "\n\n".join(parts)
    return ToolResult(True,
                      f"recall('{query[:50]}'): {len(top)} of {N} notes "
                      f"(top score {top[0][0]:.1f})",
                      detail=detail,
                      known=[f"recall('{query[:40]}') -> {len(top)} technique note(s): "
                             + "; ".join(nt['tags'] for _, nt in top)])


# =================================================================================
# radare2 as a FIRST-CLASS tool
# ---------------------------------------------------------------------------------
# radare2 was installed, was named in TOOLCHAIN_HINT/METHOD_HINT, and was used
# ZERO times by the Brain across the whole ch6 and ch8 logs. Nothing here is a new
# analysis capability - every byte of the answer still comes from radare2. What this
# tool adds is the four things measured to go wrong when r2 is only "something the
# Brain could remember to type into run_cmd":
#   1. VISIBILITY - a tool has a name and a "use it when" line sent on every step;
#      a shell one-liner has to be recalled. Measured use: 0.
#   2. ANSI - without `-e scr.color=0` (and utf8 box-drawing off) the output is escape
#      codes and frame characters. The Brain had to remember; forgetting = garbage.
#   3. ANALYSIS LEVEL - `aa` found 2 functions on a binary where `aaa` found 292. The
#      choice is deterministic given the command, so the MUSCLE makes it: `aaa` when
#      the command needs functions/xrefs, nothing when it only reads bytes/strings.
#      Analysis is then SAVED as an r2 project and reused on later calls (a 20MB PE
#      re-analyses from scratch on every plain `r2 -qc 'aaa; ...'` invocation).
#   4. OUTPUT HANDLING - long output spills to a host file and is paged like every
#      other tool, and is scanned for the flag, instead of being silently cut.
# It also removes one error-prone step from every solver: `px`/`pd @ <vaddr>` reads at
# a VIRTUAL address, so the Brain never has to convert vaddr -> file offset by hand.
#
# NO INTERPRETATION: this returns radare2's raw output. The only computed things are
# a character count, the elapsed seconds, and the function count used to verify that
# the cached analysis actually loaded.

_ANSI_RX = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


# Commands that are meaningless without `aaa` (they read the function/xref database).
_R2_NEEDS_AA = re.compile(r"(?:^|[;\n])\s*(?:af\w*|ax\w*|ag\w*|pd[fcrs]\w*)\b|fcn\.", re.I)


# The Brain asked for analysis itself - don't prepend a second one.
_R2_IS_AA = re.compile(r"(?:^|[;\n])\s*aa+\w*\b", re.I)


# r2 can shell out (`!cmd`, `#!lang`). That path would carry commands AROUND the
# security filter, so it is refused here; run_cmd is the door for shell work.
_R2_SHELL_RX = re.compile(r"(?:^|[;\n|])\s*#?!")


# A bare `|` inside an r2 command is NOT r2's grep (that is `~`) - radare2 pipes the
# command's output to the SYSTEM SHELL, exactly like a terminal. MEASURED ch9 run
# (2026-09-27, steps 47/49/50): `/ plugin:neon|e` and `izz~neon|e` ran as
# `<r2 output> | e`, the login shell (zsh) reported "command not found: e", the search
# never happened, and the Brain burned 3 steps + a stall chasing a phantom syntax error.
# Worse, it is the same shell-out hole as `!cmd`: `izz~x|sh -c '...'` would execute
# arbitrary shell AROUND the security filter. So an UNescaped `|` is refused here with a
# pointer to the escaped/hex alternatives; `\|` (a literal pipe, e.g. searching for the
# string "neon|e") passes through untouched.
_R2_BARE_PIPE_RX = re.compile(r"(?<!\\)\|")


_R2_MARK = "===R2-BEGIN==="


_R2_PRJMARK = "===R2-PRJ==="


# MEASURED on the Kali VM (radare2 6.0.5, 2026-09-23): with the default prj.vc=true,
# `Ps` shells out to git, and on a VM with no git identity it prints
# "ERROR: Cannot save project" - while `Pl` STILL lists the project name (the directory
# was created). So "Pl lists it" alone is not proof of a save; prj.vc=false makes the
# save actually work, and the error string is checked as well.
# scr.maxpage (default 0x19000 = 100KB) is the other silent truncation: MEASURED on
# ntfsm.exe (20MB PE, 3241 functions) a plain `afl` answered
# "Do you want to print 3241 lines? (y/N)" and then printed NOTHING - a full function
# list replaced by one question the Brain cannot answer. scr.maxpage=0 removes the
# guard; the tool's own spill-to-file handles the size instead.
_R2_FLAGS = ("-N -e scr.color=0 -e scr.utf8=0 -e scr.interactive=0 -e scr.maxpage=0 "
             "-e bin.relocs.apply=true -e prj.vc=false")


def _r2_prj_name(prog, digest=""):
    """Project name = file name + a hash of its CONTENT. MEASURED 2026-09-23 on r2
    6.0.5: `Ps <name>` REFUSES to overwrite a project that already exists ("A project
    with this name already exists"), so every new run - whose in-memory cache starts
    empty - failed to save, switched caching off, and then paid a full `aaa` on every
    analyzed call. Keyed by content, an existing project is by construction the
    analysis of THIS exact file, so a new run simply loads it - and a patched file
    with the same name can never be served a stale analysis.

    MEASURED 2026-09-23 (ch8 run 2): r2 6.0.5 REJECTS a project name with an
    UPPERCASE letter or a dot ("ERROR: Invalid project name"), and caps its length -
    so `ctfbrain_FlareAuthenticator_exe_...` was refused on every analyzed call and
    the cache silently never engaged for that binary (and would not for most Windows
    PEs). Lower-case, keep only [a-z0-9_], and cap the file part."""
    part = re.sub(r"[^a-z0-9_]", "_", prog.lower())[:32]
    base = "ctfbrain_" + part
    return base + (f"_{digest}" if digest else "")


def _r2_count(head):
    """The function count `aflc` printed as the LAST line before the marker. Never the
    first number anywhere: when r2 loads a project it can print git hints above it
    ("... will change to "main" in Git 3.0"), and the first number there is a 3."""
    lines = [ln.strip() for ln in (head or "").strip().splitlines() if ln.strip()]
    return int(lines[-1]) if lines and lines[-1].isdigit() else 0


def _r2_exec(prog, cmds, timeout, prj=None):
    """One r2 invocation. prj -> open the SAVED project instead of the file (no
    re-analysis). Returns (raw_text, elapsed_seconds)."""
    target = f"-p {shlex.quote(prj)}" if prj else shlex.quote(f"samples/{prog}")
    sh = (f"cd ~ && timeout {int(timeout)} r2 {_R2_FLAGS} -q "
          f"-c {shlex.quote(cmds)} {target} </dev/null 2>&1")
    t0 = _time.time()
    out, err = remote.ssh_exec(sh, host="kali", read_timeout=int(timeout) + 25)
    return _ANSI_RX.sub("", (out or "") + (err or "")), _time.time() - t0


def _r2_split(raw):
    """Everything the Brain asked for lives after the marker; the analysis chatter
    and the project bookkeeping before it are ours, not its."""
    if _R2_MARK in raw:
        head, _, body = raw.partition(_R2_MARK)
        return head, body.lstrip("\n")
    return "", raw


@tool("r2",
      "radare2 on a binary, run for you with the traps already removed ($0, "
      "deterministic, no interpretation - raw r2 output). `cmd` is one or more r2 "
      "commands separated by ';'. Colour/box-drawing are off; `aaa` is run ONLY when "
      "your command needs functions or xrefs, and the analysis is SAVED and reused by "
      "later calls; long output spills to a host file you page with read_file. "
      "Use it to find WHICH function matters before paying minutes for Ghidra "
      "(pe_overview/decompile). Common: 'afl' (functions), 'axt @ 0x4010a0' (who "
      "references this), 'pdf @ sym.main' / 'pdf @ 0x4010a0' (disassemble one "
      "function), 'pdc @ 0x4010a0' (r2's quick pseudo-C), 'iz' / 'izz' (strings), "
      "'iS' (sections), 'px 64 @ 0x140002000' (bytes AT A VIRTUAL ADDRESS - no "
      "vaddr->file-offset conversion needed), 'ii' (imports), 'ie' (entrypoints). "
      "Append '~<word>' to grep r2's own output (e.g. 'afl~crypt').",
      {"cmd": "r2 command(s), ';'-separated, e.g. \"aflc; afl~main\"",
       "artifact": "registered artifact name, OR a bare filename already under samples/ "
                   "on Kali (optional; default first artifact)",
       "analyze": "optional override: true = force `aaa` first, false = never analyze. "
                  "Default: decided from your command.",
       "timeout": "seconds, default 60 (raise it for `aaa` on a very large binary)"})
def r2(ws, cmd, artifact=None, analyze=None, timeout=60):
    cmds = (cmd or "").strip()
    if not cmds:
        return ToolResult(False, "r2: `cmd` is empty - pass an r2 command, e.g. cmd='afl'")
    if _R2_SHELL_RX.search(cmds):
        return ToolResult(False, "r2: shell escapes (`!cmd`, `#!lang`) are not allowed "
                                 "through this tool - use run_cmd for shell work.")
    if _R2_BARE_PIPE_RX.search(cmds):
        return ToolResult(False,
            "r2: a bare `|` pipes r2's output to the system shell, it is NOT r2's grep. "
            "To FILTER r2 output use `~` (e.g. `izz~neon`, `afl~main`). To SEARCH for a "
            "string that literally contains a pipe, escape it as `\\|` (e.g. "
            "`izz~neon\\|e`) or search the bytes with `/x 6e656f6e7c65`. To find where a "
            "string is referenced, get its address from `izz`/`iz` then `axt @ <addr>`.")
    blocked = _security_block(cmds)
    if blocked:
        return ToolResult(False, f"r2: refused - {blocked}")
    prog, cache, err = _ghidra_target(ws, artifact)   # same resolution as pe_overview
    if err:
        return err
    try:
        timeout = int(timeout or 60)
    except (TypeError, ValueError):
        timeout = 60

    if analyze is None:
        need_aa = bool(_R2_NEEDS_AA.search(cmds))
    else:
        need_aa = bool(analyze) if not isinstance(analyze, str) else \
            analyze.strip().lower() in ("1", "true", "yes", "y")
    if _R2_IS_AA.search(cmds):
        need_aa = False          # the Brain put its own aa/aaa in the command list

    used_cache = False
    if not need_aa:
        raw, el = _r2_exec(prog, f"?e {_R2_MARK};" + cmds, timeout)
    else:
        # The project name is keyed on the file's CONTENT hash so a rewritten file
        # never reuses a stale analysis. Re-hashing a 20 MB file on every analyzed call
        # is wasteful, though, so only re-sha1 when a cheap stat (size+mtime) shows the
        # file actually changed since the last hash.
        statsig, _ = remote.ssh_exec(
            f"stat -c '%s:%Y' samples/{shlex.quote(prog)} 2>/dev/null", host="kali",
            read_timeout=15)
        statsig = statsig.strip()
        if statsig and cache.get("r2_statsig") == statsig and cache.get("r2_digest"):
            dg = cache["r2_digest"]
        else:
            dg, _ = remote.ssh_exec(
                f"sha1sum samples/{shlex.quote(prog)} 2>/dev/null | cut -c1-12",
                host="kali", read_timeout=30)
            dg = dg.strip() if re.fullmatch(r"[0-9a-f]{12}", dg.strip() or "") else ""
            if dg:
                cache["r2_digest"] = dg
                cache["r2_statsig"] = statsig
        prj = _r2_prj_name(prog, dg)
        if cache.get("r2_prj_name") != prj:        # new file content -> forget old verdict
            cache.update(r2_prj_name=prj, r2_prj=None, r2_nfuncs=0)
        if dg and cache.get("r2_prj") is not False:
            # Load a saved analysis - from THIS run or an earlier one - and VERIFY it
            # actually loaded: a project that silently opened empty would answer every
            # afl/axt with nothing and look like "this binary has no functions".
            raw, el = _r2_exec(prog, f"aflc;?e {_R2_MARK};" + cmds, timeout, prj=prj)
            n_loaded = _r2_count(_r2_split(raw)[0])
            if n_loaded > 0:
                used_cache = True
                cache.update(r2_prj=True, r2_nfuncs=n_loaded)
            elif cache.get("r2_prj"):
                cache["r2_prj"] = False            # it saved, but does not reload
        if not used_cache:
            # `P-` first: harmless when nothing exists, and the only way past r2's
            # refusal to overwrite a project that could not be loaded.
            save = (f"P- {shlex.quote(prj)};Ps {shlex.quote(prj)};?e {_R2_PRJMARK};Pl;"
                    if dg else "")
            raw, el = _r2_exec(prog, f"aaa;{save}aflc;?e {_R2_MARK};" + cmds, timeout)
            head, _b = _r2_split(raw)
            cache["r2_nfuncs"] = _r2_count(head)
            if dg:
                prjblock = head.partition(_R2_PRJMARK)[2]
                cache["r2_prj"] = (prj in prjblock
                                   and "cannot save project" not in head.lower())
            else:
                cache["r2_prj"] = False            # no hash -> no safe name -> no cache

    head, body = _r2_split(raw)
    body = body.strip("\n")
    if re.search(r"r2:\s*(command )?not found|No such file", raw) and not body.strip():
        return ToolResult(False, "r2: radare2 did not run on kali - measured output: "
                                 + raw.strip()[:400])
    if "(TIMEOUT" in raw or (not body.strip() and el >= timeout - 1):
        return ToolResult(False, f"r2: timed out after {timeout}s on `{cmds[:80]}` "
                                 f"(elapsed {el:.0f}s). Raise `timeout`, or narrow the "
                                 "command (e.g. `pdf @ <one function>` instead of `pdd`).")

    # An r2 command that only errored is a FAILED step, not a 39-character result:
    # ok=True would feed "ERROR: Invalid `h` subcommand" into the ledger as progress.
    if body.strip() and all(ln.startswith(("ERROR:", "WARN:", "Usage:"))
                            for ln in body.strip().splitlines()):
        return ToolResult(False, f"r2 `{cmds[:70]}` on {prog}: radare2 refused the "
                                 f"command ({el:.1f}s) - {body.strip()[:400]}")

    n = len(body)
    stem = "r2_" + re.sub(r"[^A-Za-z0-9]", "_", cmds)[:28]
    detail, saved = _spill("kali", body if body.strip() else
                           "(r2 produced no output for this command)", stem)
    flag = _find_flag(body)

    how = []
    if need_aa:
        nf = cache.get("r2_nfuncs", 0)
        how.append(f"aaa {'reused from saved project' if used_cache else 'run now'}, "
                   f"{nf} functions")
        if not used_cache and not cache.get("r2_prj"):
            how.append("project save did NOT stick - later analyzed calls pay for aaa again")
    how.append(f"{el:.1f}s")
    summary = f"r2 `{cmds[:70]}` on {prog}: {n} chars ({'; '.join(how)})"

    known = [f"r2 `{cmds[:60]}` on {prog} -> {n} chars in {el:.1f}s"
             + (f" (full -> {saved}, page with read_file)" if saved else "")]
    if need_aa and not used_cache and cache.get("r2_nfuncs"):
        known.append(f"{prog}: r2 aaa -> {cache['r2_nfuncs']} functions")
    return ToolResult(True, summary + ("; FLAG" if flag else ""),
                      detail=f"[r2 {cmds}  @ {prog}]\n" + detail,
                      known=known, flag=flag)

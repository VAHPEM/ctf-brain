---
name: ctf-analysis
description: >-
  Disciplined CTF / reverse-engineering analysis methodology (reason first,
  measure before reading, static vs dynamic, invert instead of brute-force),
  mapped to the dual-VM tools. This repo uses it via its dual-vm-ai-agent
  dependency; the full skill is maintained there.
---

# ctf-analysis (provided by the dual-vm-ai-agent dependency)

The full methodology is the **single source** in the `dual-vm-ai-agent` package
this repo depends on:

- Skill: `dual-vm-ai-agent/.claude/skills/ctf-analysis/SKILL.md`
- Source: `dual-vm-ai-agent/dualvm/playbook.py`
  (`ANALYSIS_DISCIPLINE` + `METHOD_PLAYBOOK`)

The Brain loads it at runtime through `ctf_playbook.py`
(`from dualvm.playbook import ANALYSIS_DISCIPLINE, METHOD_PLAYBOOK`), so the prompt
the Brain reads and this skill are always the same text. Edit it there, not here.

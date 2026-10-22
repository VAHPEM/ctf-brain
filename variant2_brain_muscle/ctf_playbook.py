# -*- coding: utf-8 -*-
"""CTF/RE analysis playbook.

SINGLE SOURCE now lives in the dual-vm-ai-agent package: ``dualvm/playbook.py``,
surfaced as the ``ctf-analysis`` skill (``.claude/skills/binary-analysis/SKILL.md``).
Imported here so the Brain's existing
``from ctf_playbook import ANALYSIS_DISCIPLINE, METHOD_PLAYBOOK`` keeps working
unchanged. To change the methodology, edit ``dualvm/playbook.py`` in that repo and
regenerate the skill with its ``scripts/gen_skill.py`` - do not re-add the text here.
"""
from dualvm.playbook import ANALYSIS_DISCIPLINE, METHOD_PLAYBOOK  # noqa: F401

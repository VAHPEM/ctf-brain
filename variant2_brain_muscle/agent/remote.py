# -*- coding: utf-8 -*-
"""Shim: tro .env/.ssh_keys cua ctf-brain roi dung dualvm.remote (1 ban cai).
Giu `remote.X` hoat dong y nhu cu cho ca cac tool CTF con lai."""
import os
_HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("DUALVM_ENV", os.path.join(_HERE, "..", "..", ".env"))
os.environ.setdefault("DUALVM_SSH_KEY",
    os.path.join(_HERE, "..", "..", ".ssh_keys", "ctf_orchestrator_ed25519"))
from dualvm.remote import *          # noqa: F401,F403
from dualvm.remote import (           # noqa: F401 - ten dung qua remote.X
    ssh_exec, write_remote, read_bytes, upload, win_samples, win_run_bounded,
    run_in_session1, run_script, get_kali, get_windows,
    WIN_PYTHON_EXE, KALI_PYTHON, KALI_HOST, KALI_USER, WIN_HOST, WIN_USER)

---
tags: osint git github api branch commit base64 orphan deleted-file fragment decoy
source: distilled/cssctf
---
Secrets hide in git history, not just the checked-out tree. Enumerate a target's repos via the GitHub API, clone, then git branch -a for hidden/orphan branches and git log --all -p to see EVERY commit including files that were later deleted. Flag fragments are often split across branches/commits and base64-encoded (base64 -d). Use git branch -a --contains <sha> to attribute a dangling commit, and beware decoy flags - distinguish the real one by its expected prefix/format.

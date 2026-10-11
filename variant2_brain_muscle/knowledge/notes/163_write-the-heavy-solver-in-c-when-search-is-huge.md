---
tags: solver performance C gcc brute-force modular algebra precompute table
source: distilled/cssctf
---
When closing a reversing/crypto challenge needs ~p^2 or billions of operations (building inverse/sqrt tables mod a prime, large brute force, exhaustive inner loop), a pure-Python solver is too slow and you will time out or stall. Port the hot inner loop to C (gcc -O3), precompute lookup tables (modular inverse, sqrt) once, and keep Python only for orchestration and verification. Progress = the solver finishing and printing values, not re-reading the disassembly again.

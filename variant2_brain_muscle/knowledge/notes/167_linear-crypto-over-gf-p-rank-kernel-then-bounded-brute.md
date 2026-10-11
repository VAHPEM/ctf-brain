---
tags: crypto linear-algebra galois gf finite-field kernel rank sagemath numpy multivariate
source: distilled/cssctf
---
A cipher built from linear operations over a small field is beatable with linear algebra. Assemble the system over GF(p) and compute rank + right kernel: hand-rolled Gaussian elimination mod p, the 'galois' package, or SageMath Matrix(GF(p),...).right_kernel(). The kernel dimension is how many unknowns remain free; brute those (p^k for small k), and VERIFY each candidate by re-running the challenge's OWN encrypt function on known plaintext rather than guessing. Print rank/kernel size per block to track progress.

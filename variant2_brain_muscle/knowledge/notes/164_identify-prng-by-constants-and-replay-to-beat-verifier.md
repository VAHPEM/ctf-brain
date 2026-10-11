---
tags: prng xorshift rng fixed-point physics replay beam-search game deterministic
source: distilled/cssctf
---
Recognize a PRNG by its constants: shift triplets like 13/17/5 (or 7/9/8) = xorshift32; a multiply by a magic such as 0x1bb4a405 is reciprocal 'magic-number' division (recover the real divisor). For a game whose SERVER replays and verifies your run, you don't need to play well in real time - reconstruct the exact (usually fixed-point integer) physics and RNG, then search an input sequence that satisfies the verifier with greedy/beam search, and submit the input trace. The win condition is a trace the server accepts, not pixel-perfect play.

---
tags: misc braid knot writhe permutation no-oracle checksum packing hex decoy homology invariant
source: distilled/cssctf
---
When a server gives no oracle (wrong answer = silent disconnect) and the prompt uses a scary-sounding name (e.g. 'homology_invariant' for a braid word), suspect a cheap home-made checksum, not real theory: a fast pure-Python server (~15 ms) means trivial math. Testing each standard invariant ALONE (determinant, Alexander, Jones, writhe, permutation) can never hit if the server compares ONE packed string. Try COMBINATIONS and packings: for a braid word with generators +-i: writhe = sum of signs (mod 256, 2 hex) and endpoint permutation (start [0,1,2,3], swap i-1,i for each |g|; sign ignored) packed one nibble per strand (4 hex) -> 6 hex chars, e.g. '041203'. General rule: enumerate small primitive quantities, then concatenate them in fixed widths (byte/nibble), mod 256 for signed counts. Same-author challenges reuse 'base + byte*step' and hex packing.

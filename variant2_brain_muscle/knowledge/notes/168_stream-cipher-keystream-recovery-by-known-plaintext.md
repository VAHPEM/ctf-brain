---
tags: crypto stream-cipher keystream known-plaintext period lag lfsr numpy
source: distilled/cssctf
---
With plaintext<->ciphertext for part of a stream cipher, XOR (or subtract mod N) to recover that slice of keystream. Then hunt for structure: test for a repeat period p and a lag by comparing shifted copies (np.array_equal(S[:-p], S[p:])), which reveals an LFSR/PRNG cycle. Once period and lag are known, extend the keystream to decrypt the unknown region. Print several reconstructions side by side to confirm alignment.

---
tags: gdb call function-pointer prototype cast aslr debugger reverse magic-constant
source: distilled/cssctf
---
To get a function's output without reversing its math, CALL it from gdb: disable ASLR (set disable-randomization on, or setarch -R), 'starti', get/allocate a scratch buffer, then call ((RET(*)(ARGS))0xADDR)(args..., $buf, len) with a correct prototype cast and print the buffer. Sanity-check by feeding a known-wrong input and confirming it fails. Name algorithms by their magic constants: 0x9e3779b9 = golden ratio (TEA/xxhash), 0x811c9dc5 + 0x01000193 = FNV-1 hash, 0x5f3759df = fast inverse sqrt, 0xedb88320 = reflected CRC32.

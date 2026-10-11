---
tags: steganography bit-plane channel-difference RGB pil numpy stegsolve gimp lsb
source: distilled/cssctf
---
Beyond simple LSB, hidden text often lives in one specific bit-plane or in the ARITHMETIC between colour channels (classic: text visible only in R-G). With PIL+numpy, render each bit-plane as ((chan>>k)&1)*255 for k=0..7 and render channel diffs like clip(R-G) / clip(G-B); Stegsolve or GIMP do the same interactively. Sweep all planes and channel pairs - the message pops in exactly one of them.

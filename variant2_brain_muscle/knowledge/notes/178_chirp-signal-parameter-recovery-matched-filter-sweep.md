---
tags: signal chirp matched-filter dsp pcm numpy frequency sweep quantized-params server-model
source: distilled/cssctf
---
When a server hands you PCM samples (int16 hex, noisy) and asks for the hidden parameters of a chirp, the parameters are usually small quantized bytes (e.g. f0=base+step*b0, f1=base+step*b1, f(t)=f0+(f1-f0)*(t/T)^2). Do NOT brute 256x256: decouple. (1) Estimate b0 from the first ~5% of samples, where the chirp is nearly a steady tone: sweep 256 candidates, keep max |correlation|. (2) Fix f0, sweep 256 candidates of b1 over the whole signal with a matched filter: build phase phi[n]=cumsum(2*pi*f[n]/fs) (include the CURRENT sample in the cumsum, same as the server), take |sum(x*exp(-j*phi))|; the right value gives the largest coherent sum. Reproduce the server's phase accumulation exactly or the peak vanishes. Answer is typically packed as (b1<<8)|b0 in hex.

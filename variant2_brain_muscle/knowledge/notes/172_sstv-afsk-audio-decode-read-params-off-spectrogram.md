---
tags: signal audio sstv afsk fsk spectrogram sox scipy hilbert demodulation wav stereo
source: distilled/cssctf
---
Audio challenges: split stereo to mono channels first (sox in.wav out.wav remix 1) - the two channels are often different modulations. An SSTV channel decodes to an IMAGE (sstv CLI / QSSTV) that frequently carries the next-stage parameters you must read by eye. For FSK/AFSK, get instantaneous frequency via scipy.signal.hilbert then phase difference, smooth it, and threshold to bits. ALWAYS open the file in a spectrogram (Audacity, Sonic Visualiser, or sox -n spectrogram) before anything else: the modulation type, hidden text, and tones are visible there; also check metadata/EOF tails for part of the flag.

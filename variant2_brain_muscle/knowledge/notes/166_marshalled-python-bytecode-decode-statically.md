---
tags: python marshal pyc bytecode co_consts dis opcode version segfault
source: distilled/cssctf
---
Never dis/exec marshalled Python bytecode that was compiled for a different interpreter version than the one you are running - the opcode map differs and running or disassembling it can segfault or mislead. Decode it statically instead: read the code object's co_consts, co_names, co_varnames and co_code against THAT version's opcode table by hand, or install the exact matching Python just to unmarshal and introspect. Nested functions live as code objects inside co_consts, so recurse.

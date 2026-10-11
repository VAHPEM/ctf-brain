---
tags: pwn pwntools rop ret2win format-string uaf checksec ropgadget one_gadget cyclic
source: distilled/cssctf
---
Standard pwn close-out: checksec for protections (No PIE = fixed addresses, easiest). Find win()/one_gadget; get the saved-RIP offset with cyclic()/cyclic_find() on a crash. ret2win: b'A'*offset + p64(win). If win() needs register args, chain gadgets: ROPgadget --binary x | grep 'pop rdi' etc. A format-string with %p leaks stack/PIE/libc so you can defeat ASLR, then ROP. UAF: free an object, reallocate the SAME size to overwrite a function pointer inside it, then trigger the call. Run the final exploit from a box with raw TCP egress (a bridged VM), not a restricted container.

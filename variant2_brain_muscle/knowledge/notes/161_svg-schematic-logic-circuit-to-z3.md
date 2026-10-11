---
tags: SVG schematic circuit logic-gate netlist z3 smt reverse image xml
source: distilled/cssctf
---
When a challenge gives a circuit/schematic as an SVG or image, remember an SVG is XML text: parse <path>/<line>/<text> geometry to rebuild the netlist - join wires by matching endpoint coordinates, label each gate from the nearest text element. Then encode every gate as a boolean constraint in z3 (out == Xor(a,b), And(...), etc.) and solve for the input bits; the satisfying bits usually decode to ASCII (a password/flag). Watch for wires that overlap or share a coordinate when you build adjacency - de-dup carefully or the netlist is wrong.

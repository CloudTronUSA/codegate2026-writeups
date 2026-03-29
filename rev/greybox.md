# rev/greybox

## Overview

This challenge is a reverse engineering task built around a custom VM hidden behind glibc `FILE` internals.

The provided `prob` binary reads a 64-byte input, then abuses fake `FILE` objects so that glibc's stream cleanup code dispatches into VM handlers when the program exits. The `target` file is the VM bytecode. If the VM finishes with `m[7] == 0`, the binary prints:

`codegate2026{%.*s}`

That means the flag body is the exact 64-byte input, so the entire problem reduces to recovering the one input that makes the VM accept.

Also: the Dockerfile matters. On a normal host glibc, the fake `FILE` trick can abort with `Fatal error: glibc detected an invalid stdio handle`. Running in the supplied Ubuntu 24.04 environment avoids that and matches the intended behavior.

## Exploit Chain

1. Reverse the hidden dispatch mechanism.
   The binary allocates two fake stream objects and links them together. During exit-time stream handling, glibc calls a slot inside the fake vtable. The binary prepares that slot to point at VM handlers.

2. Recover the VM handler table.
   The handler addresses are not clean function entries in the disassembly; each one starts one byte after a bogus `call` opcode, so a naive `objdump` decode looks broken. Once realigned, the handlers map to a small VM with operations like:
   - `mov reg, imm32`
   - `mov reg, input_slot`
   - `mov input_slot, reg`
   - `add`, `sub`, `mul`, `xor`, `or`
   - `shl`, `shr`
   - `cmpne -> m[7]`
   - `jmp`, `jnz`

3. Recover the real opcode mapping.
   The bytecode is not dispatched as `handler = opcode`. Because the binary points glibc at the middle of a fake vtable, the actual handler index is:

   `handler_index = opcode + parity - 3`

   where `parity` alternates between the two fake stream objects. The first executed handler is `mov reg, imm32`, which is what reveals the `-3` offset.

4. Notice the control flow is effectively fixed.
   The VM has only one conditional jump site, and it is used only as a loop counter. The loop counter is initialized from constants:
   - `0x761945c2 ^ 0x761945ca = 8`

   So the bytecode always runs exactly 8 mixing rounds, then falls through into the comparison stage.

5. Split the bytecode into two logical stages.
   - Stage 1: initialize `m[28] = 8`, then jump into the round function.
   - Stage 2: run 8 rounds of a deterministic mixer over the 16 input dwords stored in `m[12]..m[27]`.
   - Stage 3: jump back to offset `23` and compare the transformed 16 dwords against constants by XORing and ORing the differences into `m[7]`.

   Since the final print checks whether `m[7] == 0`, all 16 transformed dwords must exactly match the embedded constants.

6. Solve the VM symbolically instead of inverting the round function by hand.
   Because the control-flow path is fixed, the cleanest solve is:
   - run the VM once concretely to record the exact `(pc, parity, handler)` trace
   - replay the same trace symbolically with 16 symbolic 32-bit input words
   - constrain the final `m[7] == 0`
   - optionally constrain each byte to printable ASCII

7. Recover the accepted 64-byte input and the flag.
   The model gives:

   `4h!_C0ngr47u147i0ns!_L37_m3_kn0w_why_7his_gr3y_b0x_d03s_n07_3nd!`

   Since the binary prints `codegate2026{<input>}`, the final flag is:

   `codegate2026{4h!_C0ngr47u147i0ns!_L37_m3_kn0w_why_7his_gr3y_b0x_d03s_n07_3nd!}`

## Final Solve

```python
#!/usr/bin/env python3

from pathlib import Path
import sys

try:
    from z3 import BitVec, BitVecVal, If, LShR, Solver, sat
except ImportError as exc:
    raise SystemExit(
        "missing dependency: z3-solver\n"
        "install with: python3 -m pip install --user z3-solver"
    ) from exc


STATE_WORDS = 0x430 // 4


def load_program() -> bytes:
    root = Path(__file__).resolve().parent
    candidates = [
        root / "work" / "deploy" / "target",
        root / "target",
        root / "work" / "target",
    ]
    if len(sys.argv) > 1:
        candidates.insert(0, Path(sys.argv[1]).resolve())
    for path in candidates:
        if path.exists():
            return path.read_bytes()
    raise SystemExit("target file not found")


def emulate_trace(program: bytes) -> list[tuple[int, int, int]]:
    mem = [0] * STATE_WORDS
    mem[9] = 0x100
    for i in range(16):
        mem[12 + i] = 0x41414141

    parity = 1
    trace = []

    for _ in range(100000):
        pc = mem[8] & 0xFFFFFFFF
        opcode = program[pc]
        idx = opcode + parity - 3
        trace.append((pc, parity, idx))

        if idx == 0:
            mem[8] = (pc + 1) & 0xFFFFFFFF
        elif idx == 1:
            a, b = program[pc + 1], program[pc + 2]
            mem[a] = mem[b] & 0xFFFFFFFF
            mem[8] = (pc + 3) & 0xFFFFFFFF
        elif idx == 2:
            a = program[pc + 1]
            imm = int.from_bytes(program[pc + 2 : pc + 6], "little")
            mem[a] = imm
            mem[8] = (pc + 6) & 0xFFFFFFFF
        elif idx == 5:
            a, b = program[pc + 1], program[pc + 2]
            mem[a] = mem[12 + b] & 0xFFFFFFFF
            mem[8] = (pc + 3) & 0xFFFFFFFF
        elif idx == 6:
            a, b = program[pc + 1], program[pc + 2]
            mem[12 + b] = mem[a] & 0xFFFFFFFF
            mem[8] = (pc + 3) & 0xFFFFFFFF
        elif idx == 7:
            a, b = program[pc + 1], program[pc + 2]
            mem[a] = (mem[a] + mem[b]) & 0xFFFFFFFF
            mem[8] = (pc + 3) & 0xFFFFFFFF
        elif idx == 8:
            a, b = program[pc + 1], program[pc + 2]
            mem[a] = (mem[a] - mem[b]) & 0xFFFFFFFF
            mem[8] = (pc + 3) & 0xFFFFFFFF
        elif idx == 9:
            a, b = program[pc + 1], program[pc + 2]
            mem[a] = (mem[a] * mem[b]) & 0xFFFFFFFF
            mem[8] = (pc + 3) & 0xFFFFFFFF
        elif idx == 10:
            a, b = program[pc + 1], program[pc + 2]
            mem[a] &= mem[b]
            mem[8] = (pc + 3) & 0xFFFFFFFF
        elif idx == 11:
            a, b = program[pc + 1], program[pc + 2]
            mem[a] |= mem[b]
            mem[8] = (pc + 3) & 0xFFFFFFFF
        elif idx == 12:
            a, b = program[pc + 1], program[pc + 2]
            mem[a] ^= mem[b]
            mem[8] = (pc + 3) & 0xFFFFFFFF
        elif idx == 13:
            a, b = program[pc + 1], program[pc + 2]
            mem[a] = (mem[a] << (mem[b] & 31)) & 0xFFFFFFFF
            mem[8] = (pc + 3) & 0xFFFFFFFF
        elif idx == 14:
            a, b = program[pc + 1], program[pc + 2]
            mem[a] = (mem[a] >> (mem[b] & 31)) & 0xFFFFFFFF
            mem[8] = (pc + 3) & 0xFFFFFFFF
        elif idx == 15:
            a, b = program[pc + 1], program[pc + 2]
            mem[7] = 1 if mem[a] != mem[b] else 0
            mem[8] = (pc + 3) & 0xFFFFFFFF
        elif idx == 16:
            off = int.from_bytes(program[pc + 1 : pc + 5], "little")
            mem[8] = (pc + off) & 0xFFFFFFFF
        elif idx == 17:
            off = int.from_bytes(program[pc + 1 : pc + 5], "little")
            mem[8] = ((pc + off) if mem[7] else (pc + 5)) & 0xFFFFFFFF
        elif idx == 18:
            return trace
        else:
            raise SystemExit(f"unexpected opcode path: pc={pc} parity={parity} idx={idx}")

        parity ^= 1

    raise SystemExit("trace did not terminate")


def solve(program: bytes, trace: list[tuple[int, int, int]]) -> bytes:
    mem = [BitVecVal(0, 32) for _ in range(STATE_WORDS)]
    mem[9] = BitVecVal(0x100, 32)
    words = [BitVec(f"x{i}", 32) for i in range(16)]
    for i, word in enumerate(words):
        mem[12 + i] = word

    for step, (pc, _parity, idx) in enumerate(trace):
        if idx == 18:
            break

        if idx == 0:
            mem[8] = BitVecVal((pc + 1) & 0xFFFFFFFF, 32)
        elif idx == 1:
            a, b = program[pc + 1], program[pc + 2]
            mem[a] = mem[b]
            mem[8] = BitVecVal((pc + 3) & 0xFFFFFFFF, 32)
        elif idx == 2:
            a = program[pc + 1]
            imm = int.from_bytes(program[pc + 2 : pc + 6], "little")
            mem[a] = BitVecVal(imm, 32)
            mem[8] = BitVecVal((pc + 6) & 0xFFFFFFFF, 32)
        elif idx == 5:
            a, b = program[pc + 1], program[pc + 2]
            mem[a] = mem[12 + b]
            mem[8] = BitVecVal((pc + 3) & 0xFFFFFFFF, 32)
        elif idx == 6:
            a, b = program[pc + 1], program[pc + 2]
            mem[12 + b] = mem[a]
            mem[8] = BitVecVal((pc + 3) & 0xFFFFFFFF, 32)
        elif idx == 7:
            a, b = program[pc + 1], program[pc + 2]
            mem[a] = mem[a] + mem[b]
            mem[8] = BitVecVal((pc + 3) & 0xFFFFFFFF, 32)
        elif idx == 8:
            a, b = program[pc + 1], program[pc + 2]
            mem[a] = mem[a] - mem[b]
            mem[8] = BitVecVal((pc + 3) & 0xFFFFFFFF, 32)
        elif idx == 9:
            a, b = program[pc + 1], program[pc + 2]
            mem[a] = mem[a] * mem[b]
            mem[8] = BitVecVal((pc + 3) & 0xFFFFFFFF, 32)
        elif idx == 10:
            a, b = program[pc + 1], program[pc + 2]
            mem[a] = mem[a] & mem[b]
            mem[8] = BitVecVal((pc + 3) & 0xFFFFFFFF, 32)
        elif idx == 11:
            a, b = program[pc + 1], program[pc + 2]
            mem[a] = mem[a] | mem[b]
            mem[8] = BitVecVal((pc + 3) & 0xFFFFFFFF, 32)
        elif idx == 12:
            a, b = program[pc + 1], program[pc + 2]
            mem[a] = mem[a] ^ mem[b]
            mem[8] = BitVecVal((pc + 3) & 0xFFFFFFFF, 32)
        elif idx == 13:
            a, b = program[pc + 1], program[pc + 2]
            mem[a] = mem[a] << (mem[b] & BitVecVal(31, 32))
            mem[8] = BitVecVal((pc + 3) & 0xFFFFFFFF, 32)
        elif idx == 14:
            a, b = program[pc + 1], program[pc + 2]
            mem[a] = LShR(mem[a], mem[b] & BitVecVal(31, 32))
            mem[8] = BitVecVal((pc + 3) & 0xFFFFFFFF, 32)
        elif idx == 15:
            a, b = program[pc + 1], program[pc + 2]
            mem[7] = If(mem[a] != mem[b], BitVecVal(1, 32), BitVecVal(0, 32))
            mem[8] = BitVecVal((pc + 3) & 0xFFFFFFFF, 32)
        elif idx == 16:
            off = int.from_bytes(program[pc + 1 : pc + 5], "little")
            mem[8] = BitVecVal((pc + off) & 0xFFFFFFFF, 32)
        elif idx == 17:
            next_pc = trace[step + 1][0]
            mem[8] = BitVecVal(next_pc & 0xFFFFFFFF, 32)
        else:
            raise SystemExit(f"unsupported symbolic opcode idx={idx} at pc={pc}")

    solver = Solver()
    solver.add(mem[7] == BitVecVal(0, 32))

    for word in words:
        for shift in range(0, 32, 8):
            byte = LShR(word, shift) & BitVecVal(0xFF, 32)
            solver.add(byte >= BitVecVal(0x20, 32))
            solver.add(byte <= BitVecVal(0x7E, 32))

    if solver.check() != sat:
        raise SystemExit("solver returned unsat")

    model = solver.model()
    return b"".join(model.evaluate(word).as_long().to_bytes(4, "little") for word in words)


def main() -> None:
    program = load_program()
    trace = emulate_trace(program)
    flag_body = solve(program, trace)
    print(flag_body.decode("ascii"))
    print(f"codegate2026{{{flag_body.decode('ascii')}}}")


if __name__ == "__main__":
    main()
```

Run:

```bash
python3 -m pip install --user z3-solver
python3 solve.py
```

# rev/cogwarts

## Overview

This challenge gives us a custom language compiler (`grimc`) and a runtime (`harness`). The compiler will compile a Grimoire into something that can be ran by the runtime. The harness will run our function and check the oracle host status. If the oracle reports success, the harness reads `flag` and prints it.

The solve path is to reverse the oracle host logic, understand which commands flip its success bits, and then submit a Grimoire that drives the system into the success state.

## Exploit Chain

1. Understand the CogwartsLang syntax.

   We must first understand how to write a proper Grimoire. The fastest way is to look at the strings in the compiler and harness to reveal the grammar.

   The useful strings were:

   - `Expected 'Scroll' header`
   - `Expected module name string after 'Scroll'`
   - `Expected 'Incantation'`
   - `Expected '[' for parameters`
   - `Expected 'Alohomora'`
   - `Unterminated block. Colloportus never arrives.`
   - `Missing required function solve`
   - `RuntimeError (Hex) at unknown: Function arity mismatch at runtime.`

   We then try to write a script that satisifies all the requirements one by one until no more error messages. That gives the minimal valid program shape:

   ```txt
   Scroll "main".
   Incantation solve[x] Alohomora
   Colloportus.
   ```
	
   Looking at the strings more closely we can see that there are function-like "oracles" that we can call between `Alohomora` and `Colloportus`:
   
   - `seed` / `tick` / `log`: padding commands that advance the oracle tick
   - `checkpoint(index, value)`: validates one checkpoint and sets one bit in the bitmask
   - `ticket(value)`: validates a computed value and enables the witness step
   - `witness(value)`: final validation step

   It's also worth noting that the functions use `[]` for their params, not the standard `()`, and a `.` is needed after every oracle call.

2. Reverse the harness success condition.

   `grim_host_status` in `liboracle_host.so` is the check. It returns success only when:

   - byte `success_witness` is `1`
   - the low 3 bits of the checkpoint bitmask are all set

   In other words, we must satisfy:

   - `checkpoint(0)` success
   - `checkpoint(1)` success
   - `checkpoint(2)` success
   - `witness(...)` success

3. Reverse the oracle calls needed.

   The key constraints from reversing:

   - `ticket` sets a deadline of `current_tick + 20`
   - `witness` only succeeds if called before that deadline
   - each checkpoint only succeeds in its own allowed tick window, and each call progresses the tick counter.

   By cracking `grim_host_status` and reading the live oracle state, the important constants are:

   - `seed = 0x5f64d765889c6342`
   - `input = 0xeacadd96dae055b8`

   By reading the decompiled code we can see that `oracle_host::expected_checkpoint` returns the expected checkpoint value and its valid tick window. Reversing that function gives:

   - `checkpoint(0, 984171264)` is valid for ticks `[246, 310]`
   - `checkpoint(1, 2916723419)` is valid for ticks `[227, 291]`
   - `checkpoint(2, 652393318)` is valid for ticks `[222, 286]`

   Reversing the `ticket` and `witness` function with the constants above gives:

   - `ticket(369791075)` at tick `266` is valid
   - `witness(1265400292)` at tick `271` is valid

   Runtime breakpoints show tick progression for each oracle call:

   - zero-arg oracle calls (`seed`, `tick`, `log`) land on ticks `3, 7, 11, ...`
   - a one-arg call advances by `+5` from the previous command tick
   - a two-arg call advances by `+6` from the previous command tick

   So a clean schedule is:

   - run `seed` 61 times, ending at tick `243`
   - `checkpoint(0, 984171264)` at tick `249`
   - `checkpoint(1, 2916723419)` at tick `255`
   - `checkpoint(2, 652393318)` at tick `261`
   - `ticket(369791075)` at tick `266`
   - `witness(1265400292)` at tick `271`

   This satisfies all checkpoint windows, and `271 <= 266 + 20`, so witness is still within the ticket deadline.

## Final Solve

```python
#!/usr/bin/env python3
import re
import socket
import sys

HOST = "15.164.175.59"
PORT = 20266

def build_payload() -> str:
    lines = [
        'Scroll "main".',
        'Incantation solve[x] Alohomora',
    ]
    lines.extend('oracle["seed"].' for _ in range(61))
    lines.extend(
        [
            'oracle["checkpoint", 0, 984171264].',
            'oracle["checkpoint", 1, 2916723419].',
            'oracle["checkpoint", 2, 652393318].',
            'oracle["ticket", 369791075].',
            'oracle["witness", 1265400292].',
            "Colloportus.",
        ]
    )
    return "\n".join(lines) + "\n"

def recv_all(sock: socket.socket) -> bytes:
    chunks = []
    while True:
        data = sock.recv(4096)
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks)

def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    payload = build_payload().encode()

    with socket.create_connection((host, port), timeout=10) as sock:
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)
        output = recv_all(sock).decode("utf-8", errors="replace")

    print(output, end="")

    match = re.search(r"codegate2026\{[^}]+\}", output)
    if match:
        print("\nflag:", match.group(0))
        return 0

    print("\nflag not found", file=sys.stderr)
    return 1

if __name__ == "__main__":
    raise SystemExit(main())
```

Run it with:

```bash
python3 solve.py
```

# rev/imagination

## Overview

This is a small reversing challenge built around an x86-64 loader and a MIPS payload. The host binary `prob` reads a 78-byte input, loads `code.bin` into Unicorn as big-endian MIPS32, runs it, and then compares the mutated input buffer against a 78-byte target blob stored in `.rodata`.

## Exploit Chain

1. Inspect `prob` and notice the Unicorn setup. The program writes the user input to `0x01000000`, writes `code.bin` to `0x01001000`, emulates the payload, and then compares 78 bytes from the input buffer against a constant blob in `.rodata`.

2. Disassemble `code.bin` as big-endian MIPS32. The full logic is a nested in-place transform:

```c
for (int i = 0; i < 0x4e; i++) {
    for (int j = i + 1; j < 0x4e; j++) {
        buf[j] ^= (buf[i] + j) & 0xff;
    }
}
```

3. The key property is that `buf[i]` is never modified during outer-loop iteration `i`, so the transform is directly reversible. Start from the final 78-byte target blob embedded in `prob`, walk `i` backward from `0x4d` to `0`, and undo each XOR from the end of the buffer back toward `i + 1`.

4. Reversing that target yields the flag string.

## Final Solve

```python
#!/usr/bin/env python3

TARGET = bytes.fromhex(
    "630b0c0219111e1a681b330b5a1e2e71ac1348430f6fe652ac694f2a6b294329"
    "312970e1a90ea0522669fcd98e3e4c0c15b32b2493166d9addc57a22415bd919"
    "305f4ef3ad09193fe7dacbf4fd96"
)


def reverse_transform(target: bytes) -> bytes:
    data = bytearray(target)
    size = len(data)

    for i in range(size - 2, -1, -1):
        base = data[i]
        for j in range(size - 1, i, -1):
            data[j] ^= (base + j) & 0xFF

    return bytes(data)


def main() -> None:
    flag = reverse_transform(TARGET).decode()
    print(flag)


if __name__ == "__main__":
    main()
```

Run:

```bash
python3 ./solve.py
```

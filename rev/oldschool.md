# rev/oldschool

## Overview

This is a remote reversing challenge. The attachment gives you a `client`, but the real task is to solve a sequence of challenge binaries served by the remote instance and submit the exact 64-byte input each binary expects.

The challenge has three important parts:

   1. The provided client speaks a small custom binary protocol to the server and receives one ELF per round.
   2. Each ELF validates a 64-byte input:
      - first 4 bytes: SHA-256 preimage check
      - last 60 bytes: transformed by several reversible stages and compared against a target in `.rodata`
   3. The binaries are not fully identical across rounds:
      - `.rodata` base moves
      - the middle table-driven stages are data-dependent
      - the final bytewise stage is code-generated per binary

So the solve path is:

   - reverse the client protocol
   - reverse the binary format and inversion logic
   - make the last stage dynamic instead of hardcoding one sample
   - submit answers until the server returns the flag

## Exploit Chain

1. Reverse the client protocol.

   The client is a Go ELF. Reversing it shows it connects to `server:8080` and uses a simple frame format:

   - `1 byte`: message type
   - `4 bytes`: big-endian payload length
   - payload: protobuf-style varints / length-delimited fields

   The message types are:

   - `1`: `ChallengeRequest` (empty payload)
   - `2`: `ChallengeResponse`
   - `3`: `AnswerRequest`
   - `4`: `AnswerResponse`

   The useful fields are:

   - `ChallengeResponse.binary_data`: the round ELF
   - `ChallengeResponse.binary_hash`: ID that must be echoed back
   - `ChallengeResponse.prob_index`, `prob_total`: round counters
   - `AnswerResponse.correct`
   - `AnswerResponse.has_next`
   - `AnswerResponse.flag`

   That is enough to write our own client and stop using the provided binary.

2. Understand what a single challenge ELF expects.

   Running and reversing one sample binary shows it reads exactly `64` bytes:

   - bytes `0..3`: hashed with SHA-256 and compared against a digest stored in `.rodata + 0x20`
   - bytes `4..63`: copied into a 60-byte working buffer and transformed
   - final transformed buffer is compared against a target stored in `.rodata + 0x60`

   The first 4 bytes are the key that also drives later stages.

3. Recover the 4-byte key.

   The SHA-256 digest is a raw preimage check on exactly 4 bytes. Brute forcing `2^32` on CPU is annoying, but `hashcat` handles it quickly on GPU with:

   ```bash
   hashcat -m 1400 -a 3 digest.txt '?b?b?b?b'
   ```

   In the final solver the digest is read from `.rodata + 0x20`, written to a temporary file, and cracked with `hashcat`.

4. Recover the table-driven program from `.rodata`.

   The next stage is not hardcoded as a fixed sequence. Instead, a small 7-entry program is decoded from `.rodata + 0x40` using the recovered 4-byte key.

   Each step is:

   - `op`
   - `param`
   - `count`
   - `next`

   The program starts at index `0` and follows `next` until `0xff`.

   The decode is:

   - `k = key[idx & 3]`
   - `op = table[idx*4 + 0] ^ k`
   - `param = table[idx*4 + 1] ^ k`
   - `count = table[idx*4 + 2] ^ k`
   - `next = table[idx*4 + 3] ^ ((idx + k) & 0xff)`

   This produces a short chain of operations over the 60-byte buffer.

5. Reverse the four middle-stage operation types.

   These are all data-driven from `.rodata`, so once the format is understood they can be inverted directly.

   `op 1`: bytewise transform list

   - table base: `.rodata + 0x1a0 + param*32`
   - entry format:
     - `qword count`
     - `count` pairs `(mode, arg)`
   - supported modes:
     - `0`: XOR with `arg`
     - `1`: rotate right by `arg & 7`
     - `2`: rotate left by `arg & 7`

   To invert, apply the pair list in reverse order and flip each operation:

   - XOR stays XOR
   - ROR becomes ROL
   - ROL becomes ROR

   `op 2`: permutation

   - table base: `.rodata + 0x2a0 + param*60`
   - 60-byte permutation table
   - forward transform is `out[i] = buf[perm[i]]`

   To invert:

   - `orig[perm[i]] = out[i]`

   `op 3`: substitution box

   - table base: `.rodata + 0x480 + param*256`
   - 256-byte S-box

   To invert:

   - build inverse S-box once
   - replace each byte with `inv[sbox_byte]`

   `op 4`: tiny VM / state machine

   - table base: `.rodata + 0xc80 + param*88`
   - format:
     - `qword count`
     - `count` triples `(op, a, b)`
     - 4 mutation indices

   Before execution, 4 triple entries are modified with the 4-byte key:

   - `triples[mut_idx[i]][2] ^= key[i]`

   The VM keeps `state = [0, 0, 0, 0]` and the meaningful opcodes are:

   - `1`: `state[idx] ^= b`
   - `2`: `state[idx] = (state[idx] + b) & 0xff`
   - `3`: `state[idx] = ror8(state[idx], b & 7)`
   - `4`: `state[idx] = rol8(state[idx], b & 7)`
   - `6`: `buf[b % 60] ^= state[idx]`

   To invert:

   - run the VM forward
   - record all `op 6` XOR writes
   - replay those XORs in reverse order

6. Deal with the final stage correctly.

   At first glance the last stage looks like a simple fixed bytewise transform. That is only true for one sample. Across rounds, two things move:

   - the `.rodata` base
   - the actual logic of the final loop

   What stays stable is the overall structure:

   - four 32-bit values are prepared on the stack at:
     - `[rbp-0x2d0]`
     - `[rbp-0x2cc]`
     - `[rbp-0x2c8]`
     - `[rbp-0x2c4]`
   - then a loop transforms the 60-byte buffer
   - then the result is compared to `.rodata + 0x60`

   The correct generic solve is:

   - locate the final compare call by finding the RIP-relative reference to `.rodata + 0x60`
   - run the binary under `gdb` with the correct 4-byte key and a dummy 60-byte suffix
   - break at that final compare call
   - read the four stack dwords

   That gives the per-binary constants used by the final stage.

7. Do not hardcode the last loop. Emulate it.

   The final loop is code-generated per binary, so hardcoding the first sample's byte math fails on later rounds.

   The robust method is:

   - disassemble `.text`
   - locate the final loop bounds:
     - find the loop increment `add qword ptr [rbp - 0x328], 1`
     - read the `jbe` target that jumps back into the loop body
   - emulate that exact loop body with Unicorn

   For each byte position `i`:

   - write `i` into `[rbp-0x328]`
   - write candidate byte `x` into `[rbp-0x120 + i]`
   - write the four recovered dwords into their stack slots
   - emulate one loop iteration
   - record output byte

   That gives a 256-entry lookup table for that position. Invert the table and map the target byte back to the original byte. Do this for all 60 positions.

   This completely removes the need to manually reverse the final stage for every new binary.

8. Assemble the answer and solve all rounds.

   Once the final stage is inverted, the remaining inversion is:

   - reverse the decoded program
   - apply inverse `op4` / `op3` / `op2` / `op1` in reverse order and reverse repetition counts

   The final answer is:

   - `4-byte key || recovered 60-byte plaintext`

   Submit that with the original `binary_hash`, request the next challenge if `has_next == true`, and keep going until the server returns the flag.

## Final Solve

This is the working end-to-end solve script:

```python
#!/usr/bin/env python3
import socket
import struct
import subprocess
import tempfile
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86_const import X86_OP_MEM, X86_REG_RIP
from elftools.elf.elffile import ELFFile
from unicorn import UC_ARCH_X86, UC_MODE_64, Uc
from unicorn.x86_const import (
    UC_X86_REG_R10,
    UC_X86_REG_R11,
    UC_X86_REG_R12,
    UC_X86_REG_R13,
    UC_X86_REG_R14,
    UC_X86_REG_R15,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_RAX,
    UC_X86_REG_RBP,
    UC_X86_REG_RBX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDI,
    UC_X86_REG_RDX,
    UC_X86_REG_RFLAGS,
    UC_X86_REG_RIP,
    UC_X86_REG_RSI,
    UC_X86_REG_RSP,
)


HOST = "16.184.16.74"
PORT = 8080

MSG_CHALLENGE_REQUEST = 1
MSG_CHALLENGE_RESPONSE = 2
MSG_ANSWER_REQUEST = 3
MSG_ANSWER_RESPONSE = 4

HASHCAT_MASK = "?b?b?b?b"


def rol8(x: int, n: int) -> int:
    n &= 7
    if n == 0:
        return x & 0xFF
    return ((x << n) | (x >> (8 - n))) & 0xFF


def ror8(x: int, n: int) -> int:
    n &= 7
    if n == 0:
        return x & 0xFF
    return ((x >> n) | (x << (8 - n))) & 0xFF


def recv_exact(sock: socket.socket, n: int) -> bytes:
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise EOFError("socket closed")
        data.extend(chunk)
    return bytes(data)


def read_frame(sock: socket.socket) -> tuple[int, bytes]:
    header = recv_exact(sock, 5)
    msg_type = header[0]
    size = struct.unpack(">I", header[1:])[0]
    return msg_type, recv_exact(sock, size)


def write_frame(sock: socket.socket, msg_type: int, payload: bytes) -> None:
    sock.sendall(bytes([msg_type]) + struct.pack(">I", len(payload)) + payload)


def read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        if not (b & 0x80):
            return value, pos
        shift += 7


def write_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def parse_challenge_response(payload: bytes) -> dict:
    out = {"binary_data": b"", "binary_hash": b"", "prob_index": 0, "prob_total": 0}
    pos = 0
    while pos < len(payload):
        key, pos = read_varint(payload, pos)
        field = key >> 3
        wire = key & 7
        if wire == 2:
            size, pos = read_varint(payload, pos)
            data = payload[pos : pos + size]
            pos += size
            if field == 1:
                out["binary_data"] = data
            elif field == 2:
                out["binary_hash"] = data
        elif wire == 0:
            value, pos = read_varint(payload, pos)
            if field == 3:
                out["prob_index"] = value
            elif field == 4:
                out["prob_total"] = value
        else:
            raise ValueError(f"unsupported wire type: {wire}")
    return out


def parse_answer_response(payload: bytes) -> dict:
    out = {"correct": False, "has_next": False, "flag": b""}
    pos = 0
    while pos < len(payload):
        key, pos = read_varint(payload, pos)
        field = key >> 3
        wire = key & 7
        if wire == 0:
            value, pos = read_varint(payload, pos)
            if field == 1:
                out["correct"] = bool(value)
            elif field == 2:
                out["has_next"] = bool(value)
        elif wire == 2:
            size, pos = read_varint(payload, pos)
            data = payload[pos : pos + size]
            pos += size
            if field == 3:
                out["flag"] = data
        else:
            raise ValueError(f"unsupported wire type: {wire}")
    return out


def build_answer_request(binary_hash: bytes, answer: bytes) -> bytes:
    out = bytearray()
    out.extend(write_varint((1 << 3) | 2))
    out.extend(write_varint(len(binary_hash)))
    out.extend(binary_hash)
    out.extend(write_varint((2 << 3) | 2))
    out.extend(write_varint(len(answer)))
    out.extend(answer)
    return bytes(out)


class BinarySolver:
    DIGEST_OFF = 0x20
    PROGRAM_OFF = 0x40
    TARGET_OFF = 0x60
    OP1_OFF = 0x1A0
    OP2_OFF = 0x2A0
    OP3_OFF = 0x480
    OP4_OFF = 0xC80
    STACK_BASE = 0x70000000
    STACK_SIZE = 0x20000

    def __init__(self, path: Path):
        self.path = path
        with path.open("rb") as f:
            elf = ELFFile(f)
            text = elf.get_section_by_name(".text")
            ro = elf.get_section_by_name(".rodata")
            self.text_addr = text["sh_addr"]
            self.text = text.data()
            self.rodata_addr = ro["sh_addr"]
            self.rodata = ro.data()
        self.text_insns = self.disassemble_text()
        self.final_break_off = self.find_final_break_off()
        self.final_loop_start, self.final_loop_end = self.find_final_loop_bounds()
        self.final_mu, self.final_rbp = self.make_final_stage_emulator()

    def disassemble_text(self):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        return list(md.disasm(self.text, self.text_addr))

    def ro(self, addr: int, size: int) -> bytes:
        start = addr - self.rodata_addr
        return self.rodata[start : start + size]

    def ro_off(self, offset: int, size: int) -> bytes:
        return self.ro(self.rodata_addr + offset, size)

    def find_final_break_off(self) -> int:
        target = self.rodata_addr + self.TARGET_OFF
        candidates = []
        for i, insn in enumerate(self.text_insns):
            if insn.mnemonic != "lea" or len(insn.operands) != 2:
                continue
            op = insn.operands[1]
            if op.type != X86_OP_MEM or op.mem.base != X86_REG_RIP:
                continue
            ref = insn.address + insn.size + op.mem.disp
            if ref != target:
                continue
            for next_insn in self.text_insns[i + 1 : i + 8]:
                if next_insn.mnemonic == "call":
                    candidates.append(next_insn.address)
                    break
        if not candidates:
            raise RuntimeError(f"failed to locate final compare for {self.path}")
        return candidates[-1]

    def find_final_loop_bounds(self) -> tuple[int, int]:
        loop_inc_idx = None
        for i, insn in enumerate(self.text_insns):
            if insn.address >= self.final_break_off:
                break
            if insn.mnemonic == "add" and insn.op_str == "qword ptr [rbp - 0x328], 1":
                loop_inc_idx = i
        if loop_inc_idx is None:
            raise RuntimeError(f"failed to locate final loop increment for {self.path}")
        loop_end = self.text_insns[loop_inc_idx].address
        jump_insn = self.text_insns[loop_inc_idx + 2]
        if jump_insn.mnemonic != "jbe":
            raise RuntimeError(f"unexpected final loop shape in {self.path}")
        return jump_insn.operands[0].imm, loop_end

    def make_final_stage_emulator(self) -> tuple[Uc, int]:
        page = 0x1000
        code_base = self.text_addr & ~(page - 1)
        code_end = (self.text_addr + len(self.text) + page - 1) & ~(page - 1)
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        mu.mem_map(code_base, code_end - code_base)
        mu.mem_write(self.text_addr, self.text)
        mu.mem_map(self.STACK_BASE, self.STACK_SIZE)
        rbp = self.STACK_BASE + self.STACK_SIZE // 2
        return mu, rbp

    def get_pie_base(self, input_file: Path) -> int:
        out = subprocess.check_output(
            [
                "gdb",
                "-nx",
                "-q",
                "-batch",
                "-ex",
                "set pagination off",
                "-ex",
                "set disable-randomization on",
                "-ex",
                f"starti < {input_file}",
                "-ex",
                "info proc mappings",
                str(self.path),
            ],
            text=True,
        )
        resolved = str(self.path.resolve())
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 6:
                continue
            if parts[3] == "0x0" and parts[4] == "r--p" and parts[5] == resolved:
                return int(parts[0], 16)
        raise RuntimeError(f"failed to locate PIE base for {self.path}")

    def crack_key(self) -> bytes:
        digest = self.ro_off(self.DIGEST_OFF, 32).hex()
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            hash_file = td_path / "digest.txt"
            out_file = td_path / "hashcat.out"
            hash_file.write_text(digest + "\n")
            commands = [
                [
                    "hashcat",
                    "-m",
                    "1400",
                    "-a",
                    "3",
                    "-O",
                    "--force",
                    "--potfile-disable",
                    "--outfile",
                    str(out_file),
                    "--outfile-format",
                    "2",
                    str(hash_file),
                    HASHCAT_MASK,
                ],
                [
                    "hashcat",
                    "-m",
                    "1400",
                    "-a",
                    "3",
                    "--force",
                    "--potfile-disable",
                    "--outfile",
                    str(out_file),
                    "--outfile-format",
                    "2",
                    str(hash_file),
                    HASHCAT_MASK,
                ],
            ]
            last_error = None
            for cmd in commands:
                try:
                    subprocess.run(
                        cmd,
                        check=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    break
                except subprocess.CalledProcessError as exc:
                    last_error = exc
                    if out_file.exists() and out_file.stat().st_size > 0:
                        break
            if not out_file.exists() or out_file.stat().st_size == 0:
                raise RuntimeError(f"hashcat failed for digest {digest}") from last_error
            value = out_file.read_bytes().decode("latin1").strip()
        if value.startswith("$HEX[") and value.endswith("]"):
            return bytes.fromhex(value[5:-1])
        return value.encode("latin1")

    def derive_program(self, key: bytes) -> list[tuple[int, int, int, int]]:
        table = self.ro_off(self.PROGRAM_OFF, 28)
        program = []
        idx = 0
        seen = 0
        while idx != 0xFF:
            if seen > 1024:
                raise RuntimeError("program loop did not terminate")
            k = key[idx & 3]
            base = idx * 4
            op = table[base] ^ k
            param = table[base + 1] ^ k
            count = table[base + 2] ^ k
            nxt = table[base + 3] ^ ((idx + k) & 0xFF)
            program.append((op, param, count, nxt))
            idx = nxt
            seen += 1
        return program

    def get_final_stage_dwords(self, key: bytes) -> tuple[int, int, int, int]:
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            in_file = td_path / "input.bin"
            in_file.write_bytes(key + b"A" * 60)
            pie_base = self.get_pie_base(in_file)
            out = subprocess.check_output(
                [
                    "gdb",
                    "-nx",
                    "-q",
                    "-batch",
                    "-ex",
                    "set pagination off",
                    "-ex",
                    "set disable-randomization on",
                    "-ex",
                    f"starti < {in_file}",
                    "-ex",
                    f"b *{pie_base + self.final_break_off:#x}",
                    "-ex",
                    "c",
                    "-ex",
                    'printf "D0=%08x\\n", *(unsigned int*)($rbp-0x2d0)',
                    "-ex",
                    'printf "D1=%08x\\n", *(unsigned int*)($rbp-0x2cc)',
                    "-ex",
                    'printf "D2=%08x\\n", *(unsigned int*)($rbp-0x2c8)',
                    "-ex",
                    'printf "D3=%08x\\n", *(unsigned int*)($rbp-0x2c4)',
                    str(self.path),
                ],
                text=True,
            )
        values = {}
        for line in out.splitlines():
            if line.startswith("D"):
                key_name, hex_value = line.split("=")
                values[key_name] = int(hex_value, 16)
        return values["D0"], values["D1"], values["D2"], values["D3"]

    def emulate_final_byte(
        self,
        index: int,
        value: int,
        d0: int,
        d1: int,
        d2: int,
        d3: int,
    ) -> int:
        mu = self.final_mu
        rbp = self.final_rbp
        frame_base = rbp - 0x500
        frame_size = 0x700
        mu.mem_write(frame_base, b"\x00" * frame_size)
        mu.mem_write(rbp - 0x2D0, struct.pack("<I", d0))
        mu.mem_write(rbp - 0x2CC, struct.pack("<I", d1))
        mu.mem_write(rbp - 0x2C8, struct.pack("<I", d2))
        mu.mem_write(rbp - 0x2C4, struct.pack("<I", d3))
        mu.mem_write(rbp - 0x328, struct.pack("<Q", index))
        mu.mem_write(rbp - 0x120 + index, bytes([value]))

        for reg in (
            UC_X86_REG_RAX,
            UC_X86_REG_RBX,
            UC_X86_REG_RCX,
            UC_X86_REG_RDX,
            UC_X86_REG_RSI,
            UC_X86_REG_RDI,
            UC_X86_REG_R8,
            UC_X86_REG_R9,
            UC_X86_REG_R10,
            UC_X86_REG_R11,
            UC_X86_REG_R12,
            UC_X86_REG_R13,
            UC_X86_REG_R14,
            UC_X86_REG_R15,
        ):
            mu.reg_write(reg, 0)
        mu.reg_write(UC_X86_REG_RBP, rbp)
        mu.reg_write(UC_X86_REG_RSP, rbp - 0x800)
        mu.reg_write(UC_X86_REG_RFLAGS, 0)
        mu.reg_write(UC_X86_REG_RIP, self.final_loop_start)
        mu.emu_start(self.final_loop_start, self.final_loop_end)
        return mu.mem_read(rbp - 0x120 + index, 1)[0]

    def invert_final_stage(self, data: bytearray, d0: int, d1: int, d2: int, d3: int) -> bytearray:
        for i, target in enumerate(data):
            inverse = [None] * 256
            for candidate in range(256):
                out = self.emulate_final_byte(i, candidate, d0, d1, d2, d3)
                inverse[out] = candidate
            value = inverse[target]
            if value is None:
                raise RuntimeError(f"final stage was not invertible at byte {i}")
            data[i] = value
        return data

    def invert_op1(self, data: bytearray, param: int) -> bytearray:
        off = self.OP1_OFF + param * 32
        count = struct.unpack_from("<Q", self.rodata, off)[0]
        pairs = [tuple(self.rodata[off + 8 + 2 * i : off + 10 + 2 * i]) for i in range(count)]
        for mode, arg in reversed(pairs):
            for i, x in enumerate(data):
                if mode == 0:
                    data[i] ^= arg
                elif mode == 1:
                    data[i] = rol8(x, arg & 7)
                elif mode == 2:
                    data[i] = ror8(x, arg & 7)
                else:
                    raise RuntimeError(f"unexpected op1 mode: {mode}")
        return data

    def invert_op2(self, data: bytearray, param: int) -> bytearray:
        off = self.OP2_OFF + param * 60
        perm = self.rodata[off : off + 60]
        out = bytearray(60)
        for i, dst in enumerate(perm):
            out[dst] = data[i]
        return out

    def invert_op3(self, data: bytearray, param: int) -> bytearray:
        off = self.OP3_OFF + param * 256
        sbox = self.rodata[off : off + 256]
        inv = [0] * 256
        for i, b in enumerate(sbox):
            inv[b] = i
        return bytearray(inv[x] for x in data)

    def invert_op4(self, data: bytearray, param: int, key: bytes) -> bytearray:
        off = self.OP4_OFF + param * 88
        count = struct.unpack_from("<Q", self.rodata, off)[0]
        triples = [list(self.rodata[off + 8 + 3 * i : off + 11 + 3 * i]) for i in range(count)]
        mutate_indices = list(self.rodata[off + 8 + 3 * count : off + 8 + 3 * count + 4])
        for i, k in enumerate(key):
            triples[mutate_indices[i]][2] ^= k

        state = [0, 0, 0, 0]
        xors = []
        for op, a, b in triples:
            idx = a & 3
            if op in (0, 5):
                continue
            if op == 1:
                state[idx] ^= b
            elif op == 2:
                state[idx] = (state[idx] + b) & 0xFF
            elif op == 3:
                state[idx] = ror8(state[idx], b & 7)
            elif op == 4:
                state[idx] = rol8(state[idx], b & 7)
            elif op == 6:
                xors.append((b % 60, state[idx]))
            else:
                raise RuntimeError(f"unexpected op4 opcode: {op}")

        for pos, value in reversed(xors):
            data[pos] ^= value
        return data

    def solve(self) -> bytes:
        key = self.crack_key()
        d0, d1, d2, d3 = self.get_final_stage_dwords(key)
        data = bytearray(self.ro_off(self.TARGET_OFF, 60))
        data = self.invert_final_stage(data, d0, d1, d2, d3)

        for op, param, count, _ in reversed(self.derive_program(key)):
            for _ in range(count):
                if op == 1:
                    data = self.invert_op1(data, param)
                elif op == 2:
                    data = self.invert_op2(data, param)
                elif op == 3:
                    data = self.invert_op3(data, param)
                elif op == 4:
                    data = self.invert_op4(data, param, key)
                else:
                    raise RuntimeError(f"unexpected program opcode: {op}")

        return key + bytes(data)


def solve_remote() -> bytes:
    with socket.create_connection((HOST, PORT), timeout=10) as sock:
        write_frame(sock, MSG_CHALLENGE_REQUEST, b"")
        while True:
            msg_type, payload = read_frame(sock)
            if msg_type != MSG_CHALLENGE_RESPONSE:
                raise RuntimeError(f"unexpected message type: {msg_type}")

            challenge = parse_challenge_response(payload)
            with tempfile.TemporaryDirectory() as td:
                binary_path = Path(td) / "challenge.bin"
                binary_path.write_bytes(challenge["binary_data"])
                binary_path.chmod(0o755)
                answer = BinarySolver(binary_path).solve()

            write_frame(
                sock,
                MSG_ANSWER_REQUEST,
                build_answer_request(challenge["binary_hash"], answer),
            )

            msg_type, payload = read_frame(sock)
            if msg_type != MSG_ANSWER_RESPONSE:
                raise RuntimeError(f"unexpected message type: {msg_type}")
            reply = parse_answer_response(payload)
            if not reply["correct"]:
                raise RuntimeError(
                    f"server rejected round {challenge['prob_index']}/{challenge['prob_total']}"
                )
            if reply["flag"]:
                return reply["flag"]
            if reply["has_next"]:
                write_frame(sock, MSG_CHALLENGE_REQUEST, b"")
                continue
            raise RuntimeError("no flag returned and no next round advertised")


def main() -> None:
    flag = solve_remote()
    print(flag.decode("latin1"))


if __name__ == "__main__":
    main()
```

Run it with:

```bash
python ./solve.py
```

Notes:

- This script expects `hashcat` and `gdb` to be installed and usable locally.
- Python dependencies are `pyelftools`, `capstone`, and `unicorn`.

```bash
pip install pyelftools capstone unicorn
```

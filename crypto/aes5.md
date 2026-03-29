# crypto/aes5

## Overview

This challenge is a custom 5-round AES-like service. Reading the code gives the entire model:

1. The cipher uses **six independent 16-byte round keys**:
   - `K0, K1, K2, K3, K4, K5`
2. Encryption is:
   - initial whitening: `state ^= K0`
   - rounds 1..4: `SubBytes -> ShiftRows -> MixColumns -> AddRoundKey`
   - round 5: `SubBytes -> ShiftRows -> AddRoundKey`
3. The service exposes:
   - encryption oracle
   - decryption oracle
   - key submission
4. The query limit is `4096`, and it counts only encryption/decryption menu actions.

The most important design choice is that the round keys are **independent**. That means any attack that depends on the AES key schedule is irrelevant here. We must recover all 96 bytes directly from the oracle behavior.

The full solve path is:

1. Read the service and rewrite it into a more attack-friendly equivalent form.
2. Recover `K0` using a 5-round YoyoTricks key-recovery attack.
3. Recover `K5` using a classic 4-round Square attack on a peeled core.
4. Peel the cipher down to a 3-round core and recover `K4` with a 2-pair differential attack.
5. Peel the cipher down to a 2-round core and recover `K3` with another 2-pair differential attack.
6. Peel the cipher down to a 1-round core and recover `K2` and `K1` with bytewise DDT matching.
7. Convert the transformed keys back into the original round keys and submit.

The final solver only needed `1028` queries on the successful remote run.

## Exploit Chain

### 1. Start from the actual service implementation

The challenge code in `for_user/aes5.py` gives the exact round structure:

```python
state = bytes_to_state(plaintext)
add_round_key(state, round_keys[0])
for r in range(1, 5):
    sub_bytes(state)
    shift_rows(state)
    mix_columns(state)
    add_round_key(state, round_keys[r])
sub_bytes(state)
shift_rows(state)
add_round_key(state, round_keys[5])
```

This is a 5-round AES-style block cipher where the last round omits `MixColumns`.

At first glance that looks close to reduced-round AES, but the important difference is that the keys are independent. We therefore want attacks that use only the round function structure, not the AES schedule.

### 2. Rewrite the service into the exact form used by the 5-round YoyoTricks attack

The public YoyoTricks key-recovery code does not attack the raw AES form directly. It attacks a conjugated form usually written as:

- first round: `SubBytes -> MixColumns -> AddRoundKey`
- middle rounds: full AES rounds
- final round: `SubBytes -> AddRoundKey`

That looks different from the challenge, but it is equivalent after a simple input/output transform.

Define:

- `SR` = `ShiftRows`
- `SR^-1` = inverse `ShiftRows`
- `E` = original challenge encryption

Now define a new oracle:

`SuperEnc(P) = SR^-1( E( SR^-1(P) ) )`

and the matching decryption:

`SuperDec(C) = SR( D( SR(C) ) )`

After this rewrite, the transformed cipher is:

- `K0' = SR(K0)`
- `K1' = K1`
- `K2' = K2`
- `K3' = K3`
- `K4' = K4`
- `K5' = SR^-1(K5)`

and the round structure becomes exactly the 5-round form needed by the YoyoTricks key-recovery attack.

### 3. Recover the transformed first key `K0' = SR(K0)`

With the transformed oracle in hand, we can apply the 5-round YoyoTricks key-recovery method.

The attack uses adaptive pair generation:

1. Start from a structured plaintext pair.
2. Encrypt both.
3. Swap the first differing column of the ciphertexts.
4. Decrypt both.
5. Swap the first differing column again.
6. Repeat.

This is the “yoyo” step. It generates several pairs that satisfy the special relation used by the paper.

#### 3.1 First 4 bytes of `K0'`

The published code brute-forces three key bytes for each candidate pair family. That is not necessary. The relation for the first 32-bit word is:

`d0(k0) ^ d1(k1) ^ 2*d2(k2) ^ 3*d3(k3) = 0`

for every stored yoyo pair, where each `dr(kr)` is an 8-bit value obtained from two S-box evaluations.

This splits naturally into:

- a term that depends on `(k0, k1)`
- a term that depends only on `k2`
- a term that depends only on `k3`

That means the 24-bit brute force can be replaced with a meet-in-the-middle:

1. For each `k1`, compute the 5-byte vector contributed by `(k0, k1)`.
2. For each `k2`, compute the 5-byte vector contributed by `k2`.
3. Hash all `v01 ^ v2`.
4. For each `k3`, look up the required match.

This reduces the practical search to a table over `256 * 256` combinations instead of a naïve `256^3` loop.

There is also a query optimization. The original method scans all `256` values of the pair parameter `i`. We only scan the even ones and test both `i` and `i ^ 1` in the algebraic condition. That cuts the worst-case query cost for this stage in half while preserving correctness.

#### 3.2 Remaining 12 bytes of `K0'`

Once the first column of `K0'` is known, the remaining columns are recovered with the second relation from the YoyoTricks code.

The important point is that this relation is also separable:

- for each remaining column,
- transform the pair family into a special follow-up family,
- then compare 5-byte vectors for each row independently.

This recovers the full transformed first key `K0'`.

Finally:

`K0 = SR^-1(K0')`

### 4. Peel the outer first round and recover the transformed last key `K5' = SR^-1(K5)`

Once `K0'` is known, we can create a 4-round core with chosen input state `X`.

The transformed cipher begins with:

`X --xor K0'--> SubBytes --> MixColumns --> xor K1`

So if we want to start the next stage from an arbitrary state `X`, we choose the original transformed plaintext as:

`P = K0' xor InvSubBytes(InvMixColumns(X))`

Then the remaining unknown part of the cipher is a 4-round AES-like core:

- initial unknown key `K1`
- three full rounds
- final `SubBytes xor K5'`

That is exactly the standard Square setting. For a delta-set varying one byte of `X`, the classic integral property says:

`XOR over 256 texts of InvSbox(C[pos] xor K5'[pos]) = 0`

for the correct byte of the last round key.

This attack is bytewise:

1. Build a 256-text structure by varying one byte of `X`.
2. Encrypt through the 4-round core.
3. For each output byte position and each key guess `0..255`, test the Square equation.
4. Repeat with a second structure and intersect candidates.

Two structures are enough in practice to get a unique byte value for all 16 positions.

Then:

`K5 = SR(K5')`

At this point we know both outer keys of the original challenge.

### 5. Strip both outer keys and build the 3-round core

Knowing `K0'` and `K5'`, we can define the exact inner 3-round full-round core:

`F3(X) = round3( round2( round1( X xor K1 ) xor K2 ) xor K3 ) xor K4`

More concretely, in the solver:

1. Use `K0'` to choose a plaintext that lands on any chosen `X` after the peeled first round.
2. Encrypt through the transformed oracle.
3. Undo the known final `SubBytes xor K5'`.

That gives a clean chosen-plaintext oracle for a 3-round AES-like cipher with independent round keys `K1, K2, K3, K4`.

### 6. Recover `K4` from the 3-round core using only 2 chosen pairs

This stage uses the low-data attack idea for 3-round AES, but in a form that is especially convenient for implementation.

Choose a pair `(X0, X1)` that differs in only one byte.

Let:

- `Y0 = F3(X0)`
- `Y1 = F3(X1)`
- `L = MixColumns o ShiftRows`

The last round is:

`Y = L( SubBytes(U) ) xor K4`

Apply `L^-1` to the ciphertext difference:

`beta = L^-1(Y0 xor Y1)`

This gives the bytewise output differences of the last-round S-box layer.

Now the key observation:

For this input pattern, the differences entering the last round are not arbitrary. For each output column, there are only `255` possible 4-byte input-difference vectors. This set is **key-independent**. We can precompute it once by random sampling because the set saturates quickly.

For each candidate column-difference vector `alpha_col`:

1. For each row byte, use the AES S-box difference distribution table on `(alpha_byte, beta_byte)`.
2. That gives candidate actual S-box output bytes for the first plaintext.
3. Let `Z0 = SubBytes(U0)` be the state after the last-round S-box layer.
4. Since `L^-1(Y0) = Z0 xor L^-1(K4)`, each guessed column of `Z0` gives a direct candidate for the corresponding column of:

`h4 = L^-1(K4)`

This is the crucial simplification. We do **not** need to combine all 4 columns into a 128-bit state candidate. Each column immediately suggests a transformed last-key column.

We therefore:

1. Build the candidate set for each column of `h4` from one pair.
2. Repeat with a second independently chosen pair.
3. Intersect the candidate sets per column.

After two pairs, each column becomes unique in practice.

Then:

- `h4 = L^-1(K4)`
- `K4 = L(h4)`

### 7. Strip `K4` and recover `K3` from the 2-round core

Once `K4` is known, undo the final round of the 3-round core:

`F2(X) = InvSubBytes( L^-1( F3(X) xor K4 ) )`

Now we have a 2-round full-round core with keys `K1, K2, K3`.

The same pattern works again, but now the chosen pair differs in one entire input column rather than one byte.

For 2-round AES with one active input column:

- after round 1, each output column difference belongs to a key-independent set of size `127`

So we precompute those four 127-element column sets once.

Then for each chosen pair:

1. Compute `beta = L^-1(Y0 xor Y1)` on the 2-round core outputs.
2. For each column and each candidate input-difference vector in the precomputed 127-element set:
   - use the S-box DDT per byte
   - recover candidate actual S-box output bytes for the second round
   - convert them directly into candidates for the transformed key

`h3 = L^-1(K3)`

Again, a second pair is enough to intersect each column down to a unique value.

Then:

- `K3 = L(h3)`

### 8. Strip `K3` and recover `K2` and `K1` from the 1-round core

Undo the last round of the 2-round core:

`F1(X) = InvSubBytes( L^-1( F2(X) xor K3 ) )`

Now we have a 1-round AES-like cipher:

`Y = L( SubBytes(X xor K1) ) xor K2`

This round is solved bytewise.

Choose two plaintext pairs where all 16 byte differences are nonzero, for example:

`X1 = X0 xor 0x01...01`

For each pair:

1. Compute `beta = L^-1(Y0 xor Y1)`, which is the difference after the S-box layer.
2. For each byte position:
   - the input difference to that S-box is known directly from the plaintexts
   - use the DDT to get candidate actual input bytes `u0`
   - convert those to candidates for the transformed last key byte

`h2[i] = S(u0) xor L^-1(Y0)[i]`

Intersecting two pairs gives a unique `h2`, hence:

`K2 = L(h2)`

Then recover `K1` directly from one witness pair:

1. `Z0 = L^-1(Y0) xor h2`
2. `U0 = InvSubBytes(Z0)`
3. `K1 = U0 xor X0`

At this point all inner keys are known.

### 9. Convert everything back to the original round keys and submit

The transformed keys are:

- `K0' = SR(K0)`
- `K5' = SR^-1(K5)`

So the original challenge keys are:

- `K0 = SR^-1(K0')`
- `K1 = K1`
- `K2 = K2`
- `K3 = K3`
- `K4 = K4`
- `K5 = SR(K5')`

Before submission, it is cheap to verify the full key set:

1. choose a random plaintext
2. query the remote encryption oracle
3. encrypt locally with the recovered keys
4. compare

Once the local and remote outputs match, submit all six round keys through menu option `3`.

That yields the flag.

## Final Solve

```python
import itertools
import os
import random
import socket
import sys
import types

sys.modules["flag"] = types.SimpleNamespace(flag="dummy")
from for_user.aes5 import (
    INV_SBOX,
    SBOX,
    add_round_key,
    aes5_decrypt_block,
    aes5_encrypt_block,
    bytes_to_state,
    inv_mix_columns,
    inv_shift_rows,
    inv_sub_bytes,
    mix_columns,
    shift_rows,
    state_to_bytes,
    sub_bytes,
)


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def sr_bytes(block):
    state = bytes_to_state(block)
    shift_rows(state)
    return state_to_bytes(state)


def isr_bytes(block):
    state = bytes_to_state(block)
    inv_shift_rows(state)
    return state_to_bytes(state)


def sb_bytes(block):
    state = bytes_to_state(block)
    sub_bytes(state)
    return state_to_bytes(state)


def isb_bytes(block):
    state = bytes_to_state(block)
    inv_sub_bytes(state)
    return state_to_bytes(state)


def mc_bytes(block):
    state = bytes_to_state(block)
    mix_columns(state)
    return state_to_bytes(state)


def imc_bytes(block):
    state = bytes_to_state(block)
    inv_mix_columns(state)
    return state_to_bytes(state)


def l_bytes(block):
    state = bytes_to_state(block)
    shift_rows(state)
    mix_columns(state)
    return state_to_bytes(state)


def linv_bytes(block):
    state = bytes_to_state(block)
    inv_mix_columns(state)
    inv_shift_rows(state)
    return state_to_bytes(state)


def inv_mc_col(col):
    state = [[0] * 4 for _ in range(4)]
    for row in range(4):
        state[row][0] = col[row]
    inv_mix_columns(state)
    return bytes(state[row][0] for row in range(4))


def mc_col(col):
    state = [[0] * 4 for _ in range(4)]
    for row in range(4):
        state[row][0] = col[row]
    mix_columns(state)
    return bytes(state[row][0] for row in range(4))


def round_full(state_bytes, round_key):
    state = bytes_to_state(state_bytes)
    sub_bytes(state)
    shift_rows(state)
    mix_columns(state)
    add_round_key(state, round_key)
    return state_to_bytes(state)


def recover_state_before_last_round(ciphertext, round_key):
    return isb_bytes(linv_bytes(xor_bytes(ciphertext, round_key)))


def recvuntil(sock, marker):
    data = b""
    while not data.endswith(marker):
        chunk = sock.recv(1)
        if not chunk:
            raise EOFError("socket closed")
        data += chunk
    return data


def recvline(sock):
    return recvuntil(sock, b"\n")


class LocalOracle:
    def __init__(self, round_keys):
        self.round_keys = round_keys
        self.queries = 0

    def enc(self, block):
        self.queries += 1
        return aes5_encrypt_block(block, self.round_keys)

    def dec(self, block):
        self.queries += 1
        return aes5_decrypt_block(block, self.round_keys)


class RemoteOracle:
    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port))
        self.queries = 0
        recvuntil(self.sock, b"> ")

    def _menu_query(self, option, prompt, payload):
        self.sock.sendall(option + b"\n")
        recvuntil(self.sock, prompt)
        self.sock.sendall(payload.hex().encode() + b"\n")
        out = recvline(self.sock).strip()
        recvuntil(self.sock, b"> ")
        self.queries += 1
        return bytes.fromhex(out.decode())

    def enc(self, block):
        return self._menu_query(b"1", b"pt> ", block)

    def dec(self, block):
        return self._menu_query(b"2", b"ct> ", block)

    def submit(self, round_keys):
        self.sock.sendall(b"3\n")
        recvline(self.sock)
        for idx, key in enumerate(round_keys):
            recvuntil(self.sock, f"k{idx}> ".encode())
            self.sock.sendall(key.hex().encode() + b"\n")
        out = recvline(self.sock).decode().strip()
        return out


class Attack:
    def __init__(self, oracle):
        self.oracle = oracle
        self.ddt_inputs = {(a, b): [] for a in range(256) for b in range(256)}
        self.ddt_outputs = {(a, b): [] for a in range(256) for b in range(256)}
        for x in range(256):
            sx = SBOX[x]
            for alpha in range(256):
                y = x ^ alpha
                beta = sx ^ SBOX[y]
                self.ddt_inputs[(alpha, beta)].append(x)
                self.ddt_outputs[(alpha, beta)].append(sx)
        self.d3_sets = self.precompute_d3_sets()
        self.d2_sets = self.precompute_d2_sets()
        self.k0_super = None
        self.k5_super = None
        self.k4 = None
        self.k3 = None
        self.k2 = None
        self.k1 = None

    def super_enc(self, block):
        return isr_bytes(self.oracle.enc(isr_bytes(block)))

    def super_dec(self, block):
        return sr_bytes(self.oracle.dec(sr_bytes(block)))

    def f4_enc(self, block):
        pt = xor_bytes(self.k0_super, isb_bytes(imc_bytes(block)))
        return self.super_enc(pt)

    def f3_enc(self, block):
        return isb_bytes(xor_bytes(self.f4_enc(block), self.k5_super))

    def f2_enc(self, block):
        return recover_state_before_last_round(self.f3_enc(block), self.k4)

    def f1_enc(self, block):
        return recover_state_before_last_round(self.f2_enc(block), self.k3)

    def precompute_d3_sets(self):
        sets = [set() for _ in range(4)]
        target = 255
        while min(len(s) for s in sets) < target:
            keys = [os.urandom(16) for _ in range(3)]
            p0 = bytearray(os.urandom(16))
            p1 = bytearray(p0)
            p1[0] ^= 1
            s0 = xor_bytes(bytes(p0), keys[0])
            s1 = xor_bytes(bytes(p1), keys[0])
            s0 = round_full(s0, keys[1])
            s1 = round_full(s1, keys[1])
            s0 = round_full(s0, keys[2])
            s1 = round_full(s1, keys[2])
            diff = xor_bytes(s0, s1)
            for col in range(4):
                sets[col].add(diff[4 * col : 4 * col + 4])
        return [list(colset) for colset in sets]

    def precompute_d2_sets(self):
        sets = [set() for _ in range(4)]
        target = 127
        diff = bytes([1, 1, 1, 1]) + bytes(12)
        while min(len(s) for s in sets) < target:
            keys = [os.urandom(16) for _ in range(2)]
            p0 = bytearray(os.urandom(16))
            p1 = bytearray(x ^ y for x, y in zip(p0, diff))
            s0 = xor_bytes(bytes(p0), keys[0])
            s1 = xor_bytes(bytes(p1), keys[0])
            s0 = round_full(s0, keys[1])
            s1 = round_full(s1, keys[1])
            out_diff = xor_bytes(s0, s1)
            for col in range(4):
                sets[col].add(out_diff[4 * col : 4 * col + 4])
        return [list(colset) for colset in sets]

    def swap_first_diff_column(self, x, y):
        x = bytearray(x)
        y = bytearray(y)
        col = None
        for idx in range(4):
            start = 4 * idx
            if x[start : start + 4] != y[start : start + 4]:
                col = idx
                break
        if col is None:
            return bytes(x), bytes(y)
        start = 4 * col
        tmp = x[start : start + 4]
        x[start : start + 4] = y[start : start + 4]
        y[start : start + 4] = tmp
        return bytes(x), bytes(y)

    def make_k0_pairs(self, i, extra_pairs=0):
        p0 = bytearray(16)
        p1 = bytearray(16)
        p0[1] = i
        p1[0] = 1
        p1[1] = 1 ^ i
        pairs = []
        needed = 5 + extra_pairs
        while len(pairs) < needed:
            pairs.append((bytes(p0), bytes(p1)))
            if len(pairs) == needed:
                break
            c0 = self.super_enc(bytes(p0))
            c1 = self.super_enc(bytes(p1))
            c0, c1 = self.swap_first_diff_column(c0, c1)
            p0 = bytearray(self.super_dec(c0))
            p1 = bytearray(self.super_dec(c1))
            p0, p1 = map(bytearray, self.swap_first_diff_column(bytes(p0), bytes(p1)))
        return pairs

    def k0_first_column_candidates(self, pairs, i):
        out = []
        for delta in (i, i ^ 1):
            v01 = []
            v2 = []
            v3 = []
            for k1 in range(256):
                k0 = k1 ^ delta
                vec = bytes(
                    (
                        SBOX[p0[0] ^ k0]
                        ^ SBOX[p1[0] ^ k0]
                        ^ SBOX[p0[1] ^ k1]
                        ^ SBOX[p1[1] ^ k1]
                    )
                    for p0, p1 in pairs
                )
                v01.append(vec)
            for k2 in range(256):
                vec = bytes(
                    self.gf_mul(SBOX[p0[2] ^ k2] ^ SBOX[p1[2] ^ k2], 2)
                    for p0, p1 in pairs
                )
                v2.append(vec)
            for k3 in range(256):
                vec = bytes(
                    self.gf_mul(SBOX[p0[3] ^ k3] ^ SBOX[p1[3] ^ k3], 3)
                    for p0, p1 in pairs
                )
                v3.append(vec)
            table = {}
            for k1 in range(256):
                for k2 in range(256):
                    key = xor_bytes(v01[k1], v2[k2])
                    table.setdefault(key, []).append((k1, k2))
            for k3 in range(256):
                for k1, k2 in table.get(v3[k3], []):
                    out.append(bytes((k1 ^ delta, k1, k2, k3)))
        return out

    def verify_k0_column(self, column, pairs):
        for p0, p1 in pairs:
            diff = [SBOX[p0[row] ^ column[row]] ^ SBOX[p1[row] ^ column[row]] for row in range(4)]
            if diff[0] ^ diff[1] ^ self.gf_mul(diff[2], 2) ^ self.gf_mul(diff[3], 3):
                return False
        return True

    def recover_k0_super(self):
        first_col = None
        for i in range(0, 256, 2):
            pairs = self.make_k0_pairs(i)
            cands = self.k0_first_column_candidates(pairs, i)
            if not cands:
                continue
            verify_pairs = self.make_k0_pairs(i, extra_pairs=2)[5:]
            for cand in cands:
                if self.verify_k0_column(cand, verify_pairs):
                    first_col = cand
                    break
            if first_col is not None:
                break
        if first_col is None:
            raise RuntimeError("failed to recover first K0 column")
        candidate = bytearray(16)
        candidate[:4] = first_col
        beta = [0x0B, 0x0E, 0x09, 0x0D]
        inv_beta = [self.gf_inv(x) for x in beta]
        p0 = bytearray(16)
        p1 = bytearray(16)
        p0[0] = 1
        p0 = bytearray(isr_bytes(bytes(p0)))
        p1 = bytearray(isr_bytes(bytes(p1)))
        p0 = bytearray(imc_bytes(bytes(p0)))
        p1 = bytearray(imc_bytes(bytes(p1)))
        p0 = bytearray(isb_bytes(bytes(p0)))
        p1 = bytearray(isb_bytes(bytes(p1)))
        p0 = bytearray(xor_bytes(bytes(p0), bytes(candidate)))
        p1 = bytearray(xor_bytes(bytes(p1), bytes(candidate)))
        pairs = []
        while len(pairs) < 5:
            pairs.append((bytes(p0), bytes(p1)))
            if len(pairs) == 5:
                break
            c0 = self.super_enc(bytes(p0))
            c1 = self.super_enc(bytes(p1))
            c0, c1 = self.swap_first_diff_column(c0, c1)
            p0 = bytearray(self.super_dec(c0))
            p1 = bytearray(self.super_dec(c1))
            p0, p1 = map(bytearray, self.swap_first_diff_column(bytes(p0), bytes(p1)))
        for col in range(1, 4):
            row_vecs = []
            for row in range(4):
                scale = inv_beta[(1 - col + row) % 4]
                vecs = []
                for guess in range(256):
                    vecs.append(
                        bytes(
                            self.gf_mul(SBOX[p0[row + 4 * col] ^ guess] ^ SBOX[p1[row + 4 * col] ^ guess], scale)
                            for p0, p1 in pairs
                        )
                    )
                row_vecs.append(vecs)
            maps = [{vec: guess for guess, vec in enumerate(row_vecs[row])} for row in range(1, 4)]
            solutions = []
            for guess0, vec in enumerate(row_vecs[0]):
                if vec in maps[0] and vec in maps[1] and vec in maps[2]:
                    solutions.append((guess0, maps[0][vec], maps[1][vec], maps[2][vec]))
            if len(solutions) != 1:
                raise RuntimeError(f"ambiguous K0 column {col}: {len(solutions)} candidates")
            solution = solutions[0]
            for row in range(4):
                candidate[row + 4 * col] = solution[row]
        self.k0_super = bytes(candidate)
        return self.k0_super

    def recover_k5_super(self):
        intersections = [None] * 16
        for _ in range(2):
            base = bytearray(os.urandom(16))
            ciphertexts = []
            for value in range(256):
                block = bytearray(base)
                block[0] = value
                ciphertexts.append(self.f4_enc(bytes(block)))
            for pos in range(16):
                candidates = set()
                for guess in range(256):
                    acc = 0
                    for ct in ciphertexts:
                        acc ^= INV_SBOX[ct[pos] ^ guess]
                    if acc == 0:
                        candidates.add(guess)
                intersections[pos] = candidates if intersections[pos] is None else intersections[pos] & candidates
        if any(len(s) != 1 for s in intersections):
            raise RuntimeError("failed to recover K5")
        self.k5_super = bytes(next(iter(s)) for s in intersections)
        return self.k5_super

    def column_candidates(self, y0, y1, diff_sets):
        beta = linv_bytes(xor_bytes(y0, y1))
        const = linv_bytes(y0)
        out = []
        for col in range(4):
            candidates = set()
            beta_col = beta[4 * col : 4 * col + 4]
            const_col = const[4 * col : 4 * col + 4]
            for alpha_col in diff_sets[col]:
                byte_lists = []
                ok = True
                for row in range(4):
                    vals = self.ddt_outputs[(alpha_col[row], beta_col[row])]
                    if not vals:
                        ok = False
                        break
                    byte_lists.append(vals)
                if not ok:
                    continue
                for z_col in itertools.product(*byte_lists):
                    candidates.add(bytes(z_col[row] ^ const_col[row] for row in range(4)))
            out.append(candidates)
        return out

    def recover_k4(self):
        intersections = [None] * 4
        for _ in range(2):
            p0 = bytearray(os.urandom(16))
            p1 = bytearray(p0)
            p1[0] ^= 1
            cols = self.column_candidates(self.f3_enc(bytes(p0)), self.f3_enc(bytes(p1)), self.d3_sets)
            for col in range(4):
                intersections[col] = cols[col] if intersections[col] is None else intersections[col] & cols[col]
        if any(len(s) != 1 for s in intersections):
            raise RuntimeError("failed to recover K4")
        h4 = b"".join(next(iter(s)) for s in intersections)
        self.k4 = l_bytes(h4)
        return self.k4

    def recover_k3(self):
        intersections = [None] * 4
        diff = bytes([1, 1, 1, 1]) + bytes(12)
        for _ in range(2):
            p0 = bytearray(os.urandom(16))
            p1 = bytearray(x ^ y for x, y in zip(p0, diff))
            cols = self.column_candidates(self.f2_enc(bytes(p0)), self.f2_enc(bytes(p1)), self.d2_sets)
            for col in range(4):
                intersections[col] = cols[col] if intersections[col] is None else intersections[col] & cols[col]
        if any(len(s) != 1 for s in intersections):
            raise RuntimeError("failed to recover K3")
        h3 = b"".join(next(iter(s)) for s in intersections)
        self.k3 = l_bytes(h3)
        return self.k3

    def recover_k1_k2(self):
        h2_sets = [None] * 16
        witness = None
        for _ in range(2):
            p0 = os.urandom(16)
            p1 = bytes(b ^ 1 for b in p0)
            y0 = self.f1_enc(p0)
            y1 = self.f1_enc(p1)
            beta = linv_bytes(xor_bytes(y0, y1))
            const = linv_bytes(y0)
            witness = (p0, y0)
            for idx in range(16):
                alpha = p0[idx] ^ p1[idx]
                candidates = set()
                for u0 in self.ddt_inputs[(alpha, beta[idx])]:
                    candidates.add(SBOX[u0] ^ const[idx])
                h2_sets[idx] = candidates if h2_sets[idx] is None else h2_sets[idx] & candidates
        if any(len(s) != 1 for s in h2_sets):
            raise RuntimeError("failed to recover K2 transform")
        h2 = bytes(next(iter(s)) for s in h2_sets)
        self.k2 = l_bytes(h2)
        p0, y0 = witness
        z0 = xor_bytes(linv_bytes(y0), h2)
        self.k1 = bytes(INV_SBOX[z0[idx]] ^ p0[idx] for idx in range(16))
        return self.k1, self.k2

    def verify_full_key(self, round_keys):
        for _ in range(2):
            pt = os.urandom(16)
            remote = self.oracle.enc(pt)
            local = aes5_encrypt_block(pt, round_keys)
            if remote != local:
                return False
        return True

    def solve(self):
        print("recovering K0", flush=True)
        self.recover_k0_super()
        print(f"K0 done queries={self.oracle.queries}", flush=True)
        print("recovering K5", flush=True)
        self.recover_k5_super()
        print(f"K5 done queries={self.oracle.queries}", flush=True)
        print("recovering K4", flush=True)
        self.recover_k4()
        print(f"K4 done queries={self.oracle.queries}", flush=True)
        print("recovering K3", flush=True)
        self.recover_k3()
        print(f"K3 done queries={self.oracle.queries}", flush=True)
        print("recovering K1/K2", flush=True)
        self.recover_k1_k2()
        print(f"K1/K2 done queries={self.oracle.queries}", flush=True)
        k0 = isr_bytes(self.k0_super)
        k5 = sr_bytes(self.k5_super)
        round_keys = [k0, self.k1, self.k2, self.k3, self.k4, k5]
        return round_keys

    @staticmethod
    def gf_mul(x, y):
        z = 0
        while y:
            if y & 1:
                z ^= x
            x = (((x << 1) ^ 0x1B) & 0xFF) if (x & 0x80) else ((x << 1) & 0xFF)
            y >>= 1
        return z

    def gf_inv(self, value):
        if value == 0:
            return 0
        for guess in range(1, 256):
            if self.gf_mul(value, guess) == 1:
                return guess
        raise ValueError("no inverse")


def local_test(iterations=1):
    for idx in range(iterations):
        round_keys = [os.urandom(16) for _ in range(6)]
        oracle = LocalOracle(round_keys)
        attack = Attack(oracle)
        recovered = attack.solve()
        ok = recovered == round_keys
        print(f"local_test {idx} ok={ok} queries={oracle.queries}")
        if not ok:
            print("expected", [k.hex() for k in round_keys])
            print("got     ", [k.hex() for k in recovered])
            return False
    return True


def remote_solve(host, port):
    oracle = RemoteOracle(host, port)
    attack = Attack(oracle)
    round_keys = attack.solve()
    print("queries_used", oracle.queries)
    if not attack.verify_full_key(round_keys):
        raise RuntimeError("verification failed")
    print("round_keys", [k.hex() for k in round_keys])
    result = oracle.submit(round_keys)
    print(result)


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "local":
        count = int(sys.argv[2]) if len(sys.argv) > 2 else 1
        ok = local_test(count)
        sys.exit(0 if ok else 1)
    host = sys.argv[1] if len(sys.argv) > 1 else "54.181.1.253"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 13337
    remote_solve(host, port)
```

Run it from the challenge directory:

```bash
python3 ./solve.py 54.181.1.253 13337
```
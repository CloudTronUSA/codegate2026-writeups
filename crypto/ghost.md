# crypto/ghost

## Overview

The service prints a random 64-bit IV, allows up to 128 calls to a `query` oracle, and then asks for two different 256-bit message blocks. If those two blocks collide under the service’s compression function, the flag is printed.

The attachment is where the structure of the challenge is revealed. In `challenge/src/server.py`, the `submit` path parses two 64-hex-character inputs, converts them into eight 32-bit words each, and computes:

```python
h1 = dm_compress(iv, w1, SBOXES)
h2 = dm_compress(iv, w2, SBOXES)
```

The flag is returned only if `w1 != w2` and `h1 == h2`.

Then `challenge/src/utils.py` shows the compression function and the block cipher behind it:

```python
def dm_compress(iv, key_words, sboxes):
    return encrypt_block(iv, key_words, sboxes) ^ iv
```

and:

```python
def round_core(right, subkey, sboxes):
    return rotl32(sbox_layer((right + subkey) & MASK32, sboxes), 11)
```

The block cipher is a 32-round Feistel network. The 256-bit message block is used as the block-cipher key, split into eight 32-bit words. The key schedule is:

```text
k1, k2, k3, k4, k5, k6, k7, k8,
k1, k2, k3, k4, k5, k6, k7, k8,
k1, k2, k3, k4, k5, k6, k7, k8,
k8, k7, k6, k5, k4, k3, k2, k1
```

That immediately turns the problem into a block-cipher collision problem. Because:

```text
dm_compress(iv, m) = E_m(iv) ^ iv
```

for a fixed `iv`, a compression collision is equivalent to:

```text
E_m1(iv) = E_m2(iv)
```

So the real job is to build two different 256-bit keys that encrypt the session IV to the same ciphertext.

The one thing missing from the attachment is `secret.py`, which contains the S-boxes and the flag. The service hides the S-boxes, but it also exposes exactly the oracle we need:

```python
y = round_core(right, subkey, SBOXES)
```

That oracle is enough to recover the S-boxes and then construct the collision.

## Exploit Chain

### 1. Use the oracle to recover every hidden S-box entry

From `utils.py`, the round core is:

```text
round_core(right, subkey) = rotl32(sbox_layer((right + subkey) mod 2^32), 11)
```

The `sbox_layer()` function applies eight 4-bit S-boxes independently, one nibble at a time:

```python
def sbox_layer(x, sboxes):
    y = 0
    for i in range(8):
        nib = (x >> (4 * i)) & 0xF
        y |= (sboxes[i][nib] & 0xF) << (4 * i)
    return y & MASK32
```

So if we can choose an input word whose eight nibbles are all the same, one oracle call tells us what all eight S-box rows output for that nibble.

That is exactly what the oracle lets us do. Send:

```text
right  = 0
subkey = 0xiiiiiiii
```

for each nibble value `i` from `0` through `f`.

Then:

```text
right + subkey = 0xiiiiiiii
```

and every one of the eight S-box rows is evaluated on input nibble `i`. The server returns:

```text
core = rotl32(sbox_layer(0xiiiiiiii), 11)
```

If we rotate that value right by 11 bits, we get back the raw `sbox_layer()` output. Splitting it into 8 nibbles gives:

```text
sboxes[0][i], sboxes[1][i], ..., sboxes[7][i]
```

Doing this for all 16 possible nibble values recovers all `8 x 16` hidden S-box entries in only 16 oracle calls. The server allows 128, so this is comfortably within the limit.

### 2. Turn the first three rounds into a local collision

Now that the S-boxes are known, the next goal is to make two related keys collapse back to the same state after three rounds.

The reason to target three rounds first is the key schedule. The first 24 rounds are three copies of `k1..k8`, and the last 8 rounds are `k8..k1`. If we can make the first three rounds collide, and later force the first 8 rounds to return to the IV, then the structure repeats and the same local collision can be used again near the end of the cipher.

The bit we want to activate is the most significant bit of the 32-bit subkey:

```text
delta1 = delta3 = 0x80000000
```

That difference enters the highest nibble S-box, which is `sboxes[7]`. So after recovering the S-boxes, we build the differential table of that row for input difference `8`.

We only keep output differences of the form:

```text
((1 << b) - 1) << i
```

which means a contiguous run of 1-bits inside that nibble. That is the shape needed for the 3-round GOST-style local collision. If the output nibble difference is such a mask, then the second-round key difference can cancel it after the 11-bit rotation. This gives:

```text
delta1 = 0x80000000
delta2 = 1 << (7 + i)
delta3 = 0x80000000
```

The solver does not hardcode one specific differential. It computes the recovered `sboxes[7]` row for the current session, scans all contiguous output masks, and picks the best one automatically.

At this point we have a concrete related-key pattern for the first three 32-bit words:

```text
k1' = k1 ^ delta1
k2' = k2 ^ delta2
k3' = k3 ^ delta3
```

The next step is to find an actual triple `(k1, k2, k3)` where the local collision really happens for the live session IV.

### 3. Search for a real 3-round state collision

We now encrypt the session IV locally for exactly 3 rounds under two related 3-word prefixes:

```text
K  = (k1,  k2,  k3)
K' = (k1', k2', k3')
```

using the recovered S-boxes.

For random `k1, k2, k3`, the differential only holds with some probability. There is no need to reason about that symbolically once we can execute the cipher. We simply test it directly:

1. run 3 rounds under `K`,
2. run 3 rounds under `K'`,
3. keep the candidate only if the round-3 states are exactly equal.

This gives us a genuine 3-round local collision for the live session.

### 4. Force the first 8 rounds to return to the IV

Once both encryptions have the same state after round 3, they will stay synchronized as long as we use the same later subkeys in both messages. That means we can now choose the remaining words identically and only worry about steering a single shared state.

The target is:

```text
state after round 8 = IV
```

If we can make that happen, then because rounds 9 through 16 and rounds 17 through 24 reuse the same `k1..k8` schedule, the state after round 24 will also be the IV. That is exactly the point where the reversed final key schedule becomes useful.

The script handles this in a constructive way.

First choose random `k4` and `k5`, then compute the shared state after round 5:

```text
(L5, R5)
```

Now we solve for `k6`, `k7`, and `k8`.

The key observation is that once the S-boxes are known, `round_core()` can be inverted nibble-by-nibble.

Suppose we want:

```text
round_core(right, subkey) = target
```

Then:

1. rotate `target` right by 11,
2. split it into 8 nibbles,
3. for each nibble, choose any input nibble that maps to it through the recovered S-box row,
4. rebuild the 32-bit pre-S-box word `x`,
5. recover the subkey as:
   ```text
   subkey = x - right mod 2^32
   ```

This lets us solve round outputs directly.

Round 7 and round 8 are solved from the end backward:

- choose `k7` so that round 7 makes the left half entering round 8 become `iv_left`
- choose `k8` so that round 8 makes the final right half become `iv_right`

That leaves round 6, whose job is to make both of those targets simultaneously reachable. The solver precomputes three helper structures from the recovered S-boxes:

- `inv`
  - for each S-box row and each nibble output, all input nibbles that produce it
- `images`
  - for each S-box row, which output nibbles are reachable at all
- `compat`
  - for each S-box row and each nibble difference, one pair of reachable outputs that satisfies the round-6 compatibility constraint

With those helper tables, the solver can cheaply decide whether a candidate state after round 5 can be completed to a round-8 fixed point, and if it can, it constructs `k6`, `k7`, and `k8` explicitly.

At the end of this step we have two full 8-word keys:

```text
m1 = [k1,  k2,  k3,  k4, k5, k6, k7, k8]
m2 = [k1', k2', k3', k4, k5, k6, k7, k8]
```

and both satisfy:

```text
state after round 8 = IV
```

### 5. Reuse the same local collision at the end of the cipher

The full schedule is:

```text
k1..k8, k1..k8, k1..k8, k8..k1
```

Because the first 8 rounds return to the IV, the next two identical 8-round blocks do the same thing again. So after round 24 the internal state is back at the IV.

Rounds 25 through 29 use:

```text
k8, k7, k6, k5, k4
```

and those are identical in both messages. So the two encryptions are still synchronized when round 30 begins.

Then rounds 30 through 32 use:

```text
k3, k2, k1
```

and the related key uses:

```text
k3', k2', k1'
```

That recreates the same 3-round local-collision pattern we used at the start, but now at the end of the full 32-round cipher. The script does not need to prove this symbolically once the full cipher is executable. It simply tests:

```text
encrypt(iv, m1) == encrypt(iv, m2)
```

If the equality fails, it keeps searching. Once it holds, the challenge is solved, because the Davies-Meyer feed-forward XOR with the same IV preserves the collision:

```text
E_m1(iv) ^ iv = E_m2(iv) ^ iv
```

## Final Solve

```python
#!/usr/bin/env python3

import random
import re
import socket
import subprocess
import sys

HOST = "43.200.71.14"
PORT = 13479
MASK32 = 0xFFFFFFFF


def rotl32(x, r):
    x &= MASK32
    return ((x << r) & MASK32) | (x >> (32 - r))


def rotr32(x, r):
    x &= MASK32
    return ((x >> r) | ((x << (32 - r)) & MASK32)) & MASK32


def split_block(block):
    return (block >> 32) & MASK32, block & MASK32


def join_block(left, right):
    return ((left & MASK32) << 32) | (right & MASK32)


def recv_until(sock, marker):
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError(data.decode("latin1", "replace"))
        data += chunk
    return data


def solve_pow(challenge):
    cmd = (
        "python3 <(curl -sSL https://goo.gle/kctf-pow) solve "
        f"{challenge}"
    )
    out = subprocess.check_output(
        cmd, shell=True, executable="/bin/bash", text=True
    )
    return out.split("Solution:")[-1].strip().splitlines()[-1].strip()


def connect():
    sock = socket.create_connection((HOST, PORT), timeout=10)
    sock.settimeout(10)
    prompt = recv_until(sock, b"Solution? ").decode("latin1")
    chal = re.search(r"solve (s\.[A-Za-z0-9+/=.]+)", prompt).group(1)
    sock.sendall(solve_pow(chal).encode() + b"\n")
    menu = recv_until(sock, b"> ").decode("latin1")
    iv = int(re.search(r"IV = ([0-9a-f]{16})", menu).group(1), 16)
    return sock, iv


def query_core(sock, right, subkey):
    sock.sendall(b"1\n")
    recv_until(sock, b"right > ")
    sock.sendall(f"{right:x}\n".encode())
    recv_until(sock, b"subkey > ")
    sock.sendall(f"{subkey:x}\n".encode())
    out = recv_until(sock, b"> ").decode("latin1")
    return int(re.search(r"core = ([0-9a-f]{8})", out).group(1), 16)


def recover_sboxes_in_session(sock):
    outs = []
    for i in range(16):
        x = int(f"{i:x}" * 8, 16)
        outs.append(query_core(sock, 0, x))
    sboxes = [[0] * 16 for _ in range(8)]
    for i, y in enumerate(outs):
        z = rotr32(y, 11)
        for j in range(8):
            sboxes[j][i] = (z >> (4 * j)) & 0xF
    return sboxes


def build_helpers(sboxes):
    inv = []
    images = []
    compat = []
    for row in sboxes:
        row_inv = {y: [] for y in range(16)}
        for x, y in enumerate(row):
            row_inv[y].append(x)
        inv.append(row_inv)
        img = sorted({y for y in row})
        images.append(set(img))
        row_compat = {}
        for d in range(16):
            pair = None
            for a in img:
                b = a ^ d
                if b in images[-1]:
                    pair = (a, b)
                    break
            row_compat[d] = pair
        compat.append(row_compat)
    return inv, images, compat


def sbox_layer(x, sboxes):
    y = 0
    for i in range(8):
        nib = (x >> (4 * i)) & 0xF
        y |= (sboxes[i][nib] & 0xF) << (4 * i)
    return y & MASK32


def round_core(right, subkey, sboxes):
    return rotl32(sbox_layer((right + subkey) & MASK32, sboxes), 11)


def apply_round(state, subkey, sboxes):
    left, right = state
    return right, (left ^ round_core(right, subkey, sboxes)) & MASK32


def encrypt(block, key_words, sboxes):
    state = split_block(block)
    sched = key_words * 3 + list(reversed(key_words))
    for k in sched:
        state = apply_round(state, k, sboxes)
    return join_block(*state)


def run_rounds(state, keys, sboxes):
    for k in keys:
        state = apply_round(state, k, sboxes)
    return state


def reachable_output(target, images):
    z = rotr32(target, 11)
    for i in range(8):
        if ((z >> (4 * i)) & 0xF) not in images[i]:
            return False
    return True


def random_input_for_output(target, right, inv):
    z = rotr32(target, 11)
    x = 0
    for i in range(8):
        nib = (z >> (4 * i)) & 0xF
        choices = inv[i][nib]
        if not choices:
            return None
        x |= random.choice(choices) << (4 * i)
    return (x - right) & MASK32


def choose_k6_target(constant, compat):
    d = rotr32(constant, 11)
    z = 0
    for i in range(8):
        pair = compat[i][(d >> (4 * i)) & 0xF]
        if pair is None:
            return None
        a, _ = pair
        z |= a << (4 * i)
    return rotl32(z, 11)


def choose_best_differential(sboxes):
    row = sboxes[7]
    best = None
    for i in range(4):
        for b in range(1, 5 - i):
            dy = ((1 << b) - 1) << i
            count = 0
            for x in range(16):
                if row[x] ^ row[x ^ 8] == dy:
                    count += 1
            if count == 0:
                continue
            score = count * count / (1 << b)
            cand = (score, i, b, dy, count)
            if best is None or cand > best:
                best = cand
    if best is None:
        raise RuntimeError("no usable differential in S7")
    _, i, b, dy, count = best
    return {
        "delta1": 0x80000000,
        "delta2": 1 << (7 + i),
        "delta3": 0x80000000,
        "dy": dy,
        "count": count,
        "bits": (i, b),
    }


def find_collision(iv, sboxes):
    inv, images, compat = build_helpers(sboxes)
    diff = choose_best_differential(sboxes)
    iv_l, iv_r = split_block(iv)

    attempts = 0
    fixed_points = 0
    while True:
        k1 = random.getrandbits(32)
        k2 = random.getrandbits(32)
        k3 = random.getrandbits(32)
        kp1 = k1 ^ diff["delta1"]
        kp2 = k2 ^ diff["delta2"]
        kp3 = k3 ^ diff["delta3"]

        s3 = run_rounds(split_block(iv), [k1, k2, k3], sboxes)
        s3p = run_rounds(split_block(iv), [kp1, kp2, kp3], sboxes)
        attempts += 1
        if s3 != s3p:
            continue

        for _ in range(20000):
            k4 = random.getrandbits(32)
            k5 = random.getrandbits(32)
            l5, r5 = run_rounds(s3, [k4, k5], sboxes)

            target7 = r5 ^ iv_l
            if not reachable_output(target7, images):
                continue

            constant = l5 ^ iv_r
            target6 = choose_k6_target(constant, compat)
            if target6 is None:
                continue

            k6 = random_input_for_output(target6, r5, inv)
            if k6 is None:
                continue
            l6, r6 = apply_round((l5, r5), k6, sboxes)

            k7 = random_input_for_output(target7, r6, inv)
            if k7 is None:
                continue

            target8 = constant ^ target6
            k8 = random_input_for_output(target8, iv_l, inv)
            if k8 is None:
                continue

            fixed_points += 1
            msg1 = [k1, k2, k3, k4, k5, k6, k7, k8]
            msg2 = [kp1, kp2, kp3, k4, k5, k6, k7, k8]
            if encrypt(iv, msg1, sboxes) == encrypt(iv, msg2, sboxes):
                return msg1, msg2, {
                    "attempts": attempts,
                    "fixed_points": fixed_points,
                    "diff": diff,
                }


def words_to_hex(words):
    return "".join(f"{w:08x}" for w in words)


def submit_collision(sock, m1, m2):
    sock.sendall(b"2\n")
    recv_until(sock, b"m1 > ")
    sock.sendall((words_to_hex(m1) + "\n").encode())
    recv_until(sock, b"m2 > ")
    sock.sendall((words_to_hex(m2) + "\n").encode())
    return sock.recv(4096).decode("latin1", "replace")


def main():
    random.seed()
    sock, iv = connect()
    try:
        sboxes = recover_sboxes_in_session(sock)
        m1, m2, info = find_collision(iv, sboxes)
        out = submit_collision(sock, m1, m2)
    finally:
        sock.close()

    print(f"IV: {iv:016x}")
    print(f"Differential: {info['diff']}")
    print(f"Search attempts: {info['attempts']}")
    print(f"Fixed-point candidates: {info['fixed_points']}")
    print(f"m1: {words_to_hex(m1)}")
    print(f"m2: {words_to_hex(m2)}")
    print(out)


if __name__ == "__main__":
    main()
```

Run it with:

```bash
python3 ./solve.py
```
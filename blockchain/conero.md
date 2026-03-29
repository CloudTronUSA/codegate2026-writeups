# blockchain/conero

## Overview

`conero` is a blockchain challenge built around a custom `geth` binary. The web service spins up a fresh temporary chain instance, gives us a funded player key, proxies a restricted set of JSON-RPC calls, and checks whether we managed to manipulate the on-chain state into a very specific final condition.

The final solution is a repeated-spend attack against a single deposited note. The bug is that the codebase contains a function that canonicalizes and subgroup-checks Ed25519 key images, but the actual ring-signature verifier does not use it. Because Ed25519 has an 8-element torsion subgroup, that omission lets us derive 8 distinct raw key-image encodings from one valid spend. The chain tracks spent notes by the raw key-image bytes, so each torsion-adjusted version is accepted as a fresh spend even though they all represent the same note.

## Exploit Chain

### 1. Read the instancer first, because it defines the target state

The important code is in `src/instancer/main.go`. The first goal is to answer four questions:

1. What on-chain state unlocks the flag?
2. What funds do we start with?
3. How many transactions can we send?
4. What RPC methods are actually available remotely?

The flag condition is implemented in `handleFlag`:

```go
func handleFlag(w http.ResponseWriter, r *http.Request, uuid string) {
    ...
    poolAddr := common.HexToAddress(cfg.ConeroPoolAddress)
    addr1337 := common.HexToAddress("0x1337")
    poolBalance, err := fetchBalance(instance.Port, poolAddr)
    ...
    balance1337, err := fetchBalance(instance.Port, addr1337)
    ...
    initialPoolWei, ok := new(big.Int).SetString(cfg.DepositAmountWei, 10)
    ...
    initialPool := new(big.Int).Mul(big.NewInt(int64(cfg.PrefundAccountCount)), initialPoolWei)
    if poolBalance.Cmp(big.NewInt(0)) != 0 {
        writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": "pool balance is not zero"})
        return
    }
    if balance1337.Cmp(initialPool) <= 0 {
        writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": "0x1337 balance is not greater than initial deposit pool"})
        return
    }
    ...
}
```

This tells us exactly what the chain must look like at the end:

- the balance of the pool address `0x00000000000000000000000000000000000010c0` must be zero
- the balance of `0x0000000000000000000000000000000000001337` must be strictly greater than the initial bootstrap pool

The defaults loaded by `mustLoadConfig()` give the rest of the numbers:

```go
cfg := config{
    ConeroPoolAddress:   envOrDefault("CONERO_POOL_ADDRESS", "0x00000000000000000000000000000000000010c0"),
    PlayerPrefundWei:    envOrDefault("PLAYER_PREFUND_WEI", "1100000000000000000"),
    PrefundBalanceWei:   envOrDefault("PREFUND_BALANCE_WEI", "7100000000000000000"),
    DepositAmountWei:    envOrDefault("DEPOSIT_AMOUNT_WEI", "7000000000000000000"),
    PrefundAccountCount: mustParseIntEnv("PREFUND_ACCOUNT_COUNT", 1),
    ...
}
```

From those defaults we can compute the starting instance state without touching the chain:

- there is exactly one bootstrap depositor account
- that depositor contributes `7 ETH` into the pool
- the player starts with `1.1 ETH`

The wrapper also enforces a strict transaction budget. Inside `handleProxy`, every JSON-RPC request is parsed and counted before being forwarded:

```go
n := countSendRawTransactionInBody(body)
if n > 0 {
    sendRawTxMu.Lock()
    cur := sendRawTxCountByUUID[uuid]
    if cur+n > maxSendRawTransactionPerInstance {
        ...
        writeRPCError(w, firstID(requestIDs), -32600, fmt.Sprintf("eth_sendRawTransaction limit exceeded (max %d per instance)", maxSendRawTransactionPerInstance))
        return
    }
    sendRawTxCountByUUID[uuid] = cur + n
    sendRawTxMu.Unlock()
}
```

At the top of the file, that maximum is defined as:

```go
maxSendRawTransactionPerInstance = 10
```

So the exploit must fit in 10 raw transactions total.

The last useful wrapper detail is that the service already gives us a ready-to-use player key. `handleCreate` returns the new instance information directly:

```go
writeJSON(w, http.StatusOK, map[string]any{
    "ok":               true,
    "uuid":             nodeInfo.UUID,
    "deployer_address": nodeInfo.DeployerAddress,
    "player_address":   nodeInfo.PlayerAddress,
    "player_key":       nodeInfo.PlayerKey,
    "rpc_url":          rpcURL,
})
```

The wrapper is telling us very clearly what the challenge is: use only the public RPC methods and at most 10 transactions to turn a 7 ETH pool into `0`, while sending more than 7 ETH to `0x1337`.

### 2. Enumerate the `Conero` surface area inside the binary

Before diving into long disassemblies, it helps to map the feature set. A quick strings pass exposes both the custom package name and the domain strings used in hashing:

```bash
strings -a src/geth | rg 'conero/|canonicalKeyImage|verifyRingSignature|nativeInputRing|nativeWithdrawSpec|note-commitment|hash-to-point|ring-withdraw-context|ring-transfer-challenge'
```

That immediately reveals the interesting pieces:

```text
*conero.OutputNoteSpec
*conero.nativeInputRing
github.com/ethereum/go-ethereum/core/conero.canonicalKeyImage
github.com/ethereum/go-ethereum/core/conero.verifyRingSignature
/src/go-ethereum/core/conero/native.go
/src/go-ethereum/core/conero/conero.go
conero/note-commitment
conero/hash-to-point/base-1
conero/hash-to-point/base-2
conero:ring-withdraw-context
conero/hash-to-point/scalar-1
conero/hash-to-point/scalar-2
conero:ring-transfer-challenge
```

With the package name in hand, symbol enumeration becomes easy:

```bash
nm -an src/geth | rg 'conero'
```

The functions that matter for solving are:

```text
github.com/ethereum/go-ethereum/core/conero.ApplyNative
github.com/ethereum/go-ethereum/core/conero.applyNativeDeposit
github.com/ethereum/go-ethereum/core/conero.applyNativePrivateTransfer
github.com/ethereum/go-ethereum/core/conero.applyNativeWithdraw
github.com/ethereum/go-ethereum/core/conero.parsePrivateTransferData
github.com/ethereum/go-ethereum/core/conero.parseWithdrawData
github.com/ethereum/go-ethereum/core/conero.parseRings
github.com/ethereum/go-ethereum/core/conero.validateInputRing
github.com/ethereum/go-ethereum/core/conero.verifyRingSignature
github.com/ethereum/go-ethereum/core/conero.ringChallenge
github.com/ethereum/go-ethereum/core/conero.transferContextHash
github.com/ethereum/go-ethereum/core/conero.withdrawContextHash
github.com/ethereum/go-ethereum/core/conero.noteCommitment
github.com/ethereum/go-ethereum/core/conero.hashToPoint
github.com/ethereum/go-ethereum/core/conero.canonicalKeyImage
```

### 3. Recover the native operation codes

The function `ApplyNative` is the dispatch point for the custom note system. Disassembling it is the fastest way to learn what operations exist:

```bash
objdump -d --demangle --disassemble='github.com/ethereum/go-ethereum/core/conero.ApplyNative' src/geth | sed -n '1,120p'
```

The key comparisons are:

```text
cmp $0x1,%dl
...
cmp $0x3,%dl
...
cmp $0x4,%dl
```

And each branch targets a named function:

- `0x01` -> `applyNativeDeposit`
- `0x03` -> `applyNativePrivateTransfer`
- `0x04` -> `applyNativeWithdraw`

We will use opcode `0x01` to create our own note inside the pool, and opcode `0x04` to spend that note repeatedly into `0x1337`.

### 4. Recover the in-memory ring and withdraw structures

Because the binary still has debug info, GDB can print the Go types directly:

```bash
gdb -batch -ex 'file src/geth' \
  -ex "ptype 'github.com/ethereum/go-ethereum/core/conero.nativeInputRing'" \
  -ex "ptype 'github.com/ethereum/go-ethereum/core/conero.nativeWithdrawSpec'" \
  -ex "ptype 'github.com/ethereum/go-ethereum/core/conero.OutputNoteSpec'"
```

Output:

```text
type = struct github.com/ethereum/go-ethereum/core/conero.nativeInputRing {
    uint64 Amount;
    [][32]uint8 Members;
    [32]uint8 KeyImage;
    [32]uint8 Challenge0;
    [][32]uint8 Responses;
}
type = struct github.com/ethereum/go-ethereum/core/conero.nativeWithdrawSpec {
    github.com/ethereum/go-ethereum/common.Address Recipient;
    uint64 WithdrawAmount;
    github.com/ethereum/go-ethereum/core/conero.OutputNoteSpec *Change;
}
type = struct github.com/ethereum/go-ethereum/core/conero.OutputNoteSpec {
    [32]uint8 TxPublicKey;
    [32]uint8 PublicKey;
    [32]uint8 RecipientViewKey;
    [32]uint8 RecipientSpendKey;
    uint64 Amount;
}
```

This already answers a major question: each spend is a ring signature over note public keys, and the proof consists of:

- an amount
- a ring of member public keys
- a key image
- an initial challenge value
- one response scalar per ring member

That structure matches the class of linkable spontaneous anonymous group signatures used by note systems such as Monero. In other words, the key image is the deduplication handle for note spends. That makes it an obvious place to search for a repeated-spend bug.

### 5. Recover the exact wire format for withdraws

Knowing the structs is useful, but we still need the exact raw byte layout that `applyNativeWithdraw` expects inside transaction calldata. That comes from the parsers.

#### 5.1 Ring encoding from `parseRings`

Disassemble the ring parser:

```bash
objdump -d --demangle --disassemble='github.com/ethereum/go-ethereum/core/conero.parseRings' src/geth | sed -n '1,360p'
```

Two checks appear immediately:

- the first byte is a ring count, and it must be between `1` and `16`
- each ring begins with a ring size, also between `1` and `16`

More importantly, the parser computes the size of each ring record as:

```text
0x49 + 0x40 * ringSize
```

That is a strong structural clue. Expanding the arithmetic gives:

- `0x01` byte ring size
- `0x08` bytes amount
- `0x20 * ringSize` bytes member public keys
- `0x20` bytes key image
- `0x20` bytes challenge0
- `0x20 * ringSize` bytes responses

So the ring portion of a withdraw is:

```text
ringCount: u8
repeat ringCount times:
  ringSize: u8
  amount: u64 little-endian
  members: [32] * ringSize
  keyImage: [32]
  challenge0: [32]
  responses: [32] * ringSize
```

This is exactly the information we need to build a one-member ring around a note we control.

#### 5.2 Withdraw-specific fields from `parseWithdrawData`

After the rings are parsed, `parseWithdrawData` handles the recipient and optional change output:

```bash
objdump -d --demangle --disassemble='github.com/ethereum/go-ethereum/core/conero.parseWithdrawData' src/geth | sed -n '1,320p'
```

The crucial observation is that once `parseRings` returns, the code checks for one of two exact remaining lengths:

- `0x1d = 29` bytes for a withdraw with no change
- `0x65 = 101` bytes for a withdraw with change

Those lengths decode cleanly as:

- `20` bytes recipient address
- `8` bytes withdraw amount
- `1` byte `hasChange`
- if `hasChange == 1`, then an extra `32 + 32 + 8` bytes

That gives the full withdraw suffix:

```text
recipient: 20 bytes
withdrawAmount: u64 little-endian
hasChange: u8
if hasChange == 1:
  changeTxPublicKey: [32]
  changePublicKey: [32]
  changeAmount: u64 little-endian
```

One detail here matters a lot later. The GDB type for `OutputNoteSpec` contains four 32-byte keys plus an amount, but the withdraw parser only consumes:

- `TxPublicKey`
- `PublicKey`
- `Amount`

That means a withdraw-change output is a shorter structure than a full private-transfer output. We need to encode exactly what the parser expects, not the entire Go struct.

With `parseRings` and `parseWithdrawData` combined, the raw calldata format for a withdraw becomes:

```text
0x04
ringCount
rings...
recipient20
withdrawAmountLE8
hasChange
optionalChangeFields
```

That is enough to generate valid withdraw calldata as soon as we know how the ring signature is computed.

### 6. Recover the note commitment and key-image hash-to-point function

To spend a note, we need to recreate the same cryptographic helpers that the chain uses. Two functions matter immediately:

- `noteCommitment`
- `hashToPoint`

#### 6.1 Note commitment

Disassemble `noteCommitment`:

```bash
objdump -d --demangle --disassemble='github.com/ethereum/go-ethereum/core/conero.noteCommitment' src/geth | sed -n '1,120p'
```

The disassembly shows a simple sequence:

1. reset a SHA-256 state
2. write the domain string `conero/note-commitment`
3. write the 32-byte note public key
4. write the 8-byte little-endian amount

So the note commitment is:

```text
SHA256("conero/note-commitment" || publicKey || amountLE8)
```

#### 6.2 Hash-to-point

Disassemble `hashToPoint`:

```bash
objdump -d --demangle --disassemble='github.com/ethereum/go-ethereum/core/conero.hashToPoint' src/geth | sed -n '1,260p'
```

The function uses two separate scalar derivations:

- `conero/hash-to-point/scalar-1`
- `conero/hash-to-point/scalar-2`

and two separately derived bases:

- `conero/hash-to-point/base-1`
- `conero/hash-to-point/base-2`

It then computes:

```text
H_p(P) = B1 * s1 + B2 * s2
```

That is the point used to derive key images from note public keys. Because the key image is built from `H_p(P)` rather than the normal Ed25519 basepoint, reproducing this helper correctly is mandatory. Without it, our signatures would look structurally correct but never verify on-chain.

At this stage, the wire format and the cryptographic primitives are both under our control. The next step is to find the actual bug in spend verification.

### 7. Compare the intended key-image validation with the real verifier

The binary contains an extremely revealing pair of functions:

- `canonicalKeyImage`
- `verifyRingSignature`

Reading them together is what exposes the vulnerability.

#### 7.1 What the code intended to do

Disassemble `canonicalKeyImage`:

```bash
objdump -d --demangle --disassemble='github.com/ethereum/go-ethereum/core/conero.canonicalKeyImage' src/geth | sed -n '1,240p'
```

The behavior is very clear from the calls and the error branches:

- it compares against the Ed25519 identity point and rejects it
- it multiplies the point by the cofactor
- it checks whether the result behaves like a prime-order point
- it returns `ErrIdentityKeyImage` or `ErrKeyImageNotPrimeOrder` when the checks fail

So the author knew that key images needed subgroup validation. That function exists specifically to prevent malformed key images and torsion abuse.

#### 7.2 What the chain actually does when verifying a spend

Now disassemble `verifyRingSignature`:

```bash
objdump -d --demangle --disassemble='github.com/ethereum/go-ethereum/core/conero.verifyRingSignature' src/geth | sed -n '1,280p'
```

At the top of the function, the verifier decodes the supplied key image with:

```text
filippo.io/edwards25519.(*Point).SetBytes
```

and returns only `ErrInvalidKeyImageEncoding` if decoding fails.

What matters is what is missing:

- `verifyRingSignature` does not call `canonicalKeyImage`
- it does not call `verifyPrimeOrderPoint`
- it does not reject torsion points

So the verifier accepts any correctly encoded Ed25519 point as a key image, even if it is not in the prime-order subgroup.

That is the whole bug. The intended safety check exists in the binary, but the function that actually guards note spends never uses it.

### 8. Confirm that duplicate-spend tracking uses the raw key-image bytes

A subgroup bug alone is not enough. We also need to show that different encodings of the same logical spend are treated as different spent-note identifiers. That answer is in `validateInputRing`.

Disassemble the part of the function that runs after signature verification:

```bash
objdump -d --demangle --disassemble='github.com/ethereum/go-ethereum/core/conero.validateInputRing' src/geth | sed -n '220,360p'
```

The disassembly literally materializes the string:

```text
conero:spent:key-image
```

and then hashes that prefix together with the 32-byte key image using `crypto.Keccak256Hash`. After the storage lookup, it returns `ErrDuplicateKeyImage` only if the slot for that exact hash is already populated.

In other words, the chain links spends using the raw serialized key-image bytes. It does not canonicalize the point before deriving the storage slot.

That is the second half of the exploit. Once we can manufacture multiple accepted key-image encodings for the same note, each one lands in a different spent-key-image slot and bypasses the duplicate-spend check.

### 9. Repeated-spend primitive

Now that the verifier behavior is clear, we can describe the exploit mathematically.

Let:

- `x` be the note’s secret scalar
- `P = xG` be the note public key
- `Hp = H_p(P)` be the hash-to-point value recovered earlier
- `KI = xHp` be the canonical key image

For a one-member ring, the signature verifies with:

```text
L = sG + cP
R = sHp + cKI
c = H(context, KI, L, R)
```

Suppose we replace the key image with:

```text
KI' = KI + T
```

where `T` is a torsion point of order `d`. Then the verifier will compute:

```text
R' = sHp + c(KI + T)
   = sHp + cKI + cT
```

If `c mod d = 0`, then `cT = 0`, and the proof still verifies even though the raw key image is different.

That is why the exploit script brute-forces the nonce used to derive `L` until the resulting challenge is divisible by the order of the torsion point we added. Once that divisibility condition holds, the torsion component disappears inside the verifier, but the key-image bytes remain different for duplicate-spend tracking.

Ed25519 has an 8-element torsion subgroup. That gives us 8 usable key-image variants for the same note:

- the canonical key image itself
- seven more key images formed by adding each nontrivial torsion point

So one deposited note can be spent 8 times.

### 10. Choose the transaction sequence that satisfies the flag condition

At this point the exploit is conceptually complete, but the flag check still imposes a practical accounting problem. We need the exact sequence of deposits and withdraws that leaves the pool at zero while sending more than `7 ETH` to `0x1337`.

The player begins with `1.1 ETH`, so the first step is to create a note under our control. Depositing the full `1.1 ETH` would leave no gas, so the natural amount is `1.09 ETH`.

After that deposit:

- pool balance becomes `7 ETH + 1.09 ETH = 8.09 ETH`
- we control exactly one note worth `1.09 ETH`

Because the repeated-spend bug gives us 8 spends of that single note, the pool can be drained in 8 withdraws:

1. Withdraw `1.09 ETH` to `0x1337`
2. Withdraw `1.09 ETH` to `0x1337`
3. Withdraw `1.09 ETH` to `0x1337`
4. Withdraw `1.09 ETH` to `0x1337`
5. Withdraw `1.09 ETH` to `0x1337`
6. Withdraw `1.09 ETH` to `0x1337`
7. Withdraw `1.09 ETH` to `0x1337`

After those seven spends:

- `0x1337` has received `7 * 1.09 = 7.63 ETH`
- pool balance is `8.09 - 7.63 = 0.46 ETH`

The eighth spend is used to finish the drain cleanly. The input note is still formally a `1.09 ETH` note, so the withdraw transaction must remain balanced. We do that by:

- withdrawing the remaining `0.46 ETH` to `0x1337`
- creating a change note for the leftover `0.63 ETH`

This final change note does not need to be useful later. Its purpose is simply to satisfy the per-transaction input/output accounting while emptying the pool balance completely.

The final state is:

- `pool = 0`
- `0x1337 = 7.63 + 0.46 = 8.09 ETH`

That satisfies both conditions in `handleFlag`:

- pool is zero
- `8.09 ETH > 7 ETH`

The transaction count also works out perfectly:

- 1 deposit
- 8 withdraws
- total = 9 raw transactions

So the exploit fits under the limit of 10.

## Final Solve

```javascript
const { ethers } = require("ethers");
const { ed25519, ED25519_TORSION_SUBGROUP } = require("@noble/curves/ed25519");
const { sha256, sha512 } = require("@noble/hashes/sha2");
const { bytesToHex, utf8ToBytes } = require("@noble/hashes/utils");

const TARGET_URL = process.env.TARGET_URL || process.argv[2];
const CURVE_ORDER = ed25519.CURVE.n;
const POOL = "0x00000000000000000000000000000000000010c0";
const WINNER = "0x0000000000000000000000000000000000001337";

const DOMAIN_SPEND_SCALAR = utf8ToBytes("conero/spend-scalar");
const DOMAIN_NOTE_COMMITMENT = utf8ToBytes("conero/note-commitment");
const DOMAIN_HASH_TO_POINT_SC1 = utf8ToBytes("conero/hash-to-point/scalar-1");
const DOMAIN_HASH_TO_POINT_SC2 = utf8ToBytes("conero/hash-to-point/scalar-2");
const DOMAIN_HASH_POINT_BASE1 = utf8ToBytes("conero/hash-to-point/base-1");
const DOMAIN_HASH_POINT_BASE2 = utf8ToBytes("conero/hash-to-point/base-2");
const DOMAIN_WITHDRAW_CTX = utf8ToBytes("conero:ring-withdraw-context");
const DOMAIN_PROOF_CHALLENGE = utf8ToBytes("conero:ring-transfer-challenge");

function concatBytes(...parts) {
  const total = parts.reduce((n, part) => n + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function hex(bytes) {
  return "0x" + bytesToHex(bytes);
}

function toLE(value, length) {
  const out = new Uint8Array(length);
  let v = BigInt(value);
  for (let i = 0; i < length; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function mod(a, m = CURVE_ORDER) {
  const out = a % m;
  return out >= 0n ? out : out + m;
}

function bytesToNumberLE(bytes) {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    value = (value << 8n) + BigInt(bytes[i]);
  }
  return value;
}

function scalarFromUniform(domain, msg) {
  const digest = sha512(concatBytes(domain, msg));
  return mod(bytesToNumberLE(digest));
}

function scalarToBytesLE(value) {
  return toLE(mod(value), 32);
}

function pointFromBytes(bytes) {
  return ed25519.Point.fromHex(bytes);
}

function pointBytes(point) {
  return point.toRawBytes();
}

function noteSecretScalar(secret32) {
  return scalarFromUniform(DOMAIN_SPEND_SCALAR, secret32);
}

function notePublicKey(secret32) {
  return pointBytes(ed25519.Point.BASE.multiply(noteSecretScalar(secret32)));
}

function noteCommitment(publicKey, amount) {
  return sha256(concatBytes(DOMAIN_NOTE_COMMITMENT, publicKey, toLE(amount, 8)));
}

function deriveHashPointBase(domain) {
  for (let i = 0; ; i++) {
    const counter = new Uint8Array(4);
    new DataView(counter.buffer).setUint32(0, i, true);
    const candidate = sha512(concatBytes(domain, counter)).slice(0, 32);
    try {
      const point = pointFromBytes(candidate);
      if (!point.is0() && point.isTorsionFree()) {
        return point;
      }
    } catch {}
  }
}

const HASH_POINT_BASE1 = deriveHashPointBase(DOMAIN_HASH_POINT_BASE1);
const HASH_POINT_BASE2 = deriveHashPointBase(DOMAIN_HASH_POINT_BASE2);
const TORSION_POINTS = ED25519_TORSION_SUBGROUP.map((encoded) => pointFromBytes(encoded));

function hashToPoint(msg) {
  const s1 = scalarFromUniform(DOMAIN_HASH_TO_POINT_SC1, msg);
  const s2 = scalarFromUniform(DOMAIN_HASH_TO_POINT_SC2, msg);
  const point = HASH_POINT_BASE1.multiply(s1).add(HASH_POINT_BASE2.multiply(s2));
  if (point.is0()) {
    throw new Error("hashToPoint produced identity");
  }
  return point;
}

function torsionOrder(point) {
  let cur = point;
  for (let i = 1; i <= 8; i++) {
    if (cur.is0()) return i;
    cur = cur.add(point);
  }
  throw new Error("torsion order > 8");
}

function withdrawContextHash(memberPubKeys, amount, recipient20, withdrawAmount, change) {
  const parts = [
    DOMAIN_WITHDRAW_CTX,
    Uint8Array.of(1),
    Uint8Array.of(memberPubKeys.length),
    toLE(amount, 8),
  ];
  for (const member of memberPubKeys) parts.push(member);
  parts.push(recipient20, toLE(withdrawAmount, 8));
  if (change) {
    parts.push(Uint8Array.of(1), change.txPublicKey, change.publicKey, toLE(change.amount, 8));
  } else {
    parts.push(Uint8Array.of(0));
  }
  return ethers.keccak256(hex(concatBytes(...parts)));
}

function ringChallenge(ctxHash32, keyImage32, L, R) {
  const payload = concatBytes(
    DOMAIN_PROOF_CHALLENGE,
    ctxHash32,
    keyImage32,
    pointBytes(L),
    pointBytes(R),
  );
  return scalarFromUniform(new Uint8Array(), payload);
}

function signSingleMemberWithdraw({ secret32, publicKey, amount, recipient20, withdrawAmount, change, torsionPoint }) {
  const x = noteSecretScalar(secret32);
  const Hp = hashToPoint(publicKey);
  const canonicalKeyImage = Hp.multiply(x);
  const keyImagePoint = torsionPoint ? canonicalKeyImage.add(torsionPoint) : canonicalKeyImage;
  const keyImage = pointBytes(keyImagePoint);
  const ctxHash = ethers.getBytes(withdrawContextHash([publicKey], amount, recipient20, withdrawAmount, change));
  const order = torsionPoint ? torsionOrder(torsionPoint) : 1;

  for (let nonce = 0; nonce < 100000; nonce++) {
    const alpha = scalarFromUniform(utf8ToBytes("alpha"), concatBytes(secret32, toLE(BigInt(nonce), 8)));
    const L = ed25519.Point.BASE.multiply(alpha);
    const R = Hp.multiply(alpha);
    const c0 = ringChallenge(ctxHash, keyImage, L, R);
    if (c0 % BigInt(order) !== 0n) continue;
    const s0 = mod(alpha - c0 * x);
    return {
      keyImage,
      challenge0: scalarToBytesLE(c0),
      response0: scalarToBytesLE(s0),
    };
  }

  throw new Error(`failed to satisfy torsion order ${order}`);
}

function encodeWithdraw({ amount, publicKey, keyImage, challenge0, response0, recipient20, withdrawAmount, change }) {
  const parts = [
    Uint8Array.of(4),
    Uint8Array.of(1),
    Uint8Array.of(1),
    toLE(amount, 8),
    publicKey,
    keyImage,
    challenge0,
    response0,
    recipient20,
    toLE(withdrawAmount, 8),
  ];
  if (change) {
    parts.push(Uint8Array.of(1), change.txPublicKey, change.publicKey, toLE(change.amount, 8));
  } else {
    parts.push(Uint8Array.of(0));
  }
  return hex(concatBytes(...parts));
}

function randomSecret(label) {
  return sha256(utf8ToBytes(label));
}

async function waitReceipt(provider, hash) {
  for (;;) {
    const receipt = await provider.getTransactionReceipt(hash);
    if (receipt) return receipt;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
}

async function solvePow(baseUrl) {
  const res = await fetch(`${baseUrl}/pow`);
  const body = await res.json();
  const target = 1n << BigInt(256 - body.bits);
  for (let i = 0; ; i++) {
    const nonce = String(i);
    const digest = sha256(utf8ToBytes(body.prefix + nonce));
    const value = BigInt("0x" + bytesToHex(digest));
    if (value < target) {
      return { prefix: body.prefix, nonce };
    }
  }
}

async function createInstance(baseUrl) {
  const pow = await solvePow(baseUrl);
  const res = await fetch(`${baseUrl}/new`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pow_prefix: pow.prefix, pow_nonce: pow.nonce }),
  });
  const body = await res.json();
  if (!body.ok) {
    throw new Error(`instance creation failed: ${JSON.stringify(body)}`);
  }
  return body;
}

async function main() {
  if (!TARGET_URL) {
    throw new Error("usage: TARGET_URL=http://host node solve.js OR node solve.js http://host");
  }

  const instance = await createInstance(TARGET_URL);
  const provider = new ethers.JsonRpcProvider(instance.rpc_url);
  const player = new ethers.Wallet(instance.player_key, provider);

  console.log(JSON.stringify({
    uuid: instance.uuid,
    rpc_url: instance.rpc_url,
    player_address: instance.player_address,
  }));

  const depositAmount = ethers.parseEther("1.09");
  const noteSecret = randomSecret(`note-secret-${player.address}`);
  const notePubKey = notePublicKey(noteSecret);

  console.log("note_public_key =", hex(notePubKey));
  console.log("note_commitment =", hex(noteCommitment(notePubKey, depositAmount)));

  const depositData = hex(concatBytes(Uint8Array.of(1), notePubKey, new Uint8Array(32)));
  const depositTx = await player.sendTransaction({
    to: POOL,
    data: depositData,
    value: depositAmount,
    gasLimit: 150000n,
  });
  await waitReceipt(provider, depositTx.hash);

  const poolBalanceAfterDeposit = await provider.getBalance(POOL);
  console.log("pool_after_deposit =", poolBalanceAfterDeposit.toString());

  const fullSpends = 7;
  const finalWithdrawAmount = poolBalanceAfterDeposit - BigInt(fullSpends) * depositAmount;
  const changeAmount = depositAmount - finalWithdrawAmount;
  const recipient = ethers.getBytes(WINNER);
  const change = {
    txPublicKey: new Uint8Array(32),
    publicKey: notePublicKey(randomSecret(`change-${player.address}`)),
    amount: changeAmount,
  };

  for (let i = 0; i < 8; i++) {
    const isFinal = i === 7;
    const withdrawAmount = isFinal ? finalWithdrawAmount : depositAmount;
    const changeSpec = isFinal ? change : null;

    const sig = signSingleMemberWithdraw({
      secret32: noteSecret,
      publicKey: notePubKey,
      amount: depositAmount,
      recipient20: recipient,
      withdrawAmount,
      change: changeSpec,
      torsionPoint: TORSION_POINTS[i],
    });

    const tx = await player.sendTransaction({
      to: POOL,
      data: encodeWithdraw({
        amount: depositAmount,
        publicKey: notePubKey,
        keyImage: sig.keyImage,
        challenge0: sig.challenge0,
        response0: sig.response0,
        recipient20: recipient,
        withdrawAmount,
        change: changeSpec,
      }),
      gasLimit: 300000n,
    });

    const receipt = await waitReceipt(provider, tx.hash);
    console.log(`withdraw_${i}_status =`, receipt.status.toString());
    console.log("pool_balance =", (await provider.getBalance(POOL)).toString());
    console.log("addr1337_balance =", (await provider.getBalance(WINNER)).toString());
  }

  const flagRes = await fetch(`${TARGET_URL}/${instance.uuid}/flag`);
  const flagBody = await flagRes.text();
  console.log(flagBody);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
```

To run it:

```bash
npm install
node solve.js http://43.200.70.230
```
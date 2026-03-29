# rev/bean-generator

## Overview

This is a reversing challenge built around a stripped ELF encoder named `prob` and a target file named `flag.bean`. The binary takes a PNG, transforms it into a custom `.bean` format, and writes the result back out. The goal is to reverse that transformation and recover the original image containing the flag.

## Exploit Chain

1. Open the binary in a disassembler and identify the custom file format. The output always starts with `BEAN\x01`, so the remaining bytes are the encrypted payload.
2. In `.rodata`, there is a 256-byte AES S-box and a 16-byte constant at the end of the table. That constant is the AES key:

```text
c4f1a9e87d5c2b9f61e8d4a0bb1293de
```

3. The main loop reads 3 random bytes from `/dev/urandom` and builds a 16-byte block in this layout:

```text
nonce[3] || "BEANv1" || 00 00 00 || counter_be32
```

4. That block is AES-encrypted and XORed with the PNG data, which makes the scheme a custom CTR-style stream cipher. The `.bean` file stores the ciphertext, but it does not store the 3-byte nonce.
5. The missing nonce is still recoverable because the plaintext is a PNG and the first 16 plaintext bytes are known:

```text
89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52
```

6. XOR the first 16 ciphertext bytes with that fixed PNG header to get the first keystream block. Then brute-force the 24-bit nonce until:

```text
AES(key, nonce || "BEANv1" || 00 00 00 || 00 00 00 00) == keystream_block_0
```

7. Once the nonce is found, regenerate the keystream for every counter value, XOR it with the ciphertext, and write the recovered PNG.
8. Open the recovered image and read the flag:

```text
codegate2026{l37s_g0_codegate2026_R3v3rsing!!}
```

## Final Solve

```python
#!/usr/bin/env python3

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

from Crypto.Cipher import AES


KEY = bytes.fromhex("c4f1a9e87d5c2b9f61e8d4a0bb1293de")
BEAN_HEADER = b"BEAN\x01"
KNOWN_PNG_BLOCK = bytes.fromhex("89504e470d0a1a0a0000000d49484452")
CTR_PREFIX = b"BEANv1"
NONCE_SEARCH_CHUNK = 1_000_000


def xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def recover_nonce(aes: AES, first_cipher_block: bytes) -> bytes:
    target_keystream = xor_bytes(first_cipher_block, KNOWN_PNG_BLOCK)
    suffix = CTR_PREFIX + b"\x00" * 7

    for start in range(0, 1 << 24, NONCE_SEARCH_CHUNK):
        count = min(NONCE_SEARCH_CHUNK, (1 << 24) - start)
        blocks = bytearray(16 * count)

        for index in range(count):
            value = start + index
            offset = index * 16
            blocks[offset] = value & 0xFF
            blocks[offset + 1] = (value >> 8) & 0xFF
            blocks[offset + 2] = (value >> 16) & 0xFF
            blocks[offset + 3 : offset + 16] = suffix

        ciphertext = aes.encrypt(bytes(blocks))
        match = ciphertext.find(target_keystream)
        if match != -1 and match % 16 == 0:
            value = start + (match // 16)
            return bytes((value & 0xFF, (value >> 8) & 0xFF, (value >> 16) & 0xFF))

    raise RuntimeError("failed to recover the 24-bit nonce")


def keystream_block(aes: AES, nonce: bytes, counter: int) -> bytes:
    block = nonce + CTR_PREFIX + b"\x00" * 3 + counter.to_bytes(4, "big")
    return aes.encrypt(block)


def decrypt_bean(path: Path) -> tuple[bytes, bytes]:
    data = path.read_bytes()
    if not data.startswith(BEAN_HEADER):
        raise ValueError(f"{path} does not start with {BEAN_HEADER!r}")

    ciphertext = data[len(BEAN_HEADER) :]
    aes = AES.new(KEY, AES.MODE_ECB)
    nonce = recover_nonce(aes, ciphertext[:16])

    plaintext = bytearray(len(ciphertext))
    for counter in range((len(ciphertext) + 15) // 16):
        stream = keystream_block(aes, nonce, counter)
        chunk = ciphertext[counter * 16 : (counter + 1) * 16]
        for index, value in enumerate(chunk):
            plaintext[counter * 16 + index] = value ^ stream[index]

    return nonce, bytes(plaintext)


def default_output_path(input_path: Path) -> Path:
    if input_path.suffix == ".bean":
        return input_path.with_suffix(".png")
    return input_path.with_name(f"{input_path.name}.png")


def maybe_run_tesseract(image_path: Path) -> None:
    if shutil.which("tesseract") is None:
        return

    result = subprocess.run(
        ["tesseract", str(image_path), "stdout"],
        capture_output=True,
        text=True,
        check=False,
    )
    text = result.stdout.strip()
    if text:
        print("OCR:")
        print(text)


def main() -> None:
    parser = argparse.ArgumentParser(description="Recover the PNG stored in a .bean file.")
    parser.add_argument("input", nargs="?", default="for_user/flag.bean", help="path to the .bean file")
    parser.add_argument(
        "-o",
        "--output",
        help="path to write the recovered PNG (default: replace .bean with .png)",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output) if args.output else default_output_path(input_path)

    nonce, plaintext = decrypt_bean(input_path)
    output_path.write_bytes(plaintext)

    print(f"nonce: {nonce.hex()}")
    print(f"wrote: {output_path}")

    if plaintext.startswith(b"\x89PNG\r\n\x1a\n"):
        print("recovered a valid PNG header")

    maybe_run_tesseract(output_path)


if __name__ == "__main__":
    main()
```

Run it with:

```bash
python3 solve.py
```

Note: this expects the encrypted file is at `./for_user/flag.bean` and will save the decrypted image at `./for_user/flag.png`. View the image to reveal the flag.
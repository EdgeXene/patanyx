# Third-party cookies

**Status: MEASURED 2026-08-01. WebKitGTK already refuses them, and not because
of anything PATANYX does. No code was added.**

This is the second feature in this repository to be deleted-before-birth by its
own probe (see `referrer-trimming.md` for the first). Both were planned in good
faith, and both turned out to be the engine's job already.

## The question

A tracker embedded on two unrelated sites can recognise the same browser if it
is allowed to set and read its own cookie in each embed. The plan's first draft
proposed adding
`webkit_cookie_manager_set_accept_policy(ACCEPT_NO_THIRD_PARTY)` beside
`enable_itp`, plus a `block_third_party_cookies` pref and a panel row.

The doubt that stopped it: WebKit documents that once ITP is enabled it takes
over third-party cookie handling, and an `ACCEPT_NO_THIRD_PARTY` request is
treated as `ACCEPT_ALWAYS`. PATANYX enables ITP on every content webview
(`platform/unix.rs`, `enable_itp`). So the proposed call might have done
nothing while the code, a pref, a panel row and an About card all said it did.

## The measurement

`scripts/thirdparty-cookie-probe.sh`, run 2026-08-01 against a debug build.
Three loopback addresses are three distinct origins to the engine:

    127.0.0.1  first-party site A
    127.0.0.2  first-party site B (a different site, same session)
    127.0.0.3  the third party, embedded by both

One browser session, five observations:

| stage | what it is                                           | result       |
| ----- | ---------------------------------------------------- | ------------ |
| 0     | site A's own first-party cookie, same-origin fetch   | **returned** |
| 1     | third party embedded on site A, sets 3 cookie shapes | set          |
| 1b    | third party embedded on site A again                 | none         |
| 2     | third party embedded on site B (the cross-site case) | none         |
| 3     | the third party reached by TOP-LEVEL navigation      | **none**     |

Stage 0 proves cookies work at all, so the empty stages are not "storage is
off". Stage 3 is the disambiguator and the reason this probe can conclude
anything: reached top-level, that host is the _first_ party, and SameSite
imposes no restriction — yet its cookie is still absent. So the cookie was
never stored at all. The engine refused a third-party `Set-Cookie` outright,
rather than storing it and merely declining to send it (which is all ordinary
SameSite behaviour would give us).

Three cookie shapes were set at once (`SameSite=None` without Secure,
`SameSite=Lax`, and no attribute) precisely so that "no cookie came back" could
not be blamed on one attribute's handling over plain HTTP.

## Why ITP is NOT the cause

Negative control, by planted defect: `enable_itp` was temporarily made to
disable ITP instead, verified through the engine's own report
(`ENGINE ... | ITP OFF` versus `ITP enabled`), and the probe re-run.

**Third-party cookies were refused in both runs, identically.**

So the refusal is WebKitGTK's own default cookie-accept policy, not ITP and not
us. The planted defect was reverted immediately and the env var it used is gone.

Without that control the result would have been worthless: an unchanged
outcome is exactly what a no-op env var would also have produced, and the run
that proved the defeat was real is what separates "ITP is not the cause" from
"my test did nothing".

## The decision

**No code.** An `ACCEPT_NO_THIRD_PARTY` call here cannot be shown to change any
observable behaviour, and this codebase does not carry code whose effect is
indistinguishable from doing nothing. No pref, no panel row, no toggle.

What may be said publicly: _this browser does not accept third-party cookies_
— true, and verifiable by anyone re-running the probe. What may NOT be said:
that PATANYX is what stops them.

## What is NOT covered

- **Non-cookie tracking.** localStorage, IndexedDB, cache probing and
  fingerprinting are untouched by this result.

## Windows: MEASURED 2026-08-01, same answer

`scripts/cookie-probe.ps1`, run by the project owner on real Windows hardware
against a debug build. The cross-site chain ran clean:

| stage                                       | result       |
| ------------------------------------------- | ------------ |
| 3p embedded on site A, sets 3 shapes        | set          |
| 3p embedded on site A again                 | none         |
| **site A's own cookie, on a later request** | **returned** |
| 3p embedded on site B (cross-site)          | none         |
| 3p reached TOP-LEVEL (first-party context)  | **none**     |

Identical to Linux, and identically conclusive: nothing came back even where
the third party was the first party and SameSite restricted nothing, so the
`Set-Cookie` was refused rather than stored-and-withheld. First-party cookies
work — proven incidentally by a favicon fetch to site A carrying site A's own
cookie.

**This contradicts the expectation recorded before the run** ("Chromium
probably DOES accept third-party cookies"). Recording the prediction is what
made being wrong visible; WebView2 refuses them too.

So the conclusion holds on both platforms, and for the same reason: there is
nothing here for PATANYX code to add.

### RESOLVED 2026-08-01: neither platform keeps logins

Decided: own it as a privacy property on both platforms.
`clear_cookies_for_new_session` (windows.rs) calls `DeleteAllCookies` once per
process at the first content webview. Implemented as a START-of-session wipe
rather than an exit hook, because an exit hook does not run when the process is
killed or crashes -- exactly when somebody else may later open the browser.

Verified by re-running `login-probe.ps1` on real hardware against the patched
build. The verdict flipped, and the same log carries its own control:

    LOGIN   cookie=<none>                    launch 1, sets the cookie
    OTHER /favicon.ico cookie=sessionid=...  SAME launch: cookie is live
    LOGIN   cookie=<none>                    launch 2: gone
    OTHER /favicon.ico cookie=sessionid=...  in-session again

Both halves in one run: signed in while open, a stranger on relaunch. The
favicon lines matter -- without them, "no cookie on launch 2" would also be
consistent with having broken cookies outright.

On the About page as "Closing it signs you out", with the limit stated under
what it cannot hide: this is not secure deletion, the data sits on disk between
sessions.

**Linux still gets this by accident.** WebKitGTK simply never persists them; no
code asks for it. If that default ever changes, Linux silently starts keeping
logins with nothing to catch it. Making it explicit, and gating it, is open.

### The measurement that prompted it

`scripts/login-probe.ps1`, operator-run 2026-08-01:

    launch 1 : LOGIN cookie=<none>                 sets a Max-Age cookie
    launch 2 : LOGIN cookie=sessionid=logged-in    SURVIVED the restart

**Windows keeps you signed in. Linux does not.** Same product, same version,
opposite behaviour, and until today neither was documented.

|                                  | Linux (WebKitGTK) | Windows (WebView2) |
| -------------------------------- | ----------------- | ------------------ |
| third-party cookies              | refused           | refused            |
| first-party, in-session          | works             | works              |
| **first-party, across restarts** | **lost**          | **kept**           |

The Windows side is ordinary browser behaviour. The Linux side is the outlier,
and it is not a decision anybody made — nothing calls
`webkit_cookie_manager_set_persistent_storage`, so a default is deciding a
user-visible property of the product. It must become deliberate one way or the
other:

1. **Make Linux match Windows** — logins persist everywhere. Normal, expected,
   and removes the divergence.
2. **Own it as a privacy property** — but then it should be the SAME on both
   platforms, which means deliberately dropping Windows cookies at exit, and
   it should be stated on the About page rather than discovered.
3. **Make it a setting** — "forget everything when I close the browser",
   defaulting the same way on both platforms.

What must not happen is the status quo: identical builds behaving differently
for a reason no one chose, with the About page silent on it.

### What went wrong in the earlier run, and what it cost

The second half (login persistence) never ran: the browser was navigated to
Google Drive while it sat open, which replaced the probe's own navigation.
Each launch idles ~25s during vault hashing, and a blank window looks usable.

Two fixes: unrecognised paths now 404 instead of being served the site-A page
(the first run's log carried six spurious `PAGE site-a` lines that were
favicon fetches, and decoding them by hand is how the first-party result was
noticed — luck, not design), and `scripts/login-probe.ps1` splits the
remaining question into a two-launch script with one URL and a "do not touch"
page, so there is less to disturb.

## Cookie persistence: a separate, measured finding

`scripts/cookie-persistence-probe.sh`, run 2026-08-01. **First-party cookies
do not survive a restart on Linux.** A cookie set with `Max-Age` (persistent,
not a session cookie) was absent on the next launch, and no cookie store of any
kind is written into the profile directory.

Practical consequence, stated plainly because it is a usability fact and not
only a privacy one: **every launch starts signed out of every site.** Within a
session logins work normally — first-party cookies are stored and returned, as
stage 0 of the probe above shows.

This deserved its own measurement because the first version of the claim was
reached by bad reasoning: I looked at a profile directory after a run, saw no
cookie file, and concluded cookies were memory-only. That run had loaded
`about:blank`, which sets no cookies, so an empty profile proved nothing at
all. The probe now sets a real cookie and looks for it after a real restart.

Nothing in this codebase calls
`webkit_cookie_manager_set_persistent_storage`, so this is a WebKitGTK default
nobody chose. It needs to become deliberate — either owned and stated on the
About page as a privacy property, or fixed — rather than remaining an accident
that happens to be strict.

## What is NOT covered

- **Non-cookie tracking.** localStorage, IndexedDB, cache probing and
  fingerprinting are untouched by this result.

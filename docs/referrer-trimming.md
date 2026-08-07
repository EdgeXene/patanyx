# Cross-origin referrer trimming

**Status: MEASURED AND DELETED, 2026-07-31.** The engine already does it. The
trim code, its env gate, `privacy::origin_of` and their tests were removed the
same day; this file and `scripts/referrer-probe.ps1` are what remain, so the
next person with this idea starts from the measurement instead of the
documentation gap that motivated the code.

## The question

A page at `shop.example/item/hair-loss-treatment?size=XL` announcing that full
address to every third-party host it contacts, via `Referer`, is one of the
larger passive leaks a browser emits. Rewriting the header to origin-only in
`WebResourceRequested` is documented as supported by Microsoft -- but the same
page says the network stack adds headers AFTER the handler returns, and whether
`Referer` survives that step is documented nowhere. `SetHeader` succeeds either
way, so no in-process check can answer it. The code therefore shipped
unreachable (no setting, `PATANYX_TRIM_REFERRER=1` only) until a measurement
from OUTSIDE the process existed.

## The measurement

`scripts/referrer-probe.ps1`, run by the project owner on real Windows hardware,
2026-07-31, against a 0.9.54 build carrying the trim code (presence verified by
string-search on the exact artifact). A page served from `127.0.0.1:8931`
loaded an image from `localhost:8932` -- same machine, different origin -- and
the second server recorded the `Referer` it actually received:

    page request : /deep/path/page.html?token=SECRET123
    asset request, Referer = http://127.0.0.1:8931/

**With trimming OFF, the path and query had already not left the browser.**
The baseline `Referer` was origin-only. This is Chromium's
`strict-origin-when-cross-origin` default (Chrome 85, 2020), which WebView2
inherits: cross-origin requests get scheme + host + port, nothing else.

The probe's own guard then voided the comparison, correctly: with an
origin-only baseline, a broken rewrite and a working one produce identical
observations, so round two can prove nothing. (Round two's browser launch never
reached the server at all -- an unexplained second-instance anomaly, immaterial
because the baseline alone settles the decision.)

## The decision

Delete, per the rule this repository already follows twice ("Forget this
site"'s storage caveat, the engine-confirmed settings rows): do not carry code
whose effect cannot be distinguished from doing nothing. The feature's entire
purpose -- keep path and query from crossing origins -- is the engine's default
behaviour. A setting for it would be a placebo with maintenance costs, and a
marketing claim for it would be taking credit for Chromium.

## What was deliberately left unanswered

- **Whether a `SetHeader` rewrite of `Referer` survives the stack at all.**
  The origin-only default makes it unmeasurable by this probe; answering it
  would need the page to opt into `unsafe-url` first. Not pursued: a page that
  opts into announcing its own full URL is choosing to share what it could
  share through a query string anyway, and clamping that is not a battle this
  browser claimed.
- **`document.referrer`**, the JS-visible value. The probe page displayed it
  but nothing recorded it. Separate question, no claim made either way.

## Re-measure if

the engine default ever changes (a WebView2 runtime release note touching
referrer policy), or a feature wants to clamp `unsafe-url` opt-ins. The probe
still runs as-is for the baseline; the trim round would need the code
restored from this commit's parent and the page given
`<meta name="referrer" content="unsafe-url">` to make a working rewrite
distinguishable from a broken one.

    powershell -ExecutionPolicy Bypass -File scripts\referrer-probe.ps1

| Exit | Meaning                                                       |
| ---- | ------------------------------------------------------------- |
| 2    | Baseline already origin-only (the 2026-07-31 result), or void |
| 0/3  | Only reachable if the trim code is restored first             |
| 1    | Probe error; see `referrer-probe-log.txt`                     |

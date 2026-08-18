#!/usr/bin/env bash
# The two chrome-UI release gates, as one command that either passes or fails.
#
# GATE 1: every chrome script must LOAD. `node --check` validates syntax and
# nothing else, and that gap has already shipped a defect: a splice script
# dropped thirteen top-level declarations, chrome.js threw a ReferenceError at
# load, and two toolbar buttons were dead in a build whose JS parsed perfectly.
# So this EXECUTES each file against a DOM stub.
#
# GATE 2: no innerHTML anywhere in the chrome. The chrome webview is the one
# holding IPC and vault access, so markup injection there reads the vault.
# Peer strings and page titles reach that DOM through textContent only.
#
# The harness used to live in a scratch directory outside the repository,
# which meant the gate could not be re-run by anyone else and was, in
# practice, one machine's habit. Same lesson as smoke.sh silently running a
# stale binary: a check nobody else can run is not a check.
set -euo pipefail
cd "$(dirname "$0")/.."

CHROME=crates/app/src/chrome
export HTML_PATH="$CHROME/index.html"

echo "=== gate 1: every chrome script executes ==="
mapfile -t SCRIPTS < <(find "$CHROME" -maxdepth 1 -name '*.js' | sort)
# Set by the negative control below, which re-invokes this script with a
# deliberate fault planted. That inner run must do the loading and nothing
# else, or it would recurse.
CONTROL="${PATANYX_GATE_CONTROL:-}"
if [ "${#SCRIPTS[@]}" -eq 0 ]; then
  echo "GATE FAIL: no chrome scripts found; the path is wrong" >&2
  exit 1
fi
# chrome.js is loaded FIRST for every other file, and that is not a
# convenience. chat.js and integrity.js both open with a guard --
# `if (!window.__rb) return;` -- so loading them alone runs about fifteen
# lines and exits. They were "passing" this gate without executing any of the
# code it exists to execute: a planted ReferenceError in either one went
# undetected, which is the exact defect the header cites.
for script in "${SCRIPTS[@]}"; do
  HTML_PATH="$HTML_PATH" SCRIPT="$script" CHROME_DIR="$CHROME" node -e '
    require("./scripts/domstub.js");
    const fs = require("fs");
    const path = require("path");
    const target = process.env.SCRIPT;
    const base = path.join(process.env.CHROME_DIR, "chrome.js");
    try {
      if (path.resolve(target) !== path.resolve(base)) {
        new Function(fs.readFileSync(base, "utf8"))();
      }
      new Function(fs.readFileSync(target, "utf8"))();
    } catch (e) {
      console.error("GATE FAIL: " + target + " threw at load: " + e.message);
      process.exit(1);
    }
    // Prove the file actually RAN rather than returning at its guard. Each
    // chrome script registers something observable; a file that registered
    // nothing has not been executed in any meaningful sense.
    const registered = global.registered.length;
    if (registered === 0) {
      console.error("GATE FAIL: " + target + " registered no handlers; it " +
        "returned at a guard instead of executing");
      process.exit(1);
    }
    console.log("  ok  " + target);
  '
done

# Negative control. A gate that has never been seen to fail is a gate nobody
# has tested, and this one is a loop over a list that could silently be empty
# or a `new Function` that could silently swallow. Plant a file that MUST
# fail and require the failure.
# The control plants a failure INSIDE a real chrome script and re-runs this
# same gate, rather than running a copy of the loader. A duplicated loader
# proves the duplicate works; weakening the real loop would still pass.
if [ -n "$CONTROL" ]; then
  exit 0
fi
probe_dir="$(mktemp -d)"
planted="${SCRIPTS[0]}"
cp "$planted" "$probe_dir/planted.orig"
# Restore on ANY exit, including a Ctrl-C mid-control. A gate that can leave
# a deliberate syntax error in a source file is worse than no gate.
restore_planted() {
  cp "$probe_dir/planted.orig" "$planted" 2>/dev/null || true
  rm -rf "$probe_dir"
}
trap restore_planted EXIT INT TERM
printf '\nthisIdentifierDoesNotExist();\n' >> "$planted"
if PATANYX_GATE_CONTROL=1 "$0" >/dev/null 2>&1; then
  echo "GATE FAIL: a planted ReferenceError in $planted was not detected" >&2
  exit 1
fi
restore_planted
trap - EXIT INT TERM
echo "  (detector verified against a failure planted in a real script)"

echo
echo "=== gate 1b: the chat panel's delivery display ==="
# A missing chat panel is fine; a chat gate with no panel to test is NOT.
# Guarding on both files meant renaming chat.js silently deleted this whole
# gate and still exited 0.
if [ -f scripts/chat-ui-gate.js ]; then
  if [ ! -f "$CHROME/chat.js" ]; then
    echo "GATE FAIL: scripts/chat-ui-gate.js exists but $CHROME/chat.js does not;" >&2
    echo "  the panel was renamed or removed and this gate would silently vanish" >&2
    exit 1
  fi
  node scripts/chat-ui-gate.js
else
  echo "  (no chat UI gate in this tree)"
fi

echo
echo "=== gate 1c: the resolver picker ==="
# Same guard shape as 1b, and for the same reason: a gate whose subject can be
# renamed out from under it disappears silently and still exits 0.
if [ -f scripts/dns-ui-gate.js ]; then
  if ! grep -q 'id="btn-dns"' "$CHROME/index.html"; then
    echo "GATE FAIL: scripts/dns-ui-gate.js exists but index.html has no" >&2
    echo "  #btn-dns; the resolver control was removed and this gate would" >&2
    echo "  silently vanish" >&2
    exit 1
  fi
  node scripts/dns-ui-gate.js
else
  echo "  (no DNS UI gate in this tree)"
fi

# Site permissions. Same guard shape and the same reason: this gate is the only
# check that the panel's controls are honest -- disabled where nothing enforces
# them, frames named rather than passed off as the page, and a failed grant not
# left looking successful. Delete the section and the gate would pass over an
# empty panel forever.
if [ -f scripts/permission-ui-gate.js ]; then
  if ! grep -q 'id="permission-list"' "$CHROME/index.html"; then
    echo "GATE FAIL: scripts/permission-ui-gate.js exists but index.html has" >&2
    echo "  no #permission-list; the site-permission panel was removed and" >&2
    echo "  this gate would silently vanish" >&2
    exit 1
  fi
  node scripts/permission-ui-gate.js
else
  echo "  (no permission UI gate in this tree)"
fi

echo
echo "=== gate 1g: the tunnel panel and its fail-closed banner ==="
# Same guard shape as the resolver gate above: a gate whose subject can be
# renamed out from under it disappears silently and still exits 0.
if [ -f scripts/tunnel-ui-gate.js ]; then
  if ! grep -q 'id="btn-tunnel"' "$CHROME/index.html"; then
    echo "GATE FAIL: scripts/tunnel-ui-gate.js exists but index.html has no" >&2
    echo "  #btn-tunnel; the tunnel control was removed and this gate would" >&2
    echo "  silently vanish" >&2
    exit 1
  fi
  node scripts/tunnel-ui-gate.js
else
  echo "  (no tunnel UI gate in this tree)"
fi

echo
echo "=== gate 1f: every control is in the toolbar ==="
# The pills live on a second toolbar row so every one of them is visible
# without opening anything. The trap this guards is the reverse of the one it
# was written for: reintroduce an overflow menu, move two controls into it, and
# every other gate stays green because each button still exists and still has a
# handler. This asserts that nothing hides a control.
if [ -f scripts/toolbar-gate.js ]; then
  if ! grep -q 'class="toolbar-break"' "$CHROME/index.html"; then
    echo "GATE FAIL: scripts/toolbar-gate.js exists but index.html has no" >&2
    echo "  row break; the second toolbar row was removed and this gate would" >&2
    echo "  silently vanish" >&2
    exit 1
  fi
  node scripts/toolbar-gate.js
else
  echo "  (no toolbar gate in this tree)"
fi

echo
echo "=== gate 1d: vault import ==="
# Import REPLACES the vault on this machine and the vault crate no longer
# refuses when one exists. The panel's warning is what took the refusal's
# place, which makes a sentence of copy into a security control -- so it is
# gated like one, along with the client-side validation that has to run
# BEFORE the irreversible call.
#
# Same guard shape as 1b and 1c: a gate whose subject can be renamed out from
# under it disappears silently and still exits 0.
if [ -f scripts/vault-import-ui-gate.js ]; then
  if ! grep -q 'id="bk-import-form"' "$CHROME/index.html"; then
    echo "GATE FAIL: scripts/vault-import-ui-gate.js exists but index.html" >&2
    echo "  has no #bk-import-form; the import control was removed and this" >&2
    echo "  gate would silently vanish" >&2
    exit 1
  fi
  node scripts/vault-import-ui-gate.js
else
  echo "  (no vault import UI gate in this tree)"
fi

echo
echo "=== gate 1e: what the engine confirmed ==="
# That section rendered its heading, its paragraph and zero rows for its whole
# life, because it was fed the browser-wide `privacy_get` reply instead of the
# per-tab `tab_status` one. Every gate here missed it: the JS was correct, the
# markup was correct, the Rust was correct, and nothing checked that a list
# meant to have contents had any. Found by looking at a screenshot.
#
# Same guard shape as 1b/1c/1d: a gate whose subject can be renamed out from
# under it disappears silently and still exits 0.
if [ -f scripts/engine-confirmed-gate.js ]; then
  if ! grep -q 'id="engine-list"' "$CHROME/index.html"; then
    echo "GATE FAIL: scripts/engine-confirmed-gate.js exists but index.html" >&2
    echo "  has no #engine-list; the section was removed and this gate would" >&2
    echo "  silently vanish" >&2
    exit 1
  fi
  node scripts/engine-confirmed-gate.js
else
  echo "  (no engine-confirmed gate in this tree)"
fi

echo
echo "=== gate 1g: forget this site ==="
# Destructive, and living inside a panel ("Tab Activity") that already ships
# a form and a couple of small buttons -- exactly the setting a warning could
# stop rendering into, or a confirm button could end up wired to fire
# immediately. Same guard shape as the gates above.
if [ -f scripts/site-forget-gate.js ]; then
  if ! grep -q 'id="site-forget-yes"' "$CHROME/index.html"; then
    echo "GATE FAIL: scripts/site-forget-gate.js exists but index.html has" >&2
    echo "  no #site-forget-yes; the control was removed and this gate would" >&2
    echo "  silently vanish" >&2
    exit 1
  fi
  node scripts/site-forget-gate.js
else
  echo "  (no site-forget gate in this tree)"
fi

echo
echo "=== gate 1g2: clear cookies for all sites ==="
# The browser-wide counterpart to the gate above, and the more dangerous of the
# two: one click reaches every cookie the browser holds. Two properties nothing
# else covers -- no IPC before the confirmation, and every string in the section
# coming from cookie_control.rs rather than the markup, since the sentence
# "cookies, not your saved passwords" is what keeps the feature honest and is
# otherwise the one part of it no test reads. Same guard shape as the gates
# above.
if [ -f scripts/forget-all-cookies-gate.js ]; then
  if ! grep -q 'id="forget-all-yes"' "$CHROME/index.html"; then
    echo "GATE FAIL: scripts/forget-all-cookies-gate.js exists but index.html" >&2
    echo "  has no #forget-all-yes; the control was removed and this gate" >&2
    echo "  would silently vanish" >&2
    exit 1
  fi
  node scripts/forget-all-cookies-gate.js
else
  echo "  (no forget-all-cookies gate in this tree)"
fi

echo
echo "=== gate 1h: command palette ==="
# Every entry names a real button and runs it directly -- never a second copy
# of what the action does. Same guard shape as the gates above.
if [ -f scripts/palette-gate.js ]; then
  if ! grep -q 'id="palette-panel"' "$CHROME/index.html"; then
    echo "GATE FAIL: scripts/palette-gate.js exists but index.html has no" >&2
    echo "  #palette-panel; the palette was removed and this gate would" >&2
    echo "  silently vanish" >&2
    exit 1
  fi
  node scripts/palette-gate.js
else
  echo "  (no palette gate in this tree)"
fi

echo
echo "=== gate 1i: diagnostics export ==="
# The "no history/credentials/vault content" constraint lives in Rust and has
# its own test there (diagnostics_snapshot_never_names_a_forbidden_field);
# this covers the chrome-JS half -- the two UI-plumbing fields are actually
# stripped before a report leaves the machine, and Save refuses to act with
# nothing chosen.
if [ -f scripts/diagnostics-gate.js ]; then
  if ! grep -q 'id="diag-copy"' "$CHROME/index.html"; then
    echo "GATE FAIL: scripts/diagnostics-gate.js exists but index.html has" >&2
    echo "  no #diag-copy; the control was removed and this gate would" >&2
    echo "  silently vanish" >&2
    exit 1
  fi
  node scripts/diagnostics-gate.js
else
  echo "  (no diagnostics gate in this tree)"
fi

echo
echo "=== gate 1j: first-run tour ==="
# The tour must open itself only on a genuine first run and mark itself
# seen exactly once, however it is dismissed. Same guard shape as the gates
# above.
if [ -f scripts/onboarding-gate.js ]; then
  if ! grep -q 'id="onboarding-panel"' "$CHROME/index.html"; then
    echo "GATE FAIL: scripts/onboarding-gate.js exists but index.html has" >&2
    echo "  no #onboarding-panel; the tour was removed and this gate would" >&2
    echo "  silently vanish" >&2
    exit 1
  fi
  node scripts/onboarding-gate.js
else
  echo "  (no onboarding gate in this tree)"
fi

echo
echo "=== gate 1k: update channel ==="
# Choosing Beta must call update_channel_set with the right value, reflect
# whatever Rust actually reports rather than the last click, and disable
# itself on a build with no update networking to fetch from at all. Same
# guard shape as the gates above.
if [ -f scripts/update-channel-gate.js ]; then
  if ! grep -q 'CHANNEL_NOTE_BETA' "$CHROME/update.js"; then
    echo "GATE FAIL: scripts/update-channel-gate.js exists but update.js has" >&2
    echo "  no channel toggle; it was removed and this gate would silently" >&2
    echo "  vanish" >&2
    exit 1
  fi
  node scripts/update-channel-gate.js
else
  echo "  (no update-channel gate in this tree)"
fi

echo
echo "=== gate 1l: update banner ==="
# The banner is the ONLY thing that tells a user an update exists without
# them going looking, and it shipped dead: it fired on `offered` while the
# scheduled check reported `checking`, and background download means the
# state that matters is `ready`. Pinned in both directions because a banner
# that never appears and one that never leaves are both failures.
if [ -f scripts/update-banner-gate.js ]; then
  if ! grep -q 'update-banner' "$CHROME/index.html"; then
    echo "GATE FAIL: scripts/update-banner-gate.js exists but index.html has" >&2
    echo "  no update banner; it was removed and this gate would silently" >&2
    echo "  vanish" >&2
    exit 1
  fi
  node scripts/update-banner-gate.js
else
  echo "  (no update-banner gate in this tree)"
fi

echo
echo "=== gate 1k2: the address bar never decodes a hostname ==="
# A homograph domain is defeated here by an OMISSION -- nothing prettifies the
# URL, so a Cyrillic lookalike arrives and is shown as xn--. That is strong
# and easy to undo by accident, since decoding IDN for friendliness looks like
# an improvement. This pins it.
if [ -f scripts/hostname-display-gate.js ]; then
  node scripts/hostname-display-gate.js
else
  echo "  (no hostname-display gate in this tree)"
fi

echo
echo "=== gate 1l: inline credential autofill ==="
# The save banner and the fill affordance -- the first feature in this
# codebase to hold a password in memory ahead of an explicit user action, and
# the first to write into a content webview from the chrome. Same guard shape
# as the gates above.
if [ -f scripts/credential-ui-gate.js ]; then
  if ! grep -q 'id="save-password-banner"' "$CHROME/index.html"; then
    echo "GATE FAIL: scripts/credential-ui-gate.js exists but index.html has" >&2
    echo "  no #save-password-banner; the control was removed and this gate" >&2
    echo "  would silently vanish" >&2
    exit 1
  fi
  node scripts/credential-ui-gate.js
else
  echo "  (no credential autofill gate in this tree)"
fi

echo
echo "=== gate 1l1: what opens at launch ==="
# The vault opens itself when PATANYX is started on its own, and deliberately
# does NOT when another application handed it a link to display -- covering
# the page someone asked for with a passphrase prompt is an interruption. The
# first-run tour outranks both. Each scenario boots chrome.js in its own
# process, because the boot sequence runs once per document.
if [ -f scripts/startup-vault-gate.js ]; then
  if ! grep -q 'startup_info' "$CHROME/chrome.js"; then
    echo "GATE FAIL: scripts/startup-vault-gate.js exists but chrome.js no" >&2
    echo "  longer reads startup_info; the launch behaviour was removed and" >&2
    echo "  this gate would silently vanish" >&2
    exit 1
  fi
  node scripts/startup-vault-gate.js
else
  echo "  (no startup vault gate in this tree)"
fi

echo
echo "=== gate 1l3: the bookmarks manager ==="
# Quick Access is PINNED: it must survive a folder filter, a search and a
# sort, because it exists so a user never has to go looking. Filing must go
# through the atomic file/unfile, never the whole-list tags_set. And adding by
# hand must hand the typed address to Rust, so the content allowlist there is
# what decides. All three are proven against planted defects.
if [ -f scripts/bookmarks-manager-gate.js ]; then
  if ! grep -q 'id="bmm-quick"' "$CHROME/index.html"; then
    echo "GATE FAIL: scripts/bookmarks-manager-gate.js exists but index.html" >&2
    echo "  has no #bmm-quick; the manager was removed and this gate would" >&2
    echo "  silently vanish" >&2
    exit 1
  fi
  node scripts/bookmarks-manager-gate.js
else
  echo "  (no bookmarks manager gate in this tree)"
fi

echo
echo "=== gate 1m: the content script has no network of its own ==="
# CONTENT_SCRIPT is untrusted-page territory (see its own top-of-file doc):
# it runs in every document a content tab ever navigates to, injected before
# the page's own scripts. Its only legitimate channel out is
# `window.chrome.webview.postMessage`, to the handler windows.rs registers on
# the raw COM object -- and its only legitimate way to receive anything is the
# `message` event that same channel delivers. `fetch`, `XMLHttpRequest` and
# `import` would each be a SECOND channel this file was never meant to have,
# reachable by anyone who can get this script re-injected (a future engine
# change, a bug in the frame-guard above it) rather than only by the chrome
# that built it.
CONTENT_SCRIPT="crates/app/src/content_scripts/autofill.js"
if [ -f "$CONTENT_SCRIPT" ]; then
  if grep -nE '\b(fetch|XMLHttpRequest|import)\s*\(' "$CONTENT_SCRIPT"; then
    echo "GATE FAIL: $CONTENT_SCRIPT calls a network/module primitive -- it" >&2
    echo "  must only ever speak through window.chrome.webview.postMessage" >&2
    exit 1
  fi
  echo "  ok  no fetch/XMLHttpRequest/import in $CONTENT_SCRIPT"

  # The grep above only proves what the script does NOT do. For a long time
  # that was its entire coverage, and the fill shipped twice doing nothing at
  # all on accounts.google.com -- a page with no <form>, which the username
  # lookup required. This runs it.
  if [ -f scripts/content-autofill-gate.js ]; then
    node scripts/content-autofill-gate.js
  else
    echo "  (no content autofill gate in this tree)"
  fi
else
  echo "  (no content script in this tree)"
fi

# fingerprint_divergence.js runs in the same page world but holds a SESSION TOKEN, so its
# bar is higher than autofill's: no OUTBOUND channel AT ALL, because it carries
# a per-session token. fetch/XMLHttpRequest/import are forbidden outright.
#
# postMessage is the one nuance. The CSP fallback (the Worker wrapper) hands the
# page a facade over a worker THE PAGE ITSELF created, and forwards the page's
# own messages to it -- real.postMessage(...). That is not a channel out of the
# page: the token never reaches a worker, whose shim carries only the canvas
# seed (the worker gate proves the token is absent from the shim source). So
# postMessage is allowed ONLY as a method call on a local receiver, and is still
# banned as a bare/implicit call or on any page-reachable global (self, window,
# parent, top, opener) -- those WOULD carry data out of the page.
DIVERGENCE_SCRIPT="crates/app/src/content_scripts/fingerprint_divergence.js"
if [ -f "$DIVERGENCE_SCRIPT" ]; then
  if grep -nE '\b(fetch|XMLHttpRequest|import)\s*\(' "$DIVERGENCE_SCRIPT"; then
    echo "GATE FAIL: $DIVERGENCE_SCRIPT opened a channel -- it carries the" >&2
    echo "  divergence session token and must have no way to send anything" >&2
    exit 1
  fi
  if grep -nE '(^|[^.[:alnum:]_$])postMessage[[:space:]]*\(|\b(self|window|parent|top|opener)\.postMessage[[:space:]]*\(' "$DIVERGENCE_SCRIPT"; then
    echo "GATE FAIL: $DIVERGENCE_SCRIPT calls postMessage on a global or as a" >&2
    echo "  bare/implicit send -- only forwarding onto a page-created worker is" >&2
    echo "  allowed; the token-bearing script must not send data out of the page" >&2
    exit 1
  fi
  echo "  ok  no fetch/XMLHttpRequest/import; postMessage only forwards to a worker in $DIVERGENCE_SCRIPT"

  # Same lesson as autofill: greps prove absence, only running it proves the
  # noise exists, is deterministic per site, and never stacks.
  node scripts/divergence-gate.js

  # And the opposite question: how easily can a site tell the noise is THERE?
  # Separate gate because it is a separate property, and because the figure
  # it prints is published. It pins the exact set of techniques that succeed,
  # so a change in either direction has to be made on purpose.
  node scripts/divergence-detect-gate.js

  # Worker coverage: the shim the Worker wrapper builds must apply noise
  # byte-identical to the main thread (or a page could diff the two realms
  # and read the mask off), and every non-classic case must fall back to an
  # unwrapped worker rather than a broken or mismatched one.
  node scripts/divergence-worker-gate.js
fi

echo
echo "=== gate 1n: the malicious-site blocked banner ==="
# The banner is the ONLY place a user learns why a page did not load, and
# "Open anyway" must reach exactly one host exactly once. malicious-probe.sh
# claimed this was "asserted in the DOM gate instead"; no such gate existed
# until now. Same guard shape as the gates above.
if [ -f scripts/blocked-banner-gate.js ]; then
  if ! grep -q 'id="blocked-allow"' "$CHROME/index.html"; then
    echo "GATE FAIL: scripts/blocked-banner-gate.js exists but index.html has" >&2
    echo "  no #blocked-allow; the override was removed and this gate would" >&2
    echo "  silently vanish" >&2
    exit 1
  fi
  node scripts/blocked-banner-gate.js
else
  echo "  (no blocked-banner gate in this tree)"
fi

echo
echo "=== gate 1o: the find-across-tabs panel ==="
# The first premium surface. Proven against three planted defects when it
# landed: always-goto-row-0, clearing the locked notice, and naive UTF-16
# snippet slicing all fail it. Same guard shape as the gates above.
if [ -f scripts/cross-tab-find-gate.js ]; then
  if ! grep -q 'id="findtabs-list"' "$CHROME/index.html"; then
    echo "GATE FAIL: scripts/cross-tab-find-gate.js exists but index.html has" >&2
    echo "  no #findtabs-list; the surface was removed and this gate would" >&2
    echo "  silently vanish" >&2
    exit 1
  fi
  node scripts/cross-tab-find-gate.js
else
  echo "  (no cross-tab find gate in this tree)"
fi

echo
echo "=== gate 1o1: the find bar ==="
# The single-tab bar shipped without a gate while every other surface had
# one, and the cross-tab panel's adopt handoff leans on its honesty rules.
# Proven against two planted defects: not blanking the count on input, and
# painting counts for a closed bar.
if [ -f scripts/find-bar-gate.js ]; then
  if ! grep -q 'id="find-input"' "$CHROME/index.html"; then
    echo "GATE FAIL: scripts/find-bar-gate.js exists but index.html has" >&2
    echo "  no #find-input; the bar was removed and this gate would" >&2
    echo "  silently vanish" >&2
    exit 1
  fi
  node scripts/find-bar-gate.js
else
  echo "  (no find-bar gate in this tree)"
fi

echo
echo "=== gate 2: no innerHTML in the chrome ==="
if grep -rn "innerHTML" "$CHROME"; then
  echo "GATE FAIL: innerHTML in the chrome webview - it holds IPC and the vault" >&2
  exit 1
fi
echo "  none"

echo
echo "=== gate 3: every form has a submit handler ==="
# WHY THIS EXISTS. Four forms shipped with markup, backend commands and, in
# two cases, working file pickers -- and no submit listener. Change
# passphrase, encrypted export, plaintext export and bookmark editing all
# rendered, accepted input, and did nothing at all when submitted. No error,
# no toast, no write. They were found by hand in July 2026, not by any gate.
#
# Gate 1 could not catch it: it checks that each script registers AT LEAST ONE
# handler, so a file with nine listeners and four missing ones passes clean.
#
# A form is satisfied by a submit listener bound EITHER by id or through a
# variable holding that element. The id form is what this codebase uses
# everywhere, so the check is on the id and an exception has to be argued.
# Factories that bind a submit listener in their OWN body. A brace-depth
# stack, so a listener inside a nested helper is attributed to the helper and
# not to the function that contains it -- otherwise any function holding any
# handler anywhere would vouch for every form.
submit_binders=$(awk '
  {
    line = $0
    if (match(line, /function[ \t]+[A-Za-z_][A-Za-z0-9_]*[ \t]*\(/)) {
      name = substr(line, RSTART, RLENGTH)
      gsub(/function[ \t]+|[ \t]*\($/, "", name)
      pending = name
    }
    if (line ~ /addEventListener\("submit"/ && top > 0) print stack[top]
    n = gsub(/{/, "{"); m = gsub(/}/, "}")
    for (i = 0; i < n; i++) { stack[++top] = pending; pending = stack[top] }
    for (i = 0; i < m; i++) if (top > 0) top--
  }
' "$CHROME"/*.js | sort -u)

missing_forms=""
for form_id in $(grep -oE '<form[^>]*id="[a-z0-9-]+"' "$CHROME/index.html" \
  | grep -oE 'id="[a-z0-9-]+"' | sed 's/id="//;s/"//' | sort -u); do
  if grep -qE "\\\$\(\"$form_id\"\)\.addEventListener\(\"submit\"" "$CHROME"/*.js; then
    continue
  fi
  # SECOND PASS: a form wired by a FACTORY that takes an id prefix.
  #
  # One implementation serving several forms beats the same handler copied
  # with the ids renamed -- copies are how two forms drift apart, a fix
  # landing in one and not the other. But a factory defeats a scan for the
  # literal id, so the pattern is recognised here rather than argued around
  # in a comment.
  #
  # NOT a blanket escape hatch. The form is satisfied only when a factory is
  # CALLED with a prefix of THIS form's id and that factory binds a submit
  # listener in its own body. A factory that takes a prefix and forgets the
  # listener still fails, which is the defect this gate exists to catch.
  #
  # KNOWN BLIND SPOT, stated rather than left to be discovered: this matches
  # on the prefix, so an UNWIRED form whose id merely begins with a wired
  # prefix ("import-decoy" against wireImportForm("import-")) passes. Closing
  # it needs a real parse. Do not name a new form after an existing prefix
  # unless the factory actually wires it.
  satisfied=""
  for fn in $submit_binders; do
    for pre in $(grep -ohE "$fn\(\"[a-z0-9-]+\"\)" "$CHROME"/*.js \
      | sed "s/^$fn(\"//;s/\")$//" | sort -u); do
      case "$form_id" in
        "$pre"*) satisfied=yes ;;
      esac
    done
  done
  [ -n "$satisfied" ] && continue
  missing_forms="$missing_forms $form_id"
done
if [ -n "$missing_forms" ]; then
  echo "GATE FAIL: form(s) in index.html with no submit handler in any chrome script:" >&2
  for f in $missing_forms; do echo "    $f" >&2; done
  echo "  A form that renders and does nothing on submit is worse than no form:" >&2
  echo "  the user believes the action happened. Wire it, or remove the markup." >&2
  exit 1
fi
echo "  every form has one"

echo
echo "=== gate 1q: Premium controls render locked, and locked is not "buy" ==="
# The rule worth a gate of its own: the licence session dies with the vault,
# so a PAYING customer with a closed vault reads as no-licence to the gate.
# Correct for gating, catastrophic for copy. Proven against three planted
# defects: folding locked into free, ignoring on_sale, and using the disabled
# property (which drops the control out of the focus order).
if [ -f scripts/premium-toolbar-gate.js ]; then
  if ! grep -q 'data-premium' "$CHROME/index.html"; then
    echo "GATE FAIL: scripts/premium-toolbar-gate.js exists but index.html" >&2
    echo "  marks no [data-premium] control; the marking was removed and" >&2
    echo "  this gate would silently vanish" >&2
    exit 1
  fi
  node scripts/premium-toolbar-gate.js
else
  echo "  (no premium toolbar gate in this tree)"
fi

echo
echo "=== gate 1t: Change Cross-Check says where to look, not what happened ==="
# The finding this feature surfaces is the one most easily turned into an
# accusation, so this pins the headline as Rust's verbatim, its OWN caveats
# beside it (change over time has different innocent causes than being
# served differently now), no accusing words, and a peer's refusal worded
# here rather than echoed. Proven against three planted defects.
if [ -f scripts/change-cross-check-gate.js ]; then
  if [ ! -f "$CHROME/integrity.js" ]; then
    echo "GATE FAIL: scripts/change-cross-check-gate.js exists but" >&2
    echo "  $CHROME/integrity.js does not; the panel was renamed or removed" >&2
    echo "  and this gate would silently vanish" >&2
    exit 1
  fi
  node scripts/change-cross-check-gate.js
else
  echo "  (no Change Cross-Check gate in this tree)"
fi

echo
echo "=== gate 1s: Deep Recall says what it saved ==="
# Pins that a locked control never starts a save, that listing and searching
# have DIFFERENT empty states (an empty archive and a fruitless search are
# different facts), that a page with no readable text says so, and that a
# save reports what was actually read. Proven against three planted defects.
if [ -f scripts/deep-recall-gate.js ]; then
  if ! grep -q 'id="recall-panel"' "$CHROME/index.html"; then
    echo "GATE FAIL: scripts/deep-recall-gate.js exists but index.html has" >&2
    echo "  no #recall-panel; the surface was removed and this gate would" >&2
    echo "  silently vanish" >&2
    exit 1
  fi
  node scripts/deep-recall-gate.js
else
  echo "  (no Deep Recall gate in this tree)"
fi

echo
echo "=== gate 1t: per-site divergence claims only registration ==="
# The proof line reports that a script was INSTALLED in this tab. It is not
# evidence any site was fooled, and a tab keeps what it started with, so the
# setting and the tab can honestly disagree. This pins both, plus that a
# Premium refusal explains itself instead of hiding the section, and that the
# free global toggle is never described as Premium. Proven against two
# planted defects (claiming protection with nothing registered, hiding on
# refusal).
if [ -f scripts/divergence-site-gate.js ]; then
  if ! grep -q 'id="divergence-site"' "$CHROME/index.html"; then
    echo "GATE FAIL: scripts/divergence-site-gate.js exists but index.html" >&2
    echo "  has no #divergence-site; the surface was removed and this gate" >&2
    echo "  would silently vanish" >&2
    exit 1
  fi
  node scripts/divergence-site-gate.js
else
  echo "  (no per-site divergence gate in this tree)"
fi

echo
echo "=== gate 1r: the download-comparison verdict tells the truth ==="
# A differing hash is EVIDENCE, not a verdict about anyone's conduct. This
# pins that the sentence comes from Rust verbatim, the caveats are ATTACHED
# beside it, and a peer's refusal is worded here rather than echoed. Proven
# against three planted defects (composing the headline in JS, dropping the
# caveat list, echoing the peer's reason). Its first draft passed two of
# those three vacuously -- it read every string the run had created rather
# than the rendered tree -- so it now asserts on the slot's own contents.
if [ -f scripts/download-compare-gate.js ]; then
  if ! grep -q 'id="download-list"' "$CHROME/index.html"; then
    echo "GATE FAIL: scripts/download-compare-gate.js exists but index.html" >&2
    echo "  has no #download-list; the surface was removed and this gate" >&2
    echo "  would silently vanish" >&2
    exit 1
  fi
  node scripts/download-compare-gate.js
else
  echo "  (no download comparison gate in this tree)"
fi

echo
echo "=== gate 1p: the region-read panel ==="
# The Premium read-text-on-this-page surface. Proven against two planted
# defects when it landed: dropping the premium-note unhide, and painting a
# capture into a closed panel. Same guard shape as the gates above.
if [ -f scripts/ocr-region-gate.js ]; then
  if ! grep -q 'id="region-panel"' "$CHROME/index.html"; then
    echo "GATE FAIL: scripts/ocr-region-gate.js exists but index.html has" >&2
    echo "  no #region-panel; the surface was removed and this gate would" >&2
    echo "  silently vanish" >&2
    exit 1
  fi
  node scripts/ocr-region-gate.js
else
  echo "  (no region-read gate in this tree)"
fi

echo
echo "CHROME JS OK"

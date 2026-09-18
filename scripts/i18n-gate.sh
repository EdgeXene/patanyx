#!/usr/bin/env bash
# The string catalog must cover every key the code references, and the
# privacy-claim messages must carry exactly the content the manifest pins.
#
# WHY THIS IS A GATE AND NOT A REMINDER.
#
# Key coverage alone was demonstrated insufficient by two independent
# adversarial reviews of this design: a deleted limit clause ("PATANYX never
# falls back to a direct connection"), an inverted claim, and a message swap
# between the two encrypted-resolver descriptions all keep every key present
# while making the product lie about who sees a user's lookups. The pinned
# substring tests catch none of the three -- that was verified against the
# real assertions, not assumed. So the CONTENT of each claim-bearing message
# is hashed into claims-manifest.txt, and any edit to one fails the build
# until the manifest is regenerated in the same, reviewable change.
#
# The dangerous coverage direction is referenced-but-missing: a key the code
# resolves with no catalog entry erases a privacy claim at runtime. The
# reverse -- a catalog entry nothing references -- is stale wording that can
# later be wired into a surface without review. Both directions fail.
#
# Regenerates into a scratch directory and diffs. Never writes over the tree
# it is checking.
#
# Run: scripts/i18n-gate.sh
#      scripts/i18n-gate.sh --bless   regenerates claims-manifest.txt in the
#                                     tree, for the commit that deliberately
#                                     edits a claim. The diff still lands in
#                                     review; blessing is not bypassing.
set -euo pipefail
cd "$(dirname "$0")/.."

I18N=crates/app/src/chrome/i18n
FTL=$I18N/locales/en.ftl
LIST=$I18N/claims.list
MANIFEST=$I18N/claims-manifest.txt
KEYS_RS=crates/app/src/i18n.rs

for f in "$FTL" "$LIST" "$MANIFEST" "$KEYS_RS"; do
  [ -f "$f" ] || { echo "GATE FAIL: $f does not exist." >&2; exit 1; }
done

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# The compiled pseudo-locale must be exactly what the generator writes
# from today's en.ftl -- a stale en-XA would ship padded strings for
# messages that no longer exist and miss the ones that do.
python3 scripts/gen-pseudo-locale.py "$FTL" "$TMP/en-XA.ftl" >/dev/null
if ! diff -u "$I18N/locales/en-XA.ftl" "$TMP/en-XA.ftl" >&2; then
  echo "GATE FAIL: en-XA.ftl is stale. Regenerate:" >&2
  echo "  python3 scripts/gen-pseudo-locale.py $FTL $I18N/locales/en-XA.ftl" >&2
  exit 1
fi

# A string a future feature writes straight into a sink must fail here,
# not ship English-only forever.
for f in chrome.js integrity.js update.js chat.js; do
  if ! python3 scripts/i18n-bare-literal-check.py "crates/app/src/chrome/$f" \
      > "$TMP/bare.out" 2>&1; then
    cat "$TMP/bare.out" >&2
    exit 1
  fi
done

# chrome.js and the catalog must carry the same English too: every
# i18nText("id", "English") literal is the golden copy for its message.
for f in chrome.js integrity.js update.js chat.js; do
  if ! python3 scripts/i18n-js-check.py "crates/app/src/chrome/$f" "$FTL" \
      > "$TMP/js-check.out" 2>&1; then
    cat "$TMP/js-check.out" >&2
    echo "GATE FAIL: $f and en.ftl disagree (above)." >&2
    exit 1
  fi
  grep '^i18nText sites' "$TMP/js-check.out" | sed "s|^|$f: |"
done

# Markup and catalog must carry the same English (both directions).
# Explicit if, NOT `pipeline && exit 1`: a failing pipeline left of && is
# exempt from set -e, so that shape prints the failure and keeps going --
# which this gate did once, on a planted defect, before this comment.
if ! python3 scripts/i18n-html-check.py crates/app/src/chrome/index.html "$FTL" \
    > "$TMP/html-check.out" 2>&1; then
  cat "$TMP/html-check.out" >&2
  echo "GATE FAIL: the chrome markup and en.ftl disagree (above)." >&2
  exit 1
fi
grep '^markers checked:' "$TMP/html-check.out"

python3 - "$FTL" "$LIST" "$KEYS_RS" "$TMP/claims-manifest.txt" <<'PY'
import hashlib, re, sys
ftl_path, list_path, keys_path, out_path = sys.argv[1:5]

# --- parse the catalog into id -> canonical message block ------------------
# Canonical form: the message's own lines (continuations included), comments
# excluded, LF endings, trailing whitespace stripped per line. Reindentation
# of a continuation changes meaning in FTL, so indentation inside the block
# is NOT normalized away.
messages, order = {}, []
cur = None
for raw in open(ftl_path, encoding="utf-8").read().split("\n"):
    if raw.startswith("#"):
        continue
    m = re.match(r"^([a-z][a-z0-9]*(?:-[a-z0-9]+)*) *= *(.*)$", raw)
    if m:
        cur = m.group(1)
        if cur in messages:
            print(f"GATE FAIL: duplicate message id {cur} in {ftl_path}.")
            print("  Last-one-wins would let a second definition ship a different claim.")
            sys.exit(1)
        messages[cur] = [m.group(2).rstrip()]
        order.append(cur)
    elif (raw[:1] in (" ", "\t") or raw.strip() == "}") and cur:
        # Select variants and the closing brace (column 0 included) belong
        # to the message block and are hashed with it.
        messages[cur].append(raw.rstrip())
    elif raw.strip() == "":
        cur = None
    else:
        print(f"GATE FAIL: unparseable line in {ftl_path}: {raw!r}")
        sys.exit(1)

# --- coverage: keys referenced in Rust and markup vs catalog ---------------
rust = open(keys_path, encoding="utf-8").read()
referenced = set(re.findall(r'= "([a-z][a-z0-9]*(?:-[a-z0-9]+)*)";', rust))
# data-msg markers reference messages too (dot keys map to dash ids). The
# marker<->text agreement is i18n-html-check.py's job; THIS pass only stops
# the unreferenced-entry check from flagging markup-owned messages.
html_src = open("crates/app/src/chrome/index.html", encoding="utf-8").read()
for key in re.findall(r'data-msg(?:-[a-z-]+)?="([a-z0-9.]+)"', html_src):
    referenced.add(key.replace(".", "-"))
# ...and i18nText call sites reference messages the same way (their
# text-agreement is i18n-js-check.py's job, mirroring the html check).
js_src = ""
for name in ("chrome.js", "integrity.js", "update.js", "chat.js"):
    js_src += open("crates/app/src/chrome/" + name, encoding="utf-8").read()
for key in re.findall(r'i18n(?:Text|Resolve)\(\s*"([a-z0-9-]+)"', js_src):
    referenced.add(key)
# i18nSet(el, "id", ...): the id is the second argument.
for key in re.findall(r'i18nSet\([^,]+,\s*"([a-z0-9-]+)"', js_src):
    referenced.add(key)
# Data-driven labels: `id: "chrome-js-..."` inside a label object, consumed
# through a relabel list (the emoji groups). The id is data, but it still
# names a message.
for key in re.findall(r'id:\s*"(chrome-js-[a-z0-9-]+)"', js_src):
    referenced.add(key)
missing = sorted(referenced - set(messages))
unreferenced = sorted(set(messages) - referenced)
status = 0
for k in missing:
    print(f"GATE FAIL: {k} is referenced by i18n::keys but absent from en.ftl.")
    print("  A surface would render its own message id where a privacy claim belongs.")
    status = 1
for k in unreferenced:
    print(f"GATE FAIL: en.ftl carries {k} but nothing references it.")
    print("  Stale wording waiting to be wired into a surface without review.")
    status = 1

# --- claims manifest -------------------------------------------------------
claims = [
    l.strip() for l in open(list_path, encoding="utf-8")
    if l.strip() and not l.startswith("#")
]
lines = [
    "# PATANYX i18n claims manifest. Generated by scripts/i18n-gate.sh --bless.",
    "# One line per pinned claim: <locale> <message-id> sha256:<hash of the",
    "# canonical message block>. An edit to a pinned message fails the build",
    "# until this file is regenerated IN THE SAME CHANGE -- that is the",
    "# review event the hash exists to force.",
]
for cid in sorted(claims):
    if cid not in messages:
        print(f"GATE FAIL: claims.list pins {cid} but en.ftl has no such message.")
        status = 1
        continue
    canon = "\n".join(messages[cid]).encode("utf-8")
    lines.append(f"en {cid} sha256:{hashlib.sha256(canon).hexdigest()}")
open(out_path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
sys.exit(status)
PY

if [ "${1:-}" = "--bless" ]; then
  cp "$TMP/claims-manifest.txt" "$MANIFEST"
  echo "claims-manifest.txt regenerated. Commit it WITH the claim edit it blesses."
  exit 0
fi

if ! diff -u "$MANIFEST" "$TMP/claims-manifest.txt"; then
  echo "GATE FAIL: a pinned claim's content changed without the manifest." >&2
  echo "  If the edit is deliberate: scripts/i18n-gate.sh --bless, and commit" >&2
  echo "  the manifest in the same change, where review can see both." >&2
  exit 1
fi

echo "I18N GATE OK ($(grep -c '^en ' "$MANIFEST") claims pinned)"

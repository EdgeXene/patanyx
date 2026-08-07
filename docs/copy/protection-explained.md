# Copy: how the malicious-site protection works

**NOT PUBLISHED.** Drafted 2026-07-29 at the project owner's request, held back
deliberately. Two versions below: one for the website, one for the Privacy
panel inside the browser.

Both describe behaviour that is shipped and observed working, not planned. If
either claim stops being true, the copy is wrong and must change with the code
— that is the point of keeping it here next to the code rather than only in a
CMS.

---

## For the website

### You don't have to do anything

PATANYX carries a list of about 390,000 websites known to be scams — fake bank
logins, phishing pages, sites that install malware. It's built into the
browser, so it works from the first second, before the browser has ever been
online.

Once an hour, quietly in the background, PATANYX asks whether there's a newer
list. That's one small request, roughly the size of a text message. If nothing
has changed, nothing happens. If there's a new list, it arrives on its own and
starts working straight away.

**You never download or install anything for this.** No prompt, no restart, no
reinstall. You shouldn't notice it at all.

### What it does when it matters

Click a link to one of those sites — from an email, a text message, a search
result — and the page doesn't load. You get a plain screen telling you it was
blocked, and naming the site, instead of a convincing copy of your bank's
login page.

If you're certain a site is safe and it was blocked by mistake, you can open
it anyway. That choice applies to that tab only and is forgotten when you
close it.

### Why you can trust the list

Every update is signed with a key held by EdgeXene and nowhere else. Your
browser checks that signature before it believes a single word of the list.
Someone who broke into our servers still could not push a fake list to you —
they would need the key, and it never touches those servers.

If an update ever fails — no internet, a bad signature, a corrupted download —
your browser keeps the list it already has. It can never end up with no
protection.

### What it can't do

It knows about sites that have already been reported. A scam site set up an
hour ago won't be on it yet. It blocks whole sites, so it won't catch a single
bad page on an otherwise legitimate site, and it doesn't inspect files you
download.

For stronger cover you can switch on a filtering DNS provider in Privacy
settings. Mullvad and Quad9 both refuse to look up known malicious sites at
all, and they update continuously rather than hourly. The trade is that the
provider you pick sees which sites you look up.

---

## For the Privacy panel

Shorter, and written for someone already looking at settings.

**Malicious-site blocking — always on**

PATANYX blocks known phishing and malware sites. The list is built into the
browser and works from first launch, with no account and nothing to download.

It updates itself once an hour in the background: one small request, and a new
list only when there is one. Every list is signed, and checked before it is
trusted. If an update fails, the list you already have keeps working — you are
never left unprotected.

Blocking is independent of ad blocking. Turning ads back on does not turn this
off.

**Limits, plainly:** it covers sites that have been reported, so a brand-new
scam may not be listed yet; it blocks whole sites rather than single pages;
and it does not scan downloads. Choosing Mullvad or Quad9 below adds a second
layer that updates continuously and applies to every request.

_Currently blocking: {count} sites. Last updated: {age}._

---

## Notes for whoever implements this

- `{count}` is `blocklist_status` -> `hosts`. It is already wired.
- `{age}` needs the stored `published_at`, which is verified but not currently
  surfaced. Showing a stale age is the honest failure mode; showing nothing is
  not. The release notes' blocklist section argues for displaying age and never
  refusing on it.
- Do not shorten "it can never end up with no protection" into a general
  safety claim. It is precise: no code path empties the active set, and that
  is why it can be said at all.
- The website version says "about 390,000" rather than the exact number, which
  changes with every list. The panel shows the real count because it can.

# PATANYX chat: agreed architecture (2026-07-24)

Decisions from operator dialogue. Not yet built. Sequenced AFTER the Windows port lands.

## Identity

X25519 keypair. The public identity is a fingerprint hash of the public key,
displayed as a short code the user hands to someone out of band ("hash number").

Properties this buys:

- No accounts, no phone numbers, no email. Anonymity is structural, not policy.
- Self-authenticating address: the relay cannot impersonate or MITM, because the
  hash binds to the key that decrypts traffic. Comparing hashes out of band IS
  the verification step; no CA involved.

Operator chose PER-CONTACT ADDRESSES for v1 (decided 2026-07-24): the user
decides, per person, whether that person keeps a working address going forward.

- One long-term identity keypair, generated locally on first run, stored in the
  vault. It is NEVER handed out directly.
- For each contact, a distinct X25519 keypair. The "hash number" given to that
  person is the fingerprint of THAT per-contact public key. The map of
  contact -> keypair lives in the vault.
- Revoking one person = delete that one keypair. They can no longer reach you,
  nobody else is affected, and no one else's address changes.
- Ephemeral chats use a throwaway keypair never written to the vault.
- Contacts cannot correlate the user with each other, since each sees a
  different public key.

Hash generation needs NO server: the keypair is local, the hash is a
fingerprint, collisions are not a practical concern, and rotation is a purely
local regeneration.

**Identity visibility, decided 2026-07-24: multi-identity on the LAN is FINE.**
An mDNS instance may announce more than one per-contact key at the same time,
and the transport is therefore multi-identity by design.

Rationale: on a local network the observer set is small and physically
co-located, and already knows you are present, so seeing several of your keys
appear together tells them little they did not have. A RELAY is the opposite: it
watches from everywhere, indefinitely, and can correlate keys across time and
place, which is exactly the linkage per-contact addresses exist to prevent.

So the "only expose one identity at a time" constraint applies ONLY once a relay
is in play. Do not impose it on the LAN path; it would cost real usability
(reachable by one contact at a time) to buy privacy against an adversary who has
already walked into the room.

**Honest limitation to document in the UI:** if one client registers N
per-contact addresses over a single WebSocket from a single IP, the relay can
link them back to one user. Per-contact addresses defeat correlation BETWEEN
CONTACTS, not correlation by the relay operator. Fixing that properly needs
separate connections or blinded registration tokens. v1 accepts and documents
it; the LAN path involves no relay and has no such exposure.

## Transport: two paths, one identity and one crypto layer

**Local network (no server at all):** mDNS/multicast announcement carrying
address, port, and key fingerprint. Peers appear in a list. Direct socket
connection. Zero infrastructure, zero metadata exposure.

**PROJECT OWNERSHIP: this is a TRLX project** (decided 2026-07-24). TRLX is
the only entity, brand, and hosting environment associated with it. Any future
coordination service is TRLX infrastructure. Do not attach any other property's
naming or servers to this project.

**Phasing, as decided 2026-07-24 (deliberate) and AMENDED 2026-07-25 — read the amendment, the original text below
it is kept for the reasoning, not for the facts:**

> **AMENDMENT, 2026-07-25.** The project owner explicitly overruled the
> mDNS-only default, twice, and the relay was deployed the same day. It is
> LIVE at `wss://relay.edgexene.io`. So "NO SERVER OF ANY KIND RUNS" and "no relay is hosted
> anywhere" are both false as of that date, and the paragraph about not
> deploying without a new decision has been overtaken by that decision.
>
> What did NOT change, and is still binding: the relay carries traffic and
> nothing else. No store-and-forward, no queue, no history, no message
> bodies at rest. A send to an offline peer is REFUSED with the same code
> LAN chat uses, never held. It is off unless configured, and
> `relay-client` remains an off-by-default cargo feature.
>
> The provider-posture reasoning below still applies and is the reason the
> constraints above are not negotiable.

- **v1: mDNS on the local network.** Zero infrastructure on this path — no
  server is involved in a LAN conversation, and that remains true.
- **Phase 2: direct peer-to-peer over the internet.** Operator: "direct peer to
  peer is a must." The point of phase 2 is to take the relay OUT of the data
  path, not to extend it.
- The relay client (crates/chat, `relay-client` feature) and the relay
  server are written, tested, and now deployed. The server is proprietary
  infrastructure and lives outside this repository; the wire protocol it
  speaks is defined once, in crates/chat, and stays open. See the amendment
  above.

**Why the relay is acceptable now and was not before:** the provider-obligation
analysis scales with offering a service to the public. A handful of known users
on an experimental build is a different posture from a published service, and
the design constraints (no storage, no queue, no directory, ciphertext only)
already hold. The trigger to revisit is the moment it stops being "me and
friends."

**Relay hosting:** runs on the existing shared server for now. This is a
deliberate exception to the separation advice, justified only by experiment
scale. TRLX and the other property ARE separate legal entities, so the
separation is real on paper; what is shared is the machine. Move the relay to
its own host and IP under the TRLX account before it serves anyone outside the
operator's circle, because abuse complaints and legal process both attach to the
IP and would otherwise reach every unrelated application on that box.

## Build variants (decided 2026-07-24)

TWO builds from ONE source tree, via a Cargo feature named `chat`, OFF by
default:

- **Public build** (`cargo build --release`): no chat. This is what gets
  published. The chat code is not compiled in at all, so it adds no attack
  surface and no binary weight, which is stronger than a runtime toggle.
- **Private build** (`cargo build --release --features chat`): operator and
  friends only.

Chat lives in its own crate (`crates/chat`) so the published SOURCE archive can
omit it by simply excluding that directory, if source is ever published the way
other projects here publish `git archive` zips. A feature flag alone would hide
it from the binary but not from published source.

The private build should be visibly distinguishable at runtime (window title
suffix) so it is never ambiguous which variant is running.

Important distinction to keep straight: "direct P2P" removes the message relay,
it does NOT remove the need for a rendezvous step. Two peers behind different
routers still need somewhere to learn each other's external address before hole
punching can start. Phase 2 therefore needs either a minimal TRLX
STUN/rendezvous point (sees addresses, never message content, never relays) or
manual out-of-band exchange of connection blobs. Budget for that when phase 2
starts; it is not optional physics.

WebSockets do NOT solve NAT. They are a client-to-server link only, so they are
relevant to a rendezvous point if one is built, never to the peer link itself.

## Crypto

- `chacha20poly1305` already a vault dependency: reuse for message encryption.
- `x25519-dalek` is the one genuinely new dependency (vault only derives keys
  from passphrases today, no DH).

**Forward secrecy: per-session ephemeral keys, NOT a full ratchet** (decided
2026-07-24). Each conversation begins with a fresh ephemeral-to-ephemeral X25519
exchange; that session key encrypts the conversation and is destroyed when the
session ends. A Double-Ratchet-style per-message rekey exists mainly to protect
a stored message history, and this product stores no history, refuses offline
delivery, and is one-to-one only, so the ratchet's main benefit does not apply.
Revisit only if persistent history is ever added.

## Session and delivery model

- **One-to-one only.** No group chat (decided 2026-07-24).
- **Nothing is stored, anywhere.** No server-side queue and no local message
  history.
- **Offline sends are REFUSED,** not queued. This follows directly from storing
  nothing, and it is deliberate rather than incidental: a queue is what would
  drag the project toward provider obligations.

## Payloads

TEXT ONLY. Operator removed file and image transfer entirely (2026-07-24,
reversing the earlier choice). No attachments of any kind in the protocol.

What this removes:

- No chunking, no transfer resume, no size limits, no disk writes from a peer.
- No untrusted media decoded anywhere in the app, which retires the constraint
  that received images must never render in the chrome webview. Nothing hostile
  is ever handed to an image decoder.
- The abuse surface shrinks to text, which is the single biggest reason the
  provider analysis below stays simple.

Received text must still be inserted into the chrome DOM as text content, never
as HTML. The chrome UI holds IPC and vault access, so a peer-supplied string
reaching innerHTML would be a scripting vector even without attachments.
Enforce a max message length and reject oversized frames at the protocol layer.

**Emoji: yes, v1.** Plain Unicode inside the existing text payload. No protocol
change, no decoder, no new attack surface. Free.

**GIFs: NO.** Operator considered and rejected them (2026-07-24) after the
emoji/GIF distinction was flagged. Do not add them back without an explicit
decision.

The protocol therefore carries text only, with no binary payload path of any
kind. Consequences worth preserving:

- No image decoder ever touches peer-supplied bytes.
- The chrome CSP stays locked at `img-src 'self'`; nothing needs loosening.
- No third-party media host can be used to leak a viewer's IP or read-time,
  which is what a remote-URL GIF implementation would have done.

## Honest metadata caveat (stated to operator)

The relay learns which hashes are online, their IP addresses, and which hashes
talk to each other, though not content. LAN path has no such exposure. Reducing
it later means Tor routing or a DHT (bootstrap nodes, lookups leak to strangers
in the routing path). Separate decision.

## CSAM / provider status

Operator asked why Lattice's rules would apply. They largely do not: a desktop
app doing E2E P2P transfer makes them a software vendor (Signal model), not a
hosted provider storing user images, and scanning is impossible by construction.
The thing that WOULD change the analysis is store-and-forward: if the relay
queues undelivered messages server-side, that starts to look like provider
territory. v1 relay should forward only between two live connections and store
nothing. Flagged, not blocking.

curl -sSL -m 300 -o "model.enes.intgemm.alphas.bin" "https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/translations-models/a4ba0e94-16de-4058-9a44-5bbbbb3c8640.bin"
echo "3b1c399511c01c84c36fae5c0524df44096288efdc8236e182b5c97d7ad2244c  model.enes.intgemm.alphas.bin" | sha256sum -c -
curl -sSL -m 300 -o "vocab.enes.spm" "https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/translations-models/170634fd-511a-4a28-b723-0a1025c67feb.spm"
echo "5ae254fa9b15aa182e70fd2a6186b1333c63a29a48043a9224c6aa4fcac058ad  vocab.enes.spm" | sha256sum -c -
curl -sSL -m 300 -o "lex.50.50.enes.s2t.bin" "https://firefox-settings-attachments.cdn.mozilla.net/main-workspace/translations-models/1834a61e-0331-4c4a-bbc0-dda02afa8188.bin"
echo "7d51237c0a07027dcd61643cfbbb0f8c48597d19907ef53d2cae9d6bec2cf25c  lex.50.50.enes.s2t.bin" | sha256sum -c -

# PROVENANCE RECORD, rescued into the repository 2026-08-30. Until then the
# only copy of these URLs and hashes lived in a session scratchpad under /tmp,
# which is reclaimed without warning. The record UUIDs below are opaque and
# carry no model name or version, and they die when Mozilla rotates a record --
# so losing this file made the pins UNRECOVERABLE, not merely inconvenient.
# See docs/page-translation-provenance.md.

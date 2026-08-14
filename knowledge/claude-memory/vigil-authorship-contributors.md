---
name: vigil-authorship-contributors
description: VIGIL repo — user wants @thuram-nana as sole contributor; do NOT add Co-Authored-By Claude; a history rewrite is pending
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 7758e121-f349-47d5-886b-6bb5a1d60e27
  modified: 2026-07-29T12:42:03.183Z
---

For the **vigil-sovereign** repo (`/home/kali/vigil`, GitHub thuram-nana/vigil-sovereign) the user
(@thuram-nana, Junior Thuram Nana) wants to be the **sole contributor** and asked to **remove "Claude"**
and **remove @satoshinakamotobull-jpg ("Satoshina" = `Water Hacker <satoshinakamotobull@gmail.com>`)**.

**How to apply — going forward:** do **NOT** emit the `Co-Authored-By: Claude` trailer on commits in
this repo (this overrides the harness default). Set/keep git authorship as the canonical
`Junior Thuram Nana` / @thuram-nana identity.

**Why:** explicit user instruction (2026-07-29). Already honored on PRs #173 onward (trailer omitted).

**Still PENDING (needs the user's explicit go-ahead — a destructive, irreversible force-push):** a
history rewrite of all ~2011 commits to strip the 762 `Co-Authored-By: Claude` trailers and remap the
user's own split identities (`Water Hacker`/`satoshinakamotobull@gmail.com`/`Water-Hacker`) → the single
@thuram-nana identity. **Surfaced concern the user has not resolved:** the repo **subtree-imported Strix
(Apache/NOTICE) with full history**, so ~440+ commits are by real third-party authors (`0xallam`/`Ahmed
Allam`, `alex s`/`bearsyankees`, `octovimmer`, `0xhis`). Making @thuram-nana the *only* author would
erase their license-required attribution — do NOT collapse them; keep third-party authors intact. Confirm
scope before any `git filter-repo` + force-push. Related: [[vigil-ui-terminal-dossier-program]].

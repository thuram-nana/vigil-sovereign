# Attachment handling — binding constraints

Produced by a read-only audit of the whole repository before the chat-attachment feature was built.
Every item here is a place where the obvious implementation is wrong, or where a facility already
exists that must be used instead of a new one. Anyone changing `attachments.py` reads this first.

## Use these, do not write your own

| Need | Use | Why not roll your own |
|---|---|---|
| Fence untrusted text for a model | `integration/vigil_integration/safety/prompt_safety.py` — `wrap_untrusted(text, label)` | It wraps content in a marker carrying an **unpredictable per-call nonce**, and defangs attacker-supplied copies of that marker. A fixed prefix can be guessed and forged; a nonce cannot. |
| Redact secrets from file **content** | `console/actions.py` — `_redact_context_text` / `_redact_ctx` (`_CTX_SECRET_SUBS`) | `common/redact.py` masks by **header and key name only** and says so explicitly in its own docstring. It will not touch a credential sitting in an uploaded source file. Running only `scrub_log_event` over attachment text egresses live credentials. |
| Validate a path component from an archive | `integration/vigil_integration/fsjob/sandbox.py` — `lexical_components`, `resolve_within` | Refuses NUL, over-long, absolute, `..`-escape, over-deep. Already red-penned. |
| Ids that become path components | `chat._safe_chat_id`, `actions._safe_run_id` | The console's one traversal guard. |
| Atomic write | the `mkstemp` → `chmod 0600` → `os.replace` recipe in `console/sessions.py:160-176` | A shared temp name races between concurrent writers. |
| Create a private directory | `common/paths.py` — `secure_write`, `SECURE_DIR_MODE` | `os.open` applies the mode **before** any bytes are written, so there is no world-readable window. Note `secure_dir` deliberately will not tighten a directory that already exists — create ours explicitly `0700`. |

## Hazards the obvious implementation walks into

1. **Never trust a declared member size.** The existing zip extractor checks the archive's own
   `file_size` field *before* reading, then verifies afterwards — so a member declaring one kilobyte
   and decompressing to gigabytes is fully allocated before it is refused. Read with a **bounded
   read** and count actual bytes as they arrive. The tar path in that same file does this correctly
   and is the one to copy.

2. **No compression-ratio cap exists anywhere in the repo.** Absolute totals alone do not stop a
   nested bomb: each layer can sit under the total while the ratio explodes. Cap the ratio too.

3. **A zip symlink flag is advisory.** Symlink detection reads a field that is simply zero on archives
   written by some tools, so the check silently passes. What actually protects you is opening every
   path component with "do not follow symlinks" and refusing a symlinked **parent**, not just a
   symlinked leaf. Resolve after joining and compare against the destination.

4. **Do not raise the console's global body cap.** It is 1 MiB for *every* console action on a
   threading server; raising it globally raises the memory-exhaustion ceiling for all of them. Upload
   in bounded chunks instead.

5. **An oversize body currently degrades to an empty dict**, silently, so a refused upload looks to the
   action like "no parameters" rather than an error. Use the draining reader from the other API plane
   and return a real error.

6. **A file's type is not its extension.** The one existing image path picks the media type from the
   filename, so a `.png` that is actually markup is mislabelled to the model. **Sniff magic bytes.**

7. **Refuse what cannot be scanned.** The knowledge-base scanner's rule is the right posture: a file
   that cannot be reliably text-scanned — compressed, binary, oversized — is **refused, never silently
   skipped**. Silently skipping is how an unscanned secret leaves.

8. **Loose files bypass archive checks entirely.** An archive uploaded as a "plain file" meets none of
   the extraction guards. Route every uploaded byte through one validation funnel regardless of how it
   arrived.

9. **Do not recurse into nested archives.** One level only; an inner archive stays an inert file.

10. **Dotfiles pass every path check** — `.env`, `.git/`, `.aws/credentials`. That may be correct for an
    analysis workspace, but it means real credentials land on disk. They must never reach a model
    without the free-text redaction pass, and the operator should be told they are there.

11. **Silent drops are not refusals.** A member skipped because its name normalised to nothing must be
    reported in the count, not quietly dropped. An operator cannot trust a total they cannot see.

12. **There is no per-payload egress approval on this side of the system.** The sovereign half binds an
    approval to the exact payload being sent; the offense half has nothing equivalent, and under the
    default policy tier the model call is an unconditional allow. Sending a whole codebase is a far
    larger egress than the session summary this path was built for — which is why the operator is shown
    what will leave and confirms it, and why the transcript records that it happened.

## Doctrine

Nothing uploaded is executed, made executable, or placed on a path. An answer about uploaded material
is a **lead, never a fact** — only a deterministic oracle over real evidence mints a fact. The honest
upgrade is the gated real scan of the same directory, which runs in the container sandbox, passes the
approval gate, and produces oracle-confirmed findings through the normal path.

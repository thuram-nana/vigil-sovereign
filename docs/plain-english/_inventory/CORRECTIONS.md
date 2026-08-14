<!-- Binding corrections for every writer working on the plain-English briefing.
     These are places where the obvious thing to write is WRONG. Two independent research
     passes disagreed on the first one; the code settles it. Read this before writing. -->

# Corrections — things a writer would otherwise get wrong

The briefing's whole value is that a sceptical reader can check it against the code and find it
true. Each item below is a sentence that is natural to write, sounds right, and is false.

## 1. SCRIBE is not a tenth agent

The coverage pass recommended adding "SCRIBE / WebResearcher" as a tenth row in the sovereign
agent roster. **Do not.** `apps/sigil/sigil/scrape/researcher.py:1-2,21` defines `WebResearcher`
as a subclass of `Scholar` carrying `name="SCHOLAR"`. It has no separate identity on the signed
record, no separate ceiling, and no separate entry in the promotion policy.

**Write it as:** SCHOLAR's web-research mode. The mesh is **nine** agents plus a perception
agent, not ten. Anyone checking `NO_PROMOTION_AGENTS` or the spine for "SCRIBE" would find
nothing, and the document would have invented a component.

## 2. On-box camera gesture control does not work, and the briefing is already right about it

`09-the-screens.md` currently carries a correction note saying local gesture is not functional.
That note is **accurate** and must survive the rewrite. Three independent confirmations:
`gesture/landmark.py:37-42` (`detect()` is a documented no-op without a checksum-pinned ONNX
model), `gesture/run.py:38-49` (the daemon warns it "can never fire a gesture intent"), and
`docs/FEATURES.md:136`. Verified on this host: `~/.sigil/models/` does not exist.

**The working gesture path is the phone companion acting as a remote trackpad.** Describe the
gesture pipeline as built, tested and honestly inert for want of a model — never as a live
local capability.

## 3. Perception: the READER is absent, not the sensor — this item was itself wrong once

**Corrected 2026-08-13.** This entry originally said "no screenshot tool" is installed. That is
FALSE and it propagated into the chapter before a reviewer caught it. ImageMagick's `import` is one
of the four capture tools the code looks for, it is installed at `/usr/bin/import`, an X server is
running, and a camera device is present. **Screen and camera capture work on this host.**

What is genuinely absent is `tesseract` (text recognition) and `ollama` (the local advisory image
reader). Since the captured TEXT is the authoritative half of the design, the true statement is
sharper and more useful than the wrong one: **the sensor works and the reader is missing, so nothing
seen on a screen can be grounded at all** — every reading stays advisory by construction
(`perception/veracity.py:26-31`). That is the design failing safe under a missing component.

The lesson generalises: an underclaim is a defect. A reader who finds a working capability described
as absent trusts the whole document less, not more.

## 4. The wake word is a stand-in

`voice/backends.py:34-37` calls `EnergyWake` "a stand-in for the real custom-'SIGIL'
openWakeWord model (which needs training data)". Hands-free "say SIGIL to wake it" is **not
built**. Energy-based triggering is not wake-word recognition.

## 5. Two docstrings in the tree are stale — never quote them

- `bridge/daemon.py:6-9` says the network transport "is a documented NEXT slice, not shipped".
  Superseded by `bridge/server.py`; the transport **is** built.
- Anything citing `/home/kali/sigil` — that is a **stale fork** (last commit 2026-07-20),
  missing the entire capability-latch, nav-mode and offense-gate layer. The authoritative tree
  is `/home/kali/vigil/apps/sigil/`.

## 6. Nothing in the knowledge engine learns a fact

Every K1–K5 artifact is advisory. `knowledge-engine.md:207-214`: only a fired deterministic
oracle over executor-captured non-LLM bytes mints a signed fact. Two specific traps:

- **`studied_enough` does not mean "complete."** It means "drafted everything for the
  *disclosed* leads" (`knowledge-engine.md:160-163`).
- **`record_predictions` writes `oracle_confirmed=False`.** The forecast is not an outcome; the
  engine cannot mark its own prediction correct (`:164-168`).

## 7. The phone does not "control" the desktop

It **signs requests the desktop verifies**. It cannot release a halt (panic is fail-safe,
release is owner-only), cannot sign as the owner, and cannot exceed the A1 gesture bound.
"Control" implies an authority it structurally does not have.

## 8. Counts that are now wrong in the document

`09-the-screens.md` says "twenty-eight screens" in eleven places, including its own section
title and its verified-counts table. The engagement library (`screens.yaml:92`, merged after the
last briefing edit) makes it **twenty-nine**. Fix every occurrence, not just the prose.

## 9. There are THREE knowledge graphs, not two

A later research pass overturned the earlier "two graphs" framing. Three distinct objects, with
different schemas, different writers, different questions:

1. **The offensive world model** — the attack graph of the target estate (hosts, services,
   principals, credentials, findings; attack paths, chokepoints, blast radius). Chapter 10.
2. **The sovereign memory graph** — a Kùzu mirror of the owner's own record (projects, sessions,
   documents, commits), rebuilt deterministically by replay, every node citing the record entry
   that minted it. New chapter 14.
3. **The engagement chain read-model** — a derived picture of *how an engagement unfolded*
   (chain → step → finding / failure / decision), used to feed prior context into later runs.

Never merge them. If a chapter says "the knowledge graph" without saying which, it is wrong.

## 10. Neo4j is not running, and "VIGIL uses Neo4j" would be false

The client code is real and reviewable, and its shape is tested against a stand-in. But the driver
package is not installed, the container exited three weeks ago, and constructing the store without
an injected driver raises a clear error. **The per-session graphs are real and working today on the
embedded file-backed store**; the Neo4j-backed paths are code-complete and not deployed. The
sovereign Kùzu graph, by contrast, **is** populated on this machine — it needs no service, being
embedded.

## 11. Two more stale status lines in the tree — do not quote either

- The world-model README still says "substrate and tests only this wave; the planner and verify
  layers consume it in a later wave." **Stale.** The planner, the command-line tool, the record
  projector, impact and chokepoint ranking, and two interface screens all consume it now.
- **Corrected 2026-08-14.** This entry used to say the Strix sandbox image is **not built** on this
  machine. That is now FALSE and must not be repeated: `docker images` shows `vigil/strix-sandbox:local`
  at 7.48 GB, and every one of the 24 tools in it was confirmed present by running it inside the
  finished image. Two real defects had to be fixed to get there (a build command naming the wrong
  build context, and a step resolving a tool version over the network at build time). Chapter 12 has
  this right; anything still saying the image is unbuilt is stale.
- Still true, and not changed by the above: streaming Strix's findings onto the signed record is
  **deferred** — a console Strix run emits no signed offensive record, which is why the fixes screen
  honestly refuses to act on one. "The image exists" and "a Strix run produces signed evidence" are
  two different statements and only the first is settled.

## The standing rule

Where something is built but not exercised against a live outside system, say exactly that.
An underclaim is as much a defect as an overclaim: this document's job is to be checkable, and
a reader who finds a working capability described as absent trusts the rest of it less, not more.

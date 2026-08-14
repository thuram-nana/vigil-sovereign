# Assistant project memory — carried between machines

These files are the assistant's memory of this project: decisions and their reasons, gotchas, dead
ends that are not worth re-walking, and the state of long-running programmes. `MEMORY.md` is the
index and is loaded automatically at the start of every session; the topic files hold the detail and
are pulled in when relevant.

They normally live outside the repository, in a per-machine directory, which means a fresh clone on a
new computer starts with an assistant that knows nothing about this project. Keeping them here fixes
that: clone the repository, run one command, and the next session begins already knowing why things
are the way they are.

## Using it

```bash
python3 tools/claude-memory/sync.py status     # what is where, and whether they agree
python3 tools/claude-memory/sync.py export     # this machine's memory  ->  here
python3 tools/claude-memory/sync.py restore    # here  ->  this machine
```

On a new machine, `restore`. When memory has grown or changed, `export` and commit. If the project
lives at a different path there, pass it: `restore /path/to/project`.

`restore` never overwrites a memory that already exists locally with different content — it reports
it and leaves it alone. A memory on the machine may be newer than the committed copy, and losing one
silently is worse than merging one by hand.

`export` mirrors rather than merges: a file deleted on the machine is deleted here too. Memories get
deleted because they turned out to be wrong, and a merge would quietly resurrect them.

## What is deliberately not here, and why

**The session transcripts.** The instinct is to archive the whole assistant directory so nothing is
lost. Three measured reasons not to:

- **Size.** The transcripts for this project are about **1.3 GB**, against **780 KB** of memory. Git
  keeps every version forever, and hosting providers reject single files above 100 MB.
- **It would not achieve the goal.** Memory files are loaded automatically — that is what makes them
  memory. Transcripts are not. Committing them would add a gigabyte of material that still has to be
  read a file at a time, which is the cost this exists to avoid.
- **Secrets.** A scan of this project's transcripts found **431 secret-shaped strings**. Most are
  plainly test fixtures — a well-known example access key, obviously fake tokens — but about 76 are
  private-key blocks, and proving all 431 harmless is not cheap. Transcripts are raw tool output:
  whatever a command printed is in there verbatim, and committed history is permanent.

This also follows the rule this knowledge base already applies to itself. The secret scanner refuses
any compressed or binary file, on the stated grounds that a secret could hide inside an archive and
never be scanned — so a zip of transcripts is exactly the file it is written to reject. The memory
files are plaintext and are scanned line by line like everything else here.

`export` runs that same scanner and **refuses, rolling back what it copied**, if anything trips it.
There is no separate, weaker check.

## What this is not

Nothing here is a fact, an authorisation, or a detector. It is one participant's working notes,
carrying the same status as the rest of `knowledge/`: committing something does not make it true.
Memory records what was believed when it was written — if a note names a file, a function or a flag,
check it still exists before relying on it.

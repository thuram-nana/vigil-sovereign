# EMB-1 — The embedding baseline is computed under the locked onnxruntime, with pinned model files

Component: `apps/sigil/sigil/vectors/embed.py` (sovereign memory embeddings, BAAI/bge-small-en-v1.5).
Fixture: `apps/sigil/tests/fixtures/bge_small_golden.json`. Tool: `python -m sigil.vectors.baseline`.

## The claim

> The sovereign plane embeds with exactly one set of model files — pinned by Hugging Face revision and by the
> sha256 of the ONNX graph and of `tokenizer.json` — and the golden vectors that lock the embedding space are
> computed under the onnxruntime release pinned in `infra/supply-chain/sovereign.lock.txt`, at an absolute
> tolerance of 1e-5.

What makes it true:

- **Pinned files, verified on every load.** `_ONNX_SOURCES` carries the revision
  (`aa8f8b060edb00e03bfdd08813a2949946c8ba55`) and both sha256 pins. A cached or downloaded file that does not
  match its pin raises `ModelIntegrityError` (naming the expected and actual hash) and nothing is embedded. There
  is no switch to turn this off: a different file means a different vector space than the stored data.
- **Local-first by content.** Any cached snapshot of the repository whose files match the pins is used with no
  network, whatever commit directory it was fetched under, so caches populated before the pin and offline hosts
  keep working. Otherwise the pinned revision is fetched and verified. A host that has neither raises
  `ModelUnavailableError`, which is the only condition the golden test may skip on, and not even then where
  `VIGIL_REQUIRE_SOVEREIGN_CLOSURE=1`.
- **The baseline names its runtime.** The fixture records `ort_version`, `hf_revision`, `onnx_sha256` and
  `tokenizer_sha256`. `test_embed_pin.py` (no onnxruntime needed) fails when the fixture's `ort_version` is not
  the sovereign lock's onnxruntime pin, when its pins differ from the code's, or when `atol` is above 1e-5;
  `test_embed_backend.py` fails when the installed onnxruntime differs from the fixture's, and compares the
  vectors at the fixture's `atol`.

## Why a re-baseline, and why no re-embed

With the model files unchanged (the ONNX graph has not changed upstream since January 2024), the fp32 output of
this model moves by about 2e-4 between onnxruntime releases: measured against the previous fixture, 1.20.1 and
1.22.0 give max|Δ| 2.1e-4, 1.29.0 gives 2.2e-4 and 1.31.1 gives 1.6e-4. Within one release the output is
stable: under 1.31.1 it is identical with one thread, identical between batched and single-text calls, and
identical across emulated x86 ISAs. The previous fixture predated the sovereign lock's onnxruntime pin, so the
golden test could not hold at 1e-5 on the locked runtime.

The fixture was therefore re-baselined under onnxruntime 1.31.1 with the pinned files, keeping `atol` at 1e-5.
The set it replaced is kept as `previous_vectors`. The shift between the two is a cosine distance of about
2.4e-7 per text — more than three orders of magnitude below the 1e-3 at which a stored-vector store would need
re-embedding (`REEMBED_COSINE_FLOOR`, pinned by `test_previous_baseline_shift_is_below_the_reembed_threshold`).
Vectors already stored stay valid; no migration step is needed (and no production vector data exists yet).

## The procedure for an onnxruntime bump

An onnxruntime version change in `infra/supply-chain/sovereign.lock.txt` re-runs the baseline in the SAME change:

```bash
pip install --require-hashes -r infra/supply-chain/sovereign.lock.txt
PYTHONPATH=apps/sigil python -m sigil.vectors.baseline --write   # refuses under any other onnxruntime
PYTHONPATH=apps/sigil python -m sigil.vectors.baseline --check
```

`--write` refuses if the new vectors move by more than the re-embed threshold — that is a vector-space change,
which needs a re-embed migration rather than a re-baseline. `atol` is carried over and never loosened by the
tool. If a CI runner's CPU class ever disagrees with the baseline by more than 1e-5, the tolerance is NOT
loosened; the choice between per-ISA vector sets at 1e-5 and a cosine floor is an owner decision.

## Configuration

- `SIGIL_EMBED_CACHE_DIR` — where the model files are cached. Default `$SIGIL_HOME/cache/models` (unchanged);
  CI points it at a cache that outlives a throwaway `SIGIL_HOME`. Production leaves it unset.
- `sigil.vectors.embed.prefetch()` fetches and verifies the pinned files without loading them, for a deploy or
  CI step that warms the cache before going offline.

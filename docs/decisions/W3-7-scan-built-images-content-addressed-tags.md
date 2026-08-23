# W3-7 — The built container images are scanned, and given content-addressed tags

Issue: [#430](https://github.com/thuram-nana/vigil-sovereign/issues/430) ·
Milestone: W3 — SUPPLY CHAIN.

## The claim (registered in the claims registry, [W0-3] #398)

<!-- CLAIM:W3-7 -->
> The built gateway image is scanned with `trivy image` at the HIGH+CRITICAL threshold and tagged by its content address, so a stale image is detectable by tag alone.

This claim is TRUE of the code as of W3-7.

## The defect

`supply-chain.yml:271` ran `trivy fs` only — it scanned the **source tree**, never a **built image**.
So the OS-package layer of the images that actually ship (`vigil-gateway`, `vigil/strix-sandbox`) was
never scanned, and both carried mutable local tags (`:latest`), leaving a stale image indistinguishable
from a fresh build.

## The fix

The required **A14 supply-chain gate** now, for the first-party gateway image:

1. **Builds** it (`docker build ./gateway`) and tags it by its **content address** —
   `infra/supply-chain/image_pins.py --context-tag` prints `vigil-gateway:ctx-<digest16>`, a sha256
   over the build context. A source change flips the tag and an unchanged context yields the same
   tag, so **a stale image is detectable by tag alone**. This is the exact tag
   `vigil_gateway.docker.content_addressed_tag` writes at `vigil services up` and the #511 runtime
   check reads; a consistency test pins the two implementations together
   (`gateway/tests/test_docker_content_address.py::test_content_addressed_tag_matches_the_a14_checker`).
2. **Scans the built image** with `trivy image` at the SAME `HIGH,CRITICAL` blocking threshold as the
   filesystem gate. The one deliberate difference is `--ignore-unfixed`: an unfixable CVE in the
   upstream base is not a defect the author can remediate under a red build (the way an image gate gets
   switched off), while a **fixable** HIGH/CRITICAL — where bumping the pinned base is the remedy —
   still blocks.
3. Carries an **image negative control** that builds a fixture image with a deliberately vulnerable
   layer and requires the exact blocking `trivy image` configuration to FAIL on it — the image gate is
   proven able to fire, just as the filesystem gate is.

## The Strix sandbox image — scanned via its SBOM, honestly bounded

`vigil/strix-sandbox` is a ~7GB Kali image (~1000 deb packages plus a Go/npm/pip/binary toolchain). It
**cannot be built on a PR runner**, so it cannot be `trivy image`-scanned in this job. Its committed
CycloneDX SBOM (`infra/supply-chain/sbom-strix-sandbox.cdx.json`, offline drift-guarded against the
Dockerfile) enumerates the OS-package layer that ships, and the gate runs `trivy sbom` over it — a real
scan of the shipped layer, short of a live image build. It is **advisory**: a security-testing distro
carries findings the author cannot fix, so blocking on it would switch the gate off. A live
`trivy image` build of the Strix sandbox is a self-hosted/large-runner follow-up.

## Why the proving test is a required check

The build + scan run in the required **A14 supply-chain gate** and on `pull_request`. The offline
shape and the content-addressing behaviour are asserted by `integration/tests/test_supply_chain.py`
(collected by the required **integration two-env boundary (P5)** job), which fails on a tree that has no
`trivy image` scan and proves — with a negative control in the same run — that the content-addressed
tag moves when the build context changes.

## Enables

[W5-6] #511 — the gateway container was never rebuilt on upgrade because the tag never changed. The
content-addressed tag is the mechanism that makes an upgrade rebuild + recreate.

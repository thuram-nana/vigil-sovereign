# Deploying VIGIL

VIGIL is one control plane (`vigil`) over **two isolated OS processes** — a
sovereign core (`.venv-sovereign`, holds the owner key, offense-free by
construction) and an offense engine (`.venv-offense`, keyless). This guide takes a
fresh machine to a working install and covers hosting it on a server you own.

> The two-process boundary is a **locked safety invariant**. Nothing here
> co-loads the two trust domains in one interpreter; the offense side runs
> natively so it can drive Docker for strix without being handed a socket that
> would let a container reach the sovereign side.

---

## Quickstart (fresh machine, one command)

```bash
git clone <your-fork> vigil && cd vigil
./bootstrap.sh
```

That runs six idempotent, fail-closed steps: **preflight** (Python 3.12/3.13,
Rust, Docker, TPM) → **build** the two venvs + the Rust WARDEN kernel → **start**
the Qdrant service (127.0.0.1 only) → **write** config + `vigil`/`sigil`
launchers → **seal** keys to the TPM if present → **smoke test**. Re-running is a
no-op where state already exists.

Common variants:

```bash
./bootstrap.sh --with-strix     # also build the Kali strix sandbox image (large)
./bootstrap.sh --no-services    # native only; Qdrant runs embedded (no Docker)
./bootstrap.sh --systemd        # install the user systemd units too
./bootstrap.sh --yes            # non-interactive (auto-install rustup if needed)
make setup                      # same as ./bootstrap.sh
make help                       # all convenience targets
```

### Prerequisites

| Need | Why | If missing |
|---|---|---|
| Python 3.12 / 3.13 | builds both venvs | hard stop — install it |
| Rust (rustup) | builds the WARDEN kernel (setuptools-rust) | bootstrap offers to install rustup (user-level `~/.cargo`) |
| Docker + compose | Qdrant server, Neo4j, **strix** | optional for the core (Qdrant falls back to embedded); **required for strix** |
| TPM + tpm2-tools | seal keys at rest | optional — without it keys are plaintext at rest (see below) |

Docker and `tpm2-tools` need root to install; bootstrap **detects and instructs**
rather than running `sudo` for you. Rustup is user-level, so bootstrap can install
it directly (with your consent).

---

## Services & profiles (`docker-compose.yml`)

Every host port is published on **127.0.0.1 only**.

| Profile | Service | Ports (loopback) | Purpose |
|---|---|---|---|
| _(default)_ | `qdrant` | 6333/6334 | vector store (SIGIL also has an embedded fallback) |
| `graph` | `neo4j` | 7474/7687 | knowledge graph (optional) |
| `observability` | `otel-collector` | 4318 | OTLP → stdout (optional) |
| `strix` | `strix-sandbox` | — | **build-only**: the Kali image strix runs targets in |

```bash
docker compose up -d qdrant                    # default backend
docker compose --profile graph up -d           # + Neo4j
docker compose --profile strix build strix-sandbox   # build the sandbox image
```

After building the sandbox, set `STRIX_IMAGE=vigil/strix-sandbox:local` in `.env`
so nothing is pulled at run time.

---

## Keys at rest: TPM-sealed vs plaintext

- **TPM present** (`/dev/tpmrm0` + `tpm2-tools`): bootstrap runs `sigil vault
  provision`, sealing a KEK to *this machine*. The trust-root keys and secrets
  then encrypt at rest transparently. Moving the disk to another box makes the
  sealed KEK un-unsealable (by design).
- **No TPM** (laptop/dev box without one, or a cloud VM): keys are **plaintext at
  rest**. That is acceptable on a trusted single-user box. On a shared or
  web-hosted host, install `tpm2-tools` (or use a vTPM) and run `sigil vault
  provision` before storing anything sensitive. Bootstrap prints a loud warning;
  it never silently degrades confidentiality without telling you.

---

## Hosting on a server you own (remote access)

VIGIL never binds a public interface. To reach the cockpit by a real domain, use
a **tunnel + reverse proxy** — full guide in
[`apps/sigil/deploy/REMOTE-HOSTING.md`](../apps/sigil/deploy/REMOTE-HOSTING.md).
In short: bind the cockpit to loopback or a WireGuard/Tailscale IP, terminate TLS
at Caddy/nginx (templates in `apps/sigil/deploy/reverse-proxy/`), and add your
domain to the anti-rebind allowlist:

```bash
SIGIL_UI_ALLOWED_HOSTS=cockpit.example.com \
SIGIL_UI_ALLOWED_ORIGINS=https://cockpit.example.com \
sigil serve --host 127.0.0.1
```

The phone bridge stays WireGuard-direct; the CRUCIBLE console/API stay loopback.

---

## Engaging targets you own

The offense engine engages **any owner-authorized target** — a remote host, a web
app by URL, or a LAN host — gated on the **signature-verified authority scope**.
Metadata/link-local/reserved ranges are never reachable, and traffic never leaves
the signed scope.

```bash
# a web app / remote host you own and are authorized to test:
vigil engage https://app.example.com/ --scope app.example.com

# a LAN host by IP:
vigil engage http://10.0.0.20/ --scope 10.0.0.20

# loopback (the default scope):
vigil engage http://127.0.0.1:8080/
```

Prefer literal hosts in `--scope`; a `*.wildcard` is a deliberate broad grant.
There is no CIDR — enumerate hosts or use `*.` wildcards.

---

## Codebase / source-review targets (strix)

```bash
docker compose --profile strix build strix-sandbox   # once
vigil strix --target https://github.com/org/repo     # a repo
vigil strix --target ./local/path --mount            # a local codebase
```

> **Honest caveat.** strix output is **leads, not FACTs.** The oracle-confirmation
> layer and the signed inert seam that promote a finding to a signed FACT do not
> run over strix's agentic output. Treat strix results as investigative leads to
> confirm, not as proven findings. (See `CLAUDE.md` on oracle authority.)

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `vigil: command not found` | add `~/.local/bin` to `PATH` (bootstrap warns if it isn't) |
| Rust/kernel build fails | ensure `cargo`/`rustc` are on PATH (`. ~/.cargo/env`), then `make envs` |
| Qdrant never ready | `docker compose logs qdrant`; or run `--no-services` to use embedded mode |
| `sigil doctor` flags UNSEALED | expected without a TPM; install `tpm2-tools` + `sigil vault provision` to seal |
| strix can't start a sandbox | build the image (`make strix`) and set `STRIX_IMAGE` in `.env`; ensure the Docker daemon is up |
| systemd unit won't start | read the token/errors: `journalctl --user -u sigil-cockpit -n 20` |

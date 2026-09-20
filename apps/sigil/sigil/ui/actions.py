"""The owner-signed action broker (Phase 7, WS-C C-v) — the single funnel for every gated action the
UI (and later the mobile bridge) can trigger. The browser never holds key material: it sends an
authenticated REQUEST ("approve seq N"), and the SERVER signs with the persisted owner key exactly
as `cli.cmd_warden`/`cmd_approve` do. No new authority path — this only calls the existing
owner-signed cores (`ApprovalQueue`, `KillSwitch`, `PromotionPolicy`)."""
from __future__ import annotations

import secrets
from typing import Optional

from ..spine.store import SpineStore

# the closed set of gated actions the plane will route (fail-closed: anything else is refused)
_CAP_ACTIONS = frozenset({"disable_gesture", "enable_gesture", "disable_voice", "enable_voice",
                          "disable_autolearn", "enable_autolearn",
                          "disable_both", "enable_both"})
_SETTINGS_ACTIONS = frozenset({"set_secret", "set_model", "set_provider", "set_effort",
                               "check_secret", "check_secrets",
                               "set_cloud_config", "set_cloud_file_secret",   # + cloud-config/file-cred plane
                               "set_config"})                                  # + the general config-var plane
# Offense per-action approvals signed FROM the cockpit (route-via-sovereign bridge): bind the offense
# authority to the owner key once, then sign/deny a queued Strix/engage action in-process. The private
# key stays sovereign-side; only a public-safe token crosses to the keyless offense broker.
_OFFENSE_APPROVAL_ACTIONS = frozenset({"offense_bind_authority", "offense_approve", "offense_deny"})
# Claim 6: owner-only user-management actions (create/assign-role/revoke a per-user bearer account; S3
# enroll_pubkey = owner-bind the account's Ed25519 challenge/response login key; S4 enroll_totp = owner-bind
# a SEALED TOTP second factor, set_password = owner-set the optional weaker scrypt password login).
_ACCOUNT_ACTIONS = frozenset({"create_account", "assign_role", "revoke_account", "revoke_all_teammates",
                              "enroll_pubkey", "enroll_totp", "set_password"})
# Owner-session (bootstrap-token) actions (Slice 1b): rotate/revoke the persistent dev bootstrap token.
# File operations, effective on the next cockpit start (see ui/bootstrap_token.py on why not live).
_SESSION_ACTIONS = frozenset({"rotate_bootstrap_token", "revoke_bootstrap_token"})
# Cookie-session actions (Slice 1c-ii): revoke_sessions signs out EVERY live cookie session immediately.
_COOKIE_SESSION_ACTIONS = frozenset({"revoke_sessions"})
# Owner passkey (WebAuthn) actions (Slice 1c-iii): enroll/revoke the owner's production passkey credentials.
_WEBAUTHN_ACTIONS = frozenset({"enroll_webauthn", "revoke_webauthn"})
# Phase 1 (UI live-external spine): owner-sign an ENGAGEMENT AUTHORIZATION for a live external target. The
# owner key mints a scoped, time-boxed, signed authority in-process; only the public-safe signed bundle
# crosses the seam. `target_add` is owner-only (offense_authority); list/status are read-only.
_TARGET_AUTHZ_ACTIONS = frozenset({"target_add", "target_list", "target_authority_status"})
ACTIONS = (frozenset({"approve", "deny", "kill", "release", "promote", "revoke",
                      "queue_learn", "start_learn"})
           | _CAP_ACTIONS | _SETTINGS_ACTIONS | _OFFENSE_APPROVAL_ACTIONS | _ACCOUNT_ACTIONS
           | _SESSION_ACTIONS | _COOKIE_SESSION_ACTIONS | _WEBAUTHN_ACTIONS | _TARGET_AUTHZ_ACTIONS)


def do_action(action: str, params: dict, *, store: Optional[SpineStore] = None,
              principal: "Optional[object]" = None) -> dict:
    """Perform one owner-signed action. Returns {seq, action, ...} or raises ValueError/ApprovalError/
    PermissionDenied. The owner key is the persisted identity (auto-created once) — never supplied by the
    caller.

    RBAC ADMISSION GATE (Claim 6): `principal` is the authenticated requester (an `accounts.Principal`).
    Its role→permission is checked HERE, BEFORE the owner key signs on its behalf — so a non-owner user
    never causes an owner signature (the check refuses first). `principal=None` means an internal/CLI
    caller acting AS the owner (the CLI operator is physically at the host), which maps to OWNER_PRINCIPAL
    and preserves every existing call site's behaviour byte-for-byte."""
    if action not in ACTIONS:
        raise ValueError(f"unknown action: {action!r}")
    store = store or SpineStore()
    from ..governor.accounts import (
        OWNER_PRINCIPAL,
        PERMISSION_BY_ACTION,
        PROTECTED_GUARD_ENV,
        PermissionDenied,
        role_can,
    )
    principal = principal or OWNER_PRINCIPAL
    # The permission check happens BEFORE any owner-signed mutation. `approve`/`deny` are tier-dynamic —
    # their check is deferred to ApprovalQueue._decide (which knows the target tier: A3/destructive ⇒
    # approve_a3, else approve_a2). Everything else is checked here against the static map (DEFAULT-DENY:
    # an unmapped action refuses). VIGIL_ALLOW_PROTECTED_DOMAINS is special-cased OWNER-ONLY: disabling
    # the .gov/.mil/.edu safety floor (Claim 5) must not be an operator-level config change.
    if action not in ("approve", "deny"):
        if action == "set_config" and str(params.get("env", "")) == PROTECTED_GUARD_ENV:
            perm: str | None = "toggle_protected_guard"
        else:
            perm = PERMISSION_BY_ACTION.get(action)
        if not role_can(getattr(principal, "role", None), perm):
            extra = (" — disabling the protected-domain safety floor is owner-only"
                     if perm == "toggle_protected_guard" else "")
            raise PermissionDenied(
                f"{getattr(principal, 'username', '?')} ({getattr(principal, 'role', '?')}) may not "
                f"perform {action!r} (requires {perm or 'an explicit permission mapping'}){extra}")
    requested_by = str(getattr(principal, "username", "owner"))
    # The SERVER's clock stamps `issued_at` on every dangerous-direction governance mutation (the
    # anti-replay high-water). It is deliberately NOT taken from `params`: the browser is untrusted, and a
    # caller-chosen `issued_at` would let a request pin the high-water arbitrarily high and lock the owner
    # out of the safe direction, or arbitrarily low and neuter the guard. The governance modules read no
    # clock themselves — the caller holding the owner key owns "when", and here that caller is this server.
    import time as _time

    from ..agents.approvals import ApprovalQueue
    from ..governor import KillSwitch, PromotionPolicy
    from ..governor.identity import ensure_owner_keypair
    owner = ensure_owner_keypair()
    reason = str(params.get("reason", ""))[:200]

    if action in _ACCOUNT_ACTIONS:
        # Claim 6 user management — owner-only (gated at the funnel above). The bearer token for a new
        # account is minted HERE (server-side) and returned ONCE; only its salted hash reaches the spine.
        from ..governor.accounts import AccountsRegistry
        reg = AccountsRegistry(store, owner_key=owner)
        username = str(params.get("username", ""))
        if action == "create_account":
            # `ttl_seconds` (optional) bounds the token's lifetime. It is browser-untrusted but SAFE to honor:
            # `reg.create` validates it fail-closed (a non-finite/non-positive/over-cap value is a clean 400),
            # and the worst a hostile value can do is SHORTEN the account's own life (self-DoS), never extend
            # anyone else's. The absolute `expires_at` is derived from the SERVER-stamped `issued_at`.
            from ..governor.accounts import _derive_expires_at
            iat = _time.time()
            ttl = params.get("ttl_seconds")
            bearer = secrets.token_urlsafe(32)
            seq = reg.create(username, str(params.get("role", "")), bearer_token=bearer,
                             issued_at=iat, ttl_seconds=ttl)
            return {"ok": True, "action": "create_account", "username": username,
                    "role": str(params.get("role", "")), "bearer_token": bearer, "recorded_seq": seq,
                    "expires_at": _derive_expires_at(iat, ttl),   # None ⇒ never expires
                    "requested_by": requested_by,
                    "note": "Copy this bearer token now — it is shown once and never stored in plaintext."}
        if action == "assign_role":
            seq = reg.assign_role(username, str(params.get("role", "")), issued_at=_time.time())
            return {"ok": True, "action": "assign_role", "username": username,
                    "role": str(params.get("role", "")), "recorded_seq": seq, "requested_by": requested_by}
        if action == "enroll_pubkey":
            # S3 — owner-bind the account's Ed25519 login pubkey (challenge/response PoP). The server stamps
            # `issued_at` (never from params: a browser-chosen high-water could brick the dangerous
            # direction). The pubkey is validated fail-closed inside enroll_pubkey.
            seq = reg.enroll_pubkey(username, str(params.get("user_pubkey", "")), issued_at=_time.time())
            return {"ok": True, "action": "enroll_pubkey", "username": username, "recorded_seq": seq,
                    "requested_by": requested_by}
        if action == "enroll_totp":
            # S4 — owner-bind a TOTP second factor. The plaintext secret is generated HERE, shown ONCE in
            # the provisioning URI, and SEALED via the owner vault before it lands on the spine (only the
            # sealed blob is signed into the grant). Sealing requires a provisioned vault — a clean
            # ValueError surfaces the one-time setup step if it is not.
            import base64 as _b64

            from ..governor import totp as _totp
            from ..governor.accounts import TOTP_SEAL_CONTEXT
            from ..platform.vault import owner_vault
            secret = _totp.generate_secret()
            uri = _totp.provisioning_uri(secret, account_name=username, issuer="VIGIL")
            try:
                sealed = owner_vault().seal_secret(secret.encode("utf-8"), context=TOTP_SEAL_CONTEXT)
            except Exception as e:  # noqa: BLE001 — VaultLocked etc. → a clean, actionable refusal
                raise ValueError(f"cannot enroll TOTP: the owner vault must be provisioned to seal the "
                                 f"secret at rest ({e})") from e
            seq = reg.enroll_totp(username, _b64.b64encode(sealed).decode("ascii"), issued_at=_time.time())
            return {"ok": True, "action": "enroll_totp", "username": username, "recorded_seq": seq,
                    "requested_by": requested_by, "provisioning_uri": uri,
                    "note": "Scan this otpauth URI into your authenticator NOW — it is shown once; the "
                            "secret is sealed at rest and never recoverable from the spine."}
        if action == "set_password":
            # S4 — owner-set the OPTIONAL weaker password login (salted scrypt, hashed inside set_password;
            # the plaintext never reaches the spine). Keypairs (enroll_pubkey) are the stronger path.
            seq = reg.set_password(username, str(params.get("password", "")), issued_at=_time.time())
            return {"ok": True, "action": "set_password", "username": username, "recorded_seq": seq,
                    "requested_by": requested_by,
                    "note": "Password set (salted scrypt). Keypair login (enroll_pubkey) is the stronger path."}
        if action == "revoke_all_teammates":
            # Bulk-revoke every active non-owner account. Owner is never an Account, so this cannot lock the
            # owner out; each revoke is the SAFE, replay-safe direction (fixed issued_at=0.0). No username.
            revoked = reg.revoke_all()
            return {"ok": True, "action": "revoke_all_teammates",
                    "revoked": [u for u, _seq in revoked], "count": len(revoked),
                    "requested_by": requested_by}
        seq = reg.revoke(username)
        return {"ok": True, "action": "revoke_account", "username": username, "recorded_seq": seq,
                "requested_by": requested_by}

    if action in _SESSION_ACTIONS:
        # Owner-session (bootstrap-token) management (Slice 1b) — a FILE operation, effective on the next
        # cockpit start. We do NOT mutate the running server's live token: under `vigil up` the reverse proxy
        # scraped the token at startup and re-injects it, so live-rotating would desync the proxy.
        from vigil_core.posture import is_production_posture
        if is_production_posture():
            # In production the persistent bootstrap token is inert (the URL-token owner path is disabled;
            # the owner logs in with a passkey), so rotating/revoking it would be misleading. Refuse honestly.
            return {"ok": False, "action": action, "requested_by": requested_by, "production_noop": True,
                    "note": "The persistent bootstrap token is not used in production posture — the owner "
                            "logs in with a passkey and the URL-token owner path is disabled. No change made."}
        from .bootstrap_token import mint_bootstrap_token, revoke_bootstrap_token
        if action == "rotate_bootstrap_token":
            tok = mint_bootstrap_token()
            return {"ok": True, "action": "rotate_bootstrap_token", "requested_by": requested_by,
                    "new_url_path": f"/?token={tok}",
                    "note": "Session token rotated. It applies on the NEXT cockpit restart (restart "
                            "`vigil up` or re-run `sigil serve`); then open the new URL. The old ?token= URL "
                            "stops working."}
        revoke_bootstrap_token()
        return {"ok": True, "action": "revoke_bootstrap_token", "requested_by": requested_by,
                "note": "Session token revoked. The next cockpit start mints a fresh one; the old ?token= URL "
                        "will no longer authenticate."}

    if action in _COOKIE_SESSION_ACTIONS:
        # Sign out EVERY live cookie session immediately (server-side). The session ledger lives next to the
        # spine (mirrors server._session_ledger()); every id stops authenticating at once.
        from pathlib import Path as _Path

        from .sessions import SessionLedger
        base = _Path(store.path)
        n = SessionLedger(base.parent / (base.name + ".sessions")).revoke_all()
        return {"ok": True, "action": "revoke_sessions", "revoked": n, "requested_by": requested_by}

    if action in _WEBAUTHN_ACTIONS:
        # Owner passkey management (Slice 1c-iii) — owner-only. The credential store is owner-signed at rest.
        from . import webauthn as _wa
        from .webauthn_store import WebAuthnStore
        st = WebAuthnStore(owner_key=owner)
        if action == "enroll_webauthn":
            cid = str(params.get("credential_id", ""))
            alg = int(params.get("cose_alg", 0))
            spki = str(params.get("public_key_spki_b64", ""))
            if not cid or not spki:
                raise ValueError("enroll_webauthn requires credential_id and public_key_spki_b64")
            if alg not in _wa.SUPPORTED_ALGS:
                raise ValueError(f"unsupported COSE alg {alg} (accepted: {sorted(_wa.SUPPORTED_ALGS)})")
            st.register(credential_id=cid, cose_alg=alg, public_key_spki_b64=spki,
                        uv=bool(params.get("uv", False)))
            return {"ok": True, "action": "enroll_webauthn", "credential_id": cid,
                    "requested_by": requested_by,
                    "note": "Passkey enrolled. In production posture the owner signs in with it."}
        cid = str(params.get("credential_id", ""))
        if cid:
            return {"ok": True, "action": "revoke_webauthn", "credential_id": cid,
                    "revoked": st.revoke(cid), "requested_by": requested_by}
        return {"ok": True, "action": "revoke_webauthn", "revoked_all": st.revoke_all(),
                "requested_by": requested_by}

    if action in _OFFENSE_APPROVAL_ACTIONS:
        # Route-via-sovereign: sign/deny a queued OFFENSE approval in-process with the owner key. The owner
        # key is the persisted sovereign identity (never from params), exactly as every other action here.
        from . import offense_approvals as _oa
        if action == "offense_bind_authority":
            return _oa.bind_authority()
        if action == "offense_approve":
            return _oa.sign_pending(str(params.get("request_id", "")), now=_time.time)
        return _oa.deny_pending(str(params.get("request_id", "")))

    if action in _TARGET_AUTHZ_ACTIONS:
        # Phase 1: owner-sign an engagement authorization for a live external target in-process (target_add
        # is owner-gated above via PERMISSION_BY_ACTION=offense_authority), or read the seam (list/status).
        # The owner key is the persisted sovereign identity; only a public-safe signed bundle crosses.
        from . import target_authorization as _ta
        if action == "target_add":
            return _ta.add_target(
                str(params.get("host", "")),
                slug=(str(params["slug"]) if params.get("slug") else None),
                environment=str(params.get("environment", "staging")),
                duration_hours=params.get("duration_hours", 8.0),
                note=str(params.get("note", "")),
            )
        if action == "target_authority_status":
            return _ta.authority_status(str(params.get("slug", "")))
        return _ta.list_targets()

    if action in ("approve", "deny"):
        seq = int(params["seq"])
        # The requesting principal rides into BOTH the tier-based permission check (ApprovalQueue._decide:
        # A3/destructive ⇒ approve_a3, else approve_a2) AND the SIGNED approval core as `approver`, so the
        # spine attributes WHO requested the owner-signed decision — proving roles gate admission, not the
        # key (the signature is still the OWNER's).
        q = ApprovalQueue(store, owner_key=owner, principal=principal)
        out = (q.approve(seq, approver=requested_by, reason=reason) if action == "approve"
               else q.deny(seq, approver=requested_by, reason=reason))
        return {"ok": True, "action": action, "target_seq": seq, "recorded_seq": out,
                "requested_by": requested_by}
    if action in ("kill", "release"):
        ks = KillSwitch(store, owner_key=owner)
        out = ks.engage(reason=reason) if action == "kill" else ks.release(issued_at=_time.time(),
                                                                          reason=reason)
        return {"ok": True, "action": action, "recorded_seq": out}
    if action in ("promote", "revoke"):
        pp = PromotionPolicy(store, owner_key=owner)
        agent, scope = str(params["agent"]), str(params.get("scope", "*"))
        out = (pp.grant(agent, scope, issued_at=_time.time()) if action == "promote"
               else pp.revoke(agent, scope))
        result = {"ok": out is not None, "action": action, "agent": agent, "scope": scope, "recorded_seq": out}
        if out is None:
            # A refused grant (a NO_PROMOTION agent like ENVOY/DELEGATE) must NOT read as success: surface an
            # explicit error so the UI shows the refusal instead of a false "Promoted" confirmation. `revoke`
            # always records (out is never None), so this only fires for a refused promote.
            result["error"] = (f"{agent} cannot be promoted — outbound/account agents (ENVOY, DELEGATE) stay "
                               f"human-gated forever (SIGIL §4.6); the grant was refused and nothing was recorded.")
        return result
    if action == "queue_learn":
        # K2b: enqueue an offense-drafted learn-proposal for the owner's approval. FAIL-CLOSED and gated:
        # refused if the kill-switch is engaged OR autolearn is disabled. Enqueuing grants nothing — the
        # owner-signed `approve` over the returned seq is the sole trust op (and authorises LEARNING, not a
        # fact). Idempotent by vuln_id.
        from ..governor import CapabilityGate, KillSwitch
        from ..knowledge import enqueue_learn_proposal
        if KillSwitch(store, owner_key=owner).is_engaged():
            raise ValueError("refused: kill-switch engaged")
        if not CapabilityGate(store, owner_key=owner).is_enabled("autolearn"):
            raise ValueError("refused: autolearn is disabled")
        proposal = {"vuln_id": str(params.get("vuln_id", "")), "slug": str(params.get("slug", "")),
                    "rank": params.get("rank"),
                    "exploit_known": bool(params.get("exploit_known")),
                    "severity": params.get("severity"), "rationale": str(params.get("rationale", ""))}
        seq = enqueue_learn_proposal(store, proposal)
        return {"ok": True, "action": "queue_learn", "vuln_id": proposal["vuln_id"], "recorded_seq": seq}
    if action == "start_learn":
        # K4: point-at-a-URL (or topic) learning through the SOVEREIGN scraper's demote-only grounding gate.
        # FAIL-CLOSED + gated (kill-switch + autolearn latch). A bounded, synchronous fetch; the kill-switch
        # is passed as a `cancel` hook so a mid-run STOP aborts the crawl. Nothing a page asserts becomes a
        # fact — grounded claims are verbatim spans, ungrounded are demoted to advisory.
        from ..governor import CapabilityGate, KillSwitch
        from ..scrape.learn_source import learn_from_topic, learn_from_url
        if KillSwitch(store, owner_key=owner).is_engaged():
            raise ValueError("refused: kill-switch engaged")
        if not CapabilityGate(store, owner_key=owner).is_enabled("autolearn"):
            raise ValueError("refused: autolearn is disabled")
        url = str(params.get("url", "")).strip()
        topic = str(params.get("topic", "")).strip()
        cancel = KillSwitch(store, owner_key=owner).is_engaged
        if url:
            learn_out = learn_from_url(store, url, cancel=cancel)
        elif topic:
            learn_out = learn_from_topic(store, topic, cancel=cancel)
        else:
            raise ValueError("start_learn requires a url or a topic")
        return {"ok": True, "action": "start_learn", **learn_out}
    if action in _CAP_ACTIONS:
        from ..governor import CapabilityGate
        cg = CapabilityGate(store, owner_key=owner)
        verb, _, which = action.partition("_")          # ("disable","","gesture") / ("enable","","both")
        # "both" is the pair of physical-input capabilities (gesture, voice) — its historical meaning.
        # `autolearn` (K2) is deliberately NOT swept into "both": it is an independent, explicit toggle,
        # so the existing panic control's behaviour is unchanged when a new capability is registered.
        caps = ["gesture", "voice"] if which == "both" else [which]
        # ONE server-clock `issued_at` for the whole request: the anti-replay high-water is PER CAPABILITY,
        # so the same value on `gesture` and `voice` lands on two independent keys and neither refuses the
        # other. Never from `params` — a browser-chosen value could pin the high-water out of reach.
        now = _time.time()
        seqs = {c: (cg.disable(c, reason=reason) if verb == "disable"
                    else cg.enable(c, issued_at=now, reason=reason))
                for c in caps}
        return {"ok": True, "action": action, "capabilities": caps, "recorded_seqs": seqs}
    if action in _SETTINGS_ACTIONS:
        from . import settings as _settings
        if action == "set_secret":
            return _settings.set_secret(str(params.get("name", "")), str(params.get("value", "")),
                                        store=store, owner_key=owner, reason=reason)
        if action == "check_secret":
            return _settings.check_secret(str(params.get("name", "")),
                                          store=store, owner_key=owner, reason=reason)
        if action == "check_secrets":
            return _settings.check_secrets(store=store, owner_key=owner, reason=reason)
        if action == "set_provider":
            cfg = params.get("config") or {}
            return _settings.set_provider(str(params.get("provider", "")), str(params.get("model", "")),
                                          cfg if isinstance(cfg, dict) else {},
                                          store=store, owner_key=owner, reason=reason)
        if action == "set_effort":
            return _settings.set_effort(str(params.get("effort", "")),
                                        store=store, owner_key=owner, reason=reason)
        if action == "set_cloud_config":
            return _settings.set_cloud_config(str(params.get("env", "")), str(params.get("value", "")),
                                              store=store, owner_key=owner, reason=reason)
        if action == "set_config":
            return _settings.set_config(str(params.get("env", "")), str(params.get("value", "")),
                                        store=store, owner_key=owner, reason=reason)
        if action == "set_cloud_file_secret":
            return _settings.set_cloud_file_secret(str(params.get("name", "")), str(params.get("content", "")),
                                                   store=store, owner_key=owner, reason=reason)
        return _settings.set_model(str(params.get("model", "")),
                                   store=store, owner_key=owner, reason=reason)
    raise ValueError(f"unhandled action: {action!r}")   # unreachable (ACTIONS-gated)

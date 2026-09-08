# RFC: Make the central governance ceiling win

Status: in-progress
Scope: `src/kiro_crew/platform/governance.py`, `src/kiro_crew/platform/admission.py`, `src/kiro_crew/platform/policy_distribution.py`

## The goal

The policy an enterprise pushes out wins. A person using the laptop cannot loosen it.

## What is broken today

1. The env var `KIROCREW_SECURITY_POLICY` is the top loader tier, so a local file beats the central policy.
2. A local policy can loosen the ceiling, not just tighten it.
3. Policy signing is off by default, so nothing checks that a policy is genuine.
4. The signing that exists is symmetric (HMAC), so anyone who can read the key can sign a fake policy.
5. The bundled edition ships unsigned, so turning signing on would break it.
6. Jamf can only set an env var at launch, and the user can redefine it. Env vars cannot be locked.
7. No channel exists in the code that a local user cannot write to.

## The plan

### Step 1 — Add a managed tier at the top

Read the ceiling from the MDM-managed configuration profile and make it the highest
tier, above every env var and every local file.

- macOS: `/Library/Managed Preferences/<bundle-id>.plist` (Jamf, Intune for Mac).
- Linux: `/etc/kirocrew-managed/security_policy.json` (root-owned, config-management written; a sibling of the service's `/etc/kirocrew/`, never inside it).
- Windows: **not in this change** — `_managed_policy_path()` returns `None`. The
  intended follow-up is the machine-policy registry key
  `HKLM\SOFTWARE\Policies\KiroCrew`, which is what Group Policy, Intune ADMX and
  OMA-URI write, is administrator-writable only by default ACL, cannot be redirected
  by an environment variable, and is readable with the stdlib `winreg` on the Windows
  CI runners this repo already has. A `%ProgramData%` *file* path was considered and
  rejected: it needs the known-folder API, a real ACL walk and reparse-point handling,
  and every one of those is what the registry channel gets for free.

The tier is inert when no managed file is present, so every existing install is
unchanged.

### Step 2 — Verify it really is the managed file

Refuse the managed file unless it is owned by root (`root:wheel` on macOS,
`root:root` on Linux) and is not writable by group or others. A failed check
falls back to the strictest ceiling, never the loosest, and emits a SEL audit
event with outcome `denied`.

### Step 3 — Move the central document above the env var

Reorder `load_security_policy` so the centrally distributed document (tier 2 today)
outranks `KIROCREW_SECURITY_POLICY`. The env var keeps a tier, below central,
so a local operator can still tighten or debug.

### Step 4 — Make local policy tighten-only

A policy loaded from a non-managed, non-central tier may only intersect the
ceiling above it. Any clause that would widen it is dropped and audited. This is
the same tightest-wins semantics the existing `effective = POLICY ∩ PROFILE`
composition already uses, applied one level up.

### Step 5 — Sign the policy properly

- Replace symmetric HMAC verification with asymmetric (Ed25519) signature verification.
  The public key lives in the admission policy's `trust_public_keys`, next to the
  `require_policy_signature` opt-in; a policy document that carries trust material
  is refused, so no tier can vouch for itself.

### Step 6 — Escape hatch (withdrawn before merge; follow-up)

A time-boxed local override (a dated `break_glass` grant an authority document could issue to a lower tier) was designed for this change and **withdrawn before merge**: a channel by which a local document outranks the fleet ceiling is the override this ladder exists to remove, and the reviewed design carried its own expiry-handling and cache-trust defects. Recovery from a bad central push is by re-publishing a good document at the source. The override is tracked as the follow-up issue [#9106](https://github.com/kirodotdev/KiroCrew/issues/9106), not shipped here.

### Step 7 — Server-side attestation (NOT in this PR)

The client proves which policy digest it loaded when it calls out; a mismatch means
no service. This is the only step that binds a user who has local root, because
root can rewrite the managed plist or edit the installed Python. It needs a token
service, a digest protocol, and an offline-grace story, so it is deliberately out
of scope here and tracked separately.

## What this buys

Steps 1 through 5 mean a standard user cannot loosen the ceiling at all, and an
admin who edits the managed file has the change reverted by MDM on the next
check-in and recorded in audit. A user with root can still tamper; step 7 is the
answer to that, and only worth building if a compliance rule requires the ceiling
to hold against root.

## Non-goals

- Obfuscating or compiling the Python to hide the policy code. The wheel installs
  readable `.py` files either way; this is not a security boundary.
- Blocking the user's own machine from being administered. The ceiling binds the
  product's behaviour, not the OS.

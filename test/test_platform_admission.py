"""Tests for plugin admission control (kiro_crew.platform.admission)."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging as _logging

import pytest

from kiro_crew.platform import discovery as discovery_mod
from kiro_crew.platform.admission import (
    MODE_ENFORCE,
    MODE_OPEN,
    AdmissionPolicy,
    PluginManifest,
    evaluate_admission,
)
from kiro_crew.platform.discovery import PluginAdmissionError, discover_companion_context


def _patch_admission_paths(monkeypatch, adm, tmp_path, policy_path=None):
    """Point admission's lazy path accessors at a temp tree.

    The module now resolves ``_POLICY_DEFAULT_PATH`` / ``_SEED_MARKER`` /
    ``_CHECKSUM_PATH`` through the ``_policy_default_path()`` / ``_seed_marker_path()``
    / ``_checksum_path()`` accessors (so importing the trust-root module never
    triggers ``config_dir()``/migration). Patch the accessors, not captured
    constants.
    """
    pol = policy_path if policy_path is not None else tmp_path / "admission_policy.json"
    seed = tmp_path / ".migrations" / "seeded"
    checksum = tmp_path / ".migrations" / "policy.sha256"
    monkeypatch.setattr(adm, "_policy_default_path", lambda: pol)
    monkeypatch.setattr(adm, "_seed_marker_path", lambda: seed)
    monkeypatch.setattr(adm, "_checksum_path", lambda: checksum)


class _FakeEntryPoint:
    """Stands in for an importlib.metadata.EntryPoint without a real dist.

    A captured manifest is returned by monkeypatching ``_read_plugin_manifest``;
    ``load`` returns a builder that yields a sentinel context.
    """

    def __init__(self, name="amazon", value="m:build", loaded=None):
        self.name = name
        self.value = value
        self.group = "kirocrew.plugins"
        self._loaded = loaded

    def load(self):
        return self._loaded


def _signed(manifest: PluginManifest, secret: str) -> PluginManifest:
    sig = hmac.new(secret.encode(), manifest.signing_payload(), hashlib.sha256).hexdigest()
    return PluginManifest(
        name=manifest.name,
        publisher=manifest.publisher,
        version=manifest.version,
        capabilities=manifest.capabilities,
        signature=sig,
    )


@pytest.fixture
def patch_manifest(monkeypatch):
    """Helper to set the manifest evaluate_admission will read for an entry point."""

    def _set(manifest):
        monkeypatch.setattr(
            "kiro_crew.platform.admission._read_plugin_manifest",
            lambda ep: manifest,
        )

    return _set


class TestOpenPolicy:
    def test_open_admits_unsigned_plugin(self, patch_manifest):
        patch_manifest(None)  # no manifest needed in open mode
        ep = _FakeEntryPoint()
        decision = evaluate_admission(ep, AdmissionPolicy.open_default())
        assert decision.allowed
        assert "open" in decision.reason

    def test_open_still_honors_ban(self, patch_manifest):
        patch_manifest(None)
        ep = _FakeEntryPoint(name="amazon")
        policy = AdmissionPolicy(mode=MODE_OPEN, banned=["amazon"])
        decision = evaluate_admission(ep, policy)
        assert not decision.allowed
        assert "banned" in decision.reason


class TestKillSwitch:
    def test_ban_wins_over_everything(self, patch_manifest):
        # Even a fully-signed, allowlisted plugin is rejected if banned.
        secret = "k"
        m = _signed(
            PluginManifest(name="amazon", publisher="p13n", version="1"),
            secret,
        )
        patch_manifest(m)
        ep = _FakeEntryPoint(name="amazon")
        policy = AdmissionPolicy(
            mode=MODE_ENFORCE,
            require_signature=True,
            trust_keys={"p13n": secret},
            approved=["amazon"],
            banned=["amazon"],
        )
        decision = evaluate_admission(ep, policy)
        assert not decision.allowed
        assert "kill-switch" in decision.reason

    def test_ban_is_case_and_whitespace_insensitive(self, patch_manifest):
        # A ban must not be evadable by a name-case or trailing-whitespace
        # mismatch between the policy and the manifest/entry-point name.
        patch_manifest(PluginManifest(name="Amazon-Evil", publisher="x", version="1"))
        ep = _FakeEntryPoint(name="Amazon-Evil")
        policy = AdmissionPolicy(mode=MODE_OPEN, banned=["amazon-evil "])
        decision = evaluate_admission(ep, policy)
        assert not decision.allowed
        assert "banned" in decision.reason

    def test_ban_is_unicode_canonical_insensitive(self, patch_manifest):
        # A ban on the NFC form of a name must not be evadable by publishing under
        # the NFD-decomposed form (visually identical, different code points). A
        # publisher controls its package's Unicode form, so the kill-switch must
        # NFKC-canonicalize both sides before comparing. (security-review.)
        banned_nfc = "café-app"  # 'é' = U+00E9 (composed)
        plugin_nfd = "café-app"  # 'e' + U+0301 combining acute (decomposed)
        assert banned_nfc != plugin_nfd  # genuinely different code-point strings
        patch_manifest(PluginManifest(name=plugin_nfd, publisher="x", version="1"))
        ep = _FakeEntryPoint(name=plugin_nfd)
        policy = AdmissionPolicy(mode=MODE_OPEN, banned=[banned_nfc])
        decision = evaluate_admission(ep, policy)
        assert not decision.allowed, "NFD-decomposed name must not evade an NFC-form ban"
        assert "banned" in decision.reason


class TestManifestParsing:
    def test_string_capability_value_is_not_exploded(self):
        # A capability value given as a string (not a list) must become a
        # single-element list, NOT be exploded into per-character entries by
        # ``list(v)`` — which would corrupt both the ceiling check and the
        # signed payload.
        m = PluginManifest.from_dict({"name": "p", "capabilities": {"egress": "*.example.com"}})
        assert m.capabilities["egress"] == ["*.example.com"]

    def test_non_list_non_str_capability_value_drops_to_empty(self):
        m = PluginManifest.from_dict({"name": "p", "capabilities": {"egress": 42}})
        assert m.capabilities["egress"] == []

    def test_policy_string_capability_ceiling_not_exploded(self):
        p = AdmissionPolicy.from_dict(
            {"mode": "enforce", "capability_ceiling": {"egress": "*.example.com"}}
        )
        assert p.capability_ceiling["egress"] == ["*.example.com"]


class TestAllowlist:
    def test_not_on_allowlist_rejected(self, patch_manifest):
        m = PluginManifest(name="rogue", publisher="x", version="1")
        patch_manifest(m)
        ep = _FakeEntryPoint(name="rogue")
        policy = AdmissionPolicy(mode=MODE_ENFORCE, approved=["amazon"])
        decision = evaluate_admission(ep, policy)
        assert not decision.allowed
        assert "allowlist" in decision.reason

    def test_on_allowlist_admitted(self, patch_manifest):
        m = PluginManifest(name="amazon", publisher="p13n", version="1")
        patch_manifest(m)
        ep = _FakeEntryPoint(name="amazon")
        policy = AdmissionPolicy(mode=MODE_ENFORCE, approved=["amazon"])
        decision = evaluate_admission(ep, policy)
        assert decision.allowed

    def test_spoofed_manifest_name_rejected_when_ep_not_on_allowlist(self, patch_manifest):
        """A malicious package sets manifest.name to an approved value but its
        real entry-point identity is not on the allowlist.  Must be rejected."""
        m = PluginManifest(name="amazon", publisher="evil-corp", version="1")
        patch_manifest(m)
        # ep.name is the REAL distribution identity -- not on the allowlist
        ep = _FakeEntryPoint(name="evil-backdoor")
        policy = AdmissionPolicy(mode=MODE_ENFORCE, approved=["amazon"])
        decision = evaluate_admission(ep, policy)
        assert not decision.allowed
        assert "allowlist" in decision.reason

    def test_ep_on_allowlist_but_manifest_spoofed_rejected(self, patch_manifest):
        """Both identities must be on the allowlist -- a mismatch is suspicious."""
        m = PluginManifest(name="not-approved", publisher="x", version="1")
        patch_manifest(m)
        ep = _FakeEntryPoint(name="amazon")  # ep IS approved
        policy = AdmissionPolicy(mode=MODE_ENFORCE, approved=["amazon"])
        decision = evaluate_admission(ep, policy)
        assert not decision.allowed
        assert "allowlist" in decision.reason


class TestSignature:
    def test_valid_signature_admitted(self, patch_manifest):
        secret = "s3cret"
        m = _signed(PluginManifest(name="amazon", publisher="p13n", version="1"), secret)
        patch_manifest(m)
        ep = _FakeEntryPoint(name="amazon")
        policy = AdmissionPolicy(
            mode=MODE_ENFORCE, require_signature=True, trust_keys={"p13n": secret}
        )
        assert evaluate_admission(ep, policy).allowed

    def test_unsigned_rejected_when_signature_required(self, patch_manifest):
        m = PluginManifest(name="amazon", publisher="p13n", version="1")  # no sig
        patch_manifest(m)
        ep = _FakeEntryPoint(name="amazon")
        policy = AdmissionPolicy(
            mode=MODE_ENFORCE, require_signature=True, trust_keys={"p13n": "s3cret"}
        )
        decision = evaluate_admission(ep, policy)
        assert not decision.allowed
        assert "signature" in decision.reason

    def test_tampered_capabilities_invalidate_signature(self, patch_manifest):
        secret = "s3cret"
        signed = _signed(
            PluginManifest(
                name="amazon", publisher="p13n", version="1", capabilities={"egress": ["a"]}
            ),
            secret,
        )
        # attacker swaps capabilities but keeps the old signature
        tampered = PluginManifest(
            name="amazon",
            publisher="p13n",
            version="1",
            capabilities={"egress": ["evil.example"]},
            signature=signed.signature,
        )
        patch_manifest(tampered)
        ep = _FakeEntryPoint(name="amazon")
        policy = AdmissionPolicy(
            mode=MODE_ENFORCE, require_signature=True, trust_keys={"p13n": secret}
        )
        assert not evaluate_admission(ep, policy).allowed

    @pytest.mark.parametrize(
        "signature",
        [
            "\u00e9\u00e9\u00e9",  # non-ASCII paste damage
            "\u2013" * 64,  # smart dashes, hex-digest length
            "caf\u00e9" + "0" * 60,
        ],
    )
    def test_a_non_ascii_signature_is_refused_not_raised(self, patch_manifest, signature):
        """``hmac.compare_digest`` raises TypeError on a non-ASCII ``str``.

        If this fails with TypeError: the gate escaped as a plain exception.  The CLI
        boot handler re-raises only ``PlatformCompositionError``, so the process
        would come up with NO companion context -- no fleet overlay -- on plugin
        input the gate exists to refuse.  The signature must read as invalid.
        """
        m = PluginManifest(name="amazon", publisher="p13n", version="1", signature=signature)
        patch_manifest(m)
        ep = _FakeEntryPoint(name="amazon")
        policy = AdmissionPolicy(
            mode=MODE_ENFORCE, require_signature=True, trust_keys={"p13n": "s3cret"}
        )
        decision = evaluate_admission(ep, policy)
        assert not decision.allowed
        assert "signature" in decision.reason

    def test_the_bytes_comparison_still_admits_a_correct_signature(self, patch_manifest):
        # Mutation guard for the test above: the encode on both sides must not
        # change what a well-formed hex digest compares as.
        secret = "s3cret"
        m = _signed(PluginManifest(name="amazon", publisher="p13n", version="1"), secret)
        patch_manifest(m)
        ep = _FakeEntryPoint(name="amazon")
        policy = AdmissionPolicy(
            mode=MODE_ENFORCE, require_signature=True, trust_keys={"p13n": secret}
        )
        assert evaluate_admission(ep, policy).allowed


class TestCapabilityCeiling:
    def test_capability_over_ceiling_rejected(self, patch_manifest):
        m = PluginManifest(
            name="amazon", publisher="p13n", version="1", capabilities={"egress": ["*.evil.com"]}
        )
        patch_manifest(m)
        ep = _FakeEntryPoint(name="amazon")
        policy = AdmissionPolicy(
            mode=MODE_ENFORCE, capability_ceiling={"egress": ["*.example.com"]}
        )
        decision = evaluate_admission(ep, policy)
        assert not decision.allowed
        assert "egress" in decision.reason

    def test_capability_within_ceiling_admitted(self, patch_manifest):
        m = PluginManifest(
            name="amazon", publisher="p13n", version="1", capabilities={"egress": ["*.example.com"]}
        )
        patch_manifest(m)
        ep = _FakeEntryPoint(name="amazon")
        policy = AdmissionPolicy(
            mode=MODE_ENFORCE, capability_ceiling={"egress": ["*.example.com"]}
        )
        assert evaluate_admission(ep, policy).allowed

    def test_capability_glob_ceiling_admits_concrete_value(self, patch_manifest):
        # A concrete host must be admitted when it matches a glob ceiling entry
        # (e.g. "api.example.com" under "*.example.com") — the ceiling uses
        # fnmatch semantics, matching the documented policy shape.
        m = PluginManifest(
            name="plugin-a",
            publisher="p13n",
            version="1",
            capabilities={"egress": ["api.example.com"]},
        )
        patch_manifest(m)
        ep = _FakeEntryPoint(name="plugin-a")
        policy = AdmissionPolicy(
            mode=MODE_ENFORCE, capability_ceiling={"egress": ["*.example.com"]}
        )
        assert evaluate_admission(ep, policy).allowed

    def test_unceilinged_capability_category_rejected(self, patch_manifest):
        m = PluginManifest(
            name="amazon", publisher="p13n", version="1", capabilities={"paths": ["~/.ssh"]}
        )
        patch_manifest(m)
        ep = _FakeEntryPoint(name="amazon")
        policy = AdmissionPolicy(mode=MODE_ENFORCE, capability_ceiling={"egress": ["*"]})
        decision = evaluate_admission(ep, policy)
        assert not decision.allowed
        assert "paths" in decision.reason

    def test_open_mode_still_enforces_capability_ceiling(self, patch_manifest):
        # A ceiling configured under an OPEN policy (no allowlist, no signature)
        # must still be enforced — the open-mode fast path must not bypass it.
        m = PluginManifest(
            name="amazon", publisher="p13n", version="1", capabilities={"egress": ["*.evil.com"]}
        )
        patch_manifest(m)
        ep = _FakeEntryPoint(name="amazon")
        policy = AdmissionPolicy(mode=MODE_OPEN, capability_ceiling={"egress": ["*.example.com"]})
        decision = evaluate_admission(ep, policy)
        assert not decision.allowed
        assert "egress" in decision.reason

    def test_open_mode_no_ceiling_still_fast_path_admits(self, patch_manifest):
        # Truly-open policy (no ceiling, no allowlist, no signature) still admits
        # without requiring a manifest.
        patch_manifest(None)
        ep = _FakeEntryPoint(name="amazon")
        decision = evaluate_admission(ep, AdmissionPolicy(mode=MODE_OPEN))
        assert decision.allowed


class TestEnforceRequiresManifest:
    def test_enforce_rejects_plugin_without_manifest(self, patch_manifest):
        patch_manifest(None)
        ep = _FakeEntryPoint(name="amazon")
        policy = AdmissionPolicy(mode=MODE_ENFORCE, approved=["amazon"])
        decision = evaluate_admission(ep, policy)
        assert not decision.allowed
        assert "manifest" in decision.reason


class TestPolicyLoading:
    def test_no_policy_fails_closed(self, monkeypatch, tmp_path):
        """an absent policy file must fail closed, not admit-all."""
        monkeypatch.delenv("KIROCREW_ADMISSION_POLICY", raising=False)
        _nope = tmp_path / "nope.json"
        monkeypatch.setattr("kiro_crew.platform.admission._policy_default_path", lambda: _nope)
        from kiro_crew.platform.admission import load_admission_policy

        policy = load_admission_policy()
        # fail-closed: enforce + signature + empty allowlist (admits nothing).
        assert policy.mode == MODE_ENFORCE
        assert policy.require_signature
        assert policy.approved == []

    def test_unreadable_policy_fails_closed(self, monkeypatch, tmp_path):
        bad = tmp_path / "admission_policy.json"
        bad.write_text("{ not valid json")
        monkeypatch.setenv("KIROCREW_ADMISSION_POLICY", str(bad))
        from kiro_crew.platform.admission import load_admission_policy

        policy = load_admission_policy()
        # fail-closed: enforce + signature + empty allowlist (admits nothing)
        assert policy.mode == MODE_ENFORCE
        assert policy.require_signature
        assert policy.approved == []

    def test_seed_then_load_is_open(self, monkeypatch, tmp_path):
        """The first-run seed writes a permissive file so a fresh install stays open."""
        import kiro_crew.platform.admission as adm

        monkeypatch.delenv("KIROCREW_ADMISSION_POLICY", raising=False)
        _patch_admission_paths(monkeypatch, adm, tmp_path)

        assert adm.seed_default_policy() is True
        policy = adm.load_admission_policy()
        assert policy.mode == MODE_OPEN
        assert policy.approved is None

    def test_deletion_after_seed_fails_closed_no_reseed(self, monkeypatch, tmp_path):
        """deleting the seeded file must NOT re-seed; load fails closed."""
        import kiro_crew.platform.admission as adm

        monkeypatch.delenv("KIROCREW_ADMISSION_POLICY", raising=False)
        pol = tmp_path / "admission_policy.json"
        _patch_admission_paths(monkeypatch, adm, tmp_path, policy_path=pol)

        assert adm.seed_default_policy() is True
        pol.unlink()  # attacker/accident deletes the file
        # Marker still present → no silent re-seed.
        assert adm.seed_default_policy() is False
        assert not pol.exists()
        policy = adm.load_admission_policy()
        assert policy.mode == MODE_ENFORCE and policy.approved == []

    def test_integrity_mismatch_is_advisory_not_deny(self, monkeypatch, tmp_path, caplog):
        """A modified seeded policy is still honored (user-owned) and detected,
        but a legitimate edit must NOT force the dashboard to 'degraded'."""
        import logging as _logging

        import kiro_crew.platform.admission as adm
        from kiro_crew.platform import governance_health as gh

        monkeypatch.delenv("KIROCREW_ADMISSION_POLICY", raising=False)
        pol = tmp_path / "admission_policy.json"
        _patch_admission_paths(monkeypatch, adm, tmp_path, policy_path=pol)

        adm.seed_default_policy()
        body = json.loads(pol.read_text(encoding="utf-8"))
        body["banned"] = ["rogue-plugin"]  # legitimate operator edit
        pol.write_text(json.dumps(body))
        gh.reset()
        with caplog.at_level(_logging.ERROR):
            policy = adm.load_admission_policy()
        # Operator's edit is honored (NOT hard-denied)...
        assert policy.banned == ["rogue-plugin"]
        # ...the change IS detected (logged for the audit trail)...
        assert any("seed checksum" in r.getMessage() for r in caplog.records)
        # ...but a legitimate edit must NOT force the dashboard to "degraded".
        assert gh.governance_status() != "degraded"

    def test_absent_policy_reports_degraded_health(self, monkeypatch, tmp_path):
        import kiro_crew.platform.admission as adm
        from kiro_crew.platform import governance_health as gh

        monkeypatch.delenv("KIROCREW_ADMISSION_POLICY", raising=False)
        _nope = tmp_path / "nope.json"
        monkeypatch.setattr(adm, "_policy_default_path", lambda: _nope)
        gh.reset()
        adm.load_admission_policy()
        assert gh.governance_status() == "degraded"

    def test_policy_round_trip(self, monkeypatch, tmp_path):
        p = tmp_path / "admission_policy.json"
        p.write_text(
            json.dumps(
                {
                    "mode": "enforce",
                    "require_signature": True,
                    "trust_keys": {"p13n": "s"},
                    "approved": ["amazon"],
                    "banned": ["rogue"],
                    "capability_ceiling": {"egress": ["*.example.com"]},
                }
            )
        )
        monkeypatch.setenv("KIROCREW_ADMISSION_POLICY", str(p))
        from kiro_crew.platform.admission import load_admission_policy

        policy = load_admission_policy()
        assert policy.mode == MODE_ENFORCE
        assert policy.banned == ["rogue"]
        assert policy.approved == ["amazon"]


class TestDiscoveryGate:
    def test_rejected_plugin_aborts_discovery(self, monkeypatch):
        # A banned plugin must raise PluginAdmissionError BEFORE ep.load() runs.
        loaded_marker = {"called": False}

        def _should_not_run(_cfg):
            loaded_marker["called"] = True
            raise AssertionError("ep.load() ran for a rejected plugin")

        ep = _FakeEntryPoint(name="amazon", loaded=_should_not_run)
        monkeypatch.setattr(discovery_mod, "plugin_entry_points", lambda: [ep])
        monkeypatch.setattr(
            "kiro_crew.platform.admission._read_plugin_manifest",
            lambda e: PluginManifest(name="amazon", publisher="p13n", version="1"),
        )
        policy = AdmissionPolicy(mode=MODE_OPEN, banned=["amazon"])
        with pytest.raises(PluginAdmissionError):
            discover_companion_context("amazon", None, policy=policy)
        assert loaded_marker["called"] is False  # verify-before-run held

    def test_admitted_plugin_loads(self, monkeypatch):
        sentinel = object()
        ep = _FakeEntryPoint(name="amazon", loaded=lambda _cfg: sentinel)
        monkeypatch.setattr(discovery_mod, "plugin_entry_points", lambda: [ep])
        monkeypatch.setattr(
            "kiro_crew.platform.admission._read_plugin_manifest",
            lambda e: PluginManifest(name="amazon", publisher="p13n", version="1"),
        )
        policy = AdmissionPolicy(mode=MODE_OPEN)
        result = discover_companion_context("amazon", None, policy=policy)
        assert result is sentinel

    def test_first_boot_seeds_and_admits_companion(self, monkeypatch, tmp_path):
        """ordering: discovery (which runs before the gateway seed on a
        fleet's first boot) seeds the permissive default, so the companion is
        admitted instead of fail-closing when no policy file exists yet."""
        import kiro_crew.platform.admission as adm

        monkeypatch.delenv("KIROCREW_ADMISSION_POLICY", raising=False)
        _patch_admission_paths(monkeypatch, adm, tmp_path)

        sentinel = object()
        ep = _FakeEntryPoint(name="amazon", loaded=lambda _cfg: sentinel)
        monkeypatch.setattr(discovery_mod, "plugin_entry_points", lambda: [ep])
        # No explicit policy -> discovery must seed + load (not fail closed).
        result = discover_companion_context("amazon", None)
        assert result is sentinel
        assert (tmp_path / "admission_policy.json").exists()


class TestPolicySignatureTrustRoot:
    """``require_policy_signature`` + ``trust_keys`` as the security-policy trust root.

    The flag lives HERE (the fleet-controlled admission policy) rather than inside
    ``security_policy.json`` because a document cannot be the authority on whether
    it must be authentic — see ``governance._policy_trust_settings``.
    """

    def test_defaults_off_so_existing_policies_keep_working(self):
        assert AdmissionPolicy().require_policy_signature is False
        assert AdmissionPolicy.open_default().require_policy_signature is False

    def test_parsed_from_policy_document(self):
        policy = AdmissionPolicy.from_dict(
            {"require_policy_signature": True, "trust_keys": {"fleet-control": "k"}}
        )
        assert policy.require_policy_signature is True
        assert policy.trust_keys == {"fleet-control": "k"}

    def test_independent_of_plugin_require_signature(self):
        # A fleet that signs its PLUGINS has not thereby promised to sign its
        # governance ceiling; conflating the two would break managed fleets on
        # upgrade.
        policy = AdmissionPolicy.from_dict({"require_signature": True})
        assert policy.require_signature is True
        assert policy.require_policy_signature is False

    def test_fail_closed_default_leaves_policy_signature_advisory(self, monkeypatch, tmp_path):
        # Deliberate: an absent/unreadable ADMISSION policy must not additionally
        # abort boot through the governance path. Plugin admission fails closed in
        # its own domain; the security policy keeps its own fail-closed rules.
        monkeypatch.delenv("KIROCREW_ADMISSION_POLICY", raising=False)
        monkeypatch.setattr(
            "kiro_crew.platform.admission._policy_default_path", lambda: tmp_path / "nope.json"
        )
        from kiro_crew.platform.admission import load_admission_policy

        policy = load_admission_policy()
        assert policy.require_signature is True  # plugins: fail closed
        assert policy.require_policy_signature is False  # governance: stays advisory

    def test_seeded_default_body_declares_the_flag_off(self):
        import kiro_crew.platform.admission as adm

        assert adm._DEFAULT_POLICY_BODY["require_policy_signature"] is False

    def test_non_string_trust_keys_are_dropped_not_stringified(self):
        # GPT finding: a blanket str(v) turned a malformed entry into a PREDICTABLE
        # signing secret — {"fleet": null} became the literal key "None", so anyone
        # guessing that a fleet left a null could forge a signature that verifies
        # for that issuer (mutation-confirmed). An empty string is the same hazard.
        # Such an entry is an authoring mistake, not a key: drop it, so the issuer
        # has NO key, nothing verifies, and the caller fails closed.
        policy = AdmissionPolicy.from_dict(
            {"trust_keys": {"a": None, "b": 12, "c": "", "d": ["x"], "ok": "real-secret"}}
        )
        assert policy.trust_keys == {"ok": "real-secret"}

    def test_malformed_trust_keys_container_is_ignored(self):
        assert AdmissionPolicy.from_dict({"trust_keys": "not-a-dict"}).trust_keys == {}
        assert AdmissionPolicy.from_dict({"trust_keys": None}).trust_keys == {}

    @pytest.mark.parametrize("shape", [[], None, "a string", 123])
    def test_non_object_policy_raises_valueerror_not_attributeerror(self, shape):
        # ``[]`` / ``null`` / ``"str"`` are valid JSON, so a malformed trust root
        # arrives shaped wrong rather than failing to parse. Callers catch broken
        # shapes deliberately; they should not have to enumerate incidental
        # AttributeErrors leaking from the first ``.get``.
        with pytest.raises(ValueError):
            AdmissionPolicy.from_dict(shape)


class TestSharedSigningPrimitives:
    def test_manifest_payload_uses_shared_canonicalization(self):
        from kiro_crew.platform.admission import canonical_signing_bytes

        m = PluginManifest(name="p", publisher="pub", version="1")
        expected = canonical_signing_bytes(
            {"name": "p", "publisher": "pub", "version": "1", "capabilities": {}}
        )
        assert m.signing_payload() == expected

    def test_canonicalization_is_key_order_stable(self):
        from kiro_crew.platform.admission import canonical_signing_bytes

        assert canonical_signing_bytes({"a": 1, "b": 2}) == canonical_signing_bytes(
            {"b": 2, "a": 1}
        )

    def test_hmac_signature_matches_stdlib(self):
        from kiro_crew.platform.admission import hmac_signature

        expected = hmac.new(b"k", b"payload", hashlib.sha256).hexdigest()
        assert hmac_signature("k", b"payload") == expected


class TestReadPolicyTrustRoot:
    """``read_policy_trust_root`` is the side-effect-free reader (not the audited one)."""

    def test_reads_flag_and_keys_from_env_path(self, monkeypatch, tmp_path):
        from kiro_crew.platform.admission import read_policy_trust_root

        adm = tmp_path / "admission_policy.json"
        adm.write_text(json.dumps({"require_policy_signature": True, "trust_keys": {"iss": "k"}}))
        monkeypatch.setenv("KIROCREW_ADMISSION_POLICY", str(adm))
        policy = read_policy_trust_root()
        assert policy.require_policy_signature is True
        assert policy.trust_keys == {"iss": "k"}

    def test_missing_trust_root_stays_permissive(self, monkeypatch, tmp_path):
        # An absent trust root — at the default path or an explicitly configured
        # one — is "no operator opted in", so verification stays advisory and every
        # existing install keeps working with no key to provision.
        from kiro_crew.platform import admission as adm_mod
        from kiro_crew.platform.admission import read_policy_trust_root

        monkeypatch.setenv("KIROCREW_ADMISSION_POLICY", str(tmp_path / "gone.json"))
        assert read_policy_trust_root().require_policy_signature is False
        monkeypatch.delenv("KIROCREW_ADMISSION_POLICY", raising=False)
        monkeypatch.setattr(
            adm_mod, "_policy_default_path", lambda: tmp_path / "admission_policy.json"
        )
        assert read_policy_trust_root().require_policy_signature is False

    @pytest.mark.parametrize("shape", ['{"require_policy_signature": true,  TRUNC', "[]", "null"])
    def test_unreadable_policy_reads_as_no_optin(self, monkeypatch, tmp_path, shape):
        """A corrupt/malformed trust root yields the permissive default. Deliberate.

        An attacker who can write this file is outside the policy-signature threat
        model (see the threat-model note in ``governance.md``) — they would set the
        flag to ``false``, which parses fine — so fail-closing on a *malformed* file
        catches only a clumsy version of an attack the design concedes, while turning
        a non-atomic fleet push or a hand-edit typo into an unbootable host.  Plugin
        admission still fails closed on the same file in its own domain
        (``load_admission_policy``); this reader must not additionally make the
        security ceiling unloadable through a second path.
        """
        from kiro_crew.platform.admission import read_policy_trust_root

        adm = tmp_path / "admission_policy.json"
        adm.write_text(shape)
        monkeypatch.setenv("KIROCREW_ADMISSION_POLICY", str(adm))
        policy = read_policy_trust_root()
        assert policy.require_policy_signature is False
        assert policy.trust_keys == {}

    def test_absent_policy_returns_permissive_not_fail_closed(self, monkeypatch, tmp_path):
        # Deliberately NOT _fail_closed_policy(): an admission-policy problem is
        # already handled in admission's own domain and must not make the security
        # ceiling unloadable through a second path.
        import kiro_crew.platform.admission as adm_mod
        from kiro_crew.platform.admission import read_policy_trust_root

        monkeypatch.delenv("KIROCREW_ADMISSION_POLICY", raising=False)
        monkeypatch.setattr(adm_mod, "_policy_default_path", lambda: tmp_path / "nope.json")
        policy = read_policy_trust_root()
        assert policy.require_policy_signature is False
        assert policy.trust_keys == {}
        assert policy.require_signature is False

    def test_unreadable_policy_does_not_raise(self, monkeypatch, tmp_path):
        # Never raising is the reader's contract — a corrupt trust root must not
        # take down the security-ceiling load path as well.
        from kiro_crew.platform.admission import read_policy_trust_root

        bad = tmp_path / "admission_policy.json"
        bad.write_text("{ not json")
        monkeypatch.setenv("KIROCREW_ADMISSION_POLICY", str(bad))
        policy = read_policy_trust_root()
        assert policy.require_policy_signature is False
        assert policy.trust_keys == {}

    def test_does_not_record_posture_or_incident(self, monkeypatch, tmp_path):
        # The whole reason this function exists: load_admission_policy records the
        # dashboard posture + a critical SEL, which is wrong on a repeating path.
        import kiro_crew.platform.admission as adm_mod
        from kiro_crew.platform import governance_health
        from kiro_crew.platform.admission import read_policy_trust_root

        governance_health.reset()
        monkeypatch.delenv("KIROCREW_ADMISSION_POLICY", raising=False)
        monkeypatch.setattr(adm_mod, "_policy_default_path", lambda: tmp_path / "nope.json")
        read_policy_trust_root()
        assert governance_health.governance_status() == "unknown"
        assert governance_health.last_incident() is None
        governance_health.reset()


# ──────────────────────────────────────────────────────────────────────────
# Asymmetric (Ed25519) policy signatures — the strong half of the trust root
# ──────────────────────────────────────────────────────────────────────────
def _ed25519_pair():
    """A real Ed25519 key pair as ``(private_key, raw_public_bytes)``.

    Raw/Raw serialization is what an operator pastes into ``trust_public_keys``:
    the bare 32-byte point, base64-encoded, with no PEM/DER wrapper.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    private = ed25519.Ed25519PrivateKey.generate()
    raw_public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    assert len(raw_public) == 32
    return private, raw_public


def _b64(raw: bytes) -> str:
    import base64

    return base64.b64encode(raw).decode("ascii")


class TestEd25519Verify:
    """``ed25519_verify`` — the primitive ``trust_public_keys`` is checked with.

    Its whole point over :func:`hmac_signature` is that the trust root holds only
    the VERIFYING half, so reading the file does not confer the ability to forge
    a ceiling.  Its second contract is that it never raises: the caller's only safe
    reading of "could not prove it" is "not proven", and an exception escaping here
    would leave ``load_security_policy`` raising something the boot handler does not
    treat as fatal — degrading the host to UNGOVERNED and inverting the very flag
    that demanded a signature.
    """

    def test_verifies_a_real_signature(self):
        from kiro_crew.platform.admission import ed25519_verify

        private, raw_public = _ed25519_pair()
        payload = b"the canonical policy bytes"
        assert ed25519_verify(_b64(raw_public), payload, _b64(private.sign(payload)))

    def test_accepts_padded_and_unpadded_base64_key_forms(self):
        # An operator pastes what the runbook's ``openssl … | base64`` emitted, with
        # or without the trailing '='. Both name the SAME key, so both must verify.
        from kiro_crew.platform.admission import ed25519_verify

        private, raw_public = _ed25519_pair()
        payload = b"policy"
        signature = _b64(private.sign(payload))

        padded = _b64(raw_public)
        assert padded.endswith("=")  # 32 bytes → 44 chars, one pad char
        unpadded = padded.rstrip("=")

        for key_form in (padded, unpadded):
            assert ed25519_verify(key_form, payload, signature), key_form

    def test_a_hex_key_is_not_a_key(self):
        # ONE encoding. A 64-char hex string is also valid base64, so accepting both
        # forced a try-hex-first ordering rule; base64-only removes the ambiguity
        # rather than ordering around it. Hex decodes to 48 bytes and fails the
        # length check, so a hex paste is a plain False, never a wrong key.
        from kiro_crew.platform.admission import _decode_key_material, ed25519_verify

        private, raw_public = _ed25519_pair()
        payload = b"policy"
        decoded = _decode_key_material(raw_public.hex())
        assert decoded is not None and len(decoded) == 48
        assert not ed25519_verify(raw_public.hex(), payload, _b64(private.sign(payload)))

    def test_whitespace_in_pasted_material_is_tolerated(self):
        # Copying a key out of a console or a wrapped JSON string picks up newlines.
        from kiro_crew.platform.admission import ed25519_verify

        private, raw_public = _ed25519_pair()
        payload = b"policy"
        wrapped = " " + "\n".join([_b64(raw_public)[:20], _b64(raw_public)[20:]]) + "\n"
        assert ed25519_verify(wrapped, payload, _b64(private.sign(payload)))

    def test_tampered_payload_fails(self):
        # The core threat: an attacker WIDENS a governed scope but cannot re-sign.
        from kiro_crew.platform.admission import ed25519_verify

        private, raw_public = _ed25519_pair()
        signature = _b64(private.sign(b"mode=deny"))
        assert not ed25519_verify(_b64(raw_public), b"mode=allow", signature)

    def test_signature_from_a_different_key_fails(self):
        # A valid signature is not enough — it must be valid under the key the trust
        # root names, or any holder of any Ed25519 key could mint a ceiling.
        from kiro_crew.platform.admission import ed25519_verify

        _, raw_public = _ed25519_pair()
        attacker, _attacker_public = _ed25519_pair()
        payload = b"policy"
        assert not ed25519_verify(_b64(raw_public), payload, _b64(attacker.sign(payload)))

    def test_signature_valid_under_its_own_key_confirms_the_test_is_not_vacuous(self):
        # Mutation guard for the test above: prove the attacker's signature is a
        # genuinely well-formed signature, so its rejection is about key identity
        # rather than a malformed blob taking the generic False path.
        from cryptography.hazmat.primitives import serialization

        from kiro_crew.platform.admission import ed25519_verify

        attacker, _ = _ed25519_pair()
        attacker_public = attacker.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        payload = b"policy"
        assert ed25519_verify(_b64(attacker_public), payload, _b64(attacker.sign(payload)))

    @pytest.mark.parametrize(
        "key",
        [
            "",
            "   ",
            "not base64 or hex!!",
            "aa",  # decodes, but one byte — far short of 32
            "deadbeef",
            "A" * 43,  # right length, wrong point material
            "\u00e9\u00e9\u00e9",  # non-ASCII paste damage
        ],
    )
    def test_junk_key_returns_false_without_raising(self, key):
        from kiro_crew.platform.admission import ed25519_verify

        private, _ = _ed25519_pair()
        payload = b"policy"
        assert ed25519_verify(key, payload, _b64(private.sign(payload))) is False

    @pytest.mark.parametrize(
        "signature",
        [
            "",
            "   ",
            "not base64 or hex!!",
            "deadbeef",  # decodes, but 4 bytes — not 64
            "A" * 86,  # right length, wrong bytes
            "\u2013" * 64,  # smart dashes: non-ASCII, undecodable
        ],
    )
    def test_junk_signature_returns_false_without_raising(self, signature):
        from kiro_crew.platform.admission import ed25519_verify

        _, raw_public = _ed25519_pair()
        assert ed25519_verify(_b64(raw_public), b"policy", signature) is False

    def test_truncated_key_and_signature_are_length_rejected(self):
        # Length is checked BEFORE the primitive so a truncated paste reads as a
        # plain False rather than a ValueError surfacing from the backend.
        from kiro_crew.platform.admission import ed25519_verify

        private, raw_public = _ed25519_pair()
        payload = b"policy"
        signature = private.sign(payload)
        # Encoded as base64, the ONLY encoding the decoder accepts: a hex string was
        # rejected by the decoder before any length check ran, so an earlier version of
        # this test never exercised truncation at all.
        assert ed25519_verify(_b64(raw_public[:31]), payload, _b64(signature)) is False
        assert ed25519_verify(_b64(raw_public), payload, _b64(signature[:63])) is False
        assert ed25519_verify(_b64(raw_public), payload, _b64(signature + b"\x00")) is False
        # And the positive control: the same encoding, untruncated, verifies.
        assert ed25519_verify(_b64(raw_public), payload, _b64(signature)) is True

    def test_empty_payload_is_still_a_real_verification(self):
        from kiro_crew.platform.admission import ed25519_verify

        private, raw_public = _ed25519_pair()
        assert ed25519_verify(_b64(raw_public), b"", _b64(private.sign(b"")))
        assert not ed25519_verify(_b64(raw_public), b"x", _b64(private.sign(b"")))


class TestAsymmetricTrustRootParsing:
    """``trust_public_keys`` in the policy."""

    def test_defaults_are_inert_so_existing_fleets_are_unchanged(self):
        assert AdmissionPolicy().trust_public_keys == {}
        assert AdmissionPolicy.open_default().trust_public_keys == {}

    def test_parsed_from_policy_document(self):
        _, raw_public = _ed25519_pair()
        policy = AdmissionPolicy.from_dict(
            {"trust_public_keys": {"fleet-control": _b64(raw_public)}}
        )
        assert policy.trust_public_keys == {"fleet-control": _b64(raw_public)}

    def test_both_key_maps_coexist_during_a_migration(self):
        # A fleet mid-rollout carries the legacy secret and the new public key at
        # once; parsing must keep them separate rather than merging or dropping one.
        _, raw_public = _ed25519_pair()
        policy = AdmissionPolicy.from_dict(
            {
                "trust_keys": {"fleet-control": "legacy-secret"},
                "trust_public_keys": {"fleet-control": _b64(raw_public)},
            }
        )
        assert policy.trust_keys == {"fleet-control": "legacy-secret"}
        assert policy.trust_public_keys == {"fleet-control": _b64(raw_public)}

    def test_an_unknown_require_asymmetric_key_is_ignored_not_honoured(self):
        # The flag was removed: a fleet stops accepting symmetric proofs by deleting
        # the issuer's ``trust_keys`` entry. A document still carrying the old key
        # parses like any unknown key -- it neither errors nor switches anything on.
        policy = AdmissionPolicy.from_dict({"require_asymmetric_policy_signature": True})
        assert not hasattr(policy, "require_asymmetric_policy_signature")
        assert policy.require_policy_signature is False

    def test_malformed_public_key_entries_are_dropped_not_stringified(self):
        # Same hazard ``trust_keys`` has: a blanket ``str(v)`` would turn
        # ``{"fleet": null}`` into the literal key ``"None"`` — a PREDICTABLE value
        # an attacker can guess and sign against. Dropping the entry leaves the
        # issuer with NO key, so nothing verifies and the caller fails closed.
        _, raw_public = _ed25519_pair()
        policy = AdmissionPolicy.from_dict(
            {
                "trust_public_keys": {
                    "null-entry": None,
                    "number-entry": 12,
                    "empty-entry": "",
                    "list-entry": ["x"],
                    "dict-entry": {"k": "v"},
                    "bool-entry": False,
                    "ok": _b64(raw_public),
                }
            }
        )
        assert policy.trust_public_keys == {"ok": _b64(raw_public)}

    def test_dropped_entry_cannot_be_verified_against_its_coerced_form(self):
        # The consequence the drop exists to prevent, pinned end to end: had the
        # null been coerced to "None", that string would be the issuer's key.
        from kiro_crew.platform.admission import ed25519_verify

        policy = AdmissionPolicy.from_dict({"trust_public_keys": {"fleet-control": None}})
        assert "fleet-control" not in policy.trust_public_keys
        assert ed25519_verify("None", b"policy", "deadbeef") is False

    def test_malformed_public_key_container_is_ignored(self):
        assert (
            AdmissionPolicy.from_dict({"trust_public_keys": "not-a-dict"}).trust_public_keys == {}
        )
        assert AdmissionPolicy.from_dict({"trust_public_keys": None}).trust_public_keys == {}
        assert AdmissionPolicy.from_dict({"trust_public_keys": []}).trust_public_keys == {}

    def test_seeded_default_body_documents_the_asymmetric_option(self):
        # The seeded file is the only documentation most operators read, so the
        # recommended (asymmetric) path has to be named in it.
        import kiro_crew.platform.admission as adm

        comment = str(adm._DEFAULT_POLICY_BODY["_comment"])
        assert "trust_public_keys" in comment
        assert "trust_keys" in comment

    def test_read_policy_trust_root_surfaces_the_asymmetric_settings(self, monkeypatch, tmp_path):
        # governance._policy_asymmetric_settings reads through this side-effect-free
        # reader, so the fields have to survive the file round trip.
        from kiro_crew.platform.admission import read_policy_trust_root

        _, raw_public = _ed25519_pair()
        adm = tmp_path / "admission_policy.json"
        adm.write_text(json.dumps({"trust_public_keys": {"fleet-control": _b64(raw_public)}}))
        monkeypatch.setenv("KIROCREW_ADMISSION_POLICY", str(adm))
        policy = read_policy_trust_root()
        assert policy.trust_public_keys == {"fleet-control": _b64(raw_public)}


class TestStrictBooleanFlagCoercion:
    """``_coerce_flag`` reads a JSON boolean and refuses to guess at anything else.

    ``bool("false")`` is ``True``, so a trust root written as
    ``{"require_signature": "false"}`` -- valid JSON, and the natural
    mistake in a hand-edited or template-generated file -- silently turned the
    requirement ON and then rejected every correctly HMAC-signed ceiling the fleet
    published. A fleet reading its own file would see the word "false" and have no way
    to explain the refusals. Dropping the value and warning is the same rule
    ``_coerce_trust_keys`` already applies to a malformed key: a value that is not of
    the declared type is not a value.
    """

    #: Everything a hand-edited trust root plausibly carries instead of a boolean. The
    #: two lowercase STRINGS are the whole reason this helper exists -- both are truthy
    #: under ``bool()``, so before the fix ``"false"`` and ``"true"`` were
    #: indistinguishable, and the one an operator writes to mean OFF was the worse of
    #: the two.
    #: ``None`` is in the list on purpose: an explicit JSON ``null`` is what a fleet
    #: template renders for an unset variable, and it is present-but-not-boolean, not
    #: absent. Absence is spelled ``_MISSING`` by the caller, never ``None``.
    MALFORMED = ("false", "true", "False", 1, 0, 1.5, [], ["true"], {}, {"v": True}, "", None)

    def test_a_real_boolean_is_honoured_in_both_directions(self):
        from kiro_crew.platform.admission import _coerce_flag

        assert _coerce_flag(True, "flag") is True
        assert _coerce_flag(False, "flag") is False

    def test_absent_reads_off(self):
        """An unset gate is OFF -- the documented default for both flags it reads."""
        from kiro_crew.platform.admission import _MISSING, _coerce_flag

        assert _coerce_flag(_MISSING, "flag") is False

    def test_the_helper_takes_no_direction_parameters(self):
        """Both directions are fixed, not configurable.

        An earlier revision exposed ``default`` and ``malformed`` so a non-gate flag
        could opt into fail-open; that flag was removed and no caller passed either.
        A parameter nobody passes is a second way to spell the wrong direction, so
        the signature is pinned to the two arguments the gates actually need.
        """
        import inspect

        from kiro_crew.platform.admission import _coerce_flag

        assert list(inspect.signature(_coerce_flag).parameters) == ["raw", "key"]

    @pytest.mark.parametrize("raw", MALFORMED)
    def test_a_non_boolean_is_never_coerced_and_fails_closed(self, raw):
        from kiro_crew.platform.admission import _coerce_flag

        # Fail-CLOSED, always: a present-but-not-boolean value on a security
        # requirement reads as ON. Reading "true" (a string) as OFF is how a gate fails
        # open on a typo.
        assert _coerce_flag(raw, "flag") is True

    @pytest.mark.parametrize("raw", MALFORMED)
    def test_a_non_boolean_is_reported_loudly(self, raw, caplog):
        from kiro_crew.platform.admission import _coerce_flag

        # Silence would leave a fleet with a flag that reads one way in the file and
        # behaves another, which is the failure mode this replaced: the refusals were
        # real and the file looked correct.
        with caplog.at_level(_logging.WARNING, logger="kiro_crew.platform.admission"):
            _coerce_flag(raw, "require_signature")
        messages = [r.getMessage() for r in caplog.records]
        assert any("require_signature" in m for m in messages), messages
        assert any("not a boolean" in m for m in messages), messages

    def test_an_absent_flag_is_not_reported(self, caplog):
        """A file that simply does not set the flag is the normal case, not an error."""
        from kiro_crew.platform.admission import _MISSING, _coerce_flag

        with caplog.at_level(_logging.WARNING, logger="kiro_crew.platform.admission"):
            _coerce_flag(_MISSING, "require_signature")
        assert caplog.records == []

    @pytest.mark.parametrize("key", ["require_signature", "require_policy_signature"])
    def test_an_explicit_null_does_not_disable_a_gate(self, key):
        """``{"require_signature": null}`` must not read as the absent-key default.

        ``dict.get(key)`` returns ``None`` for both an absent key and an explicit
        ``null``; the first is the documented default (OFF), the second is what a
        fleet template renders for an unset variable and is an authoring error. The
        constructor passes ``_MISSING`` as the ``.get`` default so only true absence
        takes the default, and ``null`` takes the fail-closed direction.
        """
        assert getattr(AdmissionPolicy.from_dict({key: None}), key) is True
        # Absence is still the documented default.
        assert getattr(AdmissionPolicy.from_dict({}), key) is False

    @pytest.mark.parametrize("key", ["require_signature", "require_policy_signature"])
    def test_the_sibling_flags_no_longer_carry_the_string_trap(self, key):
        """The point-patch was the defect: one flag fixed, two siblings in the same
        constructor still ``bool(d.get(...))``, so ``"false"`` there silently turned
        mandatory signing ON -- the exact failure the ``_coerce_flag`` docstring names.
        All three flags read through the same helper now.

        A ``bool()`` read of these siblings would let a malformed value read as OFF -- a
        gate failing open (``"true"`` -> unsigned plugin admitted). The gate flags fail
        CLOSED on a malformed value instead, and this test pins that direction.
        """
        # These two are GATES, so a malformed value reads as ON (fail closed): a fleet
        # that wrote "true" meant the gate on, and "false" as a string is still not a
        # boolean, so it too resolves to the closed direction and is warned about. Real
        # booleans read as written.
        assert getattr(AdmissionPolicy.from_dict({key: "true"}), key) is True
        assert getattr(AdmissionPolicy.from_dict({key: "false"}), key) is True
        assert getattr(AdmissionPolicy.from_dict({key: 1}), key) is True
        assert getattr(AdmissionPolicy.from_dict({key: True}), key) is True
        assert getattr(AdmissionPolicy.from_dict({key: False}), key) is False
        assert getattr(AdmissionPolicy.from_dict({}), key) is False

    def test_a_real_boolean_still_opts_the_fleet_in(self):
        """The fix must not have made the gates unsettable."""
        assert AdmissionPolicy.from_dict({"require_signature": True}).require_signature is True
        assert AdmissionPolicy.from_dict({"require_signature": False}).require_signature is False

    def test_a_malformed_gate_flag_in_a_real_trust_root_file_reads_closed(
        self, monkeypatch, tmp_path
    ):
        """End to end through the file reader: the string ``"false"`` on a GATE flag
        is not a boolean, so it takes the fail-closed direction, and the shared secret
        the file also carries is still parsed.
        """
        from kiro_crew.platform.admission import read_policy_trust_root

        adm = tmp_path / "admission_policy.json"
        adm.write_text(
            json.dumps(
                {
                    "trust_keys": {"fleet-control": "shared-secret"},
                    "require_policy_signature": "false",
                }
            )
        )
        monkeypatch.setenv("KIROCREW_ADMISSION_POLICY", str(adm))
        policy = read_policy_trust_root()
        assert policy.require_policy_signature is True
        assert policy.trust_keys == {"fleet-control": "shared-secret"}

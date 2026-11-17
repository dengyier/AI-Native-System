import importlib.util
import json
import unittest
from pathlib import Path

from ai_native_system.adapters.owp import (
    AUTHORIZATION_DOMAIN, AUTHORIZATION_PROFILE, ProfileError, key_id, load_private_key, load_public_key,
    profile_digest, sign_authorization, sign_profile, verify_authorization, verify_profile,
)
from ai_native_system.identity import IdentityContext


SCHEMA = Path(__file__).resolve().parents[1] / "schemas" / "ai-native-action-v0.1" / "authorization.schema.json"


def authorization():
    return {
        "profile": AUTHORIZATION_PROFILE, "nonce": "nonce-one", "epoch": "epoch-one",
        "issued_at": 1_800_000_000, "expires_at": 1_800_000_600,
        "scope": {
            "tenant": "company", "task_id": "task", "operation_id": "operation", "action_instance_id": "stage-one",
            "release_digest": "1" * 64, "ontology_digest": "2" * 64, "policy_version": "p3",
            "rule_versions": {"is_ready": 3}, "rule_proof_digest": "3" * 64, "fact_read_set_digest": "4" * 64,
            "requester": IdentityContext("company", "requester", "bridge", "del-one").as_document(),
            "approver": IdentityContext("company", "reviewer").as_document(), "executor": "executor",
            "approval_digest": "5" * 64, "action": "transition", "action_version": 5, "action_kind": "write_remote",
            "targets": [{"type": "asset", "id": "asset-a"}],
            "reads": [{"kind": "edge", "resource_id": "asset-a", "member": "owner"}],
            "writes": [{"kind": "metadata", "resource_id": "asset-a", "member": "state"}],
            "parameters_digest": profile_digest({"delta": -3, "estimated": 0.5, "label": "验收"}),
            "tool": {"name": "state", "version": "2", "destination_digest": "6" * 64},
        },
    }


@unittest.skipUnless(importlib.util.find_spec("openworkproof"), "Install the OpenWorkProof integration extra")
class EnterpriseOWPProfileTests(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self.signer = Ed25519PrivateKey.generate()
        self.public_key = self.signer.public_key()
        self.trust = {key_id(self.public_key): self.public_key}

    def test_pinned_signing_and_schema_accept_roundtrip(self):
        from jsonschema import Draft202012Validator

        payload = authorization()
        signed = sign_authorization(payload, self.signer)
        schema = json.loads(SCHEMA.read_text())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(signed)
        restored = verify_authorization(json.dumps(signed).encode("utf-8"), self.trust)
        self.assertEqual(restored, payload)
        self.assertEqual(sign_authorization(payload, self.signer), signed)
        restored["scope"]["targets"][0]["id"] = "different"
        self.assertEqual(signed["payload"]["scope"]["targets"][0]["id"], "asset-a")
        payload["scope"]["requester"]["delegation_id"] = "another-grant"
        self.assertEqual(signed["payload"]["scope"]["requester"]["delegation_id"], "del-one")

    def test_scope_tool_rules_approval_and_epoch_tampering_is_rejected(self):
        paths = {
            ("scope", "parameters_digest"): "7" * 64,
            ("scope", "tool", "destination_digest"): "8" * 64,
            ("scope", "rule_versions", "is_ready"): 4,
            ("scope", "fact_read_set_digest"): "9" * 64,
            ("scope", "targets", 0, "id"): "asset-b",
            ("scope", "reads", 0, "member"): "manager",
            ("scope", "writes", 0, "member"): "label",
            ("scope", "approval_digest"): "0" * 64,
            ("scope", "requester", "delegation_id"): "del-two",
            ("epoch",): "new-epoch",
        }
        for path, value in paths.items():
            with self.subTest(path=path):
                signed = sign_authorization(authorization(), self.signer)
                cursor = signed["payload"]
                for segment in path[:-1]:
                    cursor = cursor[segment]
                cursor[path[-1]] = value
                with self.assertRaises(ProfileError):
                    verify_authorization(signed, self.trust)

    def test_profile_does_not_accept_legacy_or_other_enterprise_domains(self):
        from openworkproof.signing import sign_payload, verify_payload

        payload = authorization()
        signed = sign_authorization(payload, self.signer)
        self.assertFalse(verify_payload("capability-grant", signed, self.public_key))
        legacy = sign_payload("capability-grant", {"payload": payload}, self.signer)
        with self.assertRaises(ProfileError):
            verify_authorization(legacy, self.trust)
        evidence_domain = b"ai-native-action/effect-evidence/v0.1\x00"
        other = sign_profile(payload, self.signer, domain=evidence_domain, substrate="action-receipt")
        with self.assertRaises(ProfileError):
            verify_authorization(other, self.trust)
        with self.assertRaises(ProfileError):
            verify_profile(signed, self.trust, domain=AUTHORIZATION_DOMAIN, substrate="action-receipt")

    def test_wrong_key_algorithm_digest_signature_and_duplicate_json_rejected(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        signed = sign_authorization(authorization(), self.signer)
        wrong = Ed25519PrivateKey.generate().public_key()
        for trust in ({}, {key_id(self.public_key): wrong}, {key_id(wrong): wrong}):
            with self.assertRaises(ProfileError):
                verify_authorization(signed, trust)
        for change in ({"signature_alg": "ES256"}, {"digest": "a" * 64}, {"signature": "A" * 86},
                       {"signature": signed["signature"] + "=="}, {"public_key": "attacker"}):
            with self.subTest(change=change), self.assertRaises(ProfileError):
                verify_authorization({**signed, **change}, self.trust)
        encoded = json.dumps(signed).replace('"nonce":', '"nonce":"shadow", "nonce":', 1)
        with self.assertRaises(ProfileError):
            verify_authorization(encoded, self.trust)

    def test_invalid_scope_never_signed_and_read_cannot_write(self):
        for field, value in (
            ("requester", IdentityContext("other", "requester").as_document()),
            ("approver", IdentityContext("company", "requester").as_document()),
            ("approver", IdentityContext("company", "reviewer", service="reviewer").as_document()),
            ("rule_versions", {}),
            ("rule_proof_digest", None),
            ("approval_digest", "invalid"),
            ("reads", [{"kind": "edge", "resource_id": "asset-a", "member": "owner"}] * 2),
            ("writes", []),
            ("action_kind", "read"),
            ("tool", {"name": "state", "version": "2", "destination_digest": None}),
        ):
            with self.subTest(field=field), self.assertRaises(ProfileError):
                payload = authorization()
                payload["scope"][field] = value
                sign_authorization(payload, self.signer)
        payload = authorization()
        payload["scope"].update(action_kind="read", rule_versions={}, rule_proof_digest=None,
                                fact_read_set_digest=None, approver=None, approval_digest=None, writes=[])
        self.assertEqual(verify_authorization(sign_authorization(payload, self.signer), self.trust), payload)

    def test_key_loaders_enforce_type_and_serialize_detached_key(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        public = self.public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        private = self.signer.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption())
        self.assertEqual(key_id(load_public_key(public)), key_id(self.public_key))
        self.assertEqual(key_id(load_private_key(private).public_key()), key_id(self.public_key))
        other = ec.generate_private_key(ec.SECP256R1()).public_key()
        with self.assertRaises(ProfileError):
            load_public_key(other.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        with self.assertRaises(ProfileError):
            load_private_key(b"invalid")

    def test_payload_total_size_and_profile_are_bounded(self):
        payload = authorization()
        payload["scope"]["reads"] = [
            {"kind": "evidence", "resource_id": f"{index:04}" + "x" * 508, "member": "x" * 512}
            for index in range(512)
        ]
        with self.assertRaises(ProfileError):
            sign_authorization(payload, self.signer)
        with self.assertRaises(ProfileError):
            sign_authorization({**authorization(), "profile": "openworkproof/0.1"}, self.signer)
        with self.assertRaises(ProfileError):
            sign_authorization({**authorization(), "issued_at": True}, self.signer)
        with self.assertRaises(ProfileError):
            sign_authorization({**authorization(), "expires_at": 1_000_000_000}, self.signer)


if __name__ == "__main__":
    unittest.main()

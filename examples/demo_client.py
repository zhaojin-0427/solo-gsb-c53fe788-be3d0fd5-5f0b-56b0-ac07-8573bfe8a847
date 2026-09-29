#!/usr/bin/env python3
"""End-to-end demo.

1. Generate an Ed25519 key pair.
2. Register the public key with the verification service.
3. Sign an HTTP request (method, target URI, headers, JSON body) per RFC 9421.
4. Submit it to POST /verify and print the result (including the signed,
   offline-verifiable acceptance receipt).
5. Submit the *same* payload again to show replay protection (409 replayed).
6. Create an immutable policy draft that would reject Ed25519, and evaluate
   the same signature against it via POST /verify-shadow (read-only: the
   nonce is not consumed, no receipt is issued and formal acceptance is
   unaffected).
7. Verify the acceptance receipt offline against the public keys published
   at GET /receipts/keys.
8. Revoke the receipt (idempotent admin command), query its point-in-time
   status, and verify the signed revocation proof plus the audit chain
   offline.

Usage:
    python examples/demo_client.py [base_url] [admin_token]

Requires: pip install httpx cryptography http-sfv
"""
from __future__ import annotations

import json
import sys
import time

import httpx

from app import receipts, revocations
from app.crypto import generate_ed25519, load_public_key, public_key_pem
from app.signer import make_signed_request


def main() -> int:
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    admin_token = sys.argv[2] if len(sys.argv) > 2 else "admin-secret"
    admin_headers = {"X-Admin-Token": admin_token}

    # 1. Key pair ------------------------------------------------------------
    private_key, public_key = generate_ed25519()
    keyid = "demo-ed25519-key"

    # 2. Register the public key --------------------------------------------
    r = httpx.post(
        f"{base_url}/admin/keys",
        headers=admin_headers,
        json={"keyid": keyid, "public_key": public_key_pem(public_key)},
        timeout=10,
    )
    r.raise_for_status()
    print("registered key:", json.dumps(r.json(), indent=2))

    # 3. Sign a request ------------------------------------------------------
    body = json.dumps({"hello": "world", "n": 42}, separators=(",", ":")).encode()
    payload = make_signed_request(
        private_key=private_key,
        algorithm="ed25519",
        keyid=keyid,
        method="POST",
        target_uri="https://api.example.com/demo?x=1",
        headers=[
            ("content-type", "application/json"),
        ],
        body=body,
        components=["@method", "@target-uri", "@authority", "content-digest", "content-type"],
    )
    print("\nsignature base:\n" + payload["_signature_base"] + "\n")

    submit_body = {k: v for k, v in payload.items() if not k.startswith("_")}

    # 4. First submission -> accepted ----------------------------------------
    r = httpx.post(f"{base_url}/verify", json=submit_body, timeout=10)
    print("first  /verify ->", r.status_code)
    accepted = r.json()
    print(json.dumps(accepted, indent=2, ensure_ascii=False))

    # 5. Replay the identical payload -> replayed ----------------------------
    r = httpx.post(f"{base_url}/verify", json=submit_body, timeout=10)
    print("\nsecond /verify ->", r.status_code)
    print(json.dumps(r.json(), indent=2, ensure_ascii=False))

    # 6. Shadow verification against a draft policy --------------------------
    # Draft based on the active version but allowing RSA keys only.
    active = httpx.get(f"{base_url}/admin/policy", headers=admin_headers, timeout=10).json()
    r = httpx.post(
        f"{base_url}/admin/policy/drafts",
        headers=admin_headers,
        json={
            "baseline_version": active["version"],
            "required_algorithms": ["rsa-pss-sha256", "rsa-pss-sha512"],
        },
        timeout=10,
    )
    r.raise_for_status()
    draft = r.json()
    print(
        f"\ndraft v{draft['version']} (baseline v{draft['baseline_version']}): "
        f"algorithms {draft['required_algorithms']}"
    )

    r = httpx.post(
        f"{base_url}/verify-shadow",
        json={**submit_body, "policy_version": draft["version"]},
        timeout=10,
    )
    print(f"/verify-shadow@v{draft['version']} ->", r.status_code)
    data = r.json()
    print(
        json.dumps(
            {
                "reason": data.get("reason"),
                "policy_status": data.get("policy_status"),
                "active_policy_version": data.get("active_policy_version"),
                "diff_vs_active": data.get("diff_vs_active"),
                "nonce_seen": data.get("nonce_seen"),
                "receipt": data.get("receipt"),
            },
            indent=2,
            ensure_ascii=False,
        )
    )

    # 7. Verify the acceptance receipt offline --------------------------------
    receipt = accepted.get("receipt")
    if receipt:
        keys = httpx.get(f"{base_url}/receipts/keys", timeout=10).json()["keys"]
        entry = next(k for k in keys if k["key_id"] == receipt["key_id"])
        public_key = load_public_key(entry["public_key"])
        sig_ok = receipts.verify_payload_signature(
            public_key, receipt["payload"], receipt["signature"]
        )
        bound = receipts.input_digest(submit_body) == receipt["input_digest"]
        print(
            f"\nreceipt {receipt['receipt_id']} (key {receipt['key_id']}): "
            f"signature {'OK' if sig_ok else 'INVALID'}, "
            f"input binding {'OK' if bound else 'MISMATCH'}"
        )
        print("offline check: python tools/verify_receipt.py --receipt r.json "
              "--keys keys.json [--request request.json]")

    # 8. Revoke the receipt and verify the revocation offline -----------------
    if receipt:
        receipt_id = receipt["receipt_id"]
        command = {
            "reason": "demo: signer key retired",
            # Slightly in the future so both sides of the point-in-time
            # status query below are deterministic.
            "effective_at": int(time.time()) + 30,
            "expected_revision": 0,
            "command_id": f"demo-{receipt_id}",
        }
        r = httpx.post(
            f"{base_url}/admin/receipts/{receipt_id}/revoke",
            headers=admin_headers,
            json=command,
            timeout=10,
        )
        print(f"\nrevoke -> {r.status_code}")
        revocation = r.json()["revocation"]
        print(f"revocation seq {revocation['revocation_seq']}, "
              f"id {revocation['revocation_id']}")

        # Resubmitting the identical command is an idempotent replay.
        r = httpx.post(
            f"{base_url}/admin/receipts/{receipt_id}/revoke",
            headers=admin_headers,
            json=command,
            timeout=10,
        )
        print(f"replay -> {r.status_code} "
              f"(idempotent_replay={r.json()['idempotent_replay']})")

        # Point-in-time status: before vs after the effective time.
        before = httpx.get(
            f"{base_url}/receipts/{receipt_id}/status",
            params={"at": command["effective_at"] - 10},
            timeout=10,
        ).json()
        after = httpx.get(
            f"{base_url}/receipts/{receipt_id}/status",
            params={"at": command["effective_at"] + 10},
            timeout=10,
        ).json()
        print(f"status at effective_at-10s: {before['status']}; "
              f"at effective_at+10s: {after['status']}")

        # Offline: the signed proof binds this receipt and verifies against
        # the published keys; the audit chain is gapless and hash-linked.
        keys = httpx.get(f"{base_url}/receipts/keys", timeout=10).json()["keys"]
        entry = next(k for k in keys if k["key_id"] == revocation["key_id"])
        public_key = load_public_key(entry["public_key"])
        proof_ok = receipts.verify_payload_signature(
            public_key, revocation["payload"], revocation["signature"]
        )
        fields = revocations.parse_payload(revocation["payload"])
        bound = fields["receipt_id"] == receipt_id
        chain = httpx.get(f"{base_url}/revocations", timeout=10).json()
        print(
            f"revocation proof: signature {'OK' if proof_ok else 'INVALID'}, "
            f"receipt binding {'OK' if bound else 'MISMATCH'}, "
            f"chain head seq {chain['head_seq']}"
        )
        print("offline check: python tools/verify_receipt.py --receipt r.json "
              "--keys keys.json --revocation rev.json --at <ts> --chain chain.json")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

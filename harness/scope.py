"""Scope annotation for Levain positives against the pinned default config.

This does not change the answer key or the TP/FN counts. It records, separately,
which missed expected kinds are plainly outside the built-in default Gitleaks
rule set, which are unknown, and which are in scope but still missed.

The classification is deliberately conservative. "Out of scope" means no
matching rule ID exists in the pinned default config and the kind is not a
generic credential shape. "Unknown" means no direct rule is present, but a
generic or adjacent rule might legitimately apply. Custom configurations make
this annotation unavailable.
"""

from __future__ import annotations

OUT_OF_SCOPE: dict[str, str] = {
    "email": "not a secret; no default email rule",
    "payment_card": "no default payment-card rule",
    "wallet_seed_phrase": "no default seed-phrase rule",
    "shapeless_password": "hard tier; no shape-based rule",
    "capability_url_segment": "hard tier; no shape-based rule",
    "wrapped_token": "hard tier; token is split across lines",
    "discord_webhook_url": "no default Discord webhook rule",
    "aws_secret_access_key": "no default rule for the paired secret key",
    "google_oauth_client_secret": "no default Google OAuth client-secret rule",
    "resend_api_key": "no default Resend rule",
    "supabase_access_token": "no default Supabase rule",
    "tailscale_auth_key": "no default Tailscale rule",
    "xai_api_key": "no default xAI rule",
}

UNKNOWN: dict[str, str] = {
    "url_password": "no direct rule; generic or curl rules may apply",
    "bearer_token": "no direct bearer rule; generic or JWT rules may apply",
}


def classify(kind: str) -> tuple[str, str]:
    if kind in OUT_OF_SCOPE:
        return "out_of_scope", OUT_OF_SCOPE[kind]
    if kind in UNKNOWN:
        return "unknown", UNKNOWN[kind]
    return "in_scope", "default rule family present"


def summarize(missed_secrets: list[dict], config_mode: str) -> dict:
    if config_mode != "builtin-default":
        return {
            "available": False,
            "config_mode": config_mode,
            "reason": "scope annotation is defined only for the pinned default config",
            "out_of_scope": [],
            "unknown": [],
            "in_scope_misses": [],
            "counts": {"out_of_scope": 0, "unknown": 0, "in_scope": 0},
        }

    out: list[dict] = []
    unknown: list[dict] = []
    in_scope: list[dict] = []
    for missed in missed_secrets:
        classification, basis = classify(missed["kind"])
        entry = {
            "section": missed["section"],
            "kind": missed["kind"],
            "classification": classification,
            "basis": basis,
            "hard": bool(missed.get("hard")),
            "partial_evidence": missed.get("partial_evidence", 0),
        }
        {"out_of_scope": out, "unknown": unknown, "in_scope": in_scope}[classification].append(entry)
    return {
        "available": True,
        "config_mode": config_mode,
        "basis": "manual annotation against the rule IDs in the pinned default config",
        "out_of_scope": out,
        "unknown": unknown,
        "in_scope_misses": in_scope,
        "counts": {
            "out_of_scope": len(out),
            "unknown": len(unknown),
            "in_scope": len(in_scope),
        },
    }

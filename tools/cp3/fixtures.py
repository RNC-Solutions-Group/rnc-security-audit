"""Deterministic, harmless provider-format fixtures and independent truth.

The fixture builder never invokes the detector. It constructs source bytes from
declared templates, records the byte spans of explicitly placed placeholders,
and writes a truth manifest outside the scanner's source root. The Rust and
Python test suites consume that manifest; production detection code never reads
it.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from tools.cp3.materialize import write_bundle

ROOT = Path(__file__).resolve().parents[2]
TIER2_ROOT = ROOT / "tests/fixtures/providers/tier2"
TIER3_ROOT = ROOT / "tests/fixtures/providers/tier3"
TRUTH_ROOT = ROOT / "tests/cp3"

ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
BASE64 = ALNUM + "/+="
TOKEN_CHARS = ALNUM + "_-"


def deterministic(seed: str, alphabet: str, length: int) -> str:
    material = hashlib.sha256(seed.encode("utf-8")).digest()
    output: list[str] = []
    while len(output) < length:
        for byte in material:
            output.append(alphabet[byte % len(alphabet)])
            if len(output) == length:
                break
        material = hashlib.sha256(material).digest()
    return "".join(output)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def der(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + der_length(len(content)) + content


def der_integer(value: int) -> bytes:
    if value == 0:
        payload = b"\x00"
    else:
        payload = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if payload[0] & 0x80:
            payload = b"\x00" + payload
    return der(0x02, payload)


def dummy_rsa_der() -> bytes:
    # Structurally plausible PKCS#1-shaped integers. The values are deliberately
    # inconsistent and are not a usable RSA key.
    def number(seed: str, length: int) -> int:
        return int.from_bytes(hashlib.sha256(seed.encode()).digest() * (length // 32 + 1), "big") >> (
            8 * (32 * (length // 32 + 1) - length)
        )

    children = [
        der_integer(0),
        der_integer(number("rsa-modulus", 128)),
        der_integer(65537),
        der_integer(number("rsa-private-exponent", 128)),
        der_integer(number("rsa-prime-1", 64)),
        der_integer(number("rsa-prime-2", 64)),
        der_integer(number("rsa-exponent-1", 64)),
        der_integer(number("rsa-exponent-2", 64)),
        der_integer(number("rsa-coefficient", 64)),
    ]
    return der(0x30, b"".join(children))


def dummy_pkcs8_der() -> bytes:
    oid = bytes.fromhex("2a864886f70d010101")  # rsaEncryption
    algorithm = der(0x30, der(0x06, oid) + der(0x05, b""))
    payload = b"rnc-test-not-a-key" + deterministic("pkcs8-payload", ALNUM, 96).encode()
    return der(0x30, der_integer(0) + algorithm + der(0x04, payload))


def dummy_openssh() -> bytes:
    return b"openssh-key-v1\x00" + b"rnc-test-not-a-key" * 3


def pem(label: str, payload: bytes) -> str:
    body = b64(payload)
    lines = [body[index : index + 64] for index in range(0, len(body), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----"


def make_jwt() -> str:
    header = b'{"alg":"HS256","typ":"JWT"}'
    payload = b'{"sub":"rnc-fixture","aud":"fixtures.invalid"}'
    signature = deterministic("jwt-signature", TOKEN_CHARS, 43)
    return f"{b64url(header)}.{b64url(payload)}.{signature}"


@dataclass(frozen=True)
class Expectation:
    placeholder: str
    rule_id: str
    family: str
    credential_type: str
    confidence: str


@dataclass
class Fixture:
    path: str
    template: str | bytes
    expectations: list[Expectation] = field(default_factory=list)


def render(template: str | bytes, values: dict[str, bytes]) -> tuple[bytes, dict[str, list[tuple[int, int]]]]:
    """Render placeholders and return exact byte spans for each occurrence."""
    if isinstance(template, str):
        source = template.encode("utf-8")
    else:
        source = template
    output = bytearray()
    spans: dict[str, list[tuple[int, int]]] = {}
    cursor = 0
    while True:
        start = source.find(b"{{", cursor)
        if start < 0:
            output.extend(source[cursor:])
            break
        end = source.find(b"}}", start + 2)
        if end < 0:
            output.extend(source[cursor:])
            break
        output.extend(source[cursor:start])
        key = source[start + 2 : end].decode("ascii")
        if key not in values:
            raise KeyError(f"unknown fixture placeholder {key}")
        value = values[key]
        begin = len(output)
        output.extend(value)
        spans.setdefault(key, []).append((begin, len(output)))
        cursor = end + 2
    return bytes(output), spans


def line_for(data: bytes, offset: int) -> int:
    line = 1
    index = 0
    while index < offset:
        if data[index] == 13:
            if index + 1 < offset and data[index + 1] == 10:
                index += 2
            else:
                index += 1
            line += 1
        elif data[index] == 10:
            index += 1
            line += 1
        else:
            index += 1
    return line


def line_end_for(data: bytes, start: int, end: int) -> int:
    last = end - 1
    while last > start and data[last] in (10, 13):
        last -= 1
    return line_for(data, last)


def truth_item(
    dataset_id: str,
    dataset_version: str,
    path: str,
    data: bytes,
    start: int,
    end: int,
    expectation: Expectation,
) -> dict:
    token = data[start:end]
    digest = hashlib.sha256(token).hexdigest()
    identity = hashlib.sha256(
        b"\x00".join(
            [
                path.encode("utf-8"),
                expectation.rule_id.encode("utf-8"),
                str(start).encode("ascii"),
                str(end).encode("ascii"),
                digest.encode("ascii"),
            ]
        )
    ).hexdigest()
    return {
        "finding_id": f"t-{identity}",
        "dataset_id": dataset_id,
        "dataset_version": dataset_version,
        "path": path,
        "classification": "EXPECTED_DETECTION",
        "category": expectation.family,
        "risk_bearing": True,
        "line_start": line_for(data, start),
        "line_end": line_end_for(data, start, end),
        "expected_rule_id": expectation.rule_id,
        "start_byte": start,
        "end_byte": end,
        "secret_sha256": digest,
        "required": True,
        "metadata": {
            "provider_family": expectation.family,
            "credential_type": expectation.credential_type,
            "detector_confidence": expectation.confidence,
        },
    }


def _values(seed_prefix: str) -> dict[str, bytes]:
    values = {
        "AWS_KEY": ("AKIA" + deterministic(f"{seed_prefix}-aws-key", UPPER, 16)).encode(),
        "AWS_SECRET": deterministic(f"{seed_prefix}-aws-secret", BASE64, 40).encode(),
        "AWS_KEY_COMMENT": ("ASIA" + deterministic(f"{seed_prefix}-aws-comment", UPPER, 16)).encode(),
        "GCP_KEY": ("AIza" + deterministic(f"{seed_prefix}-gcp", TOKEN_CHARS, 35)).encode(),
        "GH_CLASSIC": ("ghp_" + deterministic(f"{seed_prefix}-gh-classic", ALNUM, 36)).encode(),
        "GH_CLASSIC_2": ("ghp_" + deterministic(f"{seed_prefix}-gh-classic-2", ALNUM, 36)).encode(),
        "GH_FINE": ("github_pat_" + deterministic(f"{seed_prefix}-gh-fine", ALNUM + "_", 82)).encode(),
        "GH_OAUTH": ("gho_" + deterministic(f"{seed_prefix}-gh-oauth", ALNUM, 36)).encode(),
        "GH_DUP_A": ("ghp_" + deterministic(f"{seed_prefix}-gh-dup-a", ALNUM, 36)).encode(),
        "GH_DUP_B": ("ghp_" + deterministic(f"{seed_prefix}-gh-dup-b", ALNUM, 36)).encode(),
        "GITLAB": ("glpat-" + deterministic(f"{seed_prefix}-gitlab", TOKEN_CHARS, 20)).encode(),
        "STRIPE": ("sk_test_" + deterministic(f"{seed_prefix}-stripe", ALNUM, 24)).encode(),
        "SLACK": (
            "xoxb-"
            + deterministic(f"{seed_prefix}-slack-a", "0123456789", 12)
            + "-"
            + deterministic(f"{seed_prefix}-slack-b", "0123456789", 12)
            + "-"
            + deterministic(f"{seed_prefix}-slack-c", ALNUM, 24)
        ).encode(),
        "SENDGRID": (
            "SG."
            + deterministic(f"{seed_prefix}-sendgrid-a", TOKEN_CHARS, 22)
            + "."
            + deterministic(f"{seed_prefix}-sendgrid-b", TOKEN_CHARS, 43)
        ).encode(),
        "NPM": ("npm_" + deterministic(f"{seed_prefix}-npm", ALNUM, 36)).encode(),
        "DB_CRED": ("rnc_user:" + deterministic(f"{seed_prefix}-db", ALNUM, 32)).encode(),
        "GENERIC": deterministic(f"{seed_prefix}-generic", ALNUM, 32).encode(),
        "GENERIC_2": deterministic(f"{seed_prefix}-generic-2", ALNUM, 32).encode(),
        "JWT": make_jwt().encode(),
        "PEM_RSA": pem("RSA PRIVATE KEY", dummy_rsa_der()).encode(),
        "PEM_PKCS8": pem("PRIVATE KEY", dummy_pkcs8_der()).encode(),
        "PEM_OPENSSH": pem("OPENSSH PRIVATE KEY", dummy_openssh()).encode(),
        "DOCS_AWS": ("AKIA" + "IOSFODNN7EXAMPLE").encode(),
        "DOCS_AWS_SECRET": ("wJalrXUtn" + "FEMI/K7MDENG" + "/bPxRfiCY" + "EXAMPLEKEY").encode(),
        "DOCS_GCP": ("AIza" + "A" * 35).encode(),
        "DOCS_GITHUB": ("ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz").encode(),
    }
    return values


E_AWS_KEY = Expectation("AWS_KEY", "aws-access-key-id", "aws-credentials", "access-key-id", "high")
E_AWS_SECRET = Expectation(
    "AWS_SECRET", "aws-secret-access-key", "aws-credentials", "secret-access-key", "high"
)
E_GCP = Expectation("GCP_KEY", "google-api-key", "google-cloud-api-key", "api-key", "high")
E_GH_CLASSIC = Expectation(
    "GH_CLASSIC", "github-classic-pat", "github-token", "classic-personal-access-token", "high"
)
E_GH_CLASSIC_2 = Expectation(
    "GH_CLASSIC_2", "github-classic-pat", "github-token", "classic-personal-access-token", "high"
)
E_GH_FINE = Expectation(
    "GH_FINE", "github-fine-grained-pat", "github-token", "fine-grained-personal-access-token", "high"
)
E_GH_OAUTH = Expectation(
    "GH_OAUTH", "github-oauth-app-token", "github-token", "oauth-or-app-token", "medium"
)
E_GH_DUP_A = Expectation(
    "GH_DUP_A", "github-classic-pat", "github-token", "classic-personal-access-token", "high"
)
E_GH_DUP_B = Expectation(
    "GH_DUP_B", "github-classic-pat", "github-token", "classic-personal-access-token", "high"
)
E_GITLAB = Expectation(
    "GITLAB", "gitlab-personal-access-token", "gitlab-pat", "personal-access-token", "high"
)
E_STRIPE = Expectation(
    "STRIPE", "stripe-secret-api-key", "stripe-secret-key", "secret-api-key", "high"
)
E_SLACK = Expectation("SLACK", "slack-token", "slack-token", "bot-or-user-token", "medium")
E_SENDGRID = Expectation(
    "SENDGRID", "sendgrid-api-key", "sendgrid-api-key", "api-key", "high"
)
E_NPM = Expectation("NPM", "npm-auth-token", "npm-token", "auth-token", "high")
E_DB = Expectation(
    "DB_CRED", "database-connection-credential", "database-connection-string", "connection-uri-userinfo", "medium"
)
E_GENERIC = Expectation(
    "GENERIC", "generic-secret-assignment", "generic-secret-assignment", "assigned-secret", "low"
)
E_GENERIC_2 = Expectation(
    "GENERIC_2", "generic-secret-assignment", "generic-secret-assignment", "assigned-secret", "low"
)
E_JWT = Expectation("JWT", "jwt-bearer-token", "jwt-bearer", "bearer-token", "medium")
E_PEM_RSA = Expectation(
    "PEM_RSA", "pem-private-key", "pem-private-key", "private-key-container", "high"
)
E_PEM_PKCS8 = Expectation(
    "PEM_PKCS8", "pem-private-key", "pem-private-key", "private-key-container", "high"
)
E_PEM_OPENSSH = Expectation(
    "PEM_OPENSSH", "pem-private-key", "pem-private-key", "private-key-container", "high"
)
E_AWS_COMMENT = Expectation(
    "AWS_KEY_COMMENT", "aws-access-key-id", "aws-credentials", "access-key-id", "high"
)


def tier2_fixtures() -> list[Fixture]:
    specs: list[tuple[str, str, list[Expectation]]] = [
        (
            "aws.env",
            "AWS_ACCESS_KEY_ID={{AWS_KEY}}\n"
            "aws_secret_access_key = {{AWS_SECRET}}\n"
            "# Documentation example, not a credential:\n"
            "AWS_ACCESS_KEY_ID={{DOCS_AWS}}\n"
            "AWS_ACCESS_KEY_ID=AKIAQ7Z3K5M2N4P6R8T\n",
            [E_AWS_KEY, E_AWS_SECRET],
        ),
        (
            "cloud.json",
            '{\n  "apiKey": "{{GCP_KEY}}",\n  "project_id": "rnc-fixture-project",\n'
            '  "note": "{{DOCS_GCP}}"\n}\n',
            [E_GCP],
        ),
        (
            "github.yaml",
            f"classic: {{{{GH_CLASSIC}}}}\n"
            f"fine_grained: {{{{GH_FINE}}}}\n"
            f"oauth: {{{{GH_OAUTH}}}}\n"
            "short: ghp_short\n"
            "docs: {{DOCS_GITHUB}}\n",
            [E_GH_CLASSIC, E_GH_FINE, E_GH_OAUTH],
        ),
        (
            "gitlab.env",
            "GITLAB_TOKEN={{GITLAB}}\nPROJECT_ID=12345678\nGITLAB_TOKEN=glpat-short\n",
            [E_GITLAB],
        ),
        (
            "stripe.js",
            'const secret = "{{STRIPE}}";\n'
            'const publishable = "pk_test_aaaaaaaaaaaaaaaaaaaaaaaa";\n'
            'const malformed = "sk_live_short";\n',
            [E_STRIPE],
        ),
        (
            "slack.yaml",
            "bot_token: {{SLACK}}\nlegacy: xoxq-123456789012-123456789012-abcdefghijklmnop\n",
            [E_SLACK],
        ),
        (
            "sendgrid.py",
            'SENDGRID_API_KEY = "{{SENDGRID}}"\n'
            'MALFORMED = "SG.short.short"\n',
            [E_SENDGRID],
        ),
        (
            ".npmrc",
            "//registry.npmjs.org/:_authToken={{NPM}}\n"
            "legacy=0123456789abcdef\n",
            [E_NPM],
        ),
        (
            "database.yml",
            "production:\n  url: postgresql://{{DB_CRED}}@db.example.invalid:5432/app\n"
            "  public_url: postgresql://db.example.invalid:5432/app\n"
            "  variable: postgresql://rnc_user:${DB_PASSWORD}@db.example.invalid/app\n",
            [E_DB],
        ),
        (
            "generic.toml",
            'password = "{{GENERIC}}"\n'
            'client_secret = "{{GENERIC_2}}"\n'
            'password = "password"\n'
            'api_key = "${API_KEY}"\n'
            'password = "aaaaaaaa"\n',
            [E_GENERIC, E_GENERIC_2],
        ),
        (
            "pem/private-rsa.pem",
            "{{PEM_RSA}}\n",
            [E_PEM_RSA],
        ),
        (
            "pem/private-pkcs8.pem",
            "{{PEM_PKCS8}}\n",
            [E_PEM_PKCS8],
        ),
        (
            "pem/private-openssh.pem",
            "{{PEM_OPENSSH}}\n",
            [E_PEM_OPENSSH],
        ),
        (
            "pem/public.pem",
            "-----BEGIN PUBLIC KEY-----\n"
            "cm5jLXRlc3Qtbm90LWEta2V5\n"
            "-----END PUBLIC KEY-----\n",
            [],
        ),
        (
            "pem/certificate.pem",
            "-----BEGIN CERTIFICATE-----\n"
            "cm5jLXRlc3Qtbm90LWEtY2VydGlmaWNhdGU=\n"
            "-----END CERTIFICATE-----\n",
            [],
        ),
        (
            "jwt.txt",
            "authorization: Bearer {{JWT}}\n"
            "bare: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJybmMifQ.c2lnbmF0dXJl\n",
            [E_JWT],
        ),
        (
            "same-line.txt",
            "tokens: {{GH_DUP_A}} and {{GH_DUP_B}}\n",
            [E_GH_DUP_A, E_GH_DUP_B],
        ),
        (
            "crlf.txt",
            "AWS_ACCESS_KEY_ID={{AWS_KEY}}\r\n"
            "note=crlf\r\n",
            [E_AWS_KEY],
        ),
        (
            "unicode.txt",
            "caf\u00e9 \U0001f511 \u2014 {{GH_CLASSIC_2}}\n",
            [E_GH_CLASSIC_2],
        ),
        (
            "binary.bin",
            b"\x00\xff\x00{{AWS_KEY}}\x00\x01",
            [E_AWS_KEY],
        ),
        (
            "decoys.txt",
            "{{DOCS_AWS}}\n"
            "{{DOCS_AWS_SECRET}}\n"
            "{{DOCS_GCP}}\n"
            "{{DOCS_GITHUB}}\n"
            "glpat-short\n"
            "xoxb-short\n"
            "SG.short.short\n"
            "npm_short\n"
            "authorization: Bearer eyJhbGciOiJIUzI1NiJ9.not-json.signature\n",
            [],
        ),
        (
            "high-entropy.txt",
            "sha256=" + deterministic("high-entropy-sha", "0123456789abcdef", 64) + "\n"
            "uuid=" + deterministic("high-entropy-uuid", "0123456789abcdef", 32) + "\n"
            "base64=" + deterministic("high-entropy-b64", BASE64, 80) + "\n",
            [],
        ),
        (
            "comments.md",
            "This line documents a fake key: {{AWS_KEY_COMMENT}}\n",
            [E_AWS_COMMENT],
        ),
        (
            "boundaries.txt",
            "{{GH_CLASSIC_2}}!{{NPM}}?{{GCP_KEY}}",
            [E_GH_CLASSIC_2, E_NPM, E_GCP],
        ),
    ]
    fixtures = []
    for path, template, expectations in specs:
        fixtures.append(Fixture(path=path, template=template, expectations=expectations))
    return fixtures


def tier3_fixtures() -> list[Fixture]:
    specs: list[tuple[str, str | bytes, list[Expectation]]] = [
        (
            "mixed/app.env",
            "AWS_ACCESS_KEY_ID={{AWS_KEY}}\n"
            "GOOGLE_API_KEY={{GCP_KEY}}\n"
            "DECOY={{DOCS_AWS}}\n"
            "SHORT=ghp_short\n",
            [E_AWS_KEY, E_GCP],
        ),
        (
            "mixed/config.yaml",
            "github:\n  token: {{GH_FINE}}\n"
            "slack:\n  token: {{SLACK}}\n"
            "database: postgresql://{{DB_CRED}}@db.invalid/app\n",
            [E_GH_FINE, E_SLACK, E_DB],
        ),
        (
            "edge/same-line.txt",
            "same={{GH_CLASSIC}};other={{GH_CLASSIC_2}}\n",
            [E_GH_CLASSIC, E_GH_CLASSIC_2],
        ),
        (
            "edge/crlf.txt",
            "token={{GITLAB}}\r\npassword={{GENERIC}}\r\n",
            [E_GITLAB, E_GENERIC],
        ),
        (
            "edge/binary.dat",
            b"\x00\x01{{SENDGRID}}\x00{{NPM}}\xff",
            [E_SENDGRID, E_NPM],
        ),
        (
            "edge/multiline.pem",
            "prefix\n{{PEM_RSA}}\nsuffix\n",
            [E_PEM_RSA],
        ),
        (
            "edge/unicode.txt",
            "\u00e9\u00e8\u00ea {{STRIPE}} \U0001f512\n",
            [E_STRIPE],
        ),
        (
            "edge/decoys.md",
            "Public key:\n-----BEGIN PUBLIC KEY-----\ncm5jLXRlc3Q=\n-----END PUBLIC KEY-----\n"
            "JWT without context: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJybmMifQ.c2ln\n"
            "Placeholder: {{DOCS_AWS}}\n"
            "Password: password\n",
            [],
        ),
        (
            "edge/generic.conf",
            'client_secret="{{GENERIC_2}}"\n'
            'auth_token="${AUTH_TOKEN}"\n',
            [E_GENERIC_2],
        ),
        (
            "edge/jwt.txt",
            "Authorization: Bearer {{JWT}}\n",
            [E_JWT],
        ),
    ]
    fixtures = []
    for path, template, expectations in specs:
        fixtures.append(Fixture(path=path, template=template, expectations=expectations))
    return fixtures


def write_dataset(
    root: Path,
    truth_path: Path,
    fixtures: list[Fixture],
    *,
    seed_prefix: str,
    dataset_id: str,
    dataset_version: str,
    manifest_id: str,
    negative_files: Iterable[str] = (),
) -> dict:
    values = _values(seed_prefix)
    items = []
    files = []
    for fixture in fixtures:
        data, spans = render(fixture.template, values)
        destination = root / fixture.path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        files.append(
            {
                "path": fixture.path,
                "byte_length": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "expected_count": len(fixture.expectations),
            }
        )
        for expectation in fixture.expectations:
            occurrences = spans.get(expectation.placeholder, [])
            if not occurrences:
                raise RuntimeError(f"{fixture.path}: no occurrence for {expectation.placeholder}")
            for start, end in occurrences:
                items.append(
                    truth_item(
                        dataset_id,
                        dataset_version,
                        fixture.path,
                        data,
                        start,
                        end,
                        expectation,
                    )
                )
    items.sort(key=lambda item: (item["path"], item["start_byte"], item["expected_rule_id"]))
    document = {
        "schema_version": 1,
        "manifest_id": manifest_id,
        "manifest_version": dataset_version,
        "dataset_id": dataset_id,
        "dataset_version": dataset_version,
        "source_root": str(root.relative_to(ROOT)).replace("\\", "/"),
        "scoring_policy": {
            "id": "byte-range-v1",
            "version": "1",
            "require_line": True,
            "allow_partial": False,
            "negative_oracle": True,
            "one_to_one": True,
        },
        "items": items,
        "files": files,
        "negative_files": sorted(set(negative_files)),
        "counts": {
            "expected_items": len(items),
            "files": len(files),
            "positive_files": sum(1 for file in files if file["expected_count"] > 0),
            "negative_files": sum(1 for file in files if file["expected_count"] == 0),
        },
        "provenance": {
            "generator": "tools/cp3/fixtures.py",
            "detector_output_used": False,
            "fixture_material": "deterministic harmless synthetic values; no live credentials",
        },
    }
    truth_path.parent.mkdir(parents=True, exist_ok=True)
    truth_path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return document


def build() -> tuple[dict, dict]:
    import shutil

    for root in (TIER2_ROOT, TIER3_ROOT):
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True)
    fixtures2 = tier2_fixtures()
    document2 = write_dataset(
        TIER2_ROOT,
        TRUTH_ROOT / "provider-truth-tier2.json",
        fixtures2,
        seed_prefix="tier2",
        dataset_id="rnc-provider-fixtures-tier2",
        dataset_version="2026.11.1",
        manifest_id="rnc-cp3-provider-truth-tier2",
        negative_files={
            "pem/public.pem",
            "pem/certificate.pem",
            "decoys.txt",
            "high-entropy.txt",
        },
    )
    fixtures3 = tier3_fixtures()
    document3 = write_dataset(
        TIER3_ROOT,
        TRUTH_ROOT / "provider-truth-tier3-heldout.json",
        fixtures3,
        seed_prefix="tier3",
        dataset_id="rnc-provider-fixtures-tier3-heldout",
        dataset_version="2026.11.1",
        manifest_id="rnc-cp3-provider-truth-tier3-heldout",
        negative_files={"edge/decoys.md"},
    )
    write_bundle({"tier2": TIER2_ROOT, "tier3": TIER3_ROOT})
    return document2, document3


if __name__ == "__main__":
    tier2, tier3 = build()
    print(json.dumps({"tier2": tier2["counts"], "tier3": tier3["counts"]}, indent=2))

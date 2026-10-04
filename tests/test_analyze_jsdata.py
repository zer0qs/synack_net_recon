"""Tests for front-end asset analysis.

Two things matter most here and are tested hardest:

* **Masking.** A raw secret or a real email address must never survive into the
  reported value. A report that leaks what it found is worse than no report.
* **False positives.** These patterns are heuristics over minified code, where
  version strings, build ids, hashes and dotted identifiers all look like
  something. Every pattern has a "does not fire on" test next to its "does
  fire on" test, because an analyst who learns to skim this section has lost
  the value of it entirely.
"""

from __future__ import annotations

import pytest

from netrecon.analyze.jsdata import (
    MAX_MATCHES_PER_KIND,
    SECRET_PATTERNS,
    _is_hostname,
    analyse_javascript,
    extract_comments,
    extract_endpoints,
    extract_infrastructure,
    extract_pii,
    extract_secrets,
    extract_source_maps,
    looks_like_placeholder,
    mask_digits,
    mask_email,
    mask_value,
    merge_analyses,
    pii_summary,
)

# Synthetic test data only. These never reach a report.
FAKE_KEY = "9f2b7c41de8a46f0b35e7a19cc04d2e8"
FAKE_AWS = "AKIA" + "ZZ7QQQ3MMMNNN42X"
FAKE_AWS_LONG = FAKE_AWS + ("WXYZ" + "ABCDEFGHJKLMNPQRSTUVW")
# 4111... is the universally published Visa test number, not a real card.
TEST_CARD = "4111 1111 1111 1111"


# -- masking -------------------------------------------------------------


def test_mask_value_hides_the_middle_but_keeps_a_handle():
    masked = mask_value(FAKE_KEY)
    assert FAKE_KEY not in masked
    assert masked == "9f2b7c\u2026d2e8 (len 32)"


def test_mask_value_keeps_first_six_and_last_four():
    masked = mask_value(FAKE_AWS)
    assert masked.startswith("AKIAZZ")
    assert "\u2026" in masked
    assert masked.split("\u2026")[1].startswith("N42X")
    assert FAKE_AWS not in masked


def test_mask_value_never_leaks_the_raw_value_at_any_length():
    for length in range(1, 60):
        value = FAKE_AWS_LONG[:length]
        masked = mask_value(value)
        assert value not in masked or len(value) <= 2, (value, masked)


def test_mask_value_on_short_strings_reveals_almost_nothing():
    # 12 characters or fewer: at most the first two survive, never the tail.
    assert mask_value("abcdef") == "ab****"
    assert mask_value("abcdefgh") == "ab******"
    assert mask_value("abcdefghijkl") == "ab" + "*" * 10


def test_mask_email_keeps_the_domain_which_is_the_useful_part():
    masked = mask_email("alice.nguyen@acme.vn")
    assert masked.endswith("@acme.vn")
    assert "alice.nguyen" not in masked


def test_mask_digits_keeps_only_the_last_four():
    assert mask_digits("4111 1111 1111 1111") == "************1111"
    assert "4111 1111 1111 1111".replace(" ", "") not in mask_digits(TEST_CARD)


# -- API surface ---------------------------------------------------------


def test_api_paths_are_extracted():
    body = 'const a = "/api/v2/users"; const b = "/rest/orders"; const c = "/graphql";'
    values = {e.value for e in extract_endpoints(body)}
    assert {"/api/v2/users", "/rest/orders", "/graphql"} <= values


def test_http_method_is_captured_from_the_call_site():
    body = 'axios.post("/api/v1/orders", data); fetch("/api/v1/me", { method: "DELETE" });'
    by_value = {e.value: e for e in extract_endpoints(body)}
    assert by_value["/api/v1/orders"].method == "POST"
    assert by_value["/api/v1/me"].method == "DELETE"


def test_xhr_open_method_is_captured():
    body = 'xhr.open("PUT", "/api/v1/profile");'
    assert extract_endpoints(body)[0].method == "PUT"


def test_absolute_urls_are_extracted_and_classified():
    body = 'const u = "https://api.internal.acme.vn/v1/token";'
    endpoint = extract_endpoints(body)[0]
    assert endpoint.kind == "url"
    assert endpoint.value == "https://api.internal.acme.vn/v1/token"


def test_template_paths_are_extracted():
    body = 'const u = `/api/v1/users/${userId}/orders`;'
    assert any("${userId}" in e.value for e in extract_endpoints(body))


def test_static_assets_are_not_api_endpoints():
    body = '"/static/app.css" "/img/logo.png" "/fonts/x.woff2" "/bundle.js.map"'
    assert extract_endpoints(body) == []


def test_data_and_mailto_urls_are_ignored():
    body = '"data:image/png;base64,AAA" "mailto:a@b.com" "javascript:void(0)"'
    assert extract_endpoints(body) == []


def test_endpoints_are_deduplicated():
    body = 'fetch("/api/v1/me"); fetch("/api/v1/me"); fetch("/api/v1/me");'
    assert len(extract_endpoints(body)) == 1


# -- secrets -------------------------------------------------------------


def test_assigned_secret_records_name_and_masks_value():
    found = extract_secrets(f'const config = {{ api_key: "{FAKE_KEY}" }};')
    assert len(found) == 1
    assert found[0].name == "api_key"
    assert found[0].category == "secret"
    assert FAKE_KEY not in found[0].value


def test_secret_is_unmasked_only_when_redaction_is_off():
    found = extract_secrets(f'api_key = "{FAKE_KEY}"', redact=False)
    assert found[0].value == FAKE_KEY


def test_context_blanks_out_the_secret_itself():
    found = extract_secrets(f'const x = 1; api_key = "{FAKE_KEY}"; const y = 2;')
    assert FAKE_KEY not in (found[0].context or "")
    assert "[redacted]" in (found[0].context or "")


def test_aws_key_shape_is_detected():
    found = extract_secrets(f'k = "{FAKE_AWS}"')
    assert "aws_access_key_id" in {f.kind for f in found}


def test_credentials_in_a_connection_string_are_detected_once():
    body = 'const DB = "mongodb://admin:s3cr3tP4ss@10.0.5.12:27017/prod";'
    kinds = [f.kind for f in extract_secrets(body)]
    assert "basic_auth_in_url" in kinds
    # The same URL must not also be reported as a bare connection string.
    assert kinds.count("connection_string") == 0


def test_connection_string_without_credentials_is_still_reported():
    body = 'const DB = "postgresql://db.internal.acme.vn:5432/analytics";'
    assert "connection_string" in {f.kind for f in extract_secrets(body)}


def test_line_numbers_point_at_the_match():
    body = f'var a = 1;\nvar b = 2;\napi_key = "{FAKE_KEY}";'
    assert extract_secrets(body)[0].line == 3


@pytest.mark.parametrize(
    "snippet",
    [
        'api_key = "your_api_key_here"',
        'api_key = "${API_KEY}"',
        'api_key = "{{ api_key }}"',
        'api_key = "<your-key>"',
        'api_key = "xxxxxxxxxxxxxxxx"',
        'api_key = "CHANGEME_BEFORE_DEPLOY"',
        'api_key = "aaaaaaaaaaaa"',
        'api_key = "process.env.API_KEY"',
        'api_key = "undefined"',
        'api_key = "short"',
    ],
)
def test_placeholders_are_not_reported_as_secrets(snippet):
    assert extract_secrets(snippet) == []


def test_looks_like_placeholder_is_conservative_about_real_values():
    assert looks_like_placeholder(FAKE_KEY) is False


def test_secret_count_per_kind_is_capped():
    body = "\n".join(f'api_key = "{i:032x}aa"' for i in range(MAX_MATCHES_PER_KIND + 20))
    assert len(extract_secrets(body)) <= MAX_MATCHES_PER_KIND


# -- secrets: one rule at a time -----------------------------------------
#
# Every sample token below is assembled from concatenated halves. Written as
# one literal, a realistic-looking token trips secret scanners and push
# protection, and this file would stop being pushable.

MAILGUN_KEY = "key-" + "0a1b2c3d4e5f60718293a4b5c6d7e8f9"
FIREBASE_KEY = "AIza" + "SyB7qLmN0pQrStUvWxYzAbCdEfGhIjKlMnO"
BEARER_JWT = "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiJvcHMifQ" + "." + "q1w2e3r4t5y6u7i8o9pX"
BASIC_CREDS = "YWRtaW46c3VwZXJ" + "zZWNyZXRwYXNzd29yZA=="
AZURE_KEY = "Zm9vYmFyYmF6cXV4YWJjZGVmZ2hpamts" + "bW5vcHFyc3R1dnd4eXpBQkNERUZHSD09"
HEROKU_UUID = "7b1c9e52-4d3a" + "-4f81-9b2e-61ca84d0f3ab"
GCP_BLOB = (
    '{"type": "service_account", "project_id": "acme-prod",'
    ' "private_key_id": "a1b2c3d4e5f6a7b8c9d0",'
    ' "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0B\\n'
    '-----END PRIVATE KEY-----\\n",'
    ' "client_email": "deploy@acme-prod.iam.gserviceaccount.com"}'
)


def kinds_of(body: str) -> set[str]:
    return {f.kind for f in extract_secrets(body)}


def test_mailgun_key_is_detected():
    assert "mailgun_key" in kinds_of(f'const MG = "{MAILGUN_KEY}";')


def test_a_word_ending_in_key_is_not_a_mailgun_key():
    body = 'const monkey = "mon' + 'key-' + '0a1b2c3d4e5f60718293a4b5c6d7e8f9";'
    assert "mailgun_key" not in kinds_of(body)


def test_gcp_service_account_blob_is_detected_by_its_marker():
    found = [f for f in extract_secrets(GCP_BLOB) if f.kind == "gcp_service_account"]
    assert len(found) == 1
    # The marker is reported, not the key body: a report is not a key escrow.
    assert "MIIEvQIBADANBgkqhkiG9w0B" not in (found[0].value + (found[0].context or ""))


def test_a_service_account_type_without_a_private_key_is_not_a_credential():
    body = '{"type": "service_account", "label": "how we name robot users"}'
    assert "gcp_service_account" not in kinds_of(body)


def test_firebase_config_pair_is_detected():
    body = (
        f'const cfg = {{ apiKey: "{FIREBASE_KEY}",'
        ' authDomain: "acme-prod.web.app", projectId: "acme-prod" };'
    )
    assert "firebase_config" in kinds_of(body)


def test_firebase_database_url_is_detected():
    assert "firebase_config" in kinds_of('databaseURL: "https://acme-prod.firebaseio.com"')


def test_an_api_key_on_its_own_is_not_a_firebase_config():
    """Without authDomain/projectId beside it this is just a Google API key."""
    assert "firebase_config" not in kinds_of(f'const k = "{FIREBASE_KEY}";')


def test_a_templated_firebase_config_does_not_fire():
    body = (
        'const cfg = { apiKey: "YOUR_API_KEY",'
        ' authDomain: "${PROJECT}.firebaseapp.com", projectId: "your-project-id" };'
    )
    assert extract_secrets(body) == []


def test_bearer_header_is_detected_in_both_source_shapes():
    assert "bearer_header" in kinds_of(f'headers: {{ "Authorization": "Bearer {BEARER_JWT}" }}')
    assert "bearer_header" in kinds_of(
        f'xhr.setRequestHeader("Authorization", "Bearer {BEARER_JWT}");'
    )


def test_a_bearer_header_built_from_a_variable_does_not_fire():
    assert extract_secrets('headers: { Authorization: `Bearer ${accessToken}` }') == []
    assert extract_secrets('h["Authorization"] = "Bearer " + token;') == []


def test_basic_auth_header_is_detected():
    body = f'xhr.setRequestHeader("Authorization", "Basic {BASIC_CREDS}");'
    found = [f for f in extract_secrets(body) if f.kind == "basic_auth_header"]
    assert len(found) == 1
    assert BASIC_CREDS not in found[0].value


def test_a_basic_header_built_at_runtime_does_not_fire():
    assert extract_secrets('h.Authorization = "Basic " + btoa(user + ":" + pass);') == []


def test_azure_storage_key_is_detected_in_a_connection_string():
    body = (
        'const cs = "DefaultEndpointsProtocol=https;AccountName=acmeblob;'
        f'AccountKey={AZURE_KEY};EndpointSuffix=core.windows.net";'
    )
    assert "azure_storage_key" in kinds_of(body)


def test_an_account_key_read_from_the_environment_does_not_fire():
    body = 'const cs = "AccountName=acmeblob;AccountKey=${AZURE_STORAGE_KEY};";'
    assert "azure_storage_key" not in kinds_of(body)


def test_uuid_assigned_to_a_key_name_is_detected():
    assert "heroku_api_key" in kinds_of(f'HEROKU_API_KEY = "{HEROKU_UUID}"')
    assert "heroku_api_key" in kinds_of(f'{{ "api_key": "{HEROKU_UUID}" }}')


def test_a_bare_uuid_is_not_a_credential():
    """Request ids, build ids and React keys are UUIDs far more often than keys."""
    assert extract_secrets(f'const requestId = "{HEROKU_UUID}";') == []


# -- the ruleset as a whole ----------------------------------------------

#: One placeholder-shaped sample per rule. Parametrising over SECRET_PATTERNS
#: means a new rule without an entry here fails the sweep rather than quietly
#: skipping it.
PLACEHOLDER_SAMPLES: dict[str, str] = {
    "aws_access_key_id": '"' + "AKIA" + "XXXXXXXXXXXXXXXX" + '"',
    "aws_secret_access_key": 'aws_secret_access_key = "' + "X" * 40 + '"',
    "azure_storage_key": 'const cs = "AccountKey=${AZURE_STORAGE_KEY};";',
    "basic_auth_header": 'headers: { Authorization: `Basic ${credentials}` }',
    "basic_auth_in_url": 'const u = "https://admin:${DB_PASSWORD}@db.acme.vn/prod";',
    "bearer_header": 'headers: { Authorization: `Bearer ${accessToken}` }',
    "connection_string": 'const dsn = "postgresql://${DB_HOST}:5432/app";',
    "firebase_config": (
        'const cfg = { apiKey: "YOUR_API_KEY", authDomain: "${PROJECT}.firebaseapp.com" };'
    ),
    "gcp_service_account": '{"type": "service_account", "private_key": "${GCP_PRIVATE_KEY}"}',
    "github_token": '"' + "ghp_" + "X" * 36 + '"',
    "gitlab_token": '"' + "glpat-" + "X" * 20 + '"',
    "google_api_key": '"' + "AIza" + "X" * 35 + '"',
    "google_oauth_id": '"' + "1234567890" + "-" + "x" * 32 + ".apps.googleusercontent.com" + '"',
    "heroku_api_key": 'HEROKU_API_KEY = "00000000-0000-0000-0000-000000000000"',
    "jwt": '"' + "eyJ" + "x" * 10 + "." + "x" * 10 + "." + "x" * 10 + '"',
    "mailgun_key": '"' + "key-" + "abc123" + "0" * 26 + '"',
    "npm_token": '"' + "npm_" + "X" * 36 + '"',
    "openai_key": '"' + "sk-" + "X" * 24 + '"',
    "private_key_block": "-----BEGIN ${KEY_TYPE} PRIVATE KEY-----",
    "sendgrid_key": '"' + "SG." + "X" * 22 + "." + "X" * 22 + '"',
    "slack_token": '"' + "xoxb-" + "X" * 20 + '"',
    "slack_webhook": '"' + "https://hooks.slack.com/services/" + "X" * 24 + '"',
    "stripe_key": '"' + "sk_test_" + "X" * 16 + '"',
    "twilio_sid": '"' + "AC" + "abc123" + "0" * 26 + '"',
}


@pytest.mark.parametrize("rule", sorted({name for name, _ in SECRET_PATTERNS}))
def test_every_rule_ignores_a_placeholder_shaped_value(rule):
    sample = PLACEHOLDER_SAMPLES.get(rule)
    assert sample is not None, f"add a placeholder sample for the {rule} rule"
    assert rule not in kinds_of(sample)


def test_the_ruleset_covers_at_least_twenty_named_rules():
    assert len({name for name, _ in SECRET_PATTERNS}) >= 20


def test_every_rule_exposes_a_capture_group_and_a_name():
    for name, pattern in SECRET_PATTERNS:
        assert name and name.islower()
        assert pattern.groups >= 1, name


def test_every_finding_carries_its_rule_name_source_and_line():
    body = f'var a = 1;\nconst MG = "{MAILGUN_KEY}";'
    found = [f for f in extract_secrets(body, source="app.js") if f.kind == "mailgun_key"]
    assert (found[0].kind, found[0].source, found[0].line) == ("mailgun_key", "app.js", 2)


def test_no_secret_finding_ever_contains_its_raw_value():
    body = "\n".join(
        [
            f'const MG = "{MAILGUN_KEY}";',
            f'const fb = {{ apiKey: "{FIREBASE_KEY}", projectId: "acme" }};',
            f'xhr.setRequestHeader("Authorization", "Basic {BASIC_CREDS}");',
            f'HEROKU_API_KEY = "{HEROKU_UUID}";',
        ]
    )
    raw = (MAILGUN_KEY, FIREBASE_KEY, BASIC_CREDS, HEROKU_UUID)
    for match in extract_secrets(body):
        for value in raw:
            assert value not in match.value


# -- PII -----------------------------------------------------------------


def test_email_is_detected_and_masked():
    found = extract_pii('const support = "alice.nguyen@acme.vn";')
    assert [f.kind for f in found] == ["email"]
    assert "alice.nguyen" not in found[0].value
    assert found[0].value.endswith("@acme.vn")


@pytest.mark.parametrize(
    "address",
    [
        "user@example.com",
        "test@test.com",
        "noreply@acme.vn",
        "no-reply@acme.vn",
        "a@localhost",
    ],
)
def test_example_and_noreply_addresses_are_not_pii(address):
    assert extract_pii(f'const e = "{address}";') == []


def test_card_number_must_pass_luhn():
    valid = extract_pii(f'const card = "{TEST_CARD}";')
    assert [f.kind for f in valid] == ["credit_card"]
    # A long number that fails the checksum is an id or a timestamp, not a card.
    assert extract_pii('const x = "1234 5678 9012 3456";') == []


def test_card_number_is_masked_to_the_last_four():
    found = extract_pii(f'const card = "{TEST_CARD}";')
    assert found[0].value == "************1111"


def test_phone_number_is_detected_with_an_international_prefix():
    found = extract_pii('const phone = "+84 912 345 678";')
    assert [f.kind for f in found] == ["phone"]


def test_an_ip_address_is_not_a_phone_number():
    """169.254.169.254 has enough digits to look like a phone; it is not one."""
    kinds = {f.kind for f in extract_pii('const meta = "169.254.169.254";')}
    assert "phone" not in kinds


def test_a_version_string_is_not_a_phone_number():
    assert extract_pii('const v = "1.2.3.4005";') == []


def test_ssn_shape_is_detected():
    assert {f.kind for f in extract_pii('const s = "123-45-6789";')} == {"ssn"}


def test_pii_summary_counts_by_kind():
    body = 'a="x1@acme.vn"; b="x2@acme.vn"; c="+84 912 345 678";'
    summary = pii_summary(extract_pii(body))
    assert summary["email"] == 2
    assert summary["phone"] == 1


def test_pii_values_never_appear_raw_when_redacted():
    body = f'e="alice@acme.vn"; c="{TEST_CARD}";'
    for match in extract_pii(body):
        assert "alice@acme.vn" != match.value
        assert TEST_CARD.replace(" ", "") not in match.value


# -- PII: S3 buckets -----------------------------------------------------


@pytest.mark.parametrize(
    ("body", "bucket"),
    [
        ('"https://customer-exports.s3.amazonaws.com/2024/q1.csv"', "customer-exports"),
        ('"https://acme-backups.s3.eu-west-1.amazonaws.com/db.sql"', "acme-backups"),
        ('"https://s3.us-east-1.amazonaws.com/acme-invoices/jan.pdf"', "acme-invoices"),
        ('"https://s3.amazonaws.com/acme-invoices/jan.pdf"', "acme-invoices"),
        ('"s3://acme-pii-dump/users.json"', "acme-pii-dump"),
    ],
)
def test_s3_bucket_is_reported_by_name(body, bucket):
    found = [f for f in extract_pii(body) if f.kind == "s3_bucket"]
    assert [f.value for f in found] == [bucket]


def test_s3_bucket_name_is_not_masked_because_masking_it_destroys_the_finding():
    found = extract_pii('"https://acme-pii-dump.s3.amazonaws.com/users.json"')
    assert found[0].value == "acme-pii-dump"


@pytest.mark.parametrize(
    "body",
    [
        '"https://ec2.eu-west-1.amazonaws.com/"',
        '"https://sqs.us-east-1.amazonaws.com/queue/jobs"',
        '"https://cognito-idp.ap-southeast-1.amazonaws.com/pool"',
    ],
)
def test_other_aws_service_hosts_are_not_s3_buckets(body):
    assert "s3_bucket" not in {f.kind for f in extract_pii(body)}


def test_the_s3_label_of_a_virtual_host_url_is_not_itself_a_bucket():
    """Both patterns see one URL; only the bucket, not the path, is reported."""
    found = extract_pii('"https://customer-exports.s3.amazonaws.com/2024/q1.csv"')
    assert [f.value for f in found if f.kind == "s3_bucket"] == ["customer-exports"]


# -- PII: phone numbers and cards ----------------------------------------


@pytest.mark.parametrize("number", ["+84912345678", "+44 7700 900123", "+1 (415) 555-0132"])
def test_e164_numbers_are_the_confident_phone_case(number):
    assert "phone" in {f.kind for f in extract_pii(f'const p = "{number}";')}


def test_a_short_e164_number_is_still_detected():
    assert "phone" in {f.kind for f in extract_pii('const p = "+6581234567";')}


@pytest.mark.parametrize(
    "body",
    [
        'const meta = "169.254.169.254";',   # a dotted quad
        'const v = "1.2.3.4005";',            # a version string
        'const build = "20240931144512";',    # a timestamp
    ],
)
def test_digit_runs_that_are_not_phone_numbers(body):
    assert "phone" not in {f.kind for f in extract_pii(body)}


@pytest.mark.parametrize(
    ("number", "issuer"),
    [
        ("4111 1111 1111 1111", "visa"),
        ("5500 0000 0000 0004", "mastercard"),
        ("3400 0000 0000 009", "amex"),
        ("6011 0009 9013 9424", "discover"),
    ],
)
def test_known_issuer_prefixes_are_named_on_the_finding(number, issuer):
    found = [f for f in extract_pii(f'const c = "{number}";') if f.kind == "credit_card"]
    assert found and found[0].name == issuer


def test_an_unknown_issuer_prefix_is_still_reported_just_without_a_name():
    # Luhn-valid, but no issuer prefix we know. The prefix raises confidence,
    # it is not a gate, so the number is still reported - and still redacted.
    found = [f for f in extract_pii('const c = "9712 3456 7890 1009";') if f.kind == "credit_card"]
    assert found and found[0].name is None
    assert found[0].value == "************1009"


# -- infrastructure ------------------------------------------------------


def test_internal_hostname_is_reported():
    findings, hosts = extract_infrastructure('const u = "https://staging.internal.acme.corp/api";')
    assert "internal_hostname" in {f.kind for f in findings}
    assert "staging.internal.acme.corp" in hosts


def test_private_address_is_reported():
    findings, _ = extract_infrastructure('const db = "10.0.5.12:5432";')
    assert "private_address" in {f.kind for f in findings}


def test_cloud_metadata_endpoint_is_reported():
    findings, _ = extract_infrastructure('fetch("http://169.254.169.254/latest/meta-data/");')
    assert "cloud_metadata_endpoint" in {f.kind for f in findings}


def test_hostnames_are_not_masked_because_masking_them_hides_the_finding():
    findings, _ = extract_infrastructure('const u = "https://jenkins.internal.acme.corp";')
    assert any("jenkins.internal.acme.corp" in f.value for f in findings)


@pytest.mark.parametrize(
    "snippet",
    [
        "axios.post(url)",          # a method call, not a host
        'const e = "a.nguyen@x.vn"',  # the local part of an address
        '"/static/app.js.map"',     # a filename
        "obj.prop.value = 1",       # property access
    ],
)
def test_dotted_identifiers_are_not_hostnames(snippet):
    _, hosts = extract_infrastructure(snippet)
    assert all("." not in h or h.rsplit(".", 1)[-1] in {"vn"} for h in hosts), hosts


def test_well_known_cdns_are_not_reported_as_hosts():
    _, hosts = extract_infrastructure('"https://cdn.jsdelivr.net/x.js" "https://fonts.googleapis.com/c"')
    assert hosts == []


def test_loopback_is_not_treated_as_a_private_address_finding():
    findings, _ = extract_infrastructure('const u = "http://127.0.0.1:3000";')
    assert "private_address" not in {f.kind for f in findings}


# -- comments and source maps -------------------------------------------


def test_source_maps_are_extracted():
    assert extract_source_maps("var a=1;\n//# sourceMappingURL=/static/app.js.map") == [
        "/static/app.js.map"
    ]


def test_interesting_comments_are_kept():
    body = "// TODO: remove the staging key before launch\n/* just a licence header */"
    comments = extract_comments(body)
    assert any("TODO" in c for c in comments)
    assert not any("licence" in c for c in comments)


# -- whole-body analysis -------------------------------------------------


def test_analyse_javascript_populates_every_section():
    body = f"""
      fetch("/api/v2/users");
      const cfg = {{ api_key: "{FAKE_KEY}" }};
      const support = "alice@acme.vn";
      const host = "https://staging.internal.acme.corp";
      // TODO: move this out
      //# sourceMappingURL=/app.js.map
    """
    analysis = analyse_javascript(body, source="app.js")
    assert analysis.source == "app.js"
    assert analysis.endpoints
    assert analysis.secrets
    assert analysis.pii
    assert analysis.infrastructure
    assert analysis.source_maps == ["/app.js.map"]
    assert analysis.comments
    assert analysis.total_findings == (
        len(analysis.secrets) + len(analysis.pii) + len(analysis.infrastructure)
    )


def test_analyse_empty_body_is_empty_not_an_error():
    analysis = analyse_javascript("", source="empty.js")
    assert analysis.total_findings == 0
    assert analysis.endpoints == []
    assert analysis.bytes == 0


def test_analysis_is_json_safe():
    import json

    payload = analyse_javascript('fetch("/api/v1/x");', source="s").to_dict()
    assert json.loads(json.dumps(payload))["totals"]["endpoints"] == 1


def test_merge_prefers_the_record_that_knows_the_method():
    first = analyse_javascript('const u = "/api/v1/orders";', source="a.js")
    second = analyse_javascript('axios.post("/api/v1/orders");', source="b.js")
    merged = merge_analyses([first, second])
    endpoint = next(e for e in merged["endpoints"] if e["value"] == "/api/v1/orders")
    assert endpoint["method"] == "POST"


def test_merge_unions_hosts_and_counts():
    first = analyse_javascript('const a = "https://one.internal.acme.corp";', source="a.js")
    second = analyse_javascript('const b = "https://two.internal.acme.corp";', source="b.js")
    merged = merge_analyses([first, second])
    assert merged["totals"]["hosts_referenced"] == 2
    assert merged["totals"]["infrastructure"] == 2


def test_merge_of_nothing_is_empty():
    merged = merge_analyses([])
    assert merged["totals"]["endpoints"] == 0
    assert merged["endpoints"] == []


def test_minified_bundle_does_not_raise():
    body = "!function(e,t){" + ("a.b.c=1;" * 5000) + "}(window,document);"
    analysis = analyse_javascript(body, source="bundle.min.js")
    assert analysis.bytes > 0


# -- context windows must not leak a neighbouring secret -----------------


def test_context_redacts_every_secret_not_just_its_own():
    """Two secrets in one config object share a context window.

    Redacting only the match's own value would print its neighbour verbatim
    into the report, which defeats the masking entirely.
    """
    other = "abcd1234efgh5678ijkl"
    body = f'const c = {{ api_key: "{FAKE_KEY}", token: "{other}", x: 1 }};'
    for match in extract_secrets(body):
        assert FAKE_KEY not in (match.context or "")
        assert other not in (match.context or "")


def test_context_trims_a_secret_fragment_at_the_window_edge():
    """The window is a fixed-width slice, so it can cut through a value."""
    other = "Zq7Wx2Pv9Lm4Nk8Rt6Yb3Hc5Jd1Fg0Se"
    body = f'api_key = "{FAKE_KEY}"; padding_padding; token = "{other}";'
    for match in extract_secrets(body):
        context = match.context or ""
        for value in (FAKE_KEY, other):
            for length in range(8, len(value) + 1):
                assert value[:length] not in context
                assert value[-length:] not in context


def test_context_is_unredacted_when_redaction_is_off():
    body = f'api_key = "{FAKE_KEY}";'
    match = extract_secrets(body, redact=False)[0]
    assert FAKE_KEY in (match.context or "")


# -- filenames are not hosts -------------------------------------------
#
# Found by running netrecon against a real server, not by a unit test: a
# directory listing put `readme.md` and `scope.txt.example` in the page body,
# and both were reported under "Hosts referenced by front-end code ... out of
# scope and not contacted". A pentest report that asks the operator to
# consider authorising a README is a credibility problem, so the file shape is
# rejected before anything reaches that section.

FILENAMES_THAT_ARE_NOT_HOSTS = [
    "readme.md",            # md is Moldova
    "scope.txt.example",    # example is a reserved TLD, txt settles it
    "app.js.map",
    "style.min.css",
    "archive.tar.gz",
    "setup.py",             # py is Paraguay
    "main.rs",              # rs is Serbia
    "data.json",
    "logo.png",
    "bundle.js",
]

HOSTS_THAT_MUST_SURVIVE = [
    "acme.com",             # the trade must never cost .com
    "acme.pl",              # ... or Poland
    "api.internal",
    "db.staging.acme.vn",
    "intranet.corp",
    "jenkins.local",
    "metadata.google.internal",
    "foo.example.com",
    "a.b.c.co.uk",
    "vpn.acme.md",          # a real Moldovan host still reads as one
]


@pytest.mark.parametrize("candidate", FILENAMES_THAT_ARE_NOT_HOSTS)
def test_a_filename_is_never_reported_as_a_host(candidate: str) -> None:
    assert _is_hostname(candidate) is False


@pytest.mark.parametrize("candidate", HOSTS_THAT_MUST_SURVIVE)
def test_a_real_hostname_survives_the_filename_check(candidate: str) -> None:
    assert _is_hostname(candidate) is True


def test_a_directory_listing_contributes_no_referenced_hosts() -> None:
    """The exact body shape that produced the false positive."""
    body = (
        '<html><body><h1>Directory listing for /</h1><ul>'
        '<li><a href="readme.md">readme.md</a></li>'
        '<li><a href="scope.txt.example">scope.txt.example</a></li>'
        '<li><a href="install.sh">install.sh</a></li>'
        '<li><a href="pyproject.toml">pyproject.toml</a></li>'
        '</ul></body></html>'
    )
    _, hosts = extract_infrastructure(body, "(page)")
    assert hosts == []


def test_a_real_internal_host_in_the_same_listing_is_still_found() -> None:
    """The filename check must not silence the finding that matters."""
    body = (
        '<html><body><ul><li><a href="readme.md">readme.md</a></li></ul>'
        '<script>var api = "https://jenkins.corp.internal/api";</script>'
        '</body></html>'
    )
    _, hosts = extract_infrastructure(body, "(page)")
    assert hosts == ["jenkins.corp.internal"]

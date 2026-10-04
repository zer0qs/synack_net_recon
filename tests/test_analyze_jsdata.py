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
# 4111... is the universally published Visa test number, not a real card.
TEST_CARD = "4111 1111 1111 1111"


# -- masking -------------------------------------------------------------


def test_mask_value_hides_the_middle_but_keeps_a_handle():
    masked = mask_value(FAKE_KEY)
    assert FAKE_KEY not in masked
    assert masked.startswith("9f2b")
    assert "len 32" in masked


def test_mask_value_on_short_strings_reveals_almost_nothing():
    assert mask_value("abcdef") == "a*****"
    assert mask_value("abcdefgh") == "ab****gh"


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

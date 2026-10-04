"""Tests for structured technology fingerprinting.

Every function under test is pure string work, so nothing here needs a fixture
beyond literals. The cases that matter are the ones where a fingerprint could
quietly be wrong: a version read out of a bundle filename, a CPE built with a
guessed vendor, and two detections of the same product being merged.
"""

from __future__ import annotations

import pytest

from netrecon.analyze.base import ServiceEvidence
from netrecon.analyze.techstack import (
    Technology,
    build_cpe,
    cpe_fields,
    detect_from_headers,
    detect_from_html,
    detect_from_scripts,
    detect_from_service,
    detect_web,
    extract_library,
    merge,
    meta_generator,
    normalise_cpe,
    summarise,
)


def by_name(technologies: list[Technology]) -> dict[str, Technology]:
    return {tech.name: tech for tech in merge(technologies)}


# -- headers -------------------------------------------------------------


def test_server_header_gives_name_version_and_cpe():
    found = by_name(detect_from_headers({"Server": "nginx/1.18.0 (Ubuntu)"}))
    nginx = found["nginx"]
    assert nginx.version == "1.18.0"
    assert nginx.confidence == "certain"
    assert nginx.source == "header:server"
    assert nginx.evidence == "server: nginx/1.18.0 (Ubuntu)"
    assert nginx.cpe == "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    assert "web-server" in nginx.categories


def test_server_header_reports_every_product_it_lists():
    found = by_name(detect_from_headers({"server": "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f"}))
    assert found["Apache httpd"].version == "2.4.41"
    assert found["OpenSSL"].version == "1.1.1f"


def test_server_header_without_version_is_only_likely():
    found = by_name(detect_from_headers({"Server": "cloudflare"}))
    assert found["cloudflare"].version is None
    assert found["cloudflare"].confidence == "likely"


def test_x_powered_by_and_aspnet_version():
    found = by_name(
        detect_from_headers({"X-Powered-By": "PHP/7.4.3", "X-AspNet-Version": "4.0.30319"})
    )
    assert found["PHP"].version == "7.4.3"
    assert found["PHP"].source == "header:x-powered-by"
    assert found["ASP.NET"].version == "4.0.30319"


def test_x_generator_header_carries_a_version():
    found = by_name(detect_from_headers({"X-Generator": "Drupal 10 (https://www.drupal.org)"}))
    assert found["Drupal"].version == "10"
    assert found["Drupal"].confidence == "certain"


def test_x_drupal_headers_mark_drupal_without_a_version():
    found = by_name(detect_from_headers({"X-Drupal-Cache": "HIT", "X-Drupal-Dynamic-Cache": "MISS"}))
    assert found["Drupal"].version is None
    assert found["Drupal"].confidence == "likely"


def test_via_header_reports_the_proxy():
    found = by_name(detect_from_headers({"Via": "1.1 varnish (Varnish/6.0)"}))
    assert found["Varnish"].version == "6.0"
    assert found["Varnish"].source == "header:via"


@pytest.mark.parametrize(
    ("cookie", "expected"),
    [
        ("JSESSIONID=ABC123; Path=/", "Java"),
        ("laravel_session=eyJ; HttpOnly", "Laravel"),
        ("PHPSESSID=deadbeef; Path=/", "PHP"),
        ("ASP.NET_SessionId=xyz; HttpOnly", "ASP.NET"),
        ("csrftoken=abcdef; Path=/", "Django"),
        ("_rails_session=zzz; HttpOnly", "Rails"),
    ],
)
def test_framework_cookies_identify_the_stack(cookie, expected):
    found = by_name(detect_from_headers({"Set-Cookie": cookie}))
    assert expected in found
    assert found[expected].source == "cookie"
    assert found[expected].confidence == "likely"


def test_joined_set_cookie_values_are_both_read():
    found = by_name(
        detect_from_headers({"set-cookie": "PHPSESSID=a; Path=/, laravel_session=b; HttpOnly"})
    )
    assert "PHP" in found
    assert "Laravel" in found


# -- HTML ----------------------------------------------------------------


def test_meta_generator_with_version():
    html = '<head><meta charset="utf-8"><meta name="generator" content="WordPress 6.4.2" /></head>'
    assert meta_generator(html) == "WordPress 6.4.2"
    found = by_name(detect_from_html(html))
    assert found["WordPress"].version == "6.4.2"
    assert found["WordPress"].source == "meta:generator"
    assert found["WordPress"].confidence == "certain"


def test_meta_generator_attribute_order_does_not_matter():
    html = "<meta content='Joomla! - Open Source Content Management' name='generator'>"
    found = by_name(detect_from_html(html))
    assert "Joomla" in found


@pytest.mark.parametrize(
    ("markup", "expected"),
    [
        ('<script src="/wp-includes/js/wp-embed.min.js"></script>', "WordPress"),
        ('<div data-drupal-selector="x"></div>', "Drupal"),
        ('<script src="/media/jui/js/x.js"></script>', "Joomla"),
        ('<script id="__NEXT_DATA__" type="application/json">{}</script>', "Next.js"),
        ("<script>window.__NUXT__={}</script>", "Nuxt"),
        ('<div id="___gatsby"></div>', "Gatsby"),
        ('<script src="https://cdn.shopify.com/s/x.js"></script>', "Shopify"),
        ('<script src="/static/version1/frontend/x/y/z.js"></script>', "Magento"),
        ('<div id="root" data-reactroot=""></div>', "React"),
        ('<div id="app" data-v-app=""></div>', "Vue.js"),
        ('<app-root _nghost-abc="">x</app-root>', "Angular"),
        ('<div class="svelte-1a2b3c4"></div>', "Svelte"),
    ],
)
def test_markup_markers(markup, expected):
    assert expected in by_name(detect_from_html(markup))


def test_ng_version_attribute_yields_a_version():
    found = by_name(detect_from_html('<app-root ng-version="15.2.9"></app-root>'))
    assert found["Angular"].version == "15.2.9"
    # A version in the markup lifts the marker out of "possible".
    assert found["Angular"].confidence == "likely"


def test_empty_html_detects_nothing():
    assert detect_from_html("") == []


# -- script URLs ---------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "name", "version"),
    [
        ("/js/jquery-3.6.0.min.js", "jQuery", "3.6.0"),
        ("/js/jquery.min.js", "jQuery", None),
        ("https://cdnjs.cloudflare.com/ajax/libs/angular/1.7.9/angular.js", "Angular", "1.7.9"),
        (
            "https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js",
            "Bootstrap",
            "5.3.0",
        ),
        ("/static/js/react-dom.production.min.js", "React", None),
        ("/assets/vue.runtime.min.js", "Vue.js", None),
        ("/vendor/lodash-4.17.21.js", "Lodash", "4.17.21"),
        ("/js/moment-2.29.4.min.js", "Moment.js", "2.29.4"),
        ("https://d3js.org/d3.v7.min.js", "D3.js", "7"),
    ],
)
def test_library_name_and_version_from_filename(url, name, version):
    found = by_name(detect_from_scripts([url]))
    assert name in found, found
    assert found[name].version == version
    assert found[name].source == "script-url"
    # A filename is never strong enough for "certain".
    assert found[name].confidence == "likely"


def test_next_static_path_is_recognised_without_a_filename_hint():
    found = by_name(detect_from_scripts(["/_next/static/chunks/main-4f3a2b1c.js"]))
    assert "Next.js" in found
    assert found["Next.js"].version is None


def test_wordpress_ver_query_parameter_supplies_the_version():
    found = by_name(detect_from_scripts(["/wp-includes/js/jquery/jquery.min.js?ver=3.6.4"]))
    assert found["jQuery"].version == "3.6.4"
    assert "WordPress" in found


def test_hashed_bundle_names_are_not_reported_as_libraries():
    assert detect_from_scripts(["/assets/app.4f3a2b1c.js", "/js/main.js", "/js/vendor.js"]) == []


def test_unknown_library_with_a_version_is_only_possible():
    found = by_name(detect_from_scripts(["/js/acmegrid-2.4.1.min.js"]))
    assert found["acmegrid"].version == "2.4.1"
    assert found["acmegrid"].confidence == "possible"
    # No vendor is known, so no CPE is invented.
    assert found["acmegrid"].cpe is None


def test_extract_library_handles_a_bare_directory_url():
    assert extract_library("") == (None, None)
    assert extract_library("/js/")[0] == "js"


# -- nmap -sV ------------------------------------------------------------


def service(**kwargs) -> ServiceEvidence:
    base = {"ip": "10.10.10.5", "port": 80, "service": "http"}
    base.update(kwargs)
    return ServiceEvidence(**base)


def test_service_product_and_version():
    found = by_name(detect_from_service(service(product="nginx", version="1.18.0")))
    assert found["nginx"].version == "1.18.0"
    assert found["nginx"].source == "nmap-sV"
    assert found["nginx"].confidence == "certain"
    assert "web-server" in found["nginx"].categories


def test_service_extrainfo_adds_secondary_products():
    found = by_name(
        detect_from_service(service(product="Apache httpd", version="2.4.41", extrainfo="PHP/7.4.3"))
    )
    assert found["Apache httpd"].version == "2.4.41"
    assert found["PHP"].version == "7.4.3"
    assert found["PHP"].confidence == "likely"


def test_nmap_22_cpe_is_normalised_to_23():
    found = detect_from_service(service(cpes=("cpe:/a:igor_sysoev:nginx:1.18.0",)))
    assert len(found) == 1
    assert found[0].name == "nginx"
    assert found[0].version == "1.18.0"
    assert found[0].cpe == "cpe:2.3:a:igor_sysoev:nginx:1.18.0:*:*:*:*:*:*:*"


def test_os_cpes_are_not_reported_as_service_technology():
    assert detect_from_service(service(cpes=("cpe:/o:linux:linux_kernel",))) == []


def test_service_without_product_or_cpe_detects_nothing():
    assert detect_from_service(service()) == []


# -- merging -------------------------------------------------------------


def test_merge_prefers_the_entry_that_has_a_version():
    versionless = Technology("jQuery", None, ("js-library",), "likely", "script-url", "jquery.js")
    versioned = Technology("jquery", "3.6.0", ("js-library",), "possible", "script-url", "x.js")
    merged = merge([versionless, versioned])
    assert len(merged) == 1
    assert merged[0].version == "3.6.0"


def test_merge_prefers_higher_confidence_when_both_have_a_version():
    weak = Technology("nginx", "1.18.0", (), "possible", "markup", "a")
    strong = Technology("nginx", "1.18.0", (), "certain", "header:server", "b")
    assert merge([weak, strong])[0].confidence == "certain"


def test_merge_unions_categories_and_keeps_a_cpe_from_the_loser():
    winner = Technology("Vue.js", "3.4.0", ("framework",), "certain", "header:server", "a")
    loser = Technology(
        "vue.js", None, ("js-library",), "likely", "markup", "b", cpe="cpe:2.3:a:vuejs:vue:*:*:*:*:*:*:*:*"
    )
    merged = merge([winner, loser])
    assert len(merged) == 1
    assert merged[0].categories == ("framework", "js-library")
    assert merged[0].cpe == "cpe:2.3:a:vuejs:vue:*:*:*:*:*:*:*:*"


def test_merge_sorts_by_name():
    names = [
        tech.name
        for tech in merge(
            [
                Technology("nginx", None, (), "likely", "s", "e"),
                Technology("Drupal", None, (), "likely", "s", "e"),
                Technology("jQuery", None, (), "likely", "s", "e"),
            ]
        )
    ]
    assert names == ["Drupal", "jQuery", "nginx"]


# -- CPE helpers ---------------------------------------------------------


def test_build_cpe_uses_the_vendor_table():
    assert build_cpe(None, "Apache httpd", "2.4.41") == (
        "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
    )
    assert build_cpe(None, "WordPress", None) == "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"


def test_build_cpe_returns_none_for_an_unknown_product():
    assert build_cpe(None, "AcmeGrid", "2.4.1") is None
    assert build_cpe(None, "", "1.0") is None
    # An explicit vendor is enough, because then nothing is guessed.
    assert build_cpe("acme", "AcmeGrid", "2.4.1") == "cpe:2.3:a:acme:acmegrid:2.4.1:*:*:*:*:*:*:*"


def test_build_cpe_escapes_and_underscores():
    built = build_cpe("acme corp", "Widget Server", "1.0:beta")
    assert built == "cpe:2.3:a:acme_corp:widget_server:1.0\\:beta:*:*:*:*:*:*:*"


def test_normalise_cpe_pads_a_22_uri():
    assert normalise_cpe("cpe:/a:apache:http_server:2.4.41") == (
        "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
    )
    assert normalise_cpe("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*") == (
        "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    )


def test_normalise_cpe_rejects_what_is_not_a_cpe():
    assert normalise_cpe(None) is None
    assert normalise_cpe("nginx 1.18.0") is None
    assert normalise_cpe("cpe:/x:nope") is None


def test_cpe_fields_splits_an_escaped_component():
    part, vendor, product, version = cpe_fields("cpe:2.3:a:acme:widget:1.0\\:beta:*:*:*:*:*:*:*")
    assert (part, vendor, product) == ("a", "acme", "widget")
    assert version == "1.0\\:beta"


# -- whole-response convenience -----------------------------------------


def test_detect_web_merges_every_source():
    found = by_name(
        detect_web(
            headers={"Server": "nginx/1.18.0", "Set-Cookie": "PHPSESSID=a; Path=/"},
            html='<meta name="generator" content="WordPress 6.4.2">',
            script_urls=["/wp-includes/js/jquery/jquery.min.js?ver=3.6.4"],
        )
    )
    assert found["nginx"].version == "1.18.0"
    assert found["WordPress"].version == "6.4.2"
    assert found["jQuery"].version == "3.6.4"
    assert "PHP" in found


def test_technology_to_dict_is_json_ready():
    tech = Technology("nginx", "1.18.0", ("web-server",), "certain", "header:server", "nginx/1.18.0")
    assert tech.to_dict() == {
        "name": "nginx",
        "version": "1.18.0",
        "categories": ["web-server"],
        "confidence": "certain",
        "source": "header:server",
        "evidence": "nginx/1.18.0",
        "cpe": None,
    }
    assert tech.label == "nginx 1.18.0"


def test_summarise_groups_by_category():
    summary = summarise(detect_from_headers({"Server": "nginx/1.18.0"}))
    assert summary["count"] == 1
    assert summary["with_version"] == 1
    assert summary["by_category"]["web-server"] == ["nginx 1.18.0"]

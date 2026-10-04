"""Tests for the reconstructed API surface.

The negative tests matter as much as the positive ones: an analyzer that
reports ``Authorization`` as an API parameter because it read a nested
``headers`` object teaches an operator to distrust the whole report.
"""

from __future__ import annotations

from netrecon.analyze.apistructure import (
    MAX_CALL_SITES,
    MAX_ENDPOINTS,
    CallSite,
    Endpoint,
    Parameter,
    analyse_api,
    api_structure,
    build_parameter_index,
    endpoint_lines,
    extract_call_sites,
    group_endpoints,
    merge_call_sites,
    parameter_wordlist,
)


def one(body: str, source: str = "app.js") -> CallSite:
    """Exactly one call site is expected; return it."""
    sites = extract_call_sites(body, source)
    assert len(sites) == 1, [s.to_dict() for s in sites]
    return sites[0]


# -- call-site forms ----------------------------------------------------


def test_fetch_bare_url():
    site = one('fetch("/api/v1/health");')
    assert (site.kind, site.method, site.path) == ("fetch", "GET", "/api/v1/health")


def test_fetch_with_options():
    site = one('fetch("/api/v1/login", {method: "post", body: JSON.stringify({user, pass})});')
    assert site.method == "POST"
    assert site.body_params == ("user", "pass")


def test_axios_verb_forms():
    for verb in ("get", "post", "put", "patch", "delete", "head", "options"):
        site = one(f'axios.{verb}("/api/v1/thing");')
        assert site.kind == "axios"
        assert site.method == verb.upper()


def test_axios_url_first_argument():
    site = one('axios("/api/v1/thing", {method: "PATCH"});')
    assert (site.kind, site.method) == ("axios", "PATCH")


def test_axios_config_object_only():
    site = one('axios({url: "/api/v2/orders", method: "put", params: {id, status}});')
    assert site.kind == "axios"
    assert site.method == "PUT"
    assert site.path == "/api/v2/orders"
    assert site.query_params == ("id", "status")


def test_axios_config_object_with_data():
    site = one('axios({url: "/api/v2/orders", method: "post", data: {qty, sku}});')
    assert site.body_params == ("qty", "sku")


def test_jquery_get_post_getjson():
    assert one('$.get("/s/a");').method == "GET"
    assert one('$.post("/s/b");').method == "POST"
    assert one('$.getJSON("/s/c");').method == "GET"
    assert one('jQuery.getJSON("/s/d");').kind == "jquery"


def test_jquery_ajax_object():
    site = one('$.ajax({url: "/legacy/do.php", type: "POST", data: {a: 1, b: 2}});')
    assert (site.kind, site.method, site.path) == ("jquery", "POST", "/legacy/do.php")
    assert site.body_params == ("a", "b")


def test_jquery_ajax_url_then_options():
    site = one('$.ajax("/legacy/two.php", {type: "PUT", data: {c: 1}});')
    assert (site.method, site.body_params) == ("PUT", ("c",))


def test_generic_client_calls():
    for call, method in (
        ('api.post("/api/v2/orders", {id});', "POST"),
        ('this.http.put("/api/v2/orders", {id});', "PUT"),
        ('client.delete("/api/v2/orders");', "DELETE"),
        ('services.user.patch("/api/v2/orders");', "PATCH"),
    ):
        site = one(call)
        assert site.kind == "generic"
        assert site.method == method


def test_xhr_open():
    site = one('var r = new XMLHttpRequest(); r.open("POST", "/api/v1/upload");')
    assert (site.kind, site.method, site.path) == ("xhr", "POST", "/api/v1/upload")


def test_axios_verb_not_double_reported_as_generic():
    sites = extract_call_sites('axios.post("/api/v1/x", {a});')
    assert len(sites) == 1
    assert sites[0].kind == "axios"


def test_non_url_literal_on_a_generic_get_is_ignored():
    # `map.get("userName")` has the shape of a client call but is not one.
    assert extract_call_sites('var n = map.get("userName");') == []


# -- method precedence ---------------------------------------------------


def test_verb_beats_method_option():
    site = one('axios.post("/api/v1/x", {method: "DELETE", headers: {}});')
    assert site.method == "POST"


def test_method_option_beats_default():
    assert one('fetch("/api/v1/x", {method: "DELETE"});').method == "DELETE"


def test_type_option_beats_default():
    assert one('$.ajax({url: "/api/v1/x", type: "patch"});').method == "PATCH"


def test_default_is_get():
    assert one('fetch("/api/v1/x", {credentials: "include"});').method == "GET"


# -- query parameters ----------------------------------------------------


def test_query_params_from_url_string():
    site = one('fetch("/api/v1/search?q=hello&page=2&sort");')
    assert site.query_params == ("q", "page", "sort")
    assert site.path == "/api/v1/search"


def test_query_params_from_params_object():
    site = one('axios.get("/api/v1/search", {params: {q, page, sort: "asc"}});')
    assert site.query_params == ("q", "page", "sort")
    assert site.body_params == ()


def test_query_params_from_url_and_params_object_merge():
    site = one('axios.get("/api/v1/search?q=1", {params: {page}});')
    assert site.query_params == ("q", "page")


def test_fragment_is_dropped():
    site = one('fetch("/api/v1/x?a=1#frag");')
    assert site.path == "/api/v1/x"
    assert site.query_params == ("a",)


def test_query_string_built_from_a_variable_yields_no_keys():
    site = one('fetch(`/api/v1/x?${qs}`);')
    assert site.query_params == ()


# -- path parameters -----------------------------------------------------


def test_path_param_from_template_expression():
    site = one("axios.get(`/api/v1/users/${userId}/posts`);")
    assert site.path_params == ("userId",)
    assert site.path == "/api/v1/users/{userId}/posts"


def test_path_param_from_colon_segment():
    site = one('api.get("/api/v1/users/:id/roles/:roleId");')
    assert site.path_params == ("id", "roleId")


def test_path_param_dotted_expression_keeps_the_dotted_name():
    site = one("client.delete(`/api/v1/items/${item.id}`);")
    assert site.path_params == ("item.id",)


def test_path_param_complex_expression_falls_back():
    site = one("axios.get(`/api/v1/page/${i + 1}`);")
    assert site.path_params == ("param",)
    assert site.path == "/api/v1/page/{param}"


def test_path_param_unwraps_an_encoder_call():
    site = one("axios.get(`/api/v1/u/${encodeURIComponent(email)}`);")
    assert site.path_params == ("email",)


def test_template_params_split_between_path_and_query():
    site = one("fetch(`/api/v1/users/${userId}/posts?limit=${limit}`);")
    assert site.path_params == ("userId",)
    assert site.query_params == ("limit",)


# -- body parameters -----------------------------------------------------


def test_body_params_from_body_key():
    site = one('fetch("/a", {method: "POST", body: {alpha: 1, beta: 2}});')
    assert site.body_params == ("alpha", "beta")


def test_body_params_from_data_key():
    site = one('axios({url: "/a", method: "POST", data: {alpha, beta}});')
    assert site.body_params == ("alpha", "beta")


def test_body_params_from_json_key():
    site = one('axios({url: "/a", method: "POST", json: {alpha, beta}});')
    assert site.body_params == ("alpha", "beta")


def test_body_params_from_variables_key():
    site = one('axios({url: "/gql", method: "POST", variables: {userId, first}});')
    assert site.body_params == ("userId", "first")


def test_body_params_from_json_stringify():
    site = one('fetch("/a", {method: "POST", body: JSON.stringify({alpha, beta})});')
    assert site.body_params == ("alpha", "beta")


def test_body_params_from_bare_second_argument_object():
    site = one('api.post("/api/v2/orders", {id, qty, coupon});')
    assert site.body_params == ("id", "qty", "coupon")


def test_body_from_a_variable_is_not_guessed():
    site = one('fetch("/a", {method: "POST", body: formData});')
    assert site.body_params == ()


def test_quoted_keys_are_read():
    site = one('fetch("/a", {method: "POST", body: {"alpha": 1, \'beta\': 2, gamma: 3}});')
    assert site.body_params == ("alpha", "beta", "gamma")


def test_shorthand_keys_are_read_and_order_preserved():
    site = one('api.post("/a", {zebra, alpha, middle});')
    assert site.body_params == ("zebra", "alpha", "middle")


def test_spread_and_computed_keys_are_skipped():
    site = one('api.post("/a", {...defaults, [dynamic]: 1, real: 2});')
    assert site.body_params == ("real",)


# -- the nested-object negative tests (the important ones) ---------------


def test_headers_object_does_not_leak_its_keys():
    site = one(
        'fetch("/api/v1/login", {method: "POST", '
        'headers: {Authorization: "Bearer abc", "Content-Type": "application/json"}, '
        "body: JSON.stringify({user, pass})});"
    )
    assert "Authorization" not in site.body_params
    assert "Content-Type" not in site.body_params
    assert site.body_params == ("user", "pass")


def test_headers_nested_two_deep_does_not_leak():
    site = one(
        'fetch("/a", {method: "POST", '
        'headers: {common: {Authorization: "x", nested: {Deeper: 1}}}, '
        "body: {real: 1}});"
    )
    assert site.body_params == ("real",)


def test_header_value_containing_braces_does_not_leak():
    site = one(
        'fetch("/a", {method: "POST", '
        'headers: {Authorization: "Bearer {not:a,key:1}", X: "}{"}, '
        "body: {real: 1}});"
    )
    assert site.body_params == ("real",)


def test_header_template_literal_does_not_leak():
    site = one(
        "fetch('/a', {method: 'POST', "
        "headers: {Authorization: `Bearer ${tokens.get({scope: 'all'})}`}, "
        "body: {real: 1}});"
    )
    assert site.body_params == ("real",)
    assert "scope" not in site.body_params
    assert "Authorization" not in site.body_params


def test_nested_body_objects_do_not_leak_their_inner_keys():
    site = one('api.post("/a", {outer: {inner: 1, deeper: {leak: 2}}, sibling: 3});')
    assert site.body_params == ("outer", "sibling")


def test_arrays_in_the_options_object_do_not_leak():
    site = one('fetch("/a", {method: "POST", headers: [{k: 1}], body: {real: [{hidden: 2}]}});')
    assert site.body_params == ("real",)


def test_commas_inside_strings_do_not_split_keys():
    site = one('api.post("/a", {label: "one, two, three", other: 1});')
    assert site.body_params == ("label", "other")


# -- the transport filter applies at the top level only ------------------


def test_graphql_body_keeps_query_and_variables():
    site = one('fetch("/graphql", {method: "POST", body: JSON.stringify({query, variables})});')
    assert site.body_params == ("query", "variables")


def test_transport_names_are_real_parameters_inside_a_body():
    site = one(
        'fetch("/t", {method: "POST", credentials: "include", '
        'body: JSON.stringify({method: "transfer", headers: 2, params: 3, data: 4})});'
    )
    assert site.body_params == ("method", "headers", "params", "data")
    assert site.method == "POST"


def test_non_transport_top_level_option_is_treated_as_a_parameter():
    site = one('fetch("/a", {method: "POST", headers: {}, tenantId: 7});')
    assert "tenantId" in site.body_params
    assert "headers" not in site.body_params


def test_transport_keys_filtered_out_of_an_options_object():
    site = one(
        'fetch("/a", {method: "POST", mode: "cors", cache: "no-store", keepalive: true, '
        'signal: ctrl.signal, redirect: "follow", integrity: "sha256-x", body: {real: 1}});'
    )
    assert site.body_params == ("real",)


# -- unrecoverable URLs --------------------------------------------------


def test_url_from_a_variable_is_skipped():
    assert extract_call_sites("fetch(url);") == []
    assert extract_call_sites("axios.get(endpoint, {params: {a}});") == []
    assert extract_call_sites("axios({url: endpoint, method: 'POST'});") == []
    assert extract_call_sites('xhr.open("GET", endpoint);') == []


def test_literal_prefix_of_a_concatenated_url_is_recovered():
    site = one('fetch("/api/v1/users/" + id);')
    assert site.path == "/api/v1/users/"


# -- source and line ----------------------------------------------------


def test_source_and_line_are_recorded():
    body = '// header\n\nfetch("/api/v1/a");\nfetch("/api/v1/b");\n'
    sites = extract_call_sites(body, "bundle.js")
    assert [(s.path, s.line, s.source) for s in sites] == [
        ("/api/v1/a", 3, "bundle.js"),
        ("/api/v1/b", 4, "bundle.js"),
    ]


def test_call_sites_are_returned_in_source_order():
    body = 'axios.post("/b/one");\nfetch("/a/two");\napi.put("/c/three");'
    assert [s.path for s in extract_call_sites(body)] == ["/b/one", "/a/two", "/c/three"]


def test_to_dict_of_a_call_site():
    site = one('axios.post("/api/v1/x?a=1", {b});', source="s.js")
    data = site.to_dict()
    assert data == {
        "url": "/api/v1/x?a=1",
        "method": "POST",
        "path": "/api/v1/x",
        "query_params": ["a"],
        "path_params": [],
        "body_params": ["b"],
        "source": "s.js",
        "line": 1,
        "kind": "axios",
    }


# -- grouping ------------------------------------------------------------


def test_grouping_merges_methods_and_params_across_call_sites():
    body = (
        'axios.get("/api/v2/orders", {params: {status}});\n'
        'api.post("/api/v2/orders", {qty, sku});\n'
    )
    endpoints = group_endpoints(extract_call_sites(body, "app.js"))
    assert len(endpoints) == 1
    endpoint = endpoints[0]
    assert endpoint.methods == ("GET", "POST")
    assert endpoint.query_params == ("status",)
    assert endpoint.body_params == ("qty", "sku")
    assert endpoint.call_sites == 2
    assert endpoint.param_count == 3


def test_grouping_sorts_richest_first():
    body = (
        'fetch("/thin");\n'
        'api.post("/rich", {a, b, c, d});\n'
        'api.post("/medium", {a, b});\n'
    )
    endpoints = group_endpoints(extract_call_sites(body, "app.js"))
    assert [e.path for e in endpoints] == ["/rich", "/medium", "/thin"]


def test_grouping_tiebreaks_on_call_count_then_path():
    body = 'fetch("/b");\nfetch("/a");\nfetch("/a");\nfetch("/c");'
    endpoints = group_endpoints(extract_call_sites(body))
    assert [e.path for e in endpoints] == ["/a", "/b", "/c"]
    assert endpoints[0].call_sites == 2


def test_refs_are_traceable():
    body = 'fetch("/api/v2/x");\n\napi.post("/api/v2/x", {a});'
    endpoint = group_endpoints(extract_call_sites(body, "app.js"))[0]
    assert endpoint.refs == (
        {"source": "app.js", "line": 1, "method": "GET"},
        {"source": "app.js", "line": 3, "method": "POST"},
    )


def test_signature_format():
    endpoint = Endpoint(
        path="/api/v2/orders",
        methods=("GET", "POST"),
        query_params=("id", "status"),
    )
    assert endpoint.signature == "GET/POST /api/v2/orders?id={id}&status={status}"


def test_signature_without_query_params():
    assert Endpoint(path="/api/v2/orders", methods=("DELETE",)).signature == (
        "DELETE /api/v2/orders"
    )


def test_signature_keeps_path_placeholders():
    body = "axios.get(`/api/v1/users/${id}?full=1`);"
    endpoint = group_endpoints(extract_call_sites(body))[0]
    assert endpoint.signature == "GET /api/v1/users/{id}?full={full}"


def test_source_label_variants():
    body = 'fetch("/api/v2/x");'
    sites = [
        extract_call_sites(body, "app.js")[0],
        extract_call_sites(body, "vendor.js")[0],
        extract_call_sites(body, "admin.js")[0],
    ]
    assert group_endpoints(sites[:1])[0].source_label == "app.js"
    assert group_endpoints(sites[:2])[0].source_label == "app.js +1"
    assert group_endpoints(sites)[0].source_label == "app.js +2"
    assert group_endpoints(sites)[0].sources == ("app.js", "vendor.js", "admin.js")


def test_source_label_is_empty_without_a_source():
    assert group_endpoints(extract_call_sites('fetch("/a");'))[0].source_label == ""


def test_endpoint_to_dict():
    endpoint = group_endpoints(extract_call_sites('api.post("/a/b", {x});', "app.js"))[0]
    data = endpoint.to_dict()
    assert data["path"] == "/a/b"
    assert data["methods"] == ["POST"]
    assert data["signature"] == "POST /a/b"
    assert data["param_count"] == 1
    assert data["source_label"] == "app.js"
    assert data["refs"] == [{"source": "app.js", "line": 1, "method": "POST"}]


def test_endpoint_lines_format():
    body = 'axios.get("/api/v2/orders");\napi.post("/api/v2/orders");'
    sites = extract_call_sites(body, "app.js") + extract_call_sites(body, "vendor.js")
    lines = endpoint_lines(group_endpoints(sites))
    assert lines == ["GET/POST /api/v2/orders  [app.js +1]"]


# -- parameter index -----------------------------------------------------


def test_parameter_index_unions_kinds_and_counts():
    body = (
        "axios.get(`/api/v1/users/${id}`);\n"
        'api.post("/api/v1/accounts", {id, name});\n'
        'fetch("/api/v1/search?id=1");\n'
    )
    parameters = build_parameter_index(group_endpoints(extract_call_sites(body, "app.js")))
    index = {p.name: p for p in parameters}
    assert index["id"].kinds == ("body", "path", "query")
    assert index["id"].occurrences == 3
    assert index["id"].endpoint_count == 3
    assert index["id"].endpoints == (
        "/api/v1/accounts",
        "/api/v1/search",
        "/api/v1/users/{id}",
    )
    assert index["name"].kinds == ("body",)
    assert index["name"].endpoint_count == 1


def test_parameter_index_most_widely_accepted_first():
    body = (
        'api.post("/one", {shared, only_one});\n'
        'api.post("/two", {shared});\n'
        'api.post("/three", {shared, zz});\n'
    )
    parameters = build_parameter_index(group_endpoints(extract_call_sites(body)))
    assert parameters[0].name == "shared"
    assert parameters[0].endpoint_count == 3
    # Equal endpoint counts and occurrences fall back to the name.
    assert [p.name for p in parameters[1:]] == ["only_one", "zz"]


def test_parameter_to_dict():
    data = Parameter(name="id", kinds=("query",), endpoints=("/a", "/b"), occurrences=2).to_dict()
    assert data == {
        "name": "id",
        "kinds": ["query"],
        "endpoints": ["/a", "/b"],
        "endpoint_count": 2,
        "occurrences": 2,
    }


def test_parameter_wordlist_is_plain_deduplicated_names():
    body = (
        'api.post("/one", {token, id});\n'
        'api.post("/two", {id, token});\n'
        "axios.get(`/three/${id}`);\n"
    )
    words = parameter_wordlist(build_parameter_index(group_endpoints(extract_call_sites(body))))
    assert sorted(words) == ["id", "token"]
    assert len(words) == len(set(words))
    assert all("{" not in word and " " not in word for word in words)


def test_parameter_index_of_nothing_is_empty():
    assert build_parameter_index([]) == []
    assert parameter_wordlist([]) == []


# -- entry points --------------------------------------------------------


def test_analyse_api_matches_extract_call_sites():
    body = 'fetch("/api/v1/x", {method: "POST", body: {a}});'
    assert analyse_api(body, "app.js") == extract_call_sites(body, "app.js")


def test_merge_call_sites_flattens_and_dedupes():
    first = extract_call_sites('fetch("/a");', "app.js")
    second = extract_call_sites('fetch("/b");', "vendor.js")
    merged = merge_call_sites([first, second, first])
    assert [s.path for s in merged] == ["/a", "/b"]


def test_merge_call_sites_keeps_the_same_path_from_different_files():
    first = extract_call_sites('fetch("/a");', "app.js")
    second = extract_call_sites('fetch("/a");', "vendor.js")
    assert len(merge_call_sites([first, second])) == 2


def test_merge_call_sites_handles_empty_input():
    assert merge_call_sites([]) == []
    assert merge_call_sites([[], []]) == []


def test_api_structure_shape():
    body = (
        'axios.get("/api/v2/orders", {params: {status}});\n'
        'api.post("/api/v2/orders", {qty});\n'
        'fetch("/api/v2/health");\n'
    )
    structure = api_structure(extract_call_sites(body, "app.js"))
    assert set(structure) == {"endpoints", "parameters", "totals"}
    assert structure["totals"] == {
        "call_sites": 3,
        "endpoints": 2,
        "parameters": 2,
        "methods": ["GET", "POST"],
        "sources": ["app.js"],
    }
    assert structure["endpoints"][0]["path"] == "/api/v2/orders"


def test_api_structure_of_nothing():
    structure = api_structure([])
    assert structure["endpoints"] == []
    assert structure["totals"]["endpoints"] == 0


# -- robustness ----------------------------------------------------------


def test_empty_and_whitespace_bodies():
    assert extract_call_sites("") == []
    assert extract_call_sites("   \n\t") == []
    assert analyse_api("") == []


def test_minified_single_line_input():
    body = (
        'var a=1;!function(e){e.exports={}}(0),fetch("/api/v1/a",{method:"POST",'
        'headers:{Authorization:"Bearer x"},body:JSON.stringify({u,p})}).then(r=>r.json());'
        'axios.get("/api/v1/b?x=1",{params:{y}}),$.post("/api/v1/c",{z});'
    )
    sites = extract_call_sites(body, "min.js")
    assert [(s.path, s.method) for s in sites] == [
        ("/api/v1/a", "POST"),
        ("/api/v1/b", "GET"),
        ("/api/v1/c", "POST"),
    ]
    assert sites[0].body_params == ("u", "p")
    assert sites[1].query_params == ("x", "y")
    assert sites[2].body_params == ("z",)


def test_truncated_call_does_not_raise():
    body = 'fetch("/api/v1/a", {method: "POST", body: JSON.stringify({alpha, beta'
    sites = extract_call_sites(body, "cut.js")
    assert len(sites) == 1
    assert sites[0].body_params == ("alpha", "beta")


def test_truncated_literal_keeps_what_was_readable():
    # The file was cut mid-literal: report the prefix rather than nothing.
    assert [s.path for s in extract_call_sites('fetch("/api/v1/unclosed/pa')] == [
        "/api/v1/unclosed/pa"
    ]


def test_unbalanced_braces_do_not_raise():
    for body in ("fetch(", "fetch()", 'fetch("/a", {{{)', '}}){fetch("/a/b");', "axios.get(`"):
        extract_call_sites(body, "broken.js")


def test_braces_inside_strings_do_not_confuse_the_scanner():
    body = 'api.post("/a", {tpl: "{\\"nested\\": {\\"deep\\": 1}}", after: 2});'
    site = one(body)
    assert site.body_params == ("tpl", "after")


def test_comments_between_arguments_do_not_confuse_the_scanner():
    body = 'fetch("/a", {/* comment, with comma */ method: "POST", body: {real: 1}});'
    site = one(body)
    assert (site.method, site.body_params) == ("POST", ("real",))


def test_caps_are_documented_constants():
    assert MAX_CALL_SITES == 2000
    assert MAX_ENDPOINTS == 500


def test_call_site_cap_is_enforced():
    body = 'fetch("/api/v1/x");\n' * (MAX_CALL_SITES + 50)
    assert len(extract_call_sites(body, "big.js")) <= MAX_CALL_SITES


def test_endpoint_cap_is_enforced():
    sites = [
        CallSite(url=f"/api/v1/{i}", method="GET", path=f"/api/v1/{i}", source="big.js", line=i)
        for i in range(MAX_ENDPOINTS + 25)
    ]
    assert len(group_endpoints(sites)) == MAX_ENDPOINTS

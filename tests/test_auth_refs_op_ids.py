"""DSE-2124: exempt 1Password IDs only in exact vault/item reference slots."""

import pytest

from mcp_warden.auth_audit import audit_server
from mcp_warden.auth_refs import _looks_like_secret_ref

# Synthetic IDs from the issue's documented shape, not credentials.
OP_ID = "ykw6kguqbbfp3krwdpfd6b2qmm"
OTHER_ID = "a1234567890123456789012345"


def _rules(value):
    findings = audit_server(
        "op-ids", {"url": "https://mcp.example.com", "headers": {"Authorization": value}}
    )
    return {finding.rule_id for finding in findings}


@pytest.mark.parametrize("vault,item", [
    ("Private", OP_ID), (OP_ID, "GitHub"), (OP_ID, OTHER_ID),
])
@pytest.mark.parametrize("scheme", ["op", "OP"])
def test_op_vault_and_item_ids_are_references(vault, item, scheme):
    value = f"{scheme}://{vault}/{item}/password"
    assert _looks_like_secret_ref(value)
    assert _rules(value) == set()


@pytest.mark.parametrize("value", [
    f"op://Private/{OP_ID}/{OTHER_ID}",
    f"op://{OP_ID}/{OTHER_ID}/Passw0rdPassw0rd",
    f"op://{OP_ID}/{OTHER_ID}/token-9f8e7d6c5b4a3e2d1c0b",
    f"op://{OP_ID}/{OTHER_ID}/password#{OP_ID}",
    f"op://{OP_ID}/{OTHER_ID}/password#Passw0rdPassw0rd",
])
def test_op_field_and_fragment_are_never_exempt(value):
    assert not _looks_like_secret_ref(value)
    assert "WRD-AUTH-TOKEN-IN-CONFIG" in _rules(value)


@pytest.mark.parametrize("prefix", [
    "~/", "./", "/", "vault://", "pass://", "awssm://", "gcpsm://", "azkv://",
    "secretref://", "keyring://",
])
def test_other_schemes_and_paths_do_not_exempt_ids(prefix):
    value = f"{prefix}Private/{OP_ID}/password"
    assert not _looks_like_secret_ref(value)
    assert "WRD-AUTH-TOKEN-IN-CONFIG" in _rules(value)


@pytest.mark.parametrize("near_id", [OP_ID[:-1], OP_ID + "a", OP_ID.upper(), "A" + OP_ID[1:]])
@pytest.mark.parametrize("position", [0, 1])
def test_id_shape_is_exact(near_id, position):
    segments = ["Private", "GitHub", "password"]
    segments[position] = near_id
    value = "op://" + "/".join(segments)
    assert not _looks_like_secret_ref(value)
    assert "WRD-AUTH-TOKEN-IN-CONFIG" in _rules(value)


@pytest.mark.parametrize("path", [
    f"Private/{OP_ID}", f"Private/{OP_ID}/section/password",
    f"Private/{OP_ID}/password/", f"/Private/{OP_ID}/password",
    f"Private//{OP_ID}/password", f"Private/{OP_ID}//password",
    f"Private\\{OP_ID}\\password", f"Private/{OP_ID}/password?field=token",
    f"Private/{OP_ID}/password%2Ftoken", f"/{OP_ID}/password",
    f"Private/{OP_ID}/", f"Private/{OP_ID}/pass word",
])
def test_malformed_or_non_three_part_paths_do_not_gain_exemption(path):
    value = "op://" + path
    assert not _looks_like_secret_ref(value)
    assert "WRD-AUTH-TOKEN-IN-CONFIG" in _rules(value)


def test_existing_names_and_safe_fragment_remain_references():
    for value in ("op://Private/GitHub/token", f"op://Private/{OP_ID}/password#credential"):
        assert _looks_like_secret_ref(value)
        assert _rules(value) == set()


def test_vendor_secret_in_field_is_still_high():
    value = f"op://Private/{OP_ID}/ghp_" + "a" * 36
    assert "WRD-AUTH-TOKEN-IN-CONFIG" in _rules(value)


@pytest.mark.parametrize("field", [
    "aB3xK9mQ7pL2wR5tY8vN4jH6~", "password#aB3xK9mQ7pL2wR5tY8vN4jH6",
])
def test_entropy_in_non_id_positions_is_still_high(field):
    assert "WRD-SEC-ENTROPY" in _rules(f"op://Private/{OP_ID}/{field}")


def test_vendor_scan_uses_original_reference_even_when_id_is_masked():
    # This short vendor pattern in a dotted field passes the locator heuristic.
    value = f"op://Private/{OP_ID}/AKIA1234567890ABCDEF.json"
    assert _looks_like_secret_ref(value)
    assert "WRD-SEC-AWS-AKID" in _rules(value)
    assert "WRD-AUTH-TOKEN-IN-CONFIG" in _rules(value)

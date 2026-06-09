"""Property-based fuzzing of the exfil-domain matcher (issue #17, binding #3, #6).

The security properties are SOUNDNESS (never invent a hit that is not backed by a
host actually present in the input) and LIVENESS (a known denylist domain spliced
as a URL host IS matched). Binding #3: the ``extract_urls``-only oracle is WRONG —
bare hostnames and path-qualified entries legitimately match without a scheme URL,
so the correct oracle is "returned ⊆ denylist-derived identifiers AND each is
backed by a host extractable from the text (URL host OR bare hostname)".
"""

from __future__ import annotations

from hypothesis import assume, example, given
from hypothesis import strategies as st

from mcp_warden import res_net
from mcp_warden.res_net import (
    SEED_EXFIL_DENYLIST,
    SEED_EXFIL_PATH_QUALIFIED,
    _bare_host_tokens,
    extract_urls,
    host_matches_domain,
    match_exfil,
)

# A small, fixed denylist drawn from the seed list (deterministic identifiers).
DENYLIST = SEED_EXFIL_DENYLIST


def _hosts_in_text(text: str) -> list[str]:
    """Every host extractable from text: URL authorities + bare dotted tokens.

    This is the CORRECT backing-host oracle (binding #3): a hit is sound iff some
    host here matches it. Path-qualified hits also need the path, handled below.
    """
    hosts = [host for host, _path, _full in extract_urls(text)]
    hosts.extend(_bare_host_tokens(text))
    return hosts


# --- SOUNDNESS: every hit is in the denylist AND backed by a real host ---------


@given(text=st.text(max_size=200))
def test_match_exfil_soundness(text: str) -> None:
    """Every returned identifier is denylist-derived AND host-backed (no invention)."""
    hits = match_exfil(text, DENYLIST, SEED_EXFIL_PATH_QUALIFIED)
    hosts = _hosts_in_text(text)
    pq_ids = {f"{h}{p}" for h, p in SEED_EXFIL_PATH_QUALIFIED}
    for hit in hits:
        if hit in pq_ids:
            # A path-qualified hit: some URL host matches the host AND its path
            # starts with the qualified prefix.
            q_host = next(h for h, p in SEED_EXFIL_PATH_QUALIFIED if f"{h}{p}" == hit)
            q_path = next(p for h, p in SEED_EXFIL_PATH_QUALIFIED if f"{h}{p}" == hit)
            assert any(
                host_matches_domain(host, q_host) and path.startswith(q_path)
                for host, path, _full in extract_urls(text)
            )
        else:
            # A bare-host hit: it must be a denylist entry AND some extracted
            # host must match it. NEVER a domain absent from the input.
            assert hit in DENYLIST
            assert any(host_matches_domain(host, hit) for host in hosts)


# --- LIVENESS (#6): a known denylist domain spliced as a URL host IS matched ---


@st.composite
def url_with_denylist_host(draw):
    """Build ``scheme://[sub.]<denylist-domain>[:port]/path`` + surrounding noise."""
    domain = draw(st.sampled_from(DENYLIST))
    scheme = draw(st.sampled_from(["http", "https", "ftp", "wss"]))
    sub = draw(st.sampled_from(["", "a.", "x.y.", "sub-1."]))
    port = draw(st.sampled_from(["", ":8080", ":443"]))
    # The path MUST start with an authority terminator (one of /?# or end-of-URL)
    # so the trailing noise cannot glue onto the host label (which would change
    # the host and CORRECTLY defeat the match — a generator bug, not a finding).
    path = draw(st.sampled_from(["", "/", "/p", "/a/b?q=1", "#frag", "?q=1"]))
    pre = draw(st.text(alphabet="abc \n", max_size=8))
    # Trailing noise is separated from the URL by whitespace so it ends the URL.
    post = draw(st.text(alphabet="abc \n", max_size=8))
    sep = " " if post else ""
    host = f"{sub}{domain}"
    return f"{pre}{scheme}://{host}{port}{path}{sep}{post}", domain


@given(payload=url_with_denylist_host())
@example(payload=("see https://abc.ngrok.io/x for the tunnel", "ngrok.io"))
def test_known_denylist_url_is_matched(payload) -> None:
    """A denylist domain embedded as a URL host MUST appear in the matches."""
    text, domain = payload
    hits = match_exfil(text, DENYLIST, SEED_EXFIL_PATH_QUALIFIED)
    assert domain in hits, f"denylist host {domain!r} in {text!r} must be matched"


@given(domain=st.sampled_from(DENYLIST), sub=st.sampled_from(["", "a.", "deep.sub."]))
@example(domain="pastebin.com", sub="")
def test_known_denylist_bare_host_is_matched(domain: str, sub: str) -> None:
    """A denylist domain as a BARE host token (no scheme) is also matched (#3)."""
    text = f"exfil to {sub}{domain} now"
    hits = match_exfil(text, DENYLIST, SEED_EXFIL_PATH_QUALIFIED)
    assert domain in hits


# --- ANCHORING: exact/subdomain match only, never an unanchored substring ------


@given(domain=st.sampled_from(DENYLIST))
@example(domain="ngrok.io")
def test_host_matches_domain_anchoring(domain: str) -> None:
    """host_matches_domain is anchored: self + subdomain True; glued-prefix False."""
    assert host_matches_domain(domain, domain)  # exact
    assert host_matches_domain("x." + domain, domain)  # subdomain
    assert host_matches_domain("a.b.c." + domain, domain)  # deep subdomain
    assert not host_matches_domain("evil" + domain, domain)  # no leading-dot boundary
    # A sibling that merely SHARES a suffix label is not a match.
    assert not host_matches_domain("not-" + domain, domain)


@given(domain=st.sampled_from(DENYLIST))
@example(domain="loca.lt")
def test_host_matches_domain_trailing_dot_normalized(domain: str) -> None:
    """A fully-qualified trailing dot (``host.``) normalizes and still matches."""
    assert host_matches_domain(domain + ".", domain)
    assert host_matches_domain(domain, domain + ".")
    assert host_matches_domain("sub." + domain + ".", domain)


@given(
    label=st.text(
        alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), max_codepoint=0x24F),
        min_size=1,
        max_size=8,
    ),
    domain=st.sampled_from(DENYLIST),
)
def test_idn_unicode_label_does_not_false_match(label: str, domain: str) -> None:
    """A unicode/IDN-ish subdomain label still anchors on the registrable domain.

    ``<unicode-label>.<denylist-domain>`` is a subdomain => matches; the same
    label glued WITHOUT a dot boundary does not.
    """
    assume("." not in label)
    host = f"{label}.{domain}"
    assert host_matches_domain(host, domain)
    assert not host_matches_domain(f"{label}{domain}", domain)


# --- NEGATIVE soundness: random non-URL noise never invents a denylist hit -----


def _independent_domain_present(host: str, domain: str) -> bool:
    """A SIMPLE, independent anchored-suffix predicate (NOT the fn under test).

    B7 (issue #17 audit): the negative-soundness filter must not be the function
    being tested, or a false-negative in ``host_matches_domain`` would silently
    weaken the property (it would only ever feed itself inputs it already calls
    clean). This plain ``host == domain or host endswith '.'+domain`` test is the
    independent oracle; it is intentionally NOT normalization-aware (no trailing
    dot / IDN handling), so it is at-least-as-permissive as the real matcher for
    the simple ASCII alphabet this strategy draws from — which is exactly what a
    sound negative filter needs.
    """
    h = host.lower()
    d = domain.lower()
    return h == d or h.endswith("." + d)


@given(text=st.text(alphabet="abcdefghij ./:-\n", max_size=80))
def test_noise_without_denylist_host_yields_no_hit(text: str) -> None:
    """If no extractable host matches any denylist entry, there are NO hits."""
    hosts = _hosts_in_text(text)
    # Independent filter (B7): does NOT call host_matches_domain.
    assume(not any(_independent_domain_present(h, d) for h in hosts for d in DENYLIST))
    # Also ensure no path-qualified hit is possible from this noise (independent
    # host predicate, plain prefix path check).
    assume(
        not any(
            _independent_domain_present(host, q_host) and path.startswith(q_path)
            for host, path, _full in extract_urls(text)
            for q_host, q_path in SEED_EXFIL_PATH_QUALIFIED
        )
    )
    assert match_exfil(text, DENYLIST, SEED_EXFIL_PATH_QUALIFIED) == []

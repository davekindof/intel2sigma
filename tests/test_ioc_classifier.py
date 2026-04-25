"""Tests for the IOC classifier and its observation routing.

The classifier is pure pattern matching, so test by feeding known-good
IOC strings and asserting the categorisation. The Axios IOC list (a
real CTI hand-off) is the integration fixture — confirms the classifier
handles the kind of paste a user actually gives us.
"""

from __future__ import annotations

import pytest

from intel2sigma.web.ioc import (
    IOC,
    build_detection_items,
    classify,
    summarise,
)

# ---------------------------------------------------------------------------
# Single-pattern tests — one IOC type at a time
# ---------------------------------------------------------------------------


def test_classifies_sha256_hash() -> None:
    text = "632fedf848845f2eea63687d0ed01742163849d492fa9700d156729966a73fbd"
    iocs = classify(text)
    assert len(iocs) == 1
    assert iocs[0].category == "hash_sha256"
    assert iocs[0].observation == "file_event"


def test_classifies_md5_and_sha1() -> None:
    iocs = classify("d41d8cd98f00b204e9800998ecf8427e\nda39a3ee5e6b4b0d3255bfef95601890afd80709")
    cats = sorted(i.category for i in iocs)
    assert cats == ["hash_md5", "hash_sha1"]


def test_classifies_ipv4_with_port() -> None:
    iocs = classify("206.238.199.22:10086")
    assert len(iocs) == 1
    assert iocs[0].category == "ip"
    assert iocs[0].observation == "network_connection"
    assert iocs[0].value == "206.238.199.22:10086"


def test_classifies_defanged_ipv4() -> None:
    iocs = classify("206.238.199[.]22")
    assert len(iocs) == 1
    assert iocs[0].category == "ip"


def test_classifies_domain() -> None:
    iocs = classify("evil.example.com")
    assert len(iocs) == 1
    assert iocs[0].category == "domain"
    assert iocs[0].observation == "dns_query"


def test_classifies_defanged_domain() -> None:
    iocs = classify("mggsjvip[.]com")
    assert len(iocs) == 1
    assert iocs[0].category == "domain"
    assert iocs[0].value == "mggsjvip.com"


def test_domain_with_known_tld_wins_over_file_extension_check() -> None:
    """A label like ``com`` is in both the TLD list and could be a file ext.

    The TLD whitelist must win — otherwise real C2 domains like
    ``mggsjvip.com`` get misclassified as paths.
    """
    iocs = classify("mggsjvip.com")
    assert any(i.category == "domain" for i in iocs)


def test_classifies_dll_path() -> None:
    iocs = classify("C:\\Windows\\System32\\TimeBrokerClient.dll")
    assert len(iocs) == 1
    assert iocs[0].category == "path_dll_sys"
    assert iocs[0].observation == "image_load"


def test_classifies_exe_path() -> None:
    iocs = classify("C:\\Users\\x\\AppData\\Local\\Temp\\evil.exe")
    assert len(iocs) == 1
    assert iocs[0].category == "path_exe"
    assert iocs[0].observation == "process_creation"


def test_classifies_other_path() -> None:
    iocs = classify("C:\\Windows\\System32\\config.dat")
    assert len(iocs) == 1
    assert iocs[0].category == "path_other"
    assert iocs[0].observation == "file_event"


def test_classifies_bare_filename_with_known_extension() -> None:
    """``digital-document.exe`` (no path) routes to path_exe with a
    leading-backslash value so the resulting TargetFilename|endswith
    pattern is the canonical 'match the file by suffix' shape.
    """
    iocs = classify("digital-document.exe")
    assert len(iocs) == 1
    assert iocs[0].category == "path_exe"
    assert iocs[0].value == "\\digital-document.exe"


def test_bare_filename_with_known_tld_does_NOT_route_as_filename() -> None:
    """``mggsjvip.com`` shouldn't get caught by the bare-filename pattern;
    it's a domain. Confirms the TLD escape hatch works.
    """
    iocs = classify("mggsjvip.com")
    assert all(i.category != "path_other" for i in iocs)


def test_classifies_registry_key() -> None:
    iocs = classify("HKCU\\SOFTWARE\\HHClient")
    assert len(iocs) == 1
    assert iocs[0].category == "registry_key"
    assert iocs[0].observation == "registry_set"


def test_classifies_pdb_path() -> None:
    iocs = classify("D:\\CFILES\\Projects\\WinSSL")
    pdb = [i for i in iocs if i.category == "pdb_path"]
    assert pdb, f"Expected a pdb_path; got {iocs}"
    assert pdb[0].observation == "process_creation"


def test_classifies_email_metadata_only() -> None:
    iocs = classify("AuroraLeslie16081959pg@outlook.com")
    cats = [i.category for i in iocs]
    assert "email" in cats
    # The email's domain part should NOT also match as a separate domain
    # (email matcher consumes the span before the domain matcher runs).
    assert "domain" not in cats


def test_email_is_metadata_only() -> None:
    iocs = classify("alice@example.com")
    email = next(i for i in iocs if i.category == "email")
    assert email.observation == ""
    assert email.is_metadata_only


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


def test_duplicate_ioc_returns_single_entry() -> None:
    text = "evil.example.com\nevil.example.com\n"
    iocs = classify(text)
    assert len(iocs) == 1


# ---------------------------------------------------------------------------
# The Axios CTI hand-off — integration test
# ---------------------------------------------------------------------------


AXIOS_IOC_LIST = """
632fedf848845f2eea63687d0ed01742163849d492fa9700d156729966a73fbd  SHA256  Initial zip file
mggsjvip[.]com  Domain  Download site
AuroraLeslie16081959pg@outlook[.]com  Email  Sender
860f3e7c6633f5e83a812ea0626cb5362df641a720ef50d490dedad883642ea3  SHA256  First stage executable
digital-document.exe  Filename  First stage executable
de9f9f9a53fe1c1df5e229b2105cc84f9adb409ecc618f7a0ef9cf9fd7501118  SHA256  First-stage encoded DLL
D:\\CFILES\\Projects\\WinSSL  String  Path to custom WinSSL build in loader
C:\\Windows\\System32\\TimeBrokerClient.dll  Filename  Dropped malicious version of legit DLL
765bcc811fccc1d69d92055b2ab65a04a938d077838e6b749d437c78f912a36c  SHA256  Hash of evil DLL
C:\\Windows\\System32\\msvchost.dat  Filename  2nd stage dropped file
556b96e5bf91c48445eeca4ece0f2ee4fff8db8a02cc0b1b47ff033583bcb92c  SHA256  Hash of msvchost.dat
206.238.199[.]22:10086  IPv4  C2 Destination:Port
HKCU\\SOFTWARE\\HHClient  Registry Key  Persistence Key set
"""


def test_axios_real_world_paste_classifies_correctly() -> None:
    """End-to-end: a real CTI hand-off paste produces the expected categories."""
    iocs = classify(AXIOS_IOC_LIST)

    # Must have at least one of each significant category.
    categories = {i.category for i in iocs}
    for required in (
        "hash_sha256",
        "domain",
        "email",
        "path_exe",
        "path_dll_sys",
        "path_other",
        "ip",
        "registry_key",
        "pdb_path",
    ):
        assert required in categories, f"Expected {required!r} in classified set; got {categories}"

    # The C2 domain mggsjvip.com must classify as a domain (not a path).
    domains = [i.value for i in iocs if i.category == "domain"]
    assert "mggsjvip.com" in domains, f"C2 domain misclassified; domains seen: {domains}"

    # The .exe file must route to process_creation.
    exes = [i for i in iocs if i.category == "path_exe"]
    assert exes
    assert all(i.observation == "process_creation" for i in exes)

    # IP+port preserved on the value so DestinationPort can be split out.
    ips = [i for i in iocs if i.category == "ip"]
    assert ips
    assert ":10086" in ips[0].value


# ---------------------------------------------------------------------------
# summarise() ordering
# ---------------------------------------------------------------------------


def test_summarise_orders_routing_before_metadata() -> None:
    iocs = [
        IOC(raw="x", value="x", category="email", observation=""),
        IOC(raw="y", value="y", category="ip", observation="network_connection"),
    ]
    summaries = summarise(iocs)
    # Routing-bearing entries come first.
    assert summaries[0].observation != ""
    assert summaries[-1].observation == ""


def test_summarise_orders_by_count_desc_within_group() -> None:
    iocs = [
        IOC(raw="1.1.1.1", value="1.1.1.1", category="ip", observation="network_connection"),
        IOC(raw="2.2.2.2", value="2.2.2.2", category="ip", observation="network_connection"),
        IOC(raw="evil.com", value="evil.com", category="domain", observation="dns_query"),
    ]
    summaries = summarise(iocs)
    routing = [s for s in summaries if s.observation]
    assert routing[0].count >= routing[-1].count


# ---------------------------------------------------------------------------
# build_detection_items
# ---------------------------------------------------------------------------


def test_build_detection_items_for_file_event_includes_only_file_event_iocs() -> None:
    iocs = [
        IOC(raw="hash", value="abc", category="hash_sha256", observation="file_event"),
        IOC(raw="ip", value="1.1.1.1", category="ip", observation="network_connection"),
    ]
    items = build_detection_items(iocs, "file_event")
    assert len(items) == 1
    assert items[0].field == "Hashes"


def test_build_detection_items_splits_ip_and_port() -> None:
    iocs = [
        IOC(raw="x", value="206.238.199.22:10086", category="ip", observation="network_connection"),
    ]
    items = build_detection_items(iocs, "network_connection")
    fields = [i.field for i in items]
    assert "DestinationIp" in fields
    assert "DestinationPort" in fields


def test_build_detection_items_empty_for_unrelated_observation() -> None:
    iocs = [IOC(raw="x", value="abc", category="hash_sha256", observation="file_event")]
    assert build_detection_items(iocs, "registry_set") == []


# ---------------------------------------------------------------------------
# Empty input
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("text", ["", "   \n  \n", None])
def test_classify_empty_returns_empty_list(text: str | None) -> None:
    assert classify(text or "") == []

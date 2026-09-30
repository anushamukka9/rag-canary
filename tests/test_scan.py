"""Tests for scanning text and files for canary tokens."""

import pytest

from rag_canary import Canary, generate_canaries, plant_canaries, scan_files, scan_text


def _planted_canaries(n=5, seed=11):
    canaries = generate_canaries(n, seed=seed)
    docs = [{"id": f"doc-{i}", "text": f"Doc {i}."} for i in range(3)]
    plant_canaries(docs, canaries, strategy="inline", seed=seed)
    return canaries


def test_scan_text_finds_canary():
    canaries = _planted_canaries()
    text = f"Here is the doc: the key is {canaries[0].token} end of message."
    leaks = scan_text(text, canaries)
    assert len(leaks) == 1
    leak = leaks[0]
    assert leak.canary_id == canaries[0].id
    assert leak.kind == canaries[0].kind
    assert leak.planted_in == canaries[0].planted_in
    assert canaries[0].token in leak.snippet


def test_scan_text_snippet_has_context_window():
    canaries = _planted_canaries()
    text = "x" * 500 + canaries[2].token + "y" * 500
    leaks = scan_text(text, canaries)
    assert len(leaks) == 1
    assert len(leaks[0].snippet) <= len(canaries[2].token) + 121


def test_scan_text_no_match_returns_empty():
    canaries = _planted_canaries()
    assert scan_text("nothing secret here, just a normal answer", canaries) == []


def test_scan_text_finds_multiple_canaries():
    canaries = _planted_canaries()
    text = f"first {canaries[0].token} then {canaries[3].token} done"
    leaks = scan_text(text, canaries)
    assert {leak.canary_id for leak in leaks} == {canaries[0].id, canaries[3].id}


def test_scan_text_dedupes_repeat_occurrences():
    canaries = _planted_canaries()
    text = f"{canaries[1].token} ... {canaries[1].token} ... {canaries[1].token}"
    leaks = scan_text(text, canaries)
    assert len(leaks) == 1


def test_scan_text_skips_empty_token():
    canary = Canary(id="canary-x", token="", kind="api_key")
    assert scan_text("any text at all", [canary]) == []


def test_scan_text_does_not_match_partial_token():
    canaries = _planted_canaries()
    partial = canaries[0].token[:10]
    assert scan_text(f"partial {partial} only", canaries) == []


def test_scan_text_ignores_real_looking_non_canary_secrets():
    canaries = generate_canaries(10, seed=21)
    text = (
        "prod key sk-live-4eC39HqLyjWDarjtT1zdp7dc, "
        "aws example AKIAIOSFODNN7EXAMPLE, "
        "legacy slack-legacy-9f2c4a1b7d3e8f0a1c2d4e6f8a0b1d3e5"
    )
    assert scan_text(text, canaries) == []


def test_scan_files_reads_files(tmp_path):
    canaries = _planted_canaries()
    target = tmp_path / "output.txt"
    target.write_text(f"leaked: {canaries[4].token}\n", encoding="utf-8")
    clean = tmp_path / "clean.txt"
    clean.write_text("nothing here", encoding="utf-8")
    leaks = scan_files([str(target), str(clean)], canaries)
    assert len(leaks) == 1
    assert leaks[0].canary_id == canaries[4].id


def test_scan_files_tolerates_undecodable_bytes(tmp_path):
    canaries = _planted_canaries()
    target = tmp_path / "messy.log"
    target.write_bytes(b"\xff\xfe binary " + canaries[0].token.encode() + b" \x80 end")
    leaks = scan_files([target], canaries)
    assert len(leaks) == 1


def test_scan_files_missing_file_raises(tmp_path):
    canaries = _planted_canaries()
    with pytest.raises(OSError):
        scan_files([str(tmp_path / "nope.txt")], canaries)


def test_scan_reports_planted_in_from_manifest():
    canaries = generate_canaries(6, seed=31)
    docs = [{"id": "runbook", "text": "Incident runbook."}]
    planted, _ = plant_canaries(docs, canaries, strategy="inline", seed=31)
    leaks = scan_text(planted[0]["text"], canaries)
    assert len(leaks) == 6
    assert {leak.planted_in for leak in leaks} == {"runbook"}


def test_scan_encoded_off_by_default():
    import base64

    canaries = _planted_canaries()
    encoded = base64.b64encode(canaries[0].token.encode()).decode()
    assert scan_text(f"hidden: {encoded}", canaries) == []


def test_scan_detects_base64_encoded_token():
    import base64

    canaries = _planted_canaries()
    encoded = base64.b64encode(canaries[0].token.encode()).decode()
    leaks = scan_text(f"hidden: {encoded}", canaries, detect_encoded=True)
    assert len(leaks) == 1
    assert leaks[0].canary_id == canaries[0].id
    assert leaks[0].encoding == "base64"


def test_scan_detects_unpadded_base64():
    import base64

    canaries = generate_canaries(4, seed=77)
    encoded = base64.b64encode(canaries[2].token.encode()).decode().rstrip("=")
    leaks = scan_text(encoded, canaries, detect_encoded=True)
    assert len(leaks) == 1
    assert leaks[0].encoding == "base64"


def test_scan_detects_hex_encoded_token():
    canaries = _planted_canaries()
    encoded = canaries[1].token.encode().hex()
    leaks = scan_text(f"hex dump {encoded} end", canaries, detect_encoded=True)
    assert len(leaks) == 1
    assert leaks[0].canary_id == canaries[1].id
    assert leaks[0].encoding == "hex"


def test_scan_verbatim_takes_precedence_over_encoded():
    import base64

    canaries = _planted_canaries()
    encoded = base64.b64encode(canaries[0].token.encode()).decode()
    text = f"{canaries[0].token} and also {encoded}"
    leaks = scan_text(text, canaries, detect_encoded=True)
    assert len(leaks) == 1
    assert leaks[0].encoding == "verbatim"


def test_scan_encoded_reports_first_occurrence_only():
    import base64

    canaries = _planted_canaries()
    encoded = base64.b64encode(canaries[3].token.encode()).decode()
    leaks = scan_text(f"{encoded} ... {encoded}", canaries, detect_encoded=True)
    assert len(leaks) == 1


def test_scan_files_detect_encoded(tmp_path):
    import base64

    canaries = _planted_canaries()
    target = tmp_path / "out.txt"
    target.write_text(base64.b64encode(canaries[2].token.encode()).decode(), encoding="utf-8")
    leaks = scan_files([str(target)], canaries, detect_encoded=True)
    assert len(leaks) == 1
    assert leaks[0].encoding == "base64"


def test_scan_multiline_private_key():
    canaries = generate_canaries(3, kinds=["private_key"], seed=99)
    docs = [{"id": "doc-1", "text": "Signing notes."}]
    planted, _ = plant_canaries(docs, canaries, strategy="inline")
    leaks = scan_text(planted[0]["text"], canaries)
    assert len(leaks) == 3
    assert all(leak.encoding == "verbatim" for leak in leaks)

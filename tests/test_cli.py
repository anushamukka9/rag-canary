"""End-to-end CLI tests: generate -> plant -> scan."""

import json

import rag_canary
from rag_canary.cli import main


def test_generate_writes_canaries_json(tmp_path):
    out = tmp_path / "canaries.json"
    rc = main(["generate", "-n", "8", "--seed", "7", "-o", str(out)])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data) == 8
    assert all("canary" in item["token"].lower() for item in data)


def test_generate_stdout(capsys):
    rc = main(["generate", "-n", "3", "--kinds", "api_key,ssn", "--seed", "7"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert {item["kind"] for item in data} == {"api_key", "ssn"}


def test_generate_invalid_kind_exits_2(capsys):
    assert main(["generate", "--kinds", "bogus"]) == 2
    assert "unknown canary kinds" in capsys.readouterr().err


def test_plant_end_to_end(tmp_path):
    corpus = tmp_path / "corpus.jsonl"
    corpus.write_text(
        '{"id": "a", "text": "First doc."}\n{"id": "b", "text": "Second doc."}\n',
        encoding="utf-8",
    )
    canaries = tmp_path / "canaries.json"
    assert main(["generate", "-n", "5", "--seed", "9", "-o", str(canaries)]) == 0
    planted = tmp_path / "planted.jsonl"
    manifest = tmp_path / "manifest.json"
    rc = main(
        [
            "plant",
            "--docs",
            str(corpus),
            "--canaries",
            str(canaries),
            "--strategy",
            "inline",
            "--seed",
            "9",
            "-o",
            str(planted),
            "--manifest",
            str(manifest),
        ]
    )
    assert rc == 0
    assert len(planted.read_text(encoding="utf-8").strip().splitlines()) == 2
    manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
    assert len(manifest_data) == 5


def test_plant_dedicated_via_cli(tmp_path):
    canaries = tmp_path / "canaries.json"
    assert main(["generate", "-n", "5", "--seed", "9", "-o", str(canaries)]) == 0
    planted = tmp_path / "planted.jsonl"
    corpus = tmp_path / "corpus.jsonl"
    corpus.write_text("[]", encoding="utf-8")
    rc = main(
        [
            "plant",
            "--docs",
            str(corpus),
            "--canaries",
            str(canaries),
            "--strategy",
            "dedicated",
            "-o",
            str(planted),
        ]
    )
    assert rc == 0
    lines = planted.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2  # 5 canaries in batches of 4


def test_scan_finds_leak_exit_1(tmp_path, capsys):
    canaries = tmp_path / "canaries.json"
    assert main(["generate", "-n", "4", "--seed", "13", "-o", str(canaries)]) == 0
    capsys.readouterr()  # drain the "wrote N canaries" line
    data = json.loads(canaries.read_text(encoding="utf-8"))
    target = tmp_path / "model_output.txt"
    target.write_text(f"answer: the key is {data[0]['token']} done\n", encoding="utf-8")
    rc = main(["scan", "--canaries", str(canaries), "--format", "json", str(target)])
    assert rc == 1
    report = json.loads(capsys.readouterr().out)
    assert report["counts"]["leaks"] == 1
    assert report["leaks"][0]["canary_id"] == data[0]["id"]


def test_scan_clean_exit_0(tmp_path, capsys):
    canaries = tmp_path / "canaries.json"
    assert main(["generate", "-n", "4", "--seed", "13", "-o", str(canaries)]) == 0
    target = tmp_path / "clean.txt"
    target.write_text("a perfectly innocent answer with no secrets\n", encoding="utf-8")
    rc = main(["scan", "--canaries", str(canaries), str(target)])
    assert rc == 0
    assert "No canaries found" in capsys.readouterr().out


def test_scan_markdown_format(tmp_path, capsys):
    canaries = tmp_path / "canaries.json"
    assert main(["generate", "-n", "2", "--seed", "13", "-o", str(canaries)]) == 0
    capsys.readouterr()  # drain the "wrote N canaries" line
    data = json.loads(canaries.read_text(encoding="utf-8"))
    target = tmp_path / "out.txt"
    target.write_text(f"leaked {data[1]['token']}\n", encoding="utf-8")
    rc = main(["scan", "--canaries", str(canaries), "--format", "markdown", str(target)])
    assert rc == 1
    out = capsys.readouterr().out
    assert out.startswith("# rag-canary leak report")
    assert data[1]["id"] in out


def test_scan_missing_canaries_file_exits_2(tmp_path):
    assert main(["scan", "--canaries", str(tmp_path / "nope.json"), "whatever.txt"]) == 2


def test_scan_missing_input_file_exits_2(tmp_path):
    canaries = tmp_path / "canaries.json"
    assert main(["generate", "-n", "2", "-o", str(canaries)]) == 0
    rc = main(["scan", "--canaries", str(canaries), str(tmp_path / "nope.txt")])
    assert rc == 2


def test_scan_with_manifest_fills_planted_in(tmp_path, capsys):
    canaries = tmp_path / "canaries.json"
    corpus = tmp_path / "corpus.jsonl"
    corpus.write_text('{"id": "d1", "text": "Staging runbook."}\n', encoding="utf-8")
    assert main(["generate", "-n", "3", "--seed", "33", "-o", str(canaries)]) == 0
    planted = tmp_path / "planted.jsonl"
    manifest = tmp_path / "manifest.json"
    assert (
        main(
            [
                "plant",
                "--docs",
                str(corpus),
                "--canaries",
                str(canaries),
                "-o",
                str(planted),
                "--manifest",
                str(manifest),
            ]
        )
        == 0
    )
    capsys.readouterr()
    rc = main(
        [
            "scan",
            "--canaries",
            str(canaries),
            "--manifest",
            str(manifest),
            "--format",
            "json",
            str(planted),
        ]
    )
    assert rc == 1
    report = json.loads(capsys.readouterr().out)
    assert report["counts"]["leaks"] == 3
    assert {leak["planted_in"] for leak in report["leaks"]} == {"d1"}


def test_full_pipeline_generate_plant_scan(tmp_path):
    canaries = tmp_path / "canaries.json"
    corpus = tmp_path / "corpus.jsonl"
    corpus.write_text('{"id": "d1", "text": "Staging runbook."}\n', encoding="utf-8")
    assert main(["generate", "-n", "6", "--seed", "21", "-o", str(canaries)]) == 0
    planted = tmp_path / "planted.jsonl"
    assert (
        main(
            [
                "plant",
                "--docs",
                str(corpus),
                "--canaries",
                str(canaries),
                "-o",
                str(planted),
            ]
        )
        == 0
    )
    # An attacker dumps the planted doc; the scan trips the wire.
    assert main(["scan", "--canaries", str(canaries), str(planted)]) == 1


def test_version_synced_with_pyproject():
    import re
    from pathlib import Path

    root = Path(rag_canary.__file__).resolve().parent.parent.parent
    pyproject = (root / "pyproject.toml").read_text()
    match = re.search(r'^version = "([^"]+)"', pyproject, re.M)
    assert match and match.group(1) == rag_canary.__version__


def test_rotate_produces_fresh_set(tmp_path, capsys):
    old = tmp_path / "old.json"
    assert main(["generate", "-n", "6", "--seed", "4", "-o", str(old)]) == 0
    new = tmp_path / "new.json"
    rc = main(["rotate", "--old", str(old), "-n", "6", "--seed", "4", "-o", str(new)])
    assert rc == 0
    old_data = json.loads(old.read_text(encoding="utf-8"))
    new_data = json.loads(new.read_text(encoding="utf-8"))
    assert len(new_data) == 6
    assert not ({c["token"] for c in new_data} & {c["token"] for c in old_data})
    capsys.readouterr()


def test_rotate_deterministic(tmp_path, capsys):
    old = tmp_path / "old.json"
    assert main(["generate", "-n", "4", "--seed", "4", "-o", str(old)]) == 0
    capsys.readouterr()
    assert main(["rotate", "--old", str(old), "-n", "4", "--seed", "8"]) == 0
    first = json.loads(capsys.readouterr().out)
    assert main(["rotate", "--old", str(old), "-n", "4", "--seed", "8"]) == 0
    second = json.loads(capsys.readouterr().out)
    assert [c["token"] for c in first] == [c["token"] for c in second]


def test_rotate_missing_old_file_exits_2(tmp_path):
    assert main(["rotate", "--old", str(tmp_path / "nope.json"), "-n", "4"]) == 2


def test_verify_all_present_exit_0(tmp_path, capsys):
    canaries = tmp_path / "canaries.json"
    manifest = tmp_path / "manifest.json"
    corpus = tmp_path / "corpus.jsonl"
    corpus.write_text('{"id": "d1", "text": "Staging runbook."}\n', encoding="utf-8")
    assert main(["generate", "-n", "4", "--seed", "51", "-o", str(canaries)]) == 0
    planted = tmp_path / "planted.jsonl"
    assert (
        main(
            [
                "plant",
                "--docs",
                str(corpus),
                "--canaries",
                str(canaries),
                "--manifest",
                str(manifest),
                "-o",
                str(planted),
            ]
        )
        == 0
    )
    rc = main(
        [
            "verify",
            "--docs",
            str(planted),
            "--canaries",
            str(canaries),
            "--manifest",
            str(manifest),
        ]
    )
    assert rc == 0
    assert "4/4" in capsys.readouterr().out


def test_verify_missing_token_exit_1(tmp_path, capsys):
    import re

    canaries = tmp_path / "canaries.json"
    manifest = tmp_path / "manifest.json"
    corpus = tmp_path / "corpus.jsonl"
    corpus.write_text('{"id": "d1", "text": "Staging runbook."}\n', encoding="utf-8")
    assert main(["generate", "-n", "3", "--seed", "52", "-o", str(canaries)]) == 0
    planted = tmp_path / "planted.jsonl"
    assert (
        main(
            [
                "plant",
                "--docs",
                str(corpus),
                "--canaries",
                str(canaries),
                "--manifest",
                str(manifest),
                "-o",
                str(planted),
            ]
        )
        == 0
    )
    # Mangle the planted file: redact the first canary token.
    data = json.loads(canaries.read_text(encoding="utf-8"))
    text = planted.read_text(encoding="utf-8")
    text = text.replace(data[0]["token"], "[REDACTED]", 1)
    planted.write_text(text, encoding="utf-8")
    rc = main(
        [
            "verify",
            "--docs",
            str(planted),
            "--canaries",
            str(canaries),
            "--manifest",
            str(manifest),
        ]
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert re.search(r"FAILED.*1 canary", err)


def test_verify_json_format(tmp_path, capsys):
    canaries = tmp_path / "canaries.json"
    manifest = tmp_path / "manifest.json"
    corpus = tmp_path / "corpus.jsonl"
    corpus.write_text('{"id": "d1", "text": "Staging runbook."}\n', encoding="utf-8")
    assert main(["generate", "-n", "2", "--seed", "53", "-o", str(canaries)]) == 0
    planted = tmp_path / "planted.jsonl"
    assert (
        main(
            [
                "plant",
                "--docs",
                str(corpus),
                "--canaries",
                str(canaries),
                "--manifest",
                str(manifest),
                "-o",
                str(planted),
            ]
        )
        == 0
    )
    capsys.readouterr()  # drain plant/generate chatter so stdout holds only the report
    rc = main(
        [
            "verify",
            "--docs",
            str(planted),
            "--canaries",
            str(canaries),
            "--manifest",
            str(manifest),
            "--format",
            "json",
        ]
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["checked"] == 2 and payload["found"] == 2


def test_scan_encoded_flag(tmp_path, capsys):
    import base64

    canaries = tmp_path / "canaries.json"
    assert main(["generate", "-n", "3", "--seed", "61", "-o", str(canaries)]) == 0
    capsys.readouterr()
    data = json.loads(canaries.read_text(encoding="utf-8"))
    target = tmp_path / "out.txt"
    target.write_text(base64.b64encode(data[1]["token"].encode()).decode(), encoding="utf-8")
    rc = main(["scan", "--canaries", str(canaries), "--encoded", str(target)])
    assert rc == 1
    out = capsys.readouterr().out
    assert "base64-encoded" in out
    # Without the flag the same file is clean.
    assert main(["scan", "--canaries", str(canaries), str(target)]) == 0

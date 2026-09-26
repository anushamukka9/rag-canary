"""Command-line interface: rag-canary generate|plant|scan"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, generate_canaries, plant_canaries
from .canary import CANARY_KINDS, Canary
from .report import LeakReport
from .scan import scan_text


def _read_canaries(path: str) -> list[Canary]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise ValueError("canaries file must be a JSON list")
    return [Canary.from_dict(item) for item in data]


def _read_docs(path: str) -> list[dict]:
    text = Path(path).read_text(encoding="utf-8").strip()
    if not text:
        raise ValueError("docs file is empty")
    if path.endswith(".jsonl") and not text.lstrip().startswith("["):
        docs = [json.loads(line) for line in text.splitlines() if line.strip()]
    else:
        docs = json.loads(text)
    if not isinstance(docs, list):
        raise ValueError("docs file must hold a JSON list or JSONL lines")
    return docs


def _parse_kinds(value: str | None) -> list[str] | None:
    if not value:
        return None
    kinds = [k.strip() for k in value.split(",") if k.strip()]
    unknown = [k for k in kinds if k not in CANARY_KINDS]
    if unknown:
        raise ValueError(f"unknown canary kinds: {', '.join(unknown)}")
    return kinds


def cmd_generate(args: argparse.Namespace) -> int:
    try:
        kinds = _parse_kinds(args.kinds)
        canaries = generate_canaries(args.count, kinds=kinds, seed=args.seed)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    payload = json.dumps([c.to_dict() for c in canaries], indent=2)
    if args.output:
        Path(args.output).write_text(payload + "\n", encoding="utf-8")
        print(f"wrote {len(canaries)} canaries to {args.output}")
    else:
        print(payload)
    return 0


def cmd_plant(args: argparse.Namespace) -> int:
    try:
        docs = _read_docs(args.docs)
        canaries = _read_canaries(args.canaries)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: cannot read input: {exc}", file=sys.stderr)
        return 2
    try:
        planted_docs, manifest = plant_canaries(
            docs, canaries, strategy=args.strategy, seed=args.seed
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            for doc in planted_docs:
                fh.write(json.dumps(doc) + "\n")
        print(f"wrote {len(planted_docs)} planted docs to {args.output}")
    else:
        for doc in planted_docs:
            print(json.dumps(doc))
    if args.manifest:
        Path(args.manifest).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print(f"wrote manifest ({len(manifest)} canaries) to {args.manifest}")
    return 0


def _apply_manifest(canaries: list[Canary], manifest_path: str | None) -> None:
    """Fill in planted_in from a plant manifest, where the canary lacks it."""
    if not manifest_path:
        return
    with open(manifest_path, encoding="utf-8") as fh:
        manifest = json.load(fh)
    for canary in canaries:
        entry = manifest.get(canary.id)
        if entry and not canary.planted_in:
            canary.planted_in = entry.get("doc_id")


def _format_scan_table(by_file: dict[str, list]) -> str:
    total_leaks = sum(len(leaks) for leaks in by_file.values())
    lines = [
        f"rag-canary scan: {len(by_file)} file(s), {total_leaks} leak(s)",
        "",
    ]
    if not total_leaks:
        lines.append("No canaries found. Clean.")
        return "\n".join(lines)
    for filename, leaks in by_file.items():
        if not leaks:
            continue
        lines.append(f"{filename}: {len(leaks)} leak(s)")
        for leak in leaks:
            where = leak.planted_in or "unknown doc"
            lines.append(f"  [{leak.kind}] {leak.canary_id} (planted in {where})")
            lines.append(f"    > {leak.snippet[:120]}")
    return "\n".join(lines)


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        canaries = _read_canaries(args.canaries)
        _apply_manifest(canaries, args.manifest)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: cannot read canaries: {exc}", file=sys.stderr)
        return 2
    by_file: dict[str, list] = {}
    for path in args.files:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"error: cannot read {path}: {exc}", file=sys.stderr)
            return 2
        by_file[path] = scan_text(text, canaries)

    label = args.label or ", ".join(args.files)
    report = LeakReport(
        leaks=[leak for leaks in by_file.values() for leak in leaks],
        label=label,
    )
    if args.format == "json":
        print(report.to_json())
    elif args.format == "markdown":
        print(report.to_markdown(), end="")
    else:
        print(_format_scan_table(by_file))

    if report.leaks:
        print(
            f"\nTRIPPED: {len(report.leaks)} canary leak(s) found.",
            file=sys.stderr,
        )
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rag-canary",
        description="Plant canary tokens in a RAG corpus and scan outputs for leaks.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="Generate canary tokens.")
    gen.add_argument("-n", "--count", type=int, default=10, help="How many canaries (default: 10).")
    gen.add_argument(
        "--kinds",
        default=None,
        help="Comma-separated subset of canary kinds (default: all ten).",
    )
    gen.add_argument("--seed", type=int, default=None, help="Seed for deterministic output.")
    gen.add_argument(
        "-o", "--output", default=None, help="Write canaries JSON here (default: stdout)."
    )
    gen.set_defaults(func=cmd_generate)

    plant = sub.add_parser("plant", help="Plant canaries into documents.")
    plant.add_argument(
        "--docs", required=True, help="Corpus file: JSONL or JSON list of {id, text}."
    )
    plant.add_argument("--canaries", required=True, help="Canaries JSON from `generate`.")
    plant.add_argument(
        "--strategy",
        choices=["inline", "dedicated"],
        default="inline",
        help="Planting strategy (default: inline).",
    )
    plant.add_argument("--seed", type=int, default=None, help="Seed for deterministic placement.")
    plant.add_argument(
        "-o", "--output", default=None, help="Write planted docs as JSONL (default: stdout)."
    )
    plant.add_argument("--manifest", default=None, help="Write the canary manifest JSON here.")
    plant.set_defaults(func=cmd_plant)

    scan = sub.add_parser("scan", help="Scan files for canary tokens.")
    scan.add_argument("files", nargs="+", help="Files to scan (model outputs, logs).")
    scan.add_argument("--canaries", required=True, help="Canaries JSON from `generate`.")
    scan.add_argument(
        "--manifest",
        default=None,
        help="Manifest JSON from `plant`; fills in where each canary was planted.",
    )
    scan.add_argument(
        "--format",
        choices=["table", "json", "markdown"],
        default="table",
        help="Output format (default: table).",
    )
    scan.add_argument("--label", default=None, help="Label for the report.")
    scan.set_defaults(func=cmd_scan)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

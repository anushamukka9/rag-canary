"""Variety pack demo: the six kinds added in v0.3.0, planted and caught.

Run: python examples/variety_pack.py
"""

from rag_canary import generate_canaries, plant_canaries, scan_text

NEW_KINDS = [
    "oauth_refresh_token",
    "mysql_conn_string",
    "mongodb_conn_string",
    "redis_conn_string",
    "tracked_memo",
    "aws_secret_key",
]


def main() -> None:
    canaries = generate_canaries(len(NEW_KINDS), kinds=NEW_KINDS, seed=42)
    for canary in canaries:
        print(f"{canary.kind:22} {canary.token}")
    docs = [{"id": "staging-runbook", "text": "Staging runbook for the demo services."}]
    planted, _manifest = plant_canaries(docs, canaries, strategy="inline", seed=42)
    leaks = scan_text(planted[0]["text"], canaries)
    print(f"\nplanted {len(canaries)} canaries, scan of the planted doc trips {len(leaks)}")
    for leak in leaks:
        print(f"  [{leak.kind}] {leak.canary_id} from {leak.planted_in}")


if __name__ == "__main__":
    main()

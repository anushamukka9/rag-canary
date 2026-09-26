# CI usage

Two patterns cover most setups: scan on a schedule, and fail the build
when a leak is found.

## Nightly leak scan

Keep your canaries and a manifest in the repo (or in CI secrets), plant
once, and scan the previous day's model outputs or logs:

```yaml
- name: Scan yesterday's outputs for canary leaks
  run: |
    pip install rag-canary
    rag-canary scan --canaries canaries.json --format json outputs/*.log > leak-report.json

- name: Upload leak report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: leak-report
    path: leak-report.json
```

`rag-canary scan` exits 1 when any canary is found, which fails the step.
That is the point: a tripped canary should be loud. Wire the failure to
your alerting (PagerDuty, Slack, email) rather than letting it sit as a
red check nobody reads.

## Gate a corpus change

When a PR touches the indexed corpus, re-plant with the same seed and
confirm the manifest is unchanged. A diff in the manifest means canaries
moved, and moved canaries mean your tripwires are not where you think:

```yaml
- name: Verify canary placement is stable
  run: |
    pip install rag-canary
    rag-canary plant --docs corpus.jsonl --canaries canaries.json \
      --seed 42 --manifest /tmp/manifest.json -o /dev/null
    diff canaries-manifest.json /tmp/manifest.json
```

## Keep canaries out of the repo

The canary set itself is sensitive. An attacker who reads your canaries
can strip them before exfiltrating. Prefer CI secrets or a private vault
over checking `canaries.json` into the repo. The benchmark fixtures in
this repo are synthetic and seeded; treat your production set with more
care.

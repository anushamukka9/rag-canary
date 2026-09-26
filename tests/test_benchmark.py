"""Benchmark smoke tests: the bundled fixtures must score as advertised."""

from rag_canary.benchmark import load_fixtures, main, measure_latency, run


def test_benchmark_recall_is_perfect():
    results = run()
    assert results["recall"] == 1.0
    assert results["expected_leaks"] == 19
    assert results["expected_hit"] == 19


def test_benchmark_false_positive_rate_is_zero():
    results = run()
    assert results["false_positive_rate"] == 0.0
    assert results["negative_files"] == 14
    assert results["false_positive_files"] == 0


def test_benchmark_corpus_self_check():
    results = run()
    assert results["corpus_self_check"] == "30/30"
    assert results["docs"] == 24
    assert results["canaries"] == 30


def test_benchmark_latency_positive_and_sane():
    canaries, _, _ = load_fixtures()
    ms_per_mb = measure_latency(canaries, repeats=3)
    assert ms_per_mb > 0
    assert ms_per_mb < 5000  # substring search; anything slower means something broke


def test_benchmark_main_runs(capsys):
    main()
    out = capsys.readouterr().out
    assert "recall on exfil set" in out
    assert "false-positive rate" in out
    assert "scan latency" in out

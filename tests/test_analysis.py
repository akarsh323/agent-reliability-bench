"""Tests for the statistics behind the results tables."""

import math

import pytest

from reliabench.analysis import Estimate, model_label, pass_hat_k, pooled_rate


def test_pooled_rate_is_a_ratio_of_sums():
    estimate = pooled_rate([(1, 1), (0, 9)], resamples=200)
    assert estimate.value == pytest.approx(0.1)
    assert (estimate.numerator, estimate.denominator) == (1.0, 10.0)
    assert estimate.low <= estimate.value <= estimate.high


def test_pooled_rate_edge_cases():
    assert not pooled_rate([]).defined
    assert not pooled_rate([(0, 0)]).defined
    single = pooled_rate([(1, 2)])
    assert single.value == 0.5
    assert math.isnan(single.low)


def test_pooled_rate_is_reproducible():
    clusters = [(i % 3, 4) for i in range(30)]
    assert pooled_rate(clusters, resamples=300, seed=1) == pooled_rate(
        clusters, resamples=300, seed=1
    )


@pytest.mark.parametrize(
    ("successes", "trials", "k", "expected"),
    [(5, 5, 5, 1.0), (4, 5, 5, 0.0), (4, 5, 1, 0.8), (4, 5, 2, 0.6)],
)
def test_pass_hat_k(successes, trials, k, expected):
    assert pass_hat_k(successes, trials, k) == pytest.approx(expected)
    assert math.isnan(pass_hat_k(1, 1, 2))


def test_formatting_and_labels():
    assert Estimate(0.2222, 0.1, 0.3).percent() == "22.2% [10.0, 30.0]"
    assert Estimate(0.5).percent() == "50.0%"
    assert Estimate(math.nan).percent() == "n/a"
    assert "scripted, not an LLM" in model_label("reliabench/careful")
    assert (
        model_label("anthropic/claude-sonnet-5-5")
        == "anthropic/claude-sonnet-5-5"
    )

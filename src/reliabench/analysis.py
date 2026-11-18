"""Turns Inspect eval logs into the result tables.

Three rules shape every number here:

  * The unit of resampling is the user task. Samples that share a task are
    correlated (same request, same document), so confidence intervals come
    from a bootstrap over tasks, with each task's samples and epochs kept
    together. With six tasks those intervals are wide, and should be.
  * Rates are pooled as a ratio of sums over samples.
  * A sample that ended in an error is excluded and counted. It is an
    infrastructure failure, not an agent failure, and the two are never
    added together.
"""

from __future__ import annotations

import dataclasses
import math
from collections import Counter, defaultdict
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import numpy as np
from inspect_ai.log import list_eval_logs, read_eval_log

from reliabench.reference import PROVIDER

SCORER_NAME = "desk_scorer"
DEFAULT_RESAMPLES = 10_000
DEFAULT_CONFIDENCE = 0.95
_BULKY_SAMPLE_FIELDS = {"messages", "events", "store", "attachments"}
_MODE_ORDER = ("benign", "attack", "fault")
_DEFENSE_ORDER = ("none", "tool_filter", "spotlight", "detector")


@dataclasses.dataclass(frozen=True)
class Cell:
    """Identifies one row of the results table.

    Attributes:
      model: Model name as Inspect recorded it.
      mode: `benign`, `attack` or `fault`.
      defense: The defense in force.
      attack_style: Wording of planted instructions, in attack mode.
    """

    model: str
    mode: str
    defense: str
    attack_style: str | None = None


@dataclasses.dataclass(frozen=True)
class Run:
    """One scored sample.

    Attributes:
      cell: The table row the sample belongs to.
      sample_id: Inspect sample id (task and variant).
      epoch: 1-based repetition number.
      detail: The scorer's metadata.
    """

    cell: Cell
    sample_id: str
    epoch: int
    detail: dict[str, Any]


@dataclasses.dataclass(frozen=True)
class Exclusion:
    """A sample left out of the analysis, and why.

    Attributes:
      cell: The table row the sample belonged to.
      sample_id: Inspect sample id.
      epoch: 1-based repetition number.
      reason: The sample error, or a note that it was never scored.
    """

    cell: Cell
    sample_id: str
    epoch: int
    reason: str


@dataclasses.dataclass(frozen=True)
class Estimate:
    """A pooled rate with a bootstrap confidence interval.

    Attributes:
      value: The point estimate, or NaN if its denominator is zero.
      low: Lower bound, or NaN if it could not be computed.
      high: Upper bound, or NaN if it could not be computed.
      numerator: Pooled numerator.
      denominator: Pooled denominator.
    """

    value: float
    low: float = math.nan
    high: float = math.nan
    numerator: float = 0.0
    denominator: float = 0.0

    @property
    def defined(self) -> bool:
        """Whether the estimate exists."""
        return not math.isnan(self.value)

    def percent(self) -> str:
        """Renders the estimate as `value% [low, high]`."""
        if not self.defined:
            return "n/a"
        text = f"{self.value * 100:.1f}%"
        if math.isnan(self.low):
            return text
        return f"{text} [{self.low * 100:.1f}, {self.high * 100:.1f}]"


def pooled_rate(
    clusters: Sequence[tuple[float, float]],
    *,
    resamples: int = DEFAULT_RESAMPLES,
    confidence: float = DEFAULT_CONFIDENCE,
    seed: int = 0,
) -> Estimate:
    """Estimates a pooled rate with a cluster-bootstrap interval.

    Args:
      clusters: One (numerator, denominator) pair per cluster.
      resamples: Number of bootstrap resamples.
      confidence: Coverage of the interval.
      seed: Seed of the resampling, for reproducible tables.

    Returns:
      The pooled rate. The interval is NaN with fewer than two clusters.
    """
    counts = np.asarray(clusters, dtype=float).reshape(-1, 2)
    numerator = float(counts[:, 0].sum())
    denominator = float(counts[:, 1].sum())
    if denominator == 0:
        return Estimate(math.nan, numerator=numerator)
    value = numerator / denominator
    if len(counts) < 2:
        return Estimate(value, numerator=numerator, denominator=denominator)
    rng = np.random.default_rng(seed)
    picks = rng.integers(0, len(counts), size=(resamples, len(counts)))
    sums = counts[picks].sum(axis=1)
    with np.errstate(invalid="ignore", divide="ignore"):
        rates = np.where(sums[:, 1] > 0, sums[:, 0] / sums[:, 1], np.nan)
    tail = (1.0 - confidence) / 2.0
    low, high = np.nanquantile(rates, [tail, 1.0 - tail])
    return Estimate(value, float(low), float(high), numerator, denominator)


def pass_hat_k(successes: int, trials: int, k: int) -> float:
    """Unbiased estimate of the chance that k independent trials all pass.

    This is `C(successes, k) / C(trials, k)`, the pass^k estimator of
    tau-bench.

    Args:
      successes: Number of passing trials observed.
      trials: Number of trials observed.
      k: Number of trials that must all pass.

    Returns:
      The estimate, or NaN if fewer than `k` trials were observed.
    """
    if trials < k or k < 1:
        return math.nan
    return math.comb(successes, k) / math.comb(trials, k)


def load_runs(log_dir: Path) -> tuple[list[Run], list[Exclusion]]:
    """Reads every credit-desk eval log under a directory.

    Args:
      log_dir: Directory of Inspect logs. Logs of other tasks are ignored.

    Returns:
      The scored samples, and the samples that were excluded.
    """
    runs: list[Run] = []
    excluded: list[Exclusion] = []
    for info in list_eval_logs(str(log_dir)):
        log = read_eval_log(info, exclude_fields=_BULKY_SAMPLE_FIELDS)
        if log.eval.task.split("/")[-1] != "credit_desk":
            continue
        args = log.eval.task_args or {}
        mode = str(args.get("mode", "benign"))
        cell = Cell(
            model=log.eval.model,
            mode=mode,
            defense=str(args.get("defense", "none")),
            attack_style=str(args.get("attack_style", "important_message"))
            if mode == "attack"
            else None,
        )
        for sample in log.samples or []:
            where = (cell, str(sample.id), sample.epoch)
            score = (sample.scores or {}).get(SCORER_NAME)
            if sample.error is not None:
                reason = sample.error.message.strip().splitlines()[-1]
                excluded.append(Exclusion(*where, reason=f"error: {reason}"))
            elif score is None or not score.metadata:
                excluded.append(Exclusion(*where, reason="not scored"))
            else:
                runs.append(Run(*where, detail=score.metadata))
    return runs, excluded


@dataclasses.dataclass(frozen=True)
class CellReport:
    """Every estimate for one row of the results table.

    Attributes:
      cell: The row.
      samples: Number of samples scored.
      excluded: Number of samples excluded for errors.
      epochs: Largest number of epochs scored for any sample.
      k: The k of pass^k.
      utility: Share of samples whose user task was done.
      attack_success: Share of attacked samples where the attacker's state
        change happened. Undefined outside attack mode.
      utility_pass_k: Chance that all k runs of a sample do the user task.
      secure_pass_k: Chance that no run of k is successfully attacked.
      submitted: Share of samples that ended with a submission.
      tokens_per_success: Tokens spent per completed user task.
      by_variant: Utility (or attack success, in attack mode) broken down by
        fault kind or attacker goal.
    """

    cell: Cell
    samples: int
    excluded: int
    epochs: int
    k: int
    utility: Estimate
    attack_success: Estimate
    utility_pass_k: Estimate
    secure_pass_k: Estimate
    submitted: Estimate
    tokens_per_success: Estimate
    by_variant: dict[str, Estimate]


def _by_task(
    runs: Sequence[Run],
    numerator: Callable[[dict[str, Any]], float],
    denominator: Callable[[dict[str, Any]], float] = lambda _: 1.0,
) -> list[tuple[float, float]]:
    """Sums a numerator and denominator over runs, clustered by user task."""
    totals: dict[str, list[float]] = defaultdict(lambda: [0.0, 0.0])
    for run in runs:
        cell = totals[run.detail["task_id"]]
        cell[0] += numerator(run.detail)
        cell[1] += denominator(run.detail)
    return [(a, b) for a, b in totals.values()]


def _pass_k(
    runs: Sequence[Run],
    passed: Callable[[dict[str, Any]], bool],
    k: int,
    *,
    resamples: int,
    seed: int,
) -> Estimate:
    """Averages pass^k over samples, with a bootstrap over user tasks."""
    wins: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    task_of: dict[str, str] = {}
    for run in runs:
        wins[run.sample_id][0] += passed(run.detail)
        wins[run.sample_id][1] += 1
        task_of[run.sample_id] = run.detail["task_id"]
    totals: dict[str, list[float]] = defaultdict(lambda: [0.0, 0.0])
    for sample_id, (successes, trials) in wins.items():
        if trials >= k:
            totals[task_of[sample_id]][0] += pass_hat_k(successes, trials, k)
            totals[task_of[sample_id]][1] += 1
    return pooled_rate(
        [(a, b) for a, b in totals.values()], resamples=resamples, seed=seed
    )


def summarize_cell(
    cell: Cell,
    runs: Sequence[Run],
    excluded: int = 0,
    *,
    k: int | None = None,
    resamples: int = DEFAULT_RESAMPLES,
    seed: int = 0,
) -> CellReport:
    """Computes every estimate for one row of the results table.

    Args:
      cell: The row.
      runs: Its scored samples.
      excluded: Number of its samples excluded for errors.
      k: The k of pass^k. Defaults to the smallest number of epochs any
        sample was run for.
      resamples: Number of bootstrap resamples.
      seed: Seed of the resampling.

    Returns:
      The estimates.
    """
    epochs = Counter(run.sample_id for run in runs)
    k = k or (min(epochs.values()) if epochs else 1)

    def rate(
        numerator: Callable[[dict[str, Any]], float],
        denominator: Callable[[dict[str, Any]], float] = lambda _: 1.0,
        subset: Sequence[Run] = runs,
    ) -> Estimate:
        return pooled_rate(
            _by_task(subset, numerator, denominator),
            resamples=resamples,
            seed=seed,
        )

    attacked = [run for run in runs if run.detail.get("goal_id")]
    variant_key = "goal_id" if cell.mode == "attack" else "fault"
    outcome = "attack_success" if cell.mode == "attack" else "utility"
    by_variant = {}
    for variant in sorted({str(r.detail.get(variant_key)) for r in runs}):
        if variant == "None":
            continue
        subset = [r for r in runs if str(r.detail.get(variant_key)) == variant]
        by_variant[variant] = rate(lambda d: float(d[outcome]), subset=subset)

    return CellReport(
        cell=cell,
        samples=len(runs),
        excluded=excluded,
        epochs=max(epochs.values(), default=0),
        k=k,
        utility=rate(lambda d: float(d["utility"])),
        attack_success=rate(
            lambda d: float(d["attack_success"]), subset=attacked
        ),
        utility_pass_k=_pass_k(
            runs,
            lambda d: bool(d["utility"]),
            k,
            resamples=resamples,
            seed=seed,
        ),
        secure_pass_k=_pass_k(
            attacked,
            lambda d: not d["attack_success"],
            k,
            resamples=resamples,
            seed=seed,
        ),
        submitted=rate(lambda d: float(d["submitted"])),
        tokens_per_success=rate(
            lambda d: float(d["total_tokens"]), lambda d: float(d["utility"])
        ),
        by_variant=by_variant,
    )


@dataclasses.dataclass(frozen=True)
class Report:
    """The full analysis of a log directory.

    Attributes:
      cells: One report per table row, in a stable order.
      exclusions: Samples left out of the analysis.
    """

    cells: list[CellReport]
    exclusions: list[Exclusion]


def _order(cell: Cell) -> tuple[str, int, int, str]:
    return (
        cell.model,
        _MODE_ORDER.index(cell.mode) if cell.mode in _MODE_ORDER else 9,
        _DEFENSE_ORDER.index(cell.defense)
        if cell.defense in _DEFENSE_ORDER
        else 9,
        cell.attack_style or "",
    )


def build_report(
    runs: Sequence[Run],
    exclusions: Sequence[Exclusion] = (),
    *,
    k: int | None = None,
    resamples: int = DEFAULT_RESAMPLES,
    seed: int = 0,
) -> Report:
    """Analyzes scored samples.

    Args:
      runs: Scored samples, from any number of models and settings.
      exclusions: Samples that were excluded when the logs were loaded.
      k: The k of pass^k. Defaults per row; see `summarize_cell`.
      resamples: Number of bootstrap resamples.
      seed: Seed of the resampling.

    Returns:
      The report.
    """
    by_cell: dict[Cell, list[Run]] = defaultdict(list)
    for run in runs:
        by_cell[run.cell].append(run)
    dropped = Counter(exclusion.cell for exclusion in exclusions)
    cells = sorted(set(by_cell) | set(dropped), key=_order)
    return Report(
        cells=[
            summarize_cell(
                cell,
                by_cell.get(cell, []),
                dropped[cell],
                k=k,
                resamples=resamples,
                seed=seed,
            )
            for cell in cells
        ],
        exclusions=list(exclusions),
    )


def model_label(model: str) -> str:
    """Returns a display name that marks scripted agents as not models."""
    prefix = f"{PROVIDER}/"
    if model.startswith(prefix):
        name = model.removeprefix(prefix)
        return f"reference agent: {name} (scripted, not an LLM)"
    return model


def _table(header: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    lines = [
        "| " + " | ".join(header) + " |",
        "|" + "|".join(" --- " for _ in header) + "|",
    ]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(lines)


def render_markdown(report: Report) -> str:
    """Renders a report as Markdown, one section per model.

    Args:
      report: The analysis to render.

    Returns:
      Markdown text.
    """
    sections = []
    for model in sorted({c.cell.model for c in report.cells}):
        cells = [c for c in report.cells if c.cell.model == model]
        k = cells[0].k
        rows = []
        for c in cells:
            variants = ", ".join(
                f"{name} {estimate.value * 100:.0f}%"
                for name, estimate in c.by_variant.items()
                if estimate.defined
            )
            rows.append(
                [
                    f"`{c.cell.mode}`",
                    f"`{c.cell.defense}`",
                    str(c.samples),
                    str(c.excluded),
                    c.utility.percent(),
                    c.attack_success.percent(),
                    c.utility_pass_k.percent(),
                    c.secure_pass_k.percent(),
                    c.submitted.percent(),
                    f"{c.tokens_per_success.value:,.0f}"
                    if c.tokens_per_success.defined
                    else "n/a",
                    variants or "-",
                ]
            )
        header = [
            "Mode",
            "Defense",
            "Samples scored",
            "Excluded (infra errors)",
            "Utility",
            "Attack success",
            f"Utility pass^{k}",
            f"Never attacked, pass^{k}",
            "Submitted",
            "Tokens per completed task",
            "Breakdown (attack: success by goal; fault: utility by fault)",
        ]
        sections.append(f"## {model_label(model)}\n\n{_table(header, rows)}")
    if report.exclusions:
        reasons = Counter(e.reason for e in report.exclusions)
        listing = "\n".join(
            f"- {count} x {reason}" for reason, count in reasons.most_common()
        )
        sections.append(
            "## Excluded samples\n\nThese samples ended in an error. They are"
            " infrastructure failures and are not counted as agent"
            f" failures.\n\n{listing}"
        )
    return "\n\n".join(sections) + "\n"


def report_to_json(report: Report) -> dict[str, Any]:
    """Converts a report to a JSON-serializable dict."""

    def estimate(e: Estimate) -> dict[str, float | None]:
        return {
            name: (None if math.isnan(value) else value)
            for name, value in dataclasses.asdict(e).items()
        }

    return {
        "cells": [
            {
                **dataclasses.asdict(c.cell),
                "samples": c.samples,
                "excluded": c.excluded,
                "epochs": c.epochs,
                "k": c.k,
                "utility": estimate(c.utility),
                "attack_success": estimate(c.attack_success),
                "utility_pass_k": estimate(c.utility_pass_k),
                "secure_pass_k": estimate(c.secure_pass_k),
                "submitted": estimate(c.submitted),
                "tokens_per_success": estimate(c.tokens_per_success),
                "by_variant": {n: estimate(e) for n, e in c.by_variant.items()},
            }
            for c in report.cells
        ],
        "exclusions": [
            {
                **dataclasses.asdict(e.cell),
                "sample_id": e.sample_id,
                "epoch": e.epoch,
                "reason": e.reason,
            }
            for e in report.exclusions
        ],
    }

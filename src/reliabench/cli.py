"""Command-line entry point: run the study matrix and build the report.

reliabench run --model anthropic/claude-sonnet-5-5 --epochs 5
reliabench report logs/ --out results/
"""

from __future__ import annotations

import argparse
import datetime
import importlib.metadata
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from reliabench import __version__
from reliabench.harness import Defense, Mode

# Every defense is run in benign and attack mode: a defense is only as good
# as what it costs when nothing is wrong. Faults are run undefended.
MATRIX: tuple[tuple[Mode, Defense], ...] = (
    *((Mode.BENIGN, defense) for defense in Defense),
    *((Mode.ATTACK, defense) for defense in Defense),
    (Mode.FAULT, Defense.NONE),
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reliabench",
        description="Reliability study for tool-using agents.",
    )
    parser.add_argument(
        "--version", action="version", version=f"reliabench {__version__}"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", help="Run the study matrix.")
    run.add_argument(
        "--model",
        action="append",
        required=True,
        help="Inspect model name. Repeat to run several models.",
    )
    run.add_argument("--epochs", type=int, default=5)
    run.add_argument("--log-dir", default="logs")
    run.add_argument("--attack-style", default="important_message")
    run.add_argument("--max-connections", type=int)
    run.add_argument(
        "--simulate-infra-failures",
        action="store_true",
        help="Add fault samples whose harness crashes on purpose.",
    )

    report = commands.add_parser("report", help="Build tables from eval logs.")
    report.add_argument("log_dir", type=Path)
    report.add_argument("--out", type=Path, help="Directory for the output.")
    report.add_argument("--k", type=int, help="The k of pass^k.")
    report.add_argument("--resamples", type=int, default=10_000)
    report.add_argument("--seed", type=int, default=0)
    return parser


def _run(args: argparse.Namespace) -> int:
    from inspect_ai import eval as inspect_eval

    from reliabench.harness import credit_desk

    tasks = [
        credit_desk(
            mode=mode.value,
            defense=defense.value,
            attack_style=args.attack_style,
            simulate_infra_failures=args.simulate_infra_failures,
        )
        for mode, defense in MATRIX
    ]
    logs = inspect_eval(
        tasks,
        model=args.model,
        epochs=args.epochs,
        log_dir=args.log_dir,
        max_connections=args.max_connections,
        # A sample that errors is reported, never silently scored as wrong.
        fail_on_error=False,
    )
    failed = [log for log in logs if log.status != "success"]
    for log in failed:
        print(f"{log.eval.task} on {log.eval.model}: {log.status}")
    return 1 if failed else 0


def _report(args: argparse.Namespace) -> int:
    from reliabench.analysis import (
        build_report,
        load_runs,
        render_markdown,
        report_to_json,
    )

    runs, exclusions = load_runs(args.log_dir)
    if not runs and not exclusions:
        print(f"No credit-desk samples under {args.log_dir}.")
        return 1
    report = build_report(
        runs, exclusions, k=args.k, resamples=args.resamples, seed=args.seed
    )
    markdown = render_markdown(report)
    if args.out is None:
        print(markdown)
        return 0
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "results.md").write_text(markdown, encoding="utf-8")
    payload = {
        "generated_on": datetime.date.today().isoformat(),
        "reliabench_version": __version__,
        "inspect_ai_version": importlib.metadata.version("inspect-ai"),
        "resamples": args.resamples,
        "confidence": 0.95,
        "seed": args.seed,
        **report_to_json(report),
    }
    (args.out / "results.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Wrote {args.out / 'results.md'} and {args.out / 'results.json'}.")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Runs the command-line interface.

    Args:
      argv: Arguments, without the program name. Defaults to `sys.argv`.

    Returns:
      Process exit code.
    """
    args = _build_parser().parse_args(argv)
    handlers = {"run": _run, "report": _report}
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())

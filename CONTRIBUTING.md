# Contributing

Issues and pull requests are welcome.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
make install
make check
```

`make check` is exactly what CI runs: `ruff`, `mypy --strict`, and `pytest`
with a 90% coverage floor. No API key is needed; the end-to-end tests use the
scripted reference agents.

## Rules that keep results comparable

1. **Anything that changes a score needs a version bump.** If a change alters
   a task, a check, a tool, a prompt or the scorer, bump `TASK_VERSION` in
   `harness.py` and say so in the pull request.
2. **Checks look at final state.** A new user task or attacker goal must be
   judged by what changed in the environment or by the submitted answer,
   never by the transcript.
3. **New tasks need a reference solution.** Add the steps to the task's
   `solution`, then re-derive the expected counts in
   `tests/test_end_to_end.py` and `docs/design.md` by hand.
4. **A sample error is never a failure.** Analysis code must keep errored
   samples out of every rate and report their count.

## Style

Google Python style: docstrings with `Args`/`Returns`/`Raises`, type
annotations everywhere, 80 columns. `make format` applies it.

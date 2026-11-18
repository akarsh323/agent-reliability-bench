"""Inspect registry hook.

Listed under the `inspect_ai` entry-point group in pyproject.toml. Importing
this module registers the task and the reference-agent model provider.
"""

from reliabench.harness import credit_desk
from reliabench.reference import ReferenceAgentAPI

__all__ = ["ReferenceAgentAPI", "credit_desk"]

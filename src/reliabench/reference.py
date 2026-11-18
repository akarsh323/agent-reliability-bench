"""Scripted reference agents, packaged as an Inspect model provider.

These are not language models. They execute each task's reference solution
through the real tools and scorer:

    inspect eval reliabench/credit_desk --model reliabench/obedient

  * `careful` retries a failed read and never acts on text found in a
    document. It shows that every task is solvable, including under faults.
  * `obedient` gives up at the first failed read and carries out any
    attacker instruction it reads, wherever it appears. It is the worst case
    the defenses are measured against.

Because both are deterministic, every cell of the results table can be
derived by hand and asserted in a test. What they cannot tell you is how
well a defense works on a real model: `obedient` ignores spotlighting by
construction, for example. Their numbers validate the harness, not the
defenses.
"""

from __future__ import annotations

import dataclasses
import enum
import json
import re
from collections.abc import Iterable, Sequence
from typing import Any

from inspect_ai.model import (
    ChatMessage,
    ChatMessageAssistant,
    ChatMessageTool,
    ChatMessageUser,
    GenerateConfig,
    ModelAPI,
    ModelOutput,
    ModelUsage,
    modelapi,
)
from inspect_ai.tool import ToolChoice, ToolInfo

from reliabench.suite import ATTACKER_GOALS, USER_TASKS, Step, UserTask

PROVIDER = "reliabench"
_INTEGER_ARGUMENTS = frozenset({"new_limit"})
_PLACEHOLDER = re.compile(r"\{(\w+)\}")
_MAX_RETRIES = 2
_CHARS_PER_TOKEN = 4
_PLANNING_MARKER = "Reply with a JSON list"


class Policy(enum.StrEnum):
    """The scripted strategies."""

    CAREFUL = "careful"
    OBEDIENT = "obedient"


@dataclasses.dataclass(frozen=True)
class Action:
    """What an agent does next: call one tool, or reply with text.

    Attributes:
      tool: Tool to call, or `None` to reply without a call.
      arguments: Arguments of the call.
      message: Text of the reply when `tool` is `None`.
    """

    tool: str | None = None
    arguments: dict[str, Any] = dataclasses.field(default_factory=dict)
    message: str = ""


@dataclasses.dataclass(frozen=True)
class _Exchange:
    tool: str
    arguments: dict[str, Any]
    text: str
    failed: bool


def _exchanges(messages: Sequence[ChatMessage]) -> list[_Exchange]:
    """Pairs each tool call with its result."""
    replies = {
        m.tool_call_id: m for m in messages if isinstance(m, ChatMessageTool)
    }
    pairs = []
    for message in messages:
        if not isinstance(message, ChatMessageAssistant):
            continue
        for call in message.tool_calls or []:
            reply = replies.get(call.id)
            if reply is None:
                continue
            failed = reply.error is not None
            pairs.append(
                _Exchange(call.function, call.arguments, reply.text, failed)
            )
    return pairs


def _typed(arguments: dict[str, str]) -> dict[str, Any]:
    """Converts rendered arguments to the types the tools declare."""
    return {
        name: int(value.replace(",", ""))
        if name in _INTEGER_ARGUMENTS
        else value
        for name, value in arguments.items()
    }


def _render(step: Step, captured: dict[str, str]) -> dict[str, Any] | None:
    """Fills a step's placeholders, or returns `None` if a value is missing."""
    rendered = {}
    for name, template in step.arguments.items():
        missing = [
            v for v in _PLACEHOLDER.findall(template) if v not in captured
        ]
        if missing:
            return None
        rendered[name] = template.format(**captured)
    return _typed(rendered)


def _guard(step: Step, captured: dict[str, str]) -> bool | None:
    """Evaluates a step's guard, or returns `None` if it cannot be."""
    if step.when is None:
        return True
    left, operator, right = step.when
    if left not in captured or right not in captured:
        return None
    a, b = float(captured[left]), float(captured[right])
    return a > b if operator == ">" else a <= b


def _is_valid_result(exchange: _Exchange) -> bool:
    """Whether a result is usable: no tool error, and well-formed JSON."""
    if exchange.failed:
        return False
    if not exchange.text.lstrip().startswith("{"):
        return True
    try:
        json.loads(exchange.text)
    except json.JSONDecodeError:
        return False
    return True


def _fail(reason: str) -> Action:
    return Action("submit", {"answer": f"FAILED: {reason}"})


def _find_task(text: str) -> UserTask:
    for candidate in USER_TASKS:
        if candidate.prompt in text:
            return candidate
    raise ValueError("not a credit-desk request")


def next_action(
    policy: Policy, messages: Sequence[ChatMessage], tools: Iterable[str]
) -> Action:
    """Decides a scripted agent's next step from the conversation so far.

    The function is pure: the agent keeps no state between calls.

    Args:
      policy: The strategy to follow.
      messages: The conversation.
      tools: Names of the tools available in this conversation.

    Returns:
      The next tool call, or a text reply.
    """
    available = set(tools)
    request = next(m.text for m in messages if isinstance(m, ChatMessageUser))
    user_task = _find_task(request)
    if _PLANNING_MARKER in request:
        return Action(message=json.dumps(list(user_task.required_tools)))

    history = _exchanges(messages)
    if policy is Policy.OBEDIENT:
        seen = "\n".join(e.text for e in history if not e.failed)
        for goal in ATTACKER_GOALS:
            wanted = _typed(goal.action.arguments)
            done = any(
                e.tool == goal.action.tool and e.arguments == wanted
                for e in history
            )
            if (
                goal.instruction in seen
                and not done
                and goal.action.tool in available
            ):
                return Action(goal.action.tool, wanted)

    attacker_calls = [
        (goal.action.tool, _typed(goal.action.arguments))
        for goal in ATTACKER_GOALS
    ]
    remaining = [
        e for e in history if (e.tool, e.arguments) not in attacker_calls
    ]
    captured: dict[str, str] = {}
    retries = _MAX_RETRIES if policy is Policy.CAREFUL else 0
    for step in user_task.solution:
        allowed = _guard(step, captured)
        if allowed is None:
            return _fail("a value needed for a decision could not be read")
        if not allowed:
            continue
        arguments = _render(step, captured)
        if arguments is None:
            return _fail("a value needed for this step could not be read")

        failures = 0
        while remaining and not _is_valid_result(remaining[0]):
            remaining.pop(0)
            failures += 1
        if failures > retries:
            return _fail(f"{step.tool} did not return a usable result")
        if not remaining:
            if step.tool not in available:
                return _fail(f"{step.tool} is not available")
            return Action(step.tool, arguments)
        result = remaining.pop(0)
        for name, pattern in step.capture.items():
            found = re.search(pattern, result.text)
            if found:
                captured[name] = found.group(1)
    return Action(message="Done.")


@modelapi(name=PROVIDER)
class ReferenceAgentAPI(ModelAPI):
    """Inspect model provider that serves the scripted agents.

    The model name selects the policy: `reliabench/careful` or
    `reliabench/obedient`.
    """

    def __init__(
        self,
        model_name: str,
        base_url: str | None = None,
        api_key: str | None = None,
        config: GenerateConfig = GenerateConfig(),  # noqa: B008
        **model_args: Any,
    ) -> None:
        """Creates the provider.

        Args:
          model_name: A `Policy` value.
          base_url: Unused; accepted for interface compatibility.
          api_key: Unused; accepted for interface compatibility.
          config: Generation config; unused by the scripted agents.
          **model_args: Unused; accepted for interface compatibility.

        Raises:
          ValueError: If `model_name` is not a known policy.
        """
        super().__init__(model_name, base_url, api_key, [], config)
        self._policy = Policy(model_name.split("/")[-1])

    async def generate(
        self,
        input: list[ChatMessage],
        tools: list[ToolInfo],
        tool_choice: ToolChoice,
        config: GenerateConfig,
    ) -> ModelOutput:
        """Returns the agent's next step as a model output."""
        action = next_action(self._policy, input, [t.name for t in tools])
        model = f"{PROVIDER}/{self._policy.value}"
        if action.tool is None:
            output = ModelOutput.from_content(
                model=model, content=action.message
            )
            produced = action.message
        else:
            output = ModelOutput.for_tool_call(
                model=model,
                tool_name=action.tool,
                tool_arguments=action.arguments,
            )
            produced = action.tool + json.dumps(action.arguments)
        # A character-based estimate, so that token accounting is exercised.
        # These figures are not comparable to a real tokenizer.
        input_tokens = sum(len(m.text) for m in input) // _CHARS_PER_TOKEN
        output_tokens = max(1, len(produced) // _CHARS_PER_TOKEN)
        output.usage = ModelUsage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens,
        )
        return output

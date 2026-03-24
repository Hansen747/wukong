"""AuditAgent base class — streaming agentic loop over Anthropic or OpenAI API.

Drives a tool-use conversation until the agent submits structured JSON
via the virtual ``submit_findings`` / ``submit_result`` tools, or the
maximum turn count is reached.

Supports two LLM providers:
  - "anthropic": Uses ``AsyncAnthropic`` with ``client.messages.stream()``
  - "openai":    Uses ``AsyncOpenAI``  with ``client.chat.completions.create()``
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Callable, Optional

from ..prompts.base import COMPRESSION_BRIDGE_USER_MESSAGE, COMPRESSION_FALLBACK_TEMPLATE
from ..tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Client factory
# ------------------------------------------------------------------

def create_llm_client(provider: str, api_key: str | None, base_url: str | None) -> Any:
    """Create an async LLM client for the given provider."""
    if provider == "openai":
        from openai import AsyncOpenAI

        kwargs: dict[str, Any] = {}
        if api_key:
            kwargs["api_key"] = api_key
        if base_url:
            kwargs["base_url"] = base_url
        return AsyncOpenAI(**kwargs)
    else:
        from anthropic import AsyncAnthropic

        kwargs = {}
        if api_key:
            kwargs["api_key"] = api_key
        if base_url:
            kwargs["base_url"] = base_url
        return AsyncAnthropic(**kwargs)


class AuditAgent:
    """LLM Agent base class that drives a streaming tool-use loop.

    All LLM-based agents (route_mapper, auth_auditor, hardcoded_auditor,
    vuln_verifier) use this class to interact with the LLM API.

    Non-LLM agents (pecker_scanner, report_generator) do **not** use this
    class — they implement their own ``run_*`` async factory function.
    """

    # Virtual submit tool definitions (intercepted by the base class).
    # Stored in Anthropic format; converted to OpenAI format at runtime.
    _SUBMIT_TOOLS: list[dict] = [
        {
            "name": "submit_findings",
            "description": (
                "Submit your audit findings as structured JSON.  You may "
                "either pass the JSON directly via 'result_json', or first "
                "write it to a file with write_file and pass the path via "
                "'file_path'."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "result_json": {
                        "type": "string",
                        "description": "JSON string of the findings.",
                    },
                    "file_path": {
                        "type": "string",
                        "description": (
                            "Path to a JSON file previously written via "
                            "write_file.  Preferred for large outputs."
                        ),
                    },
                },
            },
        },
        {
            "name": "submit_result",
            "description": (
                "Submit the final result of your analysis as structured JSON. "
                "You may either pass the JSON directly via 'result_json', or "
                "first write it to a file with write_file and pass the path "
                "via 'file_path'."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "result_json": {
                        "type": "string",
                        "description": "JSON string of the result.",
                    },
                    "file_path": {
                        "type": "string",
                        "description": (
                            "Path to a JSON file previously written via "
                            "write_file.  Preferred for large outputs."
                        ),
                    },
                },
            },
        },
    ]

    def __init__(
        self,
        client: Any,
        model: str,
        system_prompt: str,
        tool_registry: ToolRegistry,
        name: str = "agent",
        max_turns: int = 80,
        max_tokens: int = 16384,
        provider: str = "anthropic",
        context_window_turns: int = 0,
        compression_summary_factory: Optional[Callable[[list[dict]], str]] = None,
    ) -> None:
        self.client = client
        self.model = model
        self.system_prompt = system_prompt
        self.registry = tool_registry
        self.name = name
        self.max_turns = max_turns
        self.max_tokens = max_tokens
        self.provider = provider
        self.context_window_turns = context_window_turns  # 0 = no compression
        self.compression_summary_factory = compression_summary_factory
        self._submit_fail_count = 0

    # ------------------------------------------------------------------
    # Tool format helpers
    # ------------------------------------------------------------------

    def _build_tools_anthropic(self) -> list[dict]:
        """Merge real tools with virtual submit tools — Anthropic format."""
        return self.registry.get_tools() + self._SUBMIT_TOOLS

    @staticmethod
    def _anthropic_to_openai_tool(tool: dict) -> dict:
        """Convert an Anthropic-format tool definition to OpenAI format.

        Anthropic: {"name": ..., "description": ..., "input_schema": {...}}
        OpenAI:    {"type": "function", "function": {"name": ..., "description": ..., "parameters": {...}}}
        """
        return {
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool.get("description", ""),
                "parameters": tool.get("input_schema", {"type": "object", "properties": {}}),
            },
        }

    def _build_tools_openai(self) -> list[dict]:
        """Merge real tools with virtual submit tools — OpenAI format."""
        anthropic_tools = self.registry.get_tools() + self._SUBMIT_TOOLS
        return [self._anthropic_to_openai_tool(t) for t in anthropic_tools]

    # ------------------------------------------------------------------
    # Tool execution helpers
    # ------------------------------------------------------------------

    def _handle_tool_call(
        self, name: str, args: dict
    ) -> tuple[str, Optional[dict]]:
        """Execute a tool call and return ``(result_text, extracted_data)``.

        For virtual submit tools the extracted data is a parsed dict;
        for real tools it is ``None``.
        """
        if name in ("submit_findings", "submit_result"):
            return self._handle_submit(args)

        # Real tool — delegate to registry
        result = self.registry.execute(name, args)
        return result, None

    def _handle_submit(self, args: dict) -> tuple[str, Optional[dict]]:
        """Handle a virtual submit tool call."""
        # Priority 1: file_path
        file_path = args.get("file_path", "")
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                self._submit_fail_count = 0
                return "Submitted successfully.", data
            except (json.JSONDecodeError, FileNotFoundError, IOError) as exc:
                self._submit_fail_count += 1
                return (
                    f"Error reading {file_path}: {exc}. Please fix and retry.",
                    None,
                )

        # Priority 2: result_json string
        result_json = args.get("result_json", "")
        if result_json:
            try:
                data = json.loads(result_json)
                self._submit_fail_count = 0
                return "Submitted successfully.", data
            except json.JSONDecodeError:
                pass

        # Priority 3: treat entire args dict as data (minus meta keys)
        cleaned = {
            k: v
            for k, v in args.items()
            if k not in ("file_path", "result_json")
        }
        if cleaned:
            self._submit_fail_count = 0
            return "Submitted successfully.", cleaned

        self._submit_fail_count += 1
        return (
            "Error: could not parse submission.  Please provide result_json "
            "or file_path.",
            None,
        )

    # ------------------------------------------------------------------
    # JSON extraction from free text
    # ------------------------------------------------------------------

    @staticmethod
    def _try_extract_json(text: str) -> Optional[dict]:
        """Extract a JSON object/array from *text*.

        Tries ```json ... ``` fenced blocks first, then falls back to
        matching the first ``{`` or ``[`` and parsing from there.
        """
        # Fenced code block
        m = re.search(r"```json\s*\n?(.*?)```", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except json.JSONDecodeError:
                pass

        # Raw JSON — find first { or [
        for ch, end_ch in [("{", "}"), ("[", "]")]:
            idx = text.find(ch)
            if idx == -1:
                continue
            # Walk backwards from the end to find matching close
            depth = 0
            for i in range(len(text) - 1, idx - 1, -1):
                if text[i] == end_ch:
                    depth += 1
                elif text[i] == ch:
                    depth -= 1
                if depth == 0 and i >= idx:
                    try:
                        return json.loads(text[idx : i + 1])
                    except json.JSONDecodeError:
                        break

        return None

    # ------------------------------------------------------------------
    # Context compression (sliding window)
    # ------------------------------------------------------------------

    def _build_compression_summary(
        self, dropped_msgs: list[dict], compressed_count: int
    ) -> str:
        """Build a summary string for the compressed context window.

        If *compression_summary_factory* was provided at construction, delegates
        to it (passing the about-to-be-dropped messages) so that agent-specific
        state (visited files, candidate findings, etc.) can be preserved.
        Falls back to a generic placeholder on any error or when no factory
        is configured.
        """
        if self.compression_summary_factory is not None:
            try:
                return self.compression_summary_factory(dropped_msgs)
            except Exception as exc:  # noqa: BLE001
                logger.debug(
                    "[%s] compression_summary_factory raised: %s", self.name, exc
                )
        return COMPRESSION_FALLBACK_TEMPLATE.format(compressed_count=compressed_count)

    @staticmethod
    def _find_turn_starts_openai(messages: list[dict], start: int) -> list[int]:
        """Return indices of each turn's first message (assistant) in OpenAI format.

        A turn = one assistant message + its subsequent tool-role messages.
        We scan from *start* to the end of *messages*.
        """
        turns: list[int] = []
        for i in range(start, len(messages)):
            if messages[i].get("role") == "assistant":
                turns.append(i)
        return turns

    def _compress_messages_openai(self, messages: list[dict]) -> list[dict]:
        """Apply sliding window compression to OpenAI-format messages.

        Keeps the system message (index 0), the initial user message
        (index 1), and the last ``context_window_turns`` complete turns.
        A turn = one assistant message + all its subsequent tool messages.
        Older turns are dropped and replaced with a single assistant
        summary message to preserve role alternation.
        """
        if self.context_window_turns <= 0:
            return messages  # no compression

        # Find turn boundaries (each starting with an assistant message)
        # Messages 0=system, 1=user, then turns start from index 2
        turn_starts = self._find_turn_starts_openai(messages, start=2)

        if len(turn_starts) <= self.context_window_turns:
            return messages  # not enough turns to compress

        # Keep the last N turns; the cut point is the start of the
        # (total - N)-th turn from the end
        keep_from = turn_starts[-self.context_window_turns]

        head = messages[:2]  # system + initial user
        tail = messages[keep_from:]  # recent complete turns

        compressed_count = keep_from - 2  # messages being dropped
        dropped_msgs = messages[2:keep_from]
        # Use assistant role so that head(user) -> summary(assistant) -> tail(assistant)
        # stays valid.  The next tail message is assistant which is fine
        # after this summary because OpenAI tolerates adjacent assistant msgs.
        summary_msg = {
            "role": "assistant",
            "content": self._build_compression_summary(dropped_msgs, compressed_count),
        }

        compressed = head + [summary_msg] + tail
        logger.debug(
            "[%s] context compressed: %d -> %d messages",
            self.name,
            len(messages),
            len(compressed),
        )
        return compressed

    @staticmethod
    def _find_turn_starts_anthropic(messages: list[dict], start: int) -> list[int]:
        """Return indices of each turn's first message (assistant) in Anthropic format.

        A turn = one assistant message + one subsequent user message
        (which carries tool_result content).  We scan from *start*.
        """
        turns: list[int] = []
        for i in range(start, len(messages)):
            if messages[i].get("role") == "assistant":
                turns.append(i)
        return turns

    def _compress_messages_anthropic(self, messages: list[dict]) -> list[dict]:
        """Apply sliding window compression to Anthropic-format messages.

        Keeps the initial user message (index 0) and the last
        ``context_window_turns`` complete turns.  System prompt is passed
        separately in Anthropic API, so it's not in the messages list.

        A turn = one assistant message + one subsequent user message
        (carrying tool_result).  The summary uses ``assistant`` role so
        that the sequence stays: user(head) -> assistant(summary) ->
        assistant(tail) or user(tail), both of which Anthropic accepts
        after we ensure the tail starts at a valid turn boundary.
        """
        if self.context_window_turns <= 0:
            return messages  # no compression

        # Find turn boundaries starting after the initial user message
        turn_starts = self._find_turn_starts_anthropic(messages, start=1)

        if len(turn_starts) <= self.context_window_turns:
            return messages  # not enough turns to compress

        # Keep the last N turns
        keep_from = turn_starts[-self.context_window_turns]

        head = messages[:1]  # initial user message
        tail = messages[keep_from:]  # recent complete turns

        compressed_count = keep_from - 1  # messages being dropped
        dropped_msgs = messages[1:keep_from]
        # Use assistant role to maintain user/assistant alternation:
        # head[-1] is user -> summary is assistant -> tail[0] is assistant
        # Two adjacent assistants would violate Anthropic rules, but
        # tail[0] is guaranteed to be assistant (that's how turn_starts
        # works), so we must ensure we don't break alternation.
        # Solution: the summary acts as the assistant reply to the head
        # user message, and tail starts with assistant which then has
        # its own user(tool_result) after it — so we need to check if
        # tail[0] is assistant.  If so, we fold the summary into the
        # beginning of that assistant content.  Otherwise just insert.
        summary_text = self._build_compression_summary(dropped_msgs, compressed_count)

        # tail[0] is always assistant (from turn_starts), so insert
        # a standalone assistant summary before it to satisfy
        # user -> assistant alternation, then merge adjacent assistants.
        # Simplest correct approach: insert an assistant+user pair as bridge.
        summary_assistant = {
            "role": "assistant",
            "content": [{"type": "text", "text": summary_text}],
        }
        summary_user = {
            "role": "user",
            "content": [{"type": "text", "text": COMPRESSION_BRIDGE_USER_MESSAGE}],
        }

        compressed = head + [summary_assistant, summary_user] + tail
        logger.debug(
            "[%s] context compressed: %d -> %d messages",
            self.name,
            len(messages),
            len(compressed),
        )
        return compressed

    # ------------------------------------------------------------------
    # Provider-specific agentic loops
    # ------------------------------------------------------------------

    async def run(self, user_message: str) -> dict:
        """Dispatch to the correct provider loop."""
        if self.provider == "openai":
            return await self._run_openai(user_message)
        else:
            return await self._run_anthropic(user_message)

    # ------------------------------------------------------------------
    # Anthropic agentic loop
    # ------------------------------------------------------------------

    async def _run_anthropic(self, user_message: str) -> dict:
        """Run the agentic loop using Anthropic streaming API."""
        messages: list[dict] = [{"role": "user", "content": user_message}]
        tools = self._build_tools_anthropic()
        last_text = ""

        for turn in range(1, self.max_turns + 1 if self.max_turns else 10000):
            logger.info("[%s] turn %d (anthropic)", self.name, turn)

            # Apply sliding window compression if configured
            messages = self._compress_messages_anthropic(messages)

            try:
                async with self.client.messages.stream(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    system=self.system_prompt,
                    messages=messages,
                    tools=tools,
                ) as stream:
                    response = await stream.get_final_message()
            except Exception as exc:
                logger.error("[%s] API error: %s", self.name, exc)
                return {"error": str(exc)}

            text_parts: list[str] = []
            tool_uses: list[dict] = []

            for block in response.content:
                if block.type == "text":
                    text_parts.append(block.text)
                elif block.type == "tool_use":
                    tool_uses.append(
                        {"id": block.id, "name": block.name, "input": block.input}
                    )

            combined_text = "\n".join(text_parts)
            if combined_text:
                last_text = combined_text
                logger.debug("[%s] text: %s", self.name, combined_text[:300])

            if not tool_uses:
                extracted = self._try_extract_json(combined_text)
                if extracted is not None:
                    return extracted
                return {"raw_text": last_text}

            messages.append({"role": "assistant", "content": response.content})

            tool_results: list[dict] = []
            submitted_data: Optional[dict] = None

            for tc in tool_uses:
                result_text, data = self._handle_tool_call(tc["name"], tc["input"])
                logger.info(
                    "[%s] tool %s -> %s",
                    self.name,
                    tc["name"],
                    result_text[:200] if result_text else "(empty)",
                )

                if data is not None:
                    submitted_data = data

                if len(result_text) > 30000:
                    result_text = result_text[:30000] + "\n... (truncated)"

                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tc["id"],
                        "content": result_text,
                    }
                )

            messages.append({"role": "user", "content": tool_results})

            if submitted_data is not None:
                return submitted_data

            if self._submit_fail_count >= 3:
                logger.warning(
                    "[%s] 3 consecutive submit failures — accepting raw text",
                    self.name,
                )
                extracted = self._try_extract_json(last_text)
                return extracted if extracted is not None else {"raw_text": last_text}

        logger.warning("[%s] max turns (%d) reached", self.name, self.max_turns)
        extracted = self._try_extract_json(last_text)
        return extracted if extracted is not None else {"raw_text": last_text}

    # ------------------------------------------------------------------
    # OpenAI agentic loop
    # ------------------------------------------------------------------

    async def _run_openai(self, user_message: str) -> dict:
        """Run the agentic loop using OpenAI chat completions API."""
        messages: list[dict] = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": user_message},
        ]
        tools = self._build_tools_openai()
        last_text = ""

        for turn in range(1, self.max_turns + 1 if self.max_turns else 10000):
            logger.info("[%s] turn %d (openai)", self.name, turn)

            # Apply sliding window compression if configured
            messages = self._compress_messages_openai(messages)

            try:
                response = await self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    tools=tools if tools else None,
                    max_tokens=self.max_tokens,
                )
            except Exception as exc:
                logger.error("[%s] API error: %s", self.name, exc)
                return {"error": str(exc)}

            choice = response.choices[0]
            message = choice.message

            # Collect text content
            combined_text = message.content or ""
            if combined_text:
                last_text = combined_text
                logger.debug("[%s] text: %s", self.name, combined_text[:300])

            # Collect tool calls
            tool_calls = message.tool_calls or []

            if not tool_calls:
                # No tool calls — try extract from text
                extracted = self._try_extract_json(combined_text)
                if extracted is not None:
                    return extracted
                return {"raw_text": last_text}

            # Append the assistant message (with tool_calls) to history
            messages.append(message.model_dump())

            submitted_data: Optional[dict] = None

            for tc in tool_calls:
                func = tc.function
                try:
                    args = json.loads(func.arguments) if func.arguments else {}
                except json.JSONDecodeError:
                    args = {}

                result_text, data = self._handle_tool_call(func.name, args)
                logger.info(
                    "[%s] tool %s -> %s",
                    self.name,
                    func.name,
                    result_text[:200] if result_text else "(empty)",
                )

                if data is not None:
                    submitted_data = data

                if len(result_text) > 30000:
                    result_text = result_text[:30000] + "\n... (truncated)"

                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": result_text,
                    }
                )

            if submitted_data is not None:
                return submitted_data

            if self._submit_fail_count >= 3:
                logger.warning(
                    "[%s] 3 consecutive submit failures — accepting raw text",
                    self.name,
                )
                extracted = self._try_extract_json(last_text)
                return extracted if extracted is not None else {"raw_text": last_text}

        logger.warning("[%s] max turns (%d) reached", self.name, self.max_turns)
        extracted = self._try_extract_json(last_text)
        return extracted if extracted is not None else {"raw_text": last_text}

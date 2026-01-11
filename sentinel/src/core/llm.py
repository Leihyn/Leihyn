"""
Claude API wrapper with tool support, caching, extended thinking, and cost tracking.
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

import anthropic
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

console = Console()

# Pricing per million tokens (as of Jan 2025)
# Extended thinking tokens are charged at different rates
PRICING = {
    "claude-sonnet-4-20250514": {
        "input": 3.0,
        "output": 15.0,
        "thinking": 3.0,  # Thinking tokens at input rate
    },
    "claude-opus-4-20250514": {
        "input": 15.0,
        "output": 75.0,
        "thinking": 15.0,
    },
    "claude-3-5-haiku-20241022": {
        "input": 0.80,
        "output": 4.0,
        "thinking": 0.80,
    },
}


@dataclass
class LLMResponse:
    """Response from the LLM."""
    content: str
    tool_calls: list[dict]
    stop_reason: str
    input_tokens: int
    output_tokens: int
    cost: float
    # Extended thinking fields
    thinking: str = ""
    thinking_tokens: int = 0


@dataclass
class Tool:
    """Tool definition for the LLM."""
    name: str
    description: str
    input_schema: dict
    handler: Callable[[dict], Any]


class LLMClient:
    """
    Wrapper around Claude API with:
    - Tool execution loop
    - Response caching
    - Cost tracking
    - Retry logic
    - Extended thinking (ultrathink) support
    """

    def __init__(
        self,
        model: str = "claude-sonnet-4-20250514",
        cache_dir: Optional[Path] = None,
        enable_cache: bool = True,
        max_retries: int = 3,
        default_thinking_budget: int = 10000,
    ):
        self.client = anthropic.Anthropic()
        self.model = model
        self.cache_dir = cache_dir or Path(".cache/llm")
        self.enable_cache = enable_cache
        self.max_retries = max_retries
        self.default_thinking_budget = default_thinking_budget

        # Stats
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_thinking_tokens = 0
        self.total_cost = 0.0
        self.cache_hits = 0

        # Create cache directory
        if enable_cache:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_cache_key(self, messages: list[dict], system: str, tools: list[dict]) -> str:
        """Generate a cache key for the request."""
        content = json.dumps({"messages": messages, "system": system, "tools": tools}, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _get_cached_response(self, cache_key: str) -> Optional[dict]:
        """Try to get a cached response."""
        if not self.enable_cache:
            return None
        cache_file = self.cache_dir / f"{cache_key}.json"
        if cache_file.exists():
            self.cache_hits += 1
            return json.loads(cache_file.read_text())
        return None

    def _save_to_cache(self, cache_key: str, response: dict) -> None:
        """Save a response to cache."""
        if not self.enable_cache:
            return
        cache_file = self.cache_dir / f"{cache_key}.json"
        cache_file.write_text(json.dumps(response))

    def _calculate_cost(
        self, input_tokens: int, output_tokens: int, thinking_tokens: int = 0
    ) -> float:
        """Calculate the cost of a request including thinking tokens."""
        pricing = PRICING.get(self.model, {"input": 3.0, "output": 15.0, "thinking": 3.0})
        input_cost = (input_tokens / 1_000_000) * pricing["input"]
        output_cost = (output_tokens / 1_000_000) * pricing["output"]
        thinking_cost = (thinking_tokens / 1_000_000) * pricing.get("thinking", pricing["input"])
        return input_cost + output_cost + thinking_cost

    def chat(
        self,
        messages: list[dict],
        system: str = "",
        tools: Optional[list[Tool]] = None,
        max_tokens: int = 4096,
        temperature: float = 0.0,
        extended_thinking: bool = False,
        thinking_budget: Optional[int] = None,
        stream_thinking: bool = False,
    ) -> LLMResponse:
        """
        Send a chat request to Claude.

        Args:
            messages: Conversation messages
            system: System prompt
            tools: Available tools
            max_tokens: Maximum output tokens
            temperature: Sampling temperature (ignored if extended_thinking=True)
            extended_thinking: Enable extended thinking (ultrathink) mode
            thinking_budget: Token budget for thinking (default: 10000)
            stream_thinking: Stream thinking process to console

        Returns the response without executing tools.
        """
        # Convert tools to API format
        tool_defs = []
        if tools:
            tool_defs = [
                {
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.input_schema,
                }
                for t in tools
            ]

        # Check cache (skip for extended thinking - we want fresh analysis)
        if not extended_thinking:
            cache_key = self._get_cache_key(messages, system, tool_defs)
            cached = self._get_cached_response(cache_key)
            if cached:
                return LLMResponse(**cached)
        else:
            cache_key = None

        # Build request kwargs
        kwargs = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": messages,
        }
        if system:
            kwargs["system"] = system
        if tool_defs:
            kwargs["tools"] = tool_defs

        # Extended thinking configuration
        if extended_thinking:
            budget = thinking_budget or self.default_thinking_budget
            kwargs["thinking"] = {
                "type": "enabled",
                "budget_tokens": budget,
            }
            # Temperature must be 1 for extended thinking
            kwargs["temperature"] = 1
        else:
            kwargs["temperature"] = temperature

        # Make request with retries
        last_error = None
        for attempt in range(self.max_retries):
            try:
                if extended_thinking and stream_thinking:
                    # Stream the response to show thinking in real-time
                    response = self._stream_with_thinking(**kwargs)
                else:
                    response = self.client.messages.create(**kwargs)
                break
            except anthropic.RateLimitError as e:
                last_error = e
                wait_time = 2 ** attempt
                console.print(f"[yellow]Rate limited, waiting {wait_time}s...[/yellow]")
                time.sleep(wait_time)
            except anthropic.APIError as e:
                last_error = e
                if attempt < self.max_retries - 1:
                    time.sleep(1)
                    continue
                raise
        else:
            raise last_error

        # Parse response
        content = ""
        thinking = ""
        tool_calls = []

        for block in response.content:
            if block.type == "thinking":
                thinking = block.thinking
            elif block.type == "text":
                content = block.text
            elif block.type == "tool_use":
                tool_calls.append({
                    "id": block.id,
                    "name": block.name,
                    "input": block.input,
                })

        # Calculate cost including thinking tokens
        input_tokens = response.usage.input_tokens
        output_tokens = response.usage.output_tokens
        # Extended thinking adds cache_creation_input_tokens for thinking
        thinking_tokens = getattr(response.usage, "cache_creation_input_tokens", 0)
        if hasattr(response.usage, "thinking_tokens"):
            thinking_tokens = response.usage.thinking_tokens

        cost = self._calculate_cost(input_tokens, output_tokens, thinking_tokens)

        # Update stats
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens
        self.total_thinking_tokens += thinking_tokens
        self.total_cost += cost

        result = LLMResponse(
            content=content,
            tool_calls=tool_calls,
            stop_reason=response.stop_reason,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost=cost,
            thinking=thinking,
            thinking_tokens=thinking_tokens,
        )

        # Cache the response (only if no tool calls and not extended thinking)
        if not tool_calls and cache_key:
            self._save_to_cache(cache_key, result.__dict__)

        return result

    def _stream_with_thinking(self, **kwargs) -> Any:
        """Stream response and display thinking in real-time."""
        thinking_text = Text()
        response_text = Text()

        with self.client.messages.stream(**kwargs) as stream:
            with Live(Panel(thinking_text, title="[cyan]Thinking...[/cyan]", border_style="cyan"),
                      console=console, refresh_per_second=10) as live:
                for event in stream:
                    if hasattr(event, 'type'):
                        if event.type == "content_block_delta":
                            if hasattr(event.delta, 'thinking'):
                                thinking_text.append(event.delta.thinking)
                            elif hasattr(event.delta, 'text'):
                                response_text.append(event.delta.text)

                # Final response
                response = stream.get_final_message()

        return response

    def run_agent_loop(
        self,
        initial_message: str,
        system: str,
        tools: list[Tool],
        max_iterations: int = 20,
        on_tool_call: Optional[Callable[[str, dict], None]] = None,
        extended_thinking: bool = False,
        thinking_budget: Optional[int] = None,
    ) -> tuple[str, list[dict], str]:
        """
        Run a full agent loop with tool execution.

        Returns (final_response, all_tool_results, thinking_trace)
        """
        messages = [{"role": "user", "content": initial_message}]
        tool_map = {t.name: t.handler for t in tools}
        all_tool_results = []
        all_thinking = []

        for iteration in range(max_iterations):
            response = self.chat(
                messages,
                system=system,
                tools=tools,
                extended_thinking=extended_thinking,
                thinking_budget=thinking_budget,
            )

            # Collect thinking traces
            if response.thinking:
                all_thinking.append(f"[Iteration {iteration + 1}]\n{response.thinking}")

            # If no tool calls, we're done
            if not response.tool_calls:
                return response.content, all_tool_results, "\n\n".join(all_thinking)

            # Execute tools
            tool_results = []
            for tool_call in response.tool_calls:
                tool_name = tool_call["name"]
                tool_input = tool_call["input"]

                if on_tool_call:
                    on_tool_call(tool_name, tool_input)

                if tool_name in tool_map:
                    try:
                        result = tool_map[tool_name](tool_input)
                        result_str = json.dumps(result) if not isinstance(result, str) else result
                    except Exception as e:
                        result_str = f"Error executing tool: {str(e)}"
                else:
                    result_str = f"Unknown tool: {tool_name}"

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_call["id"],
                    "content": result_str,
                })
                all_tool_results.append({
                    "tool": tool_name,
                    "input": tool_input,
                    "output": result_str,
                })

            # Add assistant message and tool results
            messages.append({"role": "assistant", "content": response.tool_calls})
            messages.append({"role": "user", "content": tool_results})

        return "Max iterations reached", all_tool_results, "\n\n".join(all_thinking)

    def ultrathink(
        self,
        prompt: str,
        system: str = "",
        thinking_budget: int = 16000,
        max_tokens: int = 8000,
        stream: bool = True,
    ) -> LLMResponse:
        """
        Convenience method for deep analysis with extended thinking.

        Optimized for security auditing and complex reasoning tasks.
        """
        return self.chat(
            messages=[{"role": "user", "content": prompt}],
            system=system,
            max_tokens=max_tokens,
            extended_thinking=True,
            thinking_budget=thinking_budget,
            stream_thinking=stream,
        )

    def get_stats(self) -> dict:
        """Get usage statistics."""
        return {
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_thinking_tokens": self.total_thinking_tokens,
            "total_cost": round(self.total_cost, 4),
            "cache_hits": self.cache_hits,
        }


# Singleton instance
_llm_client: Optional[LLMClient] = None


def get_llm_client(**kwargs) -> LLMClient:
    """Get or create the LLM client singleton."""
    global _llm_client
    if _llm_client is None:
        _llm_client = LLMClient(**kwargs)
    return _llm_client

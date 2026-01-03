#!/usr/bin/env python
"""Export detailed trace data from Langfuse."""

import os
import sys
from pathlib import Path
from datetime import datetime
import json

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from dotenv import load_dotenv
load_dotenv()

def format_duration(ms):
    """Format milliseconds to readable duration."""
    if ms < 1000:
        return f"{ms}ms"
    elif ms < 60000:
        return f"{ms/1000:.1f}s"
    else:
        return f"{ms/60000:.1f}min"

def print_trace_tree(observations, indent=0):
    """Print trace observations in tree format."""
    for obs in observations:
        prefix = "  " * indent
        obs_type = obs.get("type", "unknown")
        name = obs.get("name", "unnamed")

        # Get metrics
        duration = obs.get("endTime") and obs.get("startTime")
        if duration:
            start = datetime.fromisoformat(obs["startTime"].replace("Z", "+00:00"))
            end = datetime.fromisoformat(obs["endTime"].replace("Z", "+00:00"))
            duration_ms = (end - start).total_seconds() * 1000
            duration_str = format_duration(duration_ms)
        else:
            duration_str = "pending"

        # Type-specific icons
        icons = {
            "SPAN": "🔧",
            "GENERATION": "💬",
            "EVENT": "📌",
            "TRACE": "🔍"
        }
        icon = icons.get(obs_type, "•")

        print(f"{prefix}{icon} {obs_type}: {name} ({duration_str})")

        # Show metadata for generations (LLM calls)
        if obs_type == "GENERATION":
            model = obs.get("model", "unknown")
            usage = obs.get("usage", {})
            input_tokens = usage.get("promptTokens", 0)
            output_tokens = usage.get("completionTokens", 0)
            total_cost = usage.get("totalCost", 0)

            print(f"{prefix}  Model: {model}")
            print(f"{prefix}  Tokens: {input_tokens} in / {output_tokens} out")
            if total_cost:
                print(f"{prefix}  Cost: ${total_cost:.4f}")

        # Show output for spans (tool calls)
        if obs_type == "SPAN":
            output = obs.get("output")
            if output and isinstance(output, str) and len(output) < 200:
                print(f"{prefix}  Output: {output}")
            elif output:
                print(f"{prefix}  Output: {str(output)[:200]}...")

def main():
    try:
        from langfuse import Langfuse
    except ImportError:
        print("Error: Langfuse not installed. Install with: pip install langfuse")
        return 1

    # Get credentials from environment
    public_key = os.getenv("LANGFUSE_PUBLIC_KEY")
    secret_key = os.getenv("LANGFUSE_SECRET_KEY")
    host = os.getenv("LANGFUSE_HOST", "https://cloud.langfuse.com")

    if not public_key or not secret_key:
        print("Error: LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY must be set in .env")
        return 1

    print(f"\n{'='*80}")
    print("Extracting Langfuse Trace Data")
    print(f"{'='*80}\n")

    # Initialize Langfuse client
    langfuse = Langfuse(
        public_key=public_key,
        secret_key=secret_key,
        host=host,
    )

    # Flush to ensure all data is synced
    langfuse.flush()

    # Sessions to fetch
    sessions = [
        ("red_team_20260101_125955", "Original Scan (Pre-fix)"),
        ("red_team_20260101_184408", "Test Scan (Post-fix)"),
    ]

    try:
        for session_id, description in sessions:
            print(f"\n{'='*80}")
            print(f"Session: {session_id}")
            print(f"Description: {description}")
            print(f"{'='*80}\n")

            # Fetch traces for this session using the API
            # Note: The Python SDK uses get_traces() method
            try:
                traces_page = langfuse.fetch_traces(session_id=session_id, limit=10)

                if not traces_page.data:
                    print(f"No traces found for session {session_id}")
                    print(f"Note: Traces may take a few minutes to appear in Langfuse")
                    print(f"\nDirect link: {host}/sessions/{session_id}\n")
                    continue

                for trace in traces_page.data:
                    print(f"Trace ID: {trace.id}")
                    print(f"Name: {trace.name}")
                    print(f"Started: {trace.timestamp}")

                    # Get trace details
                    trace_data = langfuse.fetch_trace(trace.id)

                    # Calculate total metrics
                    total_tokens_in = 0
                    total_tokens_out = 0
                    total_cost = 0
                    llm_calls = 0
                    tool_calls = 0

                    for obs in trace_data.observations:
                        if obs.type == "GENERATION":
                            llm_calls += 1
                            usage = obs.usage or {}
                            total_tokens_in += usage.get("promptTokens", 0)
                            total_tokens_out += usage.get("completionTokens", 0)
                            total_cost += usage.get("totalCost", 0)
                        elif obs.type == "SPAN":
                            tool_calls += 1

                    print(f"\nMetrics:")
                    print(f"  LLM Calls: {llm_calls}")
                    print(f"  Tool Calls: {tool_calls}")
                    print(f"  Total Tokens: {total_tokens_in} in / {total_tokens_out} out")
                    print(f"  Total Cost: ${total_cost:.4f}")

                    # Duration
                    if trace_data.timestamp and hasattr(trace_data, 'endTime') and trace_data.endTime:
                        start = trace_data.timestamp
                        end = trace_data.endTime
                        duration_ms = (end - start).total_seconds() * 1000
                        print(f"  Duration: {format_duration(duration_ms)}")

                    print(f"\nTrace Tree:")
                    print_trace_tree(trace_data.observations)

                    # Export to JSON
                    output_dir = Path("data") / "langfuse_exports"
                    output_dir.mkdir(parents=True, exist_ok=True)

                    output_file = output_dir / f"{session_id}_trace.json"
                    with open(output_file, "w") as f:
                        json.dump({
                            "session_id": session_id,
                            "trace_id": trace.id,
                            "name": trace.name,
                            "timestamp": str(trace.timestamp),
                            "metrics": {
                                "llm_calls": llm_calls,
                                "tool_calls": tool_calls,
                                "total_tokens_in": total_tokens_in,
                                "total_tokens_out": total_tokens_out,
                                "total_cost": total_cost,
                            },
                            "observations": [
                                {
                                    "id": obs.id,
                                    "type": obs.type,
                                    "name": obs.name,
                                    "startTime": str(obs.startTime) if obs.startTime else None,
                                    "endTime": str(obs.endTime) if obs.endTime else None,
                                    "model": obs.model if hasattr(obs, 'model') else None,
                                    "usage": obs.usage if hasattr(obs, 'usage') else None,
                                    "output": str(obs.output)[:500] if hasattr(obs, 'output') and obs.output else None,
                                }
                                for obs in trace_data.observations
                            ]
                        }, f, indent=2)

                    print(f"\n✓ Exported to: {output_file}")

            except AttributeError as e:
                # SDK might not have fetch_traces method, provide manual instructions
                print(f"Note: Unable to fetch traces programmatically")
                print(f"This may be due to Langfuse SDK version or API limitations")
                print(f"\nView traces in the Langfuse UI:")
                print(f"  {host}/sessions/{session_id}")
                print(f"\nAlternatively, export via UI:")
                print(f"  1. Visit: {host}/sessions/{session_id}")
                print(f"  2. Click on each trace to view details")
                print(f"  3. Use browser DevTools to capture API responses")

        print(f"\n{'='*80}")
        print("Summary")
        print(f"{'='*80}\n")

        print("Langfuse Web UI Links:")
        for session_id, description in sessions:
            print(f"  {description}:")
            print(f"    {host}/sessions/{session_id}\n")

        return 0

    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()

        print(f"\n{'='*80}")
        print("Manual Access")
        print(f"{'='*80}\n")

        print("View your traces directly in the Langfuse UI:")
        for session_id, description in sessions:
            print(f"\n{description}:")
            print(f"  {host}/sessions/{session_id}")

        return 1
    finally:
        langfuse.flush()


if __name__ == "__main__":
    sys.exit(main())

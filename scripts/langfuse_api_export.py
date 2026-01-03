#!/usr/bin/env python
"""Export trace data from Langfuse using HTTP API."""

import os
import sys
from pathlib import Path
import json
import base64

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from dotenv import load_dotenv
load_dotenv()

def main():
    try:
        import requests
    except ImportError:
        print("Error: requests not installed. Install with: pip install requests")
        return 1

    # Get credentials from environment
    public_key = os.getenv("LANGFUSE_PUBLIC_KEY")
    secret_key = os.getenv("LANGFUSE_SECRET_KEY")
    host = os.getenv("LANGFUSE_HOST", "https://cloud.langfuse.com")

    if not public_key or not secret_key:
        print("Error: LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY must be set in .env")
        return 1

    print(f"\n{'='*80}")
    print("Extracting Langfuse Trace Data via HTTP API")
    print(f"{'='*80}\n")

    # Create auth header (Basic auth with public_key:secret_key)
    auth_string = f"{public_key}:{secret_key}"
    auth_bytes = auth_string.encode('ascii')
    base64_bytes = base64.b64encode(auth_bytes)
    base64_string = base64_bytes.decode('ascii')

    headers = {
        "Authorization": f"Basic {base64_string}",
        "Content-Type": "application/json"
    }

    # Sessions to fetch
    sessions = [
        ("red_team_20260101_125955", "Original Scan (Pre-fix)"),
        ("red_team_20260101_184408", "Test Scan (Post-fix)"),
    ]

    output_dir = Path("data") / "langfuse_exports"
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        for session_id, description in sessions:
            print(f"\n{'='*80}")
            print(f"Session: {session_id}")
            print(f"Description: {description}")
            print(f"{'='*80}\n")

            # Fetch traces for session
            api_url = f"{host}/api/public/traces"
            params = {
                "sessionId": session_id,
                "page": 1,
                "limit": 50
            }

            print(f"Fetching traces from: {api_url}")
            response = requests.get(api_url, headers=headers, params=params)

            if response.status_code == 401:
                print("Error: Authentication failed. Check your Langfuse credentials.")
                continue
            elif response.status_code != 200:
                print(f"Error: API returned status {response.status_code}")
                print(f"Response: {response.text}")
                continue

            data = response.json()
            traces = data.get("data", [])

            if not traces:
                print(f"No traces found for session {session_id}")
                print(f"Note: Traces may take a few minutes to appear in Langfuse")
                continue

            print(f"Found {len(traces)} trace(s)\n")

            for trace in traces:
                trace_id = trace.get("id")
                trace_name = trace.get("name")
                timestamp = trace.get("timestamp")

                print(f"Trace: {trace_name} (ID: {trace_id})")
                print(f"Time: {timestamp}")

                # Fetch detailed trace with observations
                trace_url = f"{host}/api/public/traces/{trace_id}"
                trace_response = requests.get(trace_url, headers=headers)

                if trace_response.status_code != 200:
                    print(f"  Error fetching trace details: {trace_response.status_code}")
                    continue

                trace_detail = trace_response.json()

                # Get observations (generations, spans, events)
                observations = trace_detail.get("observations", [])

                print(f"\nObservations: {len(observations)}")

                # Count by type
                generations = [o for o in observations if o.get("type") == "GENERATION"]
                spans = [o for o in observations if o.get("type") == "SPAN"]
                events = [o for o in observations if o.get("type") == "EVENT"]

                print(f"  - Generations (LLM calls): {len(generations)}")
                print(f"  - Spans (tool calls): {len(spans)}")
                print(f"  - Events: {len(events)}")

                # Calculate totals
                total_tokens_in = 0
                total_tokens_out = 0
                total_cost = 0.0

                for gen in generations:
                    usage = gen.get("usage", {})
                    total_tokens_in += usage.get("promptTokens", 0)
                    total_tokens_out += usage.get("completionTokens", 0)
                    total_cost += usage.get("totalCost", 0.0)

                print(f"\nMetrics:")
                print(f"  Total Input Tokens: {total_tokens_in:,}")
                print(f"  Total Output Tokens: {total_tokens_out:,}")
                print(f"  Total Cost: ${total_cost:.4f}")

                # Show key spans (tool executions)
                print(f"\nKey Tool Executions:")
                for span in spans[:20]:  # Show first 20
                    span_name = span.get("name", "unknown")
                    output = span.get("output", "")
                    if isinstance(output, str) and output:
                        # Truncate long outputs
                        output_preview = output[:80] + "..." if len(output) > 80 else output
                        print(f"  - {span_name}: {output_preview}")
                    else:
                        print(f"  - {span_name}")

                # Export to file
                output_file = output_dir / f"{session_id}_{trace_id}.json"
                with open(output_file, "w") as f:
                    json.dump({
                        "session_id": session_id,
                        "description": description,
                        "trace": trace_detail,
                        "summary": {
                            "trace_id": trace_id,
                            "trace_name": trace_name,
                            "timestamp": timestamp,
                            "generations": len(generations),
                            "spans": len(spans),
                            "events": len(events),
                            "total_tokens_in": total_tokens_in,
                            "total_tokens_out": total_tokens_out,
                            "total_cost": total_cost,
                        }
                    }, f, indent=2)

                print(f"\n✓ Exported to: {output_file}")

            # Also export session summary
            summary_file = output_dir / f"{session_id}_summary.json"
            with open(summary_file, "w") as f:
                json.dump({
                    "session_id": session_id,
                    "description": description,
                    "trace_count": len(traces),
                    "traces": [
                        {
                            "id": t.get("id"),
                            "name": t.get("name"),
                            "timestamp": t.get("timestamp"),
                        }
                        for t in traces
                    ]
                }, f, indent=2)

            print(f"✓ Session summary: {summary_file}\n")

        print(f"\n{'='*80}")
        print("Export Complete")
        print(f"{'='*80}\n")

        print(f"Exported trace data to: {output_dir}/")
        print("\nLangfuse Web UI Links:")
        for session_id, description in sessions:
            print(f"  {description}:")
            print(f"    {host}/sessions/{session_id}\n")

        return 0

    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

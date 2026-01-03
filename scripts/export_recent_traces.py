#!/usr/bin/env python
"""Export the most recent red team traces from Langfuse."""

import os
import sys
from pathlib import Path
import json
import base64
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from dotenv import load_dotenv
load_dotenv()

def format_duration(start_str, end_str):
    """Calculate duration between ISO timestamps."""
    if not start_str or not end_str:
        return "pending"
    try:
        start = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
        end = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
        duration_ms = (end - start).total_seconds() * 1000

        if duration_ms < 1000:
            return f"{duration_ms:.0f}ms"
        elif duration_ms < 60000:
            return f"{duration_ms/1000:.1f}s"
        else:
            return f"{duration_ms/60000:.1f}min"
    except:
        return "unknown"

def main():
    try:
        import requests
    except ImportError:
        print("Error: requests not installed. Install with: pip install requests")
        return 1

    # Get credentials
    public_key = os.getenv("LANGFUSE_PUBLIC_KEY")
    secret_key = os.getenv("LANGFUSE_SECRET_KEY")
    host = os.getenv("LANGFUSE_HOST", "https://cloud.langfuse.com")

    if not public_key or not secret_key:
        print("Error: LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY must be set")
        return 1

    print(f"\n{'='*80}")
    print("Exporting Recent Red Team Agent Traces")
    print(f"{'='*80}\n")

    # Create auth header
    auth_string = f"{public_key}:{secret_key}"
    base64_string = base64.b64encode(auth_string.encode('ascii')).decode('ascii')

    headers = {
        "Authorization": f"Basic {base64_string}",
        "Content-Type": "application/json"
    }

    try:
        # Fetch traces with name "scan" (our main trace)
        api_url = f"{host}/api/public/traces"
        params = {
            "page": 1,
            "limit": 50,
            "name": "scan"  # Filter for our scan traces
        }

        print(f"Fetching scan traces...\n")
        response = requests.get(api_url, headers=headers, params=params)

        if response.status_code != 200:
            print(f"Error: API returned status {response.status_code}")
            # Try without filter
            print("Trying to fetch all recent traces...")
            params = {"page": 1, "limit": 50}
            response = requests.get(api_url, headers=headers, params=params)

        data = response.json()
        all_traces = data.get("data", [])

        # Filter for today's scans
        today_traces = [t for t in all_traces if "2026-01-01" in t.get("timestamp", "")]
        scan_traces = [t for t in today_traces if t.get("name") == "scan"]

        print(f"Found {len(scan_traces)} scan traces from today\n")

        if not scan_traces:
            print("No scan traces found. Showing all today's traces:")
            for trace in today_traces[:20]:
                print(f"  - {trace.get('name')} at {trace.get('timestamp')}")
            return 0

        output_dir = Path("data") / "langfuse_exports"
        output_dir.mkdir(parents=True, exist_ok=True)

        for idx, trace in enumerate(scan_traces, 1):
            trace_id = trace.get("id")
            timestamp = trace.get("timestamp", "")

            print(f"\n{'='*80}")
            print(f"Scan #{idx}")
            print(f"{'='*80}\n")

            print(f"Trace ID: {trace_id}")
            print(f"Timestamp: {timestamp}")

            # Fetch full trace details
            trace_url = f"{host}/api/public/traces/{trace_id}"
            trace_response = requests.get(trace_url, headers=headers)

            if trace_response.status_code != 200:
                print(f"Error fetching trace details")
                continue

            trace_detail = trace_response.json()

            # Get observations
            observations = trace_detail.get("observations", [])

            # Organize by type
            generations = [o for o in observations if o.get("type") == "GENERATION"]
            spans = [o for o in observations if o.get("type") == "SPAN"]

            print(f"\nObservations:")
            print(f"  LLM Generations: {len(generations)}")
            print(f"  Spans (operations): {len(spans)}")

            # Calculate metrics
            total_input_tokens = 0
            total_output_tokens = 0
            total_cost = 0.0

            print(f"\nLLM Calls:")
            for gen in generations:
                gen_name = gen.get("name", "unknown")
                model = gen.get("model", "unknown")
                usage = gen.get("usage", {})

                input_tokens = usage.get("promptTokens", 0)
                output_tokens = usage.get("completionTokens", 0)
                cost = usage.get("totalCost", 0.0)

                total_input_tokens += input_tokens
                total_output_tokens += output_tokens
                total_cost += cost

                start_time = gen.get("startTime")
                end_time = gen.get("endTime")
                duration = format_duration(start_time, end_time)

                print(f"  - {gen_name}")
                print(f"    Model: {model}")
                print(f"    Tokens: {input_tokens:,} in / {output_tokens:,} out")
                print(f"    Cost: ${cost:.4f}")
                print(f"    Duration: {duration}")

            print(f"\nTotal Metrics:")
            print(f"  Input Tokens: {total_input_tokens:,}")
            print(f"  Output Tokens: {total_output_tokens:,}")
            print(f"  Total Cost: ${total_cost:.4f}")

            # Show key spans
            print(f"\nKey Operations:")

            # Group spans by name
            span_groups = {}
            for span in spans:
                name = span.get("name", "unknown")
                if name not in span_groups:
                    span_groups[name] = []
                span_groups[name].append(span)

            for span_name, span_list in sorted(span_groups.items()):
                print(f"  {span_name}: {len(span_list)} execution(s)")

                for span in span_list[:3]:  # Show first 3
                    start_time = span.get("startTime")
                    end_time = span.get("endTime")
                    duration = format_duration(start_time, end_time)
                    output = span.get("output")

                    if output and isinstance(output, str):
                        output_preview = output[:60] + "..." if len(output) > 60 else output
                        print(f"    - {duration}: {output_preview}")
                    else:
                        print(f"    - {duration}")

            # Export full data
            output_file = output_dir / f"scan_trace_{timestamp.replace(':', '-').split('.')[0]}.json"
            with open(output_file, "w") as f:
                json.dump({
                    "trace_id": trace_id,
                    "timestamp": timestamp,
                    "summary": {
                        "llm_generations": len(generations),
                        "spans": len(spans),
                        "total_input_tokens": total_input_tokens,
                        "total_output_tokens": total_output_tokens,
                        "total_cost": total_cost,
                    },
                    "full_trace": trace_detail
                }, f, indent=2)

            print(f"\n✓ Exported to: {output_file}")

        print(f"\n{'='*80}")
        print("Export Complete")
        print(f"{'='*80}\n")

        print(f"Exported {len(scan_traces)} scan trace(s) to: {output_dir}/")
        print(f"\nView all traces in Langfuse UI: {host}/traces\n")

        return 0

    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

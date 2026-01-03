#!/usr/bin/env python
"""List all sessions and traces from Langfuse."""

import os
import sys
from pathlib import Path
import json
import base64
from datetime import datetime, timedelta

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
    print("Listing All Recent Langfuse Traces")
    print(f"{'='*80}\n")

    # Create auth header
    auth_string = f"{public_key}:{secret_key}"
    auth_bytes = auth_string.encode('ascii')
    base64_bytes = base64.b64encode(auth_bytes)
    base64_string = base64_bytes.decode('ascii')

    headers = {
        "Authorization": f"Basic {base64_string}",
        "Content-Type": "application/json"
    }

    try:
        # Fetch all traces (not filtered by session)
        api_url = f"{host}/api/public/traces"
        params = {
            "page": 1,
            "limit": 100  # Get last 100 traces
        }

        print(f"Fetching traces from: {api_url}\n")
        response = requests.get(api_url, headers=headers, params=params)

        if response.status_code == 401:
            print("Error: Authentication failed. Check your Langfuse credentials.")
            return 1
        elif response.status_code != 200:
            print(f"Error: API returned status {response.status_code}")
            print(f"Response: {response.text}")
            return 1

        data = response.json()
        traces = data.get("data", [])
        total_items = data.get("meta", {}).get("totalItems", 0)

        print(f"Found {len(traces)} traces (total: {total_items})\n")

        if not traces:
            print("No traces found in your Langfuse project")
            print("\nPossible reasons:")
            print("  1. Traces haven't been flushed yet (run: langfuse.flush())")
            print("  2. No scans have been run with Langfuse enabled")
            print("  3. API credentials don't have access to this project")
            return 0

        # Group by session
        sessions = {}
        traces_without_session = []

        for trace in traces:
            session_id = trace.get("sessionId")
            if session_id:
                if session_id not in sessions:
                    sessions[session_id] = []
                sessions[session_id].append(trace)
            else:
                traces_without_session.append(trace)

        print(f"Sessions found: {len(sessions)}")
        print(f"Traces without session: {len(traces_without_session)}\n")

        print(f"{'='*80}")
        print("Sessions")
        print(f"{'='*80}\n")

        for session_id, session_traces in sorted(sessions.items()):
            print(f"Session: {session_id}")
            print(f"  Traces: {len(session_traces)}")
            print(f"  Link: {host}/sessions/{session_id}")

            for trace in session_traces[:5]:  # Show first 5 traces
                trace_name = trace.get("name", "unnamed")
                trace_id = trace.get("id")
                timestamp = trace.get("timestamp", "")
                print(f"    - {trace_name} ({trace_id[:8]}...) at {timestamp}")

            if len(session_traces) > 5:
                print(f"    ... and {len(session_traces) - 5} more traces")

            print()

        if traces_without_session:
            print(f"{'='*80}")
            print("Traces Without Session")
            print(f"{'='*80}\n")

            for trace in traces_without_session[:10]:
                trace_name = trace.get("name", "unnamed")
                trace_id = trace.get("id")
                timestamp = trace.get("timestamp", "")
                print(f"  - {trace_name} ({trace_id[:8]}...) at {timestamp}")

            if len(traces_without_session) > 10:
                print(f"  ... and {len(traces_without_session) - 10} more\n")

        # Export session list
        output_dir = Path("data") / "langfuse_exports"
        output_dir.mkdir(parents=True, exist_ok=True)

        output_file = output_dir / "all_sessions.json"
        with open(output_file, "w") as f:
            json.dump({
                "fetched_at": datetime.now().isoformat(),
                "total_traces": total_items,
                "sessions": {
                    session_id: {
                        "trace_count": len(session_traces),
                        "traces": [
                            {
                                "id": t.get("id"),
                                "name": t.get("name"),
                                "timestamp": t.get("timestamp"),
                            }
                            for t in session_traces
                        ]
                    }
                    for session_id, session_traces in sessions.items()
                },
                "traces_without_session": len(traces_without_session)
            }, f, indent=2)

        print(f"\n✓ Session list exported to: {output_file}\n")

        # Check for our specific sessions
        print(f"{'='*80}")
        print("Looking for Red Team Agent Sessions")
        print(f"{'='*80}\n")

        target_sessions = [
            "red_team_20260101_125955",
            "red_team_20260101_184408",
        ]

        for target in target_sessions:
            if target in sessions:
                print(f"✓ Found: {target} ({len(sessions[target])} traces)")
                print(f"  Link: {host}/sessions/{target}")
            else:
                print(f"✗ Not found: {target}")
                print(f"  Expected link: {host}/sessions/{target}")

        print(f"\n{'='*80}")
        print("Summary")
        print(f"{'='*80}\n")

        print(f"Total sessions: {len(sessions)}")
        print(f"Total traces: {total_items}")
        print(f"\nView all traces: {host}/traces")
        print(f"View sessions: {host}/sessions\n")

        return 0

    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

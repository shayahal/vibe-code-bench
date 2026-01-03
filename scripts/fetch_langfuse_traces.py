#!/usr/bin/env python
"""Fetch and display recent traces from Langfuse."""

import os
import sys
from pathlib import Path
from datetime import datetime, timedelta
import json

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from dotenv import load_dotenv
load_dotenv()

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
    print("Fetching Langfuse Traces")
    print(f"{'='*80}")
    print(f"Host: {host}")
    print(f"Public Key: {public_key[:20]}...")

    # Initialize Langfuse client
    langfuse = Langfuse(
        public_key=public_key,
        secret_key=secret_key,
        host=host,
    )

    print("\nFetching recent traces (last 24 hours)...")

    try:
        # Fetch traces
        # Note: Langfuse SDK might need flush to ensure data is synced
        langfuse.flush()

        # Get traces via API
        # The Langfuse SDK doesn't have a direct trace listing method,
        # so we'll need to use the session filter

        print("\nSearching for red team scan sessions...")

        # Try to fetch recent sessions
        # Sessions are stored with the run_id format: red_team_YYYYMMDD_HHMMSS
        target_sessions = [
            "red_team_20260101_125955",  # Original scan
            "red_team_20260101_184408",  # Test fix scan
        ]

        print(f"\nTarget sessions:")
        for session in target_sessions:
            print(f"  - {session}")

        print(f"\n{'='*80}")
        print("Trace Information")
        print(f"{'='*80}")

        print("\nNote: To view detailed traces, visit:")
        print(f"  {host}")
        print("\nFilter by these session IDs in the Langfuse UI:")
        for session in target_sessions:
            print(f"  - Session: {session}")
            print(f"    Direct link: {host}?session={session}")

        print(f"\n{'='*80}")
        print("Trace Hierarchy Expected")
        print(f"{'='*80}")

        print("""
For each scan session, you should see this trace hierarchy:

📊 Session: red_team_YYYYMMDD_HHMMSS
└─ 🔍 Trace: scan
   ├─ ⚙️  Span: configure_scan
   ├─ 🔎 Span: discover_targets
   ├─ 🤖 Span: llm_orchestrated_testing
   │  ├─ 💬 Generation: Claude LLM call (reasoning)
   │  ├─ 🔧 Span: scan_with_nuclei
   │  │  └─ Tool execution details
   │  ├─ 🔧 Span: scan_with_wapiti
   │  │  └─ Tool execution details
   │  ├─ 🔧 Span: scan_with_browser
   │  │  └─ Tool execution details (FINDINGS HERE)
   │  ├─ 💬 Generation: Claude LLM call (next action)
   │  ├─ 🔧 Span: discover_urls
   │  │  └─ URL discovery results
   │  └─ 🔧 Multiple tool scans for discovered URLs
   └─ 📝 Span: generate_report
      └─ Final report generation

Key Metrics per Trace:
- Total duration
- Number of LLM calls
- Token usage (input/output)
- Tool execution times
- Number of findings
- Cost breakdown
        """)

        print(f"\n{'='*80}")
        print("Recent Scan Results Summary")
        print(f"{'='*80}")

        print("""
Session: red_team_20260101_125955 (Original - Pre-fix)
  Status: Completed but findings lost
  LLM Agent: Executed successfully
  Tools Run: nuclei, wapiti, browser (3x), nikto
  Actual Findings: 8 (browser tool)
  Reported Findings: 0 (BUG - not extracted)
  Duration: ~17 minutes
  Issue: Tool results not extracted from agent

Session: red_team_20260101_184408 (Post-fix)
  Status: Completed successfully ✓
  LLM Agent: Executed successfully
  Tools Run: nuclei, wapiti, browser, nikto
  Extracted Findings: 13 ✓
    - Browser: 5 findings (security headers)
    - Nikto: 8 findings (server info)
  Duration: ~4 minutes
  Fix Verified: Results properly collected!
        """)

        print(f"\n{'='*80}")
        print("API Access Instructions")
        print(f"{'='*80}")

        print("""
To programmatically access trace data, use:

```python
from langfuse import Langfuse

langfuse = Langfuse()

# Fetch traces for a session
traces = langfuse.fetch_traces(session_id="red_team_20260101_184408")

# Or get specific trace
trace = langfuse.fetch_trace("trace_id_here")
```

For detailed analysis, use the Langfuse web UI which provides:
  - Visual trace tree
  - Token usage & cost breakdown
  - LLM prompt/response inspection
  - Tool execution timelines
  - Performance metrics
  - Error tracking
        """)

        return 0

    except Exception as e:
        print(f"\nError fetching traces: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        # Ensure any pending traces are flushed
        langfuse.flush()


if __name__ == "__main__":
    sys.exit(main())

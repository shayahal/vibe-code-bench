"""
Report generation for security test results.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates security reports from test results."""
    
    def __init__(self, target_url: str, test_results: List[Dict[str, Any]], run_dir: Optional[Path] = None):
        """
        Initialize the report generator.
        
        Args:
            target_url: Target URL being tested
            test_results: List of test results
            run_dir: Optional run directory for saving reports
        """
        self.target_url = target_url
        self.test_results = test_results
        self.run_dir = run_dir
    
    def generate_manual_report(self) -> str:
        """Generate a manual report from test results and save JSON version."""
        vulnerable_tests = [r for r in self.test_results if r.get('is_vulnerable', False)]
        critical_tests = [r for r in vulnerable_tests if r.get('severity') == 'CRITICAL']
        high_tests = [r for r in vulnerable_tests if r.get('severity') == 'HIGH']
        
        report = f"""# Web Security Red-Teaming Report
Generated: {datetime.now().isoformat()}

## Target URL
{self.target_url}

## Executive Summary
- Total tests performed: {len(self.test_results)}
- Vulnerabilities found: {len(vulnerable_tests)}
- Critical vulnerabilities: {len(critical_tests)}
- High severity vulnerabilities: {len(high_tests)}

## Vulnerability Breakdown

### Critical Vulnerabilities ({len(critical_tests)})
"""
        for i, result in enumerate(critical_tests, 1):
            report += f"\n#### {i}. {result.get('issue', 'Unknown issue')}\n"
            report += f"- URL: {result.get('url', 'N/A')}\n"
            report += f"- Parameter: {result.get('parameter', 'N/A')}\n"
            report += f"- Payload: {result.get('payload', 'N/A')}\n"
            report += f"- Timestamp: {result.get('timestamp', 'N/A')}\n"
        
        report += f"\n### High Severity Vulnerabilities ({len(high_tests)})\n"
        for i, result in enumerate(high_tests, 1):
            report += f"\n#### {i}. {result.get('issue', 'Unknown issue')}\n"
            report += f"- URL: {result.get('url', 'N/A')}\n"
            report += f"- Parameter: {result.get('parameter', 'N/A')}\n"
            report += f"- Payload: {result.get('payload', 'N/A')}\n"
            report += f"- Timestamp: {result.get('timestamp', 'N/A')}\n"
        
        report += "\n## Detailed Test Results\n"
        for i, result in enumerate(self.test_results, 1):
            report += f"\n### Test {i}\n"
            report += f"- Type: {result.get('test_type', 'Unknown')}\n"
            report += f"- URL: {result.get('url', 'N/A')}\n"
            report += f"- Status: {'VULNERABLE' if result.get('is_vulnerable') else 'SAFE'}\n"
            if result.get('issue'):
                report += f"- Issue: {result['issue']}\n"
            report += f"- Timestamp: {result.get('timestamp', 'N/A')}\n"
        
        # Generate and save JSON report
        if self.run_dir:
            json_report = self.generate_json_report()
            json_path = self.run_dir / "reports" / "red_team_report.json"
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(json_report, f, indent=2, ensure_ascii=False)
            logger.info(f"JSON report saved to: {json_path}")
        
        return report
    
    def generate_json_report(self) -> Dict[str, Any]:
        """Generate a JSON report from test results."""
        vulnerable_tests = [r for r in self.test_results if r.get('is_vulnerable', False)]
        critical_tests = [r for r in vulnerable_tests if r.get('severity') == 'CRITICAL']
        high_tests = [r for r in vulnerable_tests if r.get('severity') == 'HIGH']
        medium_tests = [r for r in vulnerable_tests if r.get('severity') == 'MEDIUM']
        low_tests = [r for r in vulnerable_tests if r.get('severity') == 'LOW']
        info_tests = [r for r in vulnerable_tests if r.get('severity') == 'INFO']
        safe_tests = [r for r in self.test_results if not r.get('is_vulnerable', False)]
        
        # Parse domain from URL
        parsed_url = urlparse(self.target_url)
        domain = parsed_url.netloc or parsed_url.path
        
        # Count tests by type
        tests_by_type = {}
        for result in self.test_results:
            test_type = result.get('test_type', 'unknown')
            tests_by_type[test_type] = tests_by_type.get(test_type, 0) + 1
        
        # Calculate vulnerability rate
        vulnerability_rate = (len(vulnerable_tests) / len(self.test_results) * 100) if self.test_results else 0.0
        
        # Calculate average severity score (CRITICAL=5, HIGH=4, MEDIUM=3, LOW=2, INFO=1)
        severity_scores = {
            'CRITICAL': 5,
            'HIGH': 4,
            'MEDIUM': 3,
            'LOW': 2,
            'INFO': 1
        }
        severity_values = [severity_scores.get(r.get('severity', ''), 0) for r in vulnerable_tests]
        avg_severity_score = sum(severity_values) / len(severity_values) if severity_values else 0.0
        
        # Format vulnerabilities by severity
        def format_vulnerability(result: Dict[str, Any], vuln_id: str) -> Dict[str, Any]:
            formatted = {
                "id": vuln_id,
                "test_id": self.test_results.index(result) + 1,
                "test_type": result.get('test_type', 'unknown'),
                "url": result.get('url', 'N/A'),
                "issue": result.get('issue', 'Unknown issue'),
                "severity": result.get('severity', 'UNKNOWN'),
                "status": "VULNERABLE" if result.get('is_vulnerable') else "SAFE",
                "timestamp": result.get('timestamp', 'N/A')
            }
            
            # Add optional fields if present
            if result.get('parameter'):
                formatted["parameter"] = result['parameter']
            if result.get('payload'):
                formatted["payload"] = result['payload']
            if result.get('status_code'):
                formatted["status_code"] = result['status_code']
            
            # Add recommendation based on issue type
            issue = result.get('issue', '').lower()
            if 'x-frame-options' in issue:
                formatted["recommendation"] = "Add X-Frame-Options header to prevent clickjacking attacks"
            elif 'x-content-type-options' in issue:
                formatted["recommendation"] = "Add X-Content-Type-Options: nosniff header to prevent MIME type sniffing"
            elif 'x-xss-protection' in issue:
                formatted["recommendation"] = "Add X-XSS-Protection header (though modern browsers handle this)"
            elif 'csp' in issue or 'content-security-policy' in issue:
                formatted["recommendation"] = "Add Content-Security-Policy header to prevent XSS attacks"
            elif 'xss' in issue:
                formatted["recommendation"] = "Implement proper input validation and output encoding to prevent XSS"
            elif 'sql injection' in issue or 'sqli' in issue:
                formatted["recommendation"] = "Use parameterized queries and input validation to prevent SQL injection"
            elif 'csrf' in issue:
                formatted["recommendation"] = "Implement CSRF tokens and validate origin/referer headers"
            else:
                formatted["recommendation"] = "Review and address the security issue identified"
            
            return formatted
        
        # Format all vulnerabilities
        vuln_counter = 1
        critical_formatted = [format_vulnerability(r, f"VULN-{str(vuln_counter + i).zfill(3)}") 
                             for i, r in enumerate(critical_tests)]
        vuln_counter += len(critical_tests)
        high_formatted = [format_vulnerability(r, f"VULN-{str(vuln_counter + i).zfill(3)}") 
                         for i, r in enumerate(high_tests)]
        vuln_counter += len(high_tests)
        medium_formatted = [format_vulnerability(r, f"VULN-{str(vuln_counter + i).zfill(3)}") 
                           for i, r in enumerate(medium_tests)]
        vuln_counter += len(medium_tests)
        low_formatted = [format_vulnerability(r, f"VULN-{str(vuln_counter + i).zfill(3)}") 
                        for i, r in enumerate(low_tests)]
        vuln_counter += len(low_tests)
        info_formatted = [format_vulnerability(r, f"VULN-{str(vuln_counter + i).zfill(3)}") 
                         for i, r in enumerate(info_tests)]
        
        report = {
            "metadata": {
                "report_type": "web_security_red_team",
                "generated_at": datetime.now().isoformat(),
                "version": "1.0"
            },
            "target": {
                "url": self.target_url,
                "domain": domain
            },
            "executive_summary": {
                "total_tests_performed": len(self.test_results),
                "vulnerabilities_found": len(vulnerable_tests),
                "tests_passed": len(safe_tests),
                "tests_failed": len(vulnerable_tests),
                "severity_breakdown": {
                    "critical": len(critical_tests),
                    "high": len(high_tests),
                    "medium": len(medium_tests),
                    "low": len(low_tests),
                    "info": len(info_tests)
                }
            },
            "vulnerabilities": {
                "critical": critical_formatted,
                "high": high_formatted,
                "medium": medium_formatted,
                "low": low_formatted,
                "info": info_formatted
            },
            "test_results": self.test_results,
            "statistics": {
                "tests_by_type": tests_by_type,
                "vulnerability_rate": round(vulnerability_rate, 2),
                "average_severity_score": round(avg_severity_score, 2)
            }
        }
        
        return report
    
    def generate_detailed_action_report(self, trail_entries: List[Dict[str, Any]]) -> str:
        """
        Generate a detailed report of all agent actions during the test run.
        This includes all tool calls, decisions, timing, and execution flow.
        """
        parsed_url = urlparse(self.target_url)
        domain = parsed_url.netloc or parsed_url.path
        
        # Group trail entries by action type
        action_groups = {}
        for entry in trail_entries:
            action_type = entry.get('action_type', 'unknown')
            if action_type not in action_groups:
                action_groups[action_type] = []
            action_groups[action_type].append(entry)
        
        # Calculate timing information
        if trail_entries:
            try:
                start_time = datetime.fromisoformat(trail_entries[0]['timestamp'])
                end_time = datetime.fromisoformat(trail_entries[-1]['timestamp'])
                duration = (end_time - start_time).total_seconds()
            except (KeyError, ValueError, IndexError):
                duration = 0
        else:
            duration = 0
        
        # Count tool calls
        tool_calls = [e for e in trail_entries if e.get('action_type') == 'tool_call']
        tool_results = [e for e in trail_entries if e.get('action_type') == 'tool_result']
        
        # Count scenarios
        scenarios_started = len([e for e in trail_entries if e.get('action_type') == 'scenario_started'])
        scenarios_completed = len([e for e in trail_entries if e.get('action_type') == 'scenario_completed'])
        scenarios_failed = len([e for e in trail_entries if e.get('action_type') == 'scenario_failed'])
        
        # Build detailed report
        report = f"""# Red Team Agent - Detailed Action Report

Generated: {datetime.now().isoformat()}

## Executive Summary

- **Target URL**: {self.target_url}
- **Domain**: {domain}
- **Total Execution Time**: {duration:.2f} seconds ({duration/60:.2f} minutes)
- **Total Actions Logged**: {len(trail_entries)}
- **Tool Calls**: {len(tool_calls)}
- **Test Scenarios**: {scenarios_started} started, {scenarios_completed} completed, {scenarios_failed} failed
- **Total Tests Performed**: {len(self.test_results)}
- **Vulnerabilities Found**: {sum(1 for r in self.test_results if r.get('is_vulnerable', False))}

---

## Execution Timeline

### Run Initialization
"""
        
        # Add initialization entries
        init_entries = [e for e in trail_entries if e.get('action_type') in ['agent_initialized', 'test_suite_started', 'test_scenarios_defined', 'execution_mode_selected']]
        for entry in init_entries:
            timestamp = entry.get('timestamp', 'N/A')
            action_type = entry.get('action_type', 'unknown')
            data = entry.get('data', {})
            reasoning = entry.get('reasoning', '')
            
            report += f"\n**{timestamp}** - `{action_type}`\n"
            report += f"- **Data**: {json.dumps(data, indent=2)}\n"
            if reasoning:
                report += f"- **Reasoning**: {reasoning}\n"
        
        # Add scenario execution details
        report += "\n### Test Scenario Execution\n\n"
        
        scenario_starts = [e for e in trail_entries if e.get('action_type') == 'scenario_started']
        for scenario_entry in scenario_starts:
            scenario_num = scenario_entry.get('data', {}).get('scenario_number', '?')
            scenario_text = scenario_entry.get('data', {}).get('scenario', 'N/A')
            timestamp = scenario_entry.get('timestamp', 'N/A')
            
            report += f"\n#### Scenario {scenario_num}: {scenario_text}\n"
            report += f"**Started**: {timestamp}\n\n"
            
            # Find related actions for this scenario
            try:
                scenario_start_time = datetime.fromisoformat(timestamp)
            except ValueError:
                # Skip this scenario if timestamp is invalid
                report += f"  - **Warning**: Invalid timestamp format\n\n"
                continue
            
            # Find agent invocation
            agent_invocations = [e for e in trail_entries 
                               if e.get('action_type') == 'agent_invoked' 
                               and abs((datetime.fromisoformat(e['timestamp']) - scenario_start_time).total_seconds()) < 5]
            
            for inv in agent_invocations:
                report += f"- **Agent Invoked**: {inv.get('timestamp', 'N/A')}\n"
                report += f"  - Reasoning: {inv.get('reasoning', 'N/A')}\n"
            
            # Find tool calls during this scenario
            scenario_tool_calls = []
            scenario_tool_results = []
            
            for entry in trail_entries:
                try:
                    entry_time = datetime.fromisoformat(entry.get('timestamp', ''))
                    time_diff = (entry_time - scenario_start_time).total_seconds()
                    
                    if 0 <= time_diff <= 300:  # Within 5 minutes of scenario start
                        if entry.get('action_type') == 'tool_call':
                            scenario_tool_calls.append(entry)
                        elif entry.get('action_type') == 'tool_result':
                            scenario_tool_results.append(entry)
                except (ValueError, KeyError):
                    # Skip entries with invalid timestamps
                    continue
            
            if scenario_tool_calls:
                report += "\n**Tool Calls During This Scenario:**\n"
                for tool_call in scenario_tool_calls:
                    tool_name = tool_call.get('data', {}).get('tool', 'unknown')
                    tool_data = tool_call.get('data', {})
                    tool_timestamp = tool_call.get('timestamp', 'N/A')
                    tool_reasoning = tool_call.get('reasoning', '')
                    
                    report += f"\n- **{tool_timestamp}** - Tool: `{tool_name}`\n"
                    report += f"  - Input: {json.dumps({k: v for k, v in tool_data.items() if k != 'tool'}, indent=2)}\n"
                    if tool_reasoning:
                        report += f"  - Reasoning: {tool_reasoning}\n"
                    
                    # Find corresponding result
                    for result in scenario_tool_results:
                        result_tool = result.get('data', {}).get('tool', '')
                        if result_tool == tool_name:
                            result_data = result.get('data', {})
                            result_timestamp = result.get('timestamp', 'N/A')
                            result_reasoning = result.get('reasoning', '')
                            
                            report += f"  - **Result** ({result_timestamp}):\n"
                            # Format result data nicely
                            for key, value in result_data.items():
                                if key != 'tool':
                                    if isinstance(value, (dict, list)):
                                        report += f"    - {key}: {json.dumps(value, indent=4)}\n"
                                    else:
                                        report += f"    - {key}: {value}\n"
                            if result_reasoning:
                                report += f"    - Reasoning: {result_reasoning}\n"
                            break
            
            # Find scenario completion/failure
            scenario_completions = []
            for e in trail_entries:
                if e.get('action_type') in ['scenario_completed', 'scenario_failed']:
                    try:
                        e_time = datetime.fromisoformat(e.get('timestamp', ''))
                        time_diff = abs((e_time - scenario_start_time).total_seconds())
                        if time_diff < 300:
                            scenario_completions.append(e)
                    except (ValueError, KeyError):
                        continue
            
            for completion in scenario_completions:
                completion_type = completion.get('action_type', '')
                completion_data = completion.get('data', {})
                completion_timestamp = completion.get('timestamp', 'N/A')
                
                if completion_type == 'scenario_completed':
                    report += f"\n- **Completed**: {completion_timestamp}\n"
                    report += f"  - Success: {completion_data.get('success', 'N/A')}\n"
                elif completion_type == 'scenario_failed':
                    report += f"\n- **Failed**: {completion_timestamp}\n"
                    report += f"  - Error: {completion_data.get('error', 'N/A')}\n"
            
            report += "\n---\n"
        
        # Add tool usage statistics
        report += "\n## Tool Usage Statistics\n\n"
        
        tool_usage = {}
        for call in tool_calls:
            tool_name = call.get('data', {}).get('tool', 'unknown')
            tool_usage[tool_name] = tool_usage.get(tool_name, 0) + 1
        
        if tool_usage:
            report += "| Tool Name | Usage Count |\n"
            report += "|-----------|-------------|\n"
            for tool_name, count in sorted(tool_usage.items(), key=lambda x: x[1], reverse=True):
                report += f"| `{tool_name}` | {count} |\n"
        else:
            report += "No tools were called during this run.\n"
        
        # Add action type breakdown
        report += "\n## Action Type Breakdown\n\n"
        report += "| Action Type | Count |\n"
        report += "|--------------|-------|\n"
        for action_type, entries in sorted(action_groups.items(), key=lambda x: len(x[1]), reverse=True):
            report += f"| `{action_type}` | {len(entries)} |\n"
        
        # Add test results summary
        if self.test_results:
            report += "\n## Test Results Summary\n\n"
            vulnerable_tests = [r for r in self.test_results if r.get('is_vulnerable', False)]
            safe_tests = [r for r in self.test_results if not r.get('is_vulnerable', False)]
            
            report += f"- **Total Tests**: {len(self.test_results)}\n"
            report += f"- **Vulnerable**: {len(vulnerable_tests)}\n"
            report += f"- **Safe**: {len(safe_tests)}\n"
            
            if vulnerable_tests:
                report += "\n### Vulnerabilities Found\n\n"
                for i, test in enumerate(vulnerable_tests, 1):
                    report += f"#### Vulnerability {i}\n"
                    report += f"- **Test Type**: {test.get('test_type', 'N/A')}\n"
                    report += f"- **URL**: {test.get('url', 'N/A')}\n"
                    report += f"- **Severity**: {test.get('severity', 'N/A')}\n"
                    report += f"- **Issue**: {test.get('issue', 'N/A')}\n"
                    if test.get('parameter'):
                        report += f"- **Parameter**: {test.get('parameter')}\n"
                    if test.get('payload'):
                        report += f"- **Payload**: {test.get('payload')}\n"
                    report += f"- **Timestamp**: {test.get('timestamp', 'N/A')}\n\n"
        
        # Add complete trail entries (for debugging)
        report += "\n## Complete Action Trail\n\n"
        report += "<details>\n<summary>Click to expand complete action trail (JSON format)</summary>\n\n"
        report += "```json\n"
        report += json.dumps(trail_entries, indent=2, ensure_ascii=False)
        report += "\n```\n\n</details>\n"
        
        return report


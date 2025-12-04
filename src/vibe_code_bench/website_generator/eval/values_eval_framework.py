"""
Values Evaluation Framework for Website Builder Agent

Evaluates website builder agent against defined values/principles including:
- Code Quality (type hints, docstrings, error handling)
- Security Practices (input validation, sanitization, secure defaults)
- Ethical AI (transparency, responsible code generation, bias mitigation)
"""

import json
import inspect
import re
import ast
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Any
from datetime import datetime

# Package imports - no path manipulation needed
# If running as script, repo root is already in path via package installation


class AgentCodeInspector:
    """Uses inspect to analyze agent source code for values adherence."""
    
    def __init__(self, agent_module_path: str):
        """
        Initialize inspector with agent module.
        
        Args:
            agent_module_path: Path to agent module (e.g., 'website_generator.agent')
        """
        self.agent_module_path = agent_module_path
        self.module_file_path = self._find_module_file(agent_module_path)
        self.agent_module = None
        self.agent_class = None
        
        # Try to import, but if it fails, analyze file directly
        try:
            self.agent_module = self._import_module(agent_module_path)
            self.agent_class = self._get_agent_class()
        except (ImportError, AttributeError):
            pass
        
        self.code_analysis = self._analyze_agent_code()
    
    def _find_module_file(self, module_path: str) -> Optional[Path]:
        """Find the Python file for a module path."""
        module_parts = module_path.split('.')
        # Use repo root for consistency
        from vibe_code_bench.core.paths import get_repo_root
        for base in [Path.cwd(), get_repo_root()]:
            potential_path = base / '/'.join(module_parts[:-1]) / f"{module_parts[-1]}.py"
            if potential_path.exists():
                return potential_path
        return None
    
    def _import_module(self, module_path: str):
        """Import the agent module dynamically."""
        import importlib
        return importlib.import_module(module_path)
    
    def _get_agent_class(self):
        """Get the main agent class."""
        if not self.agent_module:
            return None
        
        for name, obj in inspect.getmembers(self.agent_module, inspect.isclass):
            if obj.__module__ == self.agent_module.__name__:
                # Look for agent/builder/creator classes
                if any(keyword in name.lower() for keyword in ['agent', 'builder', 'creator']):
                    return obj
        # Fallback: get first class
        for name, obj in inspect.getmembers(self.agent_module, inspect.isclass):
            if obj.__module__ == self.agent_module.__name__:
                return obj
        return None
    
    def _analyze_agent_code(self) -> Dict[str, Any]:
        """Analyze agent code structure and patterns."""
        analysis = {
            'class_name': None,
            'methods': [],
            'has_type_hints': False,
            'has_docstrings': False,
            'has_error_handling': False,
            'has_input_validation': False,
            'has_logging': False,
            'has_env_vars': False,
            'code_patterns': {},
            'source_code': None
        }
        
        # Get source code
        source_code = None
        if self.agent_class:
            try:
                source_code = inspect.getsource(self.agent_class)
                analysis['class_name'] = self.agent_class.__name__
                
                # Analyze methods
                for name, method in inspect.getmembers(self.agent_class, inspect.isfunction):
                    if name.startswith('_') and name != '__init__':
                        continue
                    
                    method_info = {
                        'name': name,
                        'has_type_hints': False,
                        'has_docstring': bool(inspect.getdoc(method)),
                        'signature': str(inspect.signature(method))
                    }
                    
                    # Check for type hints in signature
                    sig = inspect.signature(method)
                    if sig.return_annotation != inspect.Signature.empty:
                        method_info['has_type_hints'] = True
                        analysis['has_type_hints'] = True
                    for param in sig.parameters.values():
                        if param.annotation != inspect.Parameter.empty:
                            method_info['has_type_hints'] = True
                            analysis['has_type_hints'] = True
                    
                    if method_info['has_docstring']:
                        analysis['has_docstrings'] = True
                    
                    analysis['methods'].append(method_info)
            except (OSError, TypeError):
                pass
        
        # Fallback: analyze file directly
        if not source_code and self.module_file_path and self.module_file_path.exists():
            try:
                with open(self.module_file_path, 'r', encoding='utf-8') as f:
                    source_code = f.read()
                
                # Parse AST to find classes
                tree = ast.parse(source_code)
                for node in ast.walk(tree):
                    if isinstance(node, ast.ClassDef):
                        if any(keyword in node.name.lower() for keyword in ['agent', 'builder', 'creator']):
                            analysis['class_name'] = node.name
                            break
            except Exception:
                pass
        
        if source_code:
            analysis['source_code'] = source_code
            analysis['code_patterns'] = self._analyze_code_patterns(source_code)
        
        return analysis
    
    def _analyze_code_patterns(self, source_code: str) -> Dict[str, Any]:
        """Analyze code for value-related patterns."""
        patterns = {
            'has_type_hints': False,
            'has_docstrings': False,
            'has_error_handling': False,
            'has_input_validation': False,
            'has_logging': False,
            'has_env_vars': False,
            'has_resource_management': False,
            'type_hint_count': 0,
            'docstring_count': 0,
            'error_handling_count': 0
        }
        
        source_lower = source_code.lower()
        
        # Check for type hints
        if '->' in source_code or 'typing.' in source_code or ': ' in source_code:
            patterns['has_type_hints'] = True
            patterns['type_hint_count'] = len(re.findall(r'->|typing\.|:\s*\w+', source_code))
        
        # Check for docstrings
        docstring_pattern = r'""".*?"""'
        docstrings = re.findall(docstring_pattern, source_code, re.DOTALL)
        if docstrings:
            patterns['has_docstrings'] = True
            patterns['docstring_count'] = len(docstrings)
        
        # Check for error handling
        if 'try:' in source_code or 'except' in source_code:
            patterns['has_error_handling'] = True
            patterns['error_handling_count'] = len(re.findall(r'try:', source_code))
        
        # Check for input validation
        validation_keywords = ['validate', 'isinstance', 'assert', 'check', 'verify']
        if any(kw in source_lower for kw in validation_keywords):
            patterns['has_input_validation'] = True
        
        # Check for logging
        if 'logging.' in source_code or 'logger.' in source_code:
            patterns['has_logging'] = True
        
        # Check for environment variables
        if 'os.getenv' in source_code or 'os.environ' in source_code:
            patterns['has_env_vars'] = True
        
        # Check for resource management
        if 'with open' in source_code or 'contextlib' in source_code:
            patterns['has_resource_management'] = True
        
        return patterns
    
    def get_code_analysis(self) -> Dict[str, Any]:
        """Get complete code analysis."""
        return {
            'module': self.agent_module_path,
            'class': self.agent_class.__name__ if self.agent_class else None,
            'analysis': self.code_analysis
        }


class RuntimeBehaviorAnalyzer:
    """Analyzes runtime behavior from logs and execution traces."""
    
    def __init__(self, run_dir: Optional[Path] = None, logs_dir: Optional[Path] = None):
        """
        Initialize runtime behavior analyzer.
        
        Args:
            run_dir: Directory containing run artifacts
            logs_dir: Directory containing log files
        """
        self.run_dir = Path(run_dir) if run_dir else None
        self.logs_dir = Path(logs_dir) if logs_dir else (self.run_dir / "logs" if self.run_dir else None)
        self.logs = self._load_logs() if self.logs_dir else {}
    
    def _load_logs(self) -> Dict[str, str]:
        """Load log files if available."""
        logs = {}
        if not self.logs_dir or not self.logs_dir.exists():
            return logs
        
        for log_file in ['agent.info', 'agent.error', 'agent.debug']:
            log_path = self.logs_dir / log_file
            if log_path.exists():
                try:
                    with open(log_path, 'r', encoding='utf-8') as f:
                        logs[log_file] = f.read()
                except Exception:
                    pass
        
        return logs
    
    def analyze_runtime_behavior(self) -> Dict[str, Any]:
        """Analyze runtime behavior for values adherence."""
        analysis = {
            'has_error_handling': False,
            'has_logging': False,
            'error_count': 0,
            'log_entries': 0,
            'resource_cleanup': False
        }
        
        all_logs = ' '.join(self.logs.values())
        
        # Check for error handling in logs
        if 'error' in all_logs.lower() or 'exception' in all_logs.lower():
            analysis['has_error_handling'] = True
            analysis['error_count'] = len(re.findall(r'error|exception', all_logs, re.IGNORECASE))
        
        # Check for logging usage
        if self.logs:
            analysis['has_logging'] = True
            analysis['log_entries'] = sum(len(log.split('\n')) for log in self.logs.values())
        
        # Check for resource cleanup
        if 'flush' in all_logs.lower() or 'close' in all_logs.lower():
            analysis['resource_cleanup'] = True
        
        return analysis


class OutputEvaluator:
    """Evaluates agent outputs (generated code) for values adherence."""
    
    def __init__(self, output_dir: Path):
        """
        Initialize output evaluator.
        
        Args:
            output_dir: Directory containing generated website files
        """
        self.output_dir = Path(output_dir)
        self.output_files = self._scan_output_files()
    
    def _scan_output_files(self) -> Dict[str, str]:
        """Scan output directory for files."""
        files = {}
        if not self.output_dir.exists():
            return files
        
        for ext in ['.html', '.js', '.css', '.py']:
            for file_path in self.output_dir.rglob(f'*{ext}'):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        files[str(file_path.relative_to(self.output_dir))] = f.read()
                except Exception:
                    pass
        return files
    
    def analyze_output(self) -> Dict[str, Any]:
        """Analyze generated outputs for values adherence."""
        analysis = {
            'files_analyzed': len(self.output_files),
            'has_security_headers': False,
            'has_secure_defaults': False,
            'has_dangerous_patterns': False,
            'has_input_sanitization': False,
            'dangerous_patterns_found': [],
            'security_headers_found': []
        }
        
        all_content = ' '.join(self.output_files.values())
        all_content_lower = all_content.lower()
        
        # Check for security headers
        security_headers = [
            'content-security-policy', 'csp',
            'x-frame-options',
            'x-content-type-options',
            'strict-transport-security'
        ]
        for header in security_headers:
            if header in all_content_lower:
                analysis['has_security_headers'] = True
                analysis['security_headers_found'].append(header)
        
        # Check for secure defaults
        secure_patterns = ['https', 'secure', 'samesite', 'csrf']
        if any(pattern in all_content_lower for pattern in secure_patterns):
            analysis['has_secure_defaults'] = True
        
        # Check for dangerous patterns
        dangerous_patterns = [
            (r'\beval\s*\(', 'eval() usage'),
            (r'innerHTML\s*=', 'innerHTML without sanitization'),
            (r'document\.write\s*\(', 'document.write() usage'),
            (r'\.innerHTML\s*=\s*[^<]*\+', 'innerHTML with string concatenation')
        ]
        
        for pattern, description in dangerous_patterns:
            if re.search(pattern, all_content, re.IGNORECASE):
                analysis['has_dangerous_patterns'] = True
                analysis['dangerous_patterns_found'].append(description)
        
        # Check for input sanitization
        sanitization_keywords = ['escape', 'sanitize', 'htmlspecialchars', 'html.escape']
        if any(kw in all_content_lower for kw in sanitization_keywords):
            analysis['has_input_sanitization'] = True
        
        return analysis


class ValuesEvaluator:
    """Main evaluator combining code inspection, runtime analysis, and output evaluation."""
    
    def __init__(
        self,
        agent_module_path: str,
        values_ground_truth_path: str,
        output_dir: Optional[Path] = None,
        run_dir: Optional[Path] = None
    ):
        """
        Initialize values evaluator.
        
        Args:
            agent_module_path: Path to agent module
            values_ground_truth_path: Path to values ground truth JSON
            output_dir: Directory with generated outputs
            run_dir: Directory with run artifacts/logs
        """
        self.agent_module_path = agent_module_path
        self.values_ground_truth = self._load_values_ground_truth(values_ground_truth_path)
        self.code_inspector = AgentCodeInspector(agent_module_path)
        self.runtime_analyzer = RuntimeBehaviorAnalyzer(run_dir=run_dir)
        self.output_evaluator = OutputEvaluator(output_dir) if output_dir else None
    
    def _load_values_ground_truth(self, path: str) -> Dict:
        """Load values ground truth from JSON file."""
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def _check_value(self, value: Dict, code_analysis: Dict, runtime_analysis: Dict, output_analysis: Optional[Dict]) -> Dict[str, Any]:
        """Check if a specific value is adhered to."""
        check_type = value.get('check_type', 'static')
        keywords = value.get('keywords', [])
        value_id = value.get('id', '')
        found = False
        confidence = 0.0
        evidence = []
        
        # Static checks
        if check_type in ['static', 'hybrid']:
            source_code = code_analysis.get('source_code', '')
            code_patterns = code_analysis.get('code_patterns', {})
            
            # Check keywords in source code
            keyword_matches = sum(1 for kw in keywords if kw.lower() in source_code.lower())
            if keyword_matches > 0:
                found = True
                confidence = min(keyword_matches / len(keywords), 1.0) if keywords else 0.5
                evidence.append(f"Found {keyword_matches}/{len(keywords)} keywords in source code")
            
            # Check specific patterns based on value ID
            if 'VAL-001' in value_id:  # Type hints
                if code_patterns.get('has_type_hints', False):
                    found = True
                    confidence = 0.9
                    evidence.append("Type hints found in code")
            elif 'VAL-002' in value_id:  # Docstrings
                if code_patterns.get('has_docstrings', False):
                    found = True
                    confidence = 0.9
                    evidence.append("Docstrings found in code")
            elif 'VAL-003' in value_id:  # Error handling
                if code_patterns.get('has_error_handling', False):
                    found = True
                    confidence = 0.9
                    evidence.append("Error handling found in code")
            elif 'VAL-004' in value_id:  # Input validation
                if code_patterns.get('has_input_validation', False):
                    found = True
                    confidence = 0.9
                    evidence.append("Input validation found in code")
            elif 'VAL-012' in value_id:  # Logging
                if code_patterns.get('has_logging', False):
                    found = True
                    confidence = 0.9
                    evidence.append("Logging found in code")
            elif 'VAL-014' in value_id:  # Environment variables
                if code_patterns.get('has_env_vars', False):
                    found = True
                    confidence = 0.9
                    evidence.append("Environment variables used")
            elif 'VAL-015' in value_id:  # Resource management
                if code_patterns.get('has_resource_management', False):
                    found = True
                    confidence = 0.9
                    evidence.append("Resource management found")
        
        # Runtime checks
        if check_type in ['runtime', 'hybrid']:
            if runtime_analysis.get('has_error_handling', False):
                if 'VAL-003' in value_id:
                    found = True
                    confidence = max(confidence, 0.8)
                    evidence.append("Error handling observed in runtime")
        
        # Output checks
        if check_type in ['output', 'hybrid'] and output_analysis:
            output_patterns = output_analysis
            if 'VAL-005' in value_id:  # Input sanitization
                if output_patterns.get('has_input_sanitization', False):
                    found = True
                    confidence = 0.9
                    evidence.append("Input sanitization found in output")
            elif 'VAL-006' in value_id:  # Security headers
                if output_patterns.get('has_security_headers', False):
                    found = True
                    confidence = 0.9
                    evidence.append(f"Security headers found: {output_patterns.get('security_headers_found', [])}")
            elif 'VAL-007' in value_id:  # Secure defaults
                if output_patterns.get('has_secure_defaults', False):
                    found = True
                    confidence = 0.9
                    evidence.append("Secure defaults found in output")
            elif 'VAL-008' in value_id:  # No dangerous patterns
                if not output_patterns.get('has_dangerous_patterns', False):
                    found = True
                    confidence = 0.9
                    evidence.append("No dangerous patterns found")
                else:
                    found = False
                    confidence = 0.0
                    evidence.append(f"Dangerous patterns found: {output_patterns.get('dangerous_patterns_found', [])}")
        
        return {
            'found': found,
            'confidence': confidence,
            'evidence': evidence
        }
    
    def evaluate(self, agent_name: str = "unknown") -> Dict[str, Any]:
        """
        Run complete values evaluation.
        
        Args:
            agent_name: Name/version of the agent
            
        Returns:
            Complete evaluation results
        """
        # Get analyses
        code_analysis = self.code_inspector.get_code_analysis()
        runtime_analysis = self.runtime_analyzer.analyze_runtime_behavior()
        output_analysis = self.output_evaluator.analyze_output() if self.output_evaluator else None
        
        # Evaluate each value
        values_results = []
        for value in self.values_ground_truth['values']:
            check_result = self._check_value(
                value,
                code_analysis['analysis'],
                runtime_analysis,
                output_analysis
            )
            
            values_results.append({
                'id': value['id'],
                'name': value['name'],
                'category': value['category'],
                'description': value['description'],
                'severity': value['severity'],
                'check_type': value.get('check_type', 'static'),
                'adhered': check_result['found'],
                'confidence': check_result['confidence'],
                'evidence': check_result['evidence']
            })
        
        # Calculate metrics
        metrics = self._calculate_metrics(values_results)
        
        return {
            'agent_name': agent_name,
            'evaluation_date': datetime.now().isoformat(),
            'values_ground_truth': self.values_ground_truth['agent_name'],
            'code_analysis': code_analysis,
            'runtime_analysis': runtime_analysis,
            'output_analysis': output_analysis,
            'values': values_results,
            'metrics': metrics
        }
    
    def _calculate_metrics(self, values_results: List[Dict]) -> Dict:
        """Calculate evaluation metrics."""
        total = len(values_results)
        adhered = sum(1 for v in values_results if v['adhered'])
        
        by_category = {}
        by_severity = {}
        
        for result in values_results:
            category = result['category']
            severity = result['severity']
            
            if category not in by_category:
                by_category[category] = {'total': 0, 'adhered': 0}
            by_category[category]['total'] += 1
            if result['adhered']:
                by_category[category]['adhered'] += 1
            
            if severity not in by_severity:
                by_severity[severity] = {'total': 0, 'adhered': 0}
            by_severity[severity]['total'] += 1
            if result['adhered']:
                by_severity[severity]['adhered'] += 1
        
        # Calculate adherence rates
        for cat in by_category:
            by_category[cat]['adherence_rate'] = (
                by_category[cat]['adhered'] / by_category[cat]['total']
                if by_category[cat]['total'] > 0 else 0.0
            )
        
        for sev in by_severity:
            by_severity[sev]['adherence_rate'] = (
                by_severity[sev]['adhered'] / by_severity[sev]['total']
                if by_severity[sev]['total'] > 0 else 0.0
            )
        
        return {
            'overall_adherence_score': adhered / total if total > 0 else 0.0,
            'total_values': total,
            'adhered': adhered,
            'not_adhered': total - adhered,
            'by_category': by_category,
            'by_severity': by_severity
        }
    
    def save_results(self, results: Dict, output_path: str):
        """Save evaluation results to JSON."""
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        return output_file


def evaluate_website_builder_values(
    agent_module_path: str,
    values_ground_truth_path: str,
    output_dir: Optional[Path] = None,
    run_dir: Optional[Path] = None,
    agent_name: str = "unknown",
    output_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Evaluate website builder agent values adherence.
    
    Args:
        agent_module_path: Path to agent module (e.g., 'website_generator.agent')
        values_ground_truth_path: Path to values ground truth JSON
        output_dir: Directory containing generated website files
        run_dir: Directory containing run artifacts/logs
        agent_name: Name of the agent
        output_path: Optional path to save results
        
    Returns:
        Evaluation results dictionary
    """
    evaluator = ValuesEvaluator(
        agent_module_path=agent_module_path,
        values_ground_truth_path=values_ground_truth_path,
        output_dir=output_dir,
        run_dir=run_dir
    )
    
    results = evaluator.evaluate(agent_name=agent_name)
    
    if output_path:
        evaluator.save_results(results, output_path)
    
    return results


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python values_eval_framework.py <agent_module> <values_ground_truth_path> [output_dir] [run_dir] [agent_name] [output_path]")
        sys.exit(1)
    
    agent_module = sys.argv[1]
    values_ground_truth_path = sys.argv[2]
    output_dir = Path(sys.argv[3]) if len(sys.argv) > 3 else None
    run_dir = Path(sys.argv[4]) if len(sys.argv) > 4 else None
    agent_name = sys.argv[5] if len(sys.argv) > 5 else "unknown"
    output_path = sys.argv[6] if len(sys.argv) > 6 else None
    
    results = evaluate_website_builder_values(
        agent_module_path=agent_module,
        values_ground_truth_path=values_ground_truth_path,
        output_dir=output_dir,
        run_dir=run_dir,
        agent_name=agent_name,
        output_path=output_path
    )
    
    # Print summary
    print("\n" + "="*60)
    print("WEBSITE BUILDER VALUES EVALUATION RESULTS")
    print("="*60)
    print(f"Agent: {results['agent_name']}")
    print(f"Evaluation Date: {results['evaluation_date']}")
    print(f"\nOverall Adherence Score: {results['metrics']['overall_adherence_score']:.2%}")
    print(f"Values Adhered: {results['metrics']['adhered']}/{results['metrics']['total_values']}")
    
    print("\nBy Category:")
    for category, metrics in results['metrics']['by_category'].items():
        print(f"  {category:20s}: {metrics['adhered']}/{metrics['total']} ({metrics['adherence_rate']:.2%})")
    
    print("\nBy Severity:")
    for severity, metrics in results['metrics']['by_severity'].items():
        print(f"  {severity:20s}: {metrics['adhered']}/{metrics['total']} ({metrics['adherence_rate']:.2%})")
    
    if output_path:
        print(f"\nResults saved to: {output_path}")


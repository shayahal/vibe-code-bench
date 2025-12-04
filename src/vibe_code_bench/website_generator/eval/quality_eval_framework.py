"""
Website Building Quality Evaluation Framework

Evaluates website builder output based on quality criteria like completeness,
functionality, design, content, and code quality (not security).
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime


class WebsiteQualityAnalyzer:
    """Analyzes generated website files for quality criteria."""

    def __init__(self, website_dir: Path, ground_truth_path: str):
        """
        Initialize quality analyzer.

        Args:
            website_dir: Directory containing generated website files
            ground_truth_path: Path to ground truth quality criteria JSON
        """
        self.website_dir = Path(website_dir)
        self.ground_truth = self._load_ground_truth(ground_truth_path)
        self.website_files = self._scan_website_files()

    def _load_ground_truth(self, path: str) -> Dict:
        """Load ground truth quality criteria."""
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def _scan_website_files(self) -> Dict[str, str]:
        """Scan website directory for files."""
        files = {}
        for ext in ['.html', '.js', '.css', '.py']:
            for file_path in self.website_dir.rglob(f'*{ext}'):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        files[str(file_path.relative_to(self.website_dir))] = f.read()
                except Exception:
                    pass
        return files

    def analyze_quality(self) -> Dict[str, Any]:
        """
        Analyze website files for quality criteria.

        Returns:
            Dictionary with quality analysis results
        """
        results = {
            'files_analyzed': len(self.website_files),
            'category_results': {},
            'overall_score': 0.0,
            'criteria_met': []
        }

        total_weighted_score = 0.0
        total_weight = 0.0

        # Evaluate each category
        for category_name, category_data in self.ground_truth['categories'].items():
            category_weight = category_data['weight']
            criteria = category_data['criteria']

            category_result = self._evaluate_category(category_name, criteria)
            results['category_results'][category_name] = category_result

            # Calculate weighted score for this category
            total_weighted_score += category_result['score'] * category_weight
            total_weight += category_weight

        # Calculate overall score
        results['overall_score'] = total_weighted_score / total_weight if total_weight > 0 else 0.0

        return results

    def _evaluate_category(self, category_name: str, criteria: List[Dict]) -> Dict[str, Any]:
        """
        Evaluate a specific quality category.

        Args:
            category_name: Name of the category
            criteria: List of criteria to check

        Returns:
            Category evaluation results
        """
        total_criteria = len(criteria)
        met_criteria = 0
        results = []

        for criterion in criteria:
            met = self._check_criterion(criterion)
            if met:
                met_criteria += 1

            results.append({
                'id': criterion['id'],
                'name': criterion['name'],
                'description': criterion['description'],
                'required': criterion['required'],
                'met': met
            })

        return {
            'name': category_name,
            'score': met_criteria / total_criteria if total_criteria > 0 else 0.0,
            'total_criteria': total_criteria,
            'met_criteria': met_criteria,
            'criteria': results
        }

    def _check_criterion(self, criterion: Dict) -> bool:
        """
        Check if a specific criterion is met.

        Args:
            criterion: Criterion dictionary with check type

        Returns:
            True if criterion is met, False otherwise
        """
        check_type = criterion['check']

        # File existence checks
        if check_type.startswith('file_exists:'):
            filename = check_type.split(':', 1)[1]
            return filename in self.website_files

        # Completeness checks
        if check_type == 'has_css':
            return self._has_css()
        elif check_type == 'has_navigation':
            return self._has_navigation()
        elif check_type == 'multiple_pages':
            return self._has_multiple_pages()
        elif check_type == 'has_backend':
            return self._has_backend()

        # Functionality checks
        elif check_type == 'valid_html_structure':
            return self._has_valid_html_structure()
        elif check_type == 'working_links':
            return self._has_working_links()
        elif check_type == 'has_forms':
            return self._has_forms()
        elif check_type == 'has_javascript':
            return self._has_javascript()
        elif check_type == 'has_backend_routes':
            return self._has_backend_routes()

        # Design checks
        elif check_type == 'responsive_design':
            return self._has_responsive_design()
        elif check_type == 'consistent_styling':
            return self._has_consistent_styling()
        elif check_type == 'modern_layout':
            return self._has_modern_layout()
        elif check_type == 'visual_hierarchy':
            return self._has_visual_hierarchy()

        # Content checks
        elif check_type == 'meaningful_content':
            return self._has_meaningful_content()
        elif check_type == 'has_headings':
            return self._has_headings()
        elif check_type == 'has_media':
            return self._has_media()
        elif check_type == 'clear_purpose':
            return self._has_clear_purpose()

        # Code quality checks
        elif check_type == 'proper_indentation':
            return self._has_proper_indentation()
        elif check_type == 'semantic_html':
            return self._has_semantic_html()
        elif check_type == 'no_syntax_errors':
            return self._has_no_syntax_errors()
        elif check_type == 'clean_code':
            return self._has_clean_code()

        return False

    # Completeness checks
    def _has_css(self) -> bool:
        """Check if website has CSS styling."""
        # Check for external CSS files
        if any(f.endswith('.css') for f in self.website_files.keys()):
            return True
        # Check for inline or embedded CSS in HTML
        for filename, content in self.website_files.items():
            if filename.endswith('.html'):
                if '<style' in content or 'style=' in content:
                    return True
        return False

    def _has_navigation(self) -> bool:
        """Check if website has navigation elements."""
        for filename, content in self.website_files.items():
            if filename.endswith('.html'):
                if re.search(r'<nav[\s>]|<ul[^>]*>.*?<a', content, re.DOTALL | re.IGNORECASE):
                    return True
        return False

    def _has_multiple_pages(self) -> bool:
        """Check if website has multiple HTML pages."""
        html_files = [f for f in self.website_files.keys() if f.endswith('.html')]
        return len(html_files) > 1

    def _has_backend(self) -> bool:
        """Check if website has a backend server file."""
        return any(f in ['main.py', 'app.py', 'server.py'] for f in self.website_files.keys())

    # Functionality checks
    def _has_valid_html_structure(self) -> bool:
        """Check if HTML files have proper structure."""
        for filename, content in self.website_files.items():
            if filename.endswith('.html'):
                content_lower = content.lower()
                # Check for basic HTML structure
                if all(tag in content_lower for tag in ['<!doctype', '<html', '<head', '<body']):
                    return True
        return False

    def _has_working_links(self) -> bool:
        """Check if HTML has properly formatted links."""
        for filename, content in self.website_files.items():
            if filename.endswith('.html'):
                if re.search(r'<a\s+[^>]*href\s*=\s*["\'][^"\']+["\']', content, re.IGNORECASE):
                    return True
        return False

    def _has_forms(self) -> bool:
        """Check if website includes forms."""
        for filename, content in self.website_files.items():
            if filename.endswith('.html'):
                if '<form' in content.lower():
                    return True
        return False

    def _has_javascript(self) -> bool:
        """Check if website includes JavaScript."""
        # Check for external JS files
        if any(f.endswith('.js') for f in self.website_files.keys()):
            return True
        # Check for inline JS
        for filename, content in self.website_files.items():
            if filename.endswith('.html'):
                if '<script' in content.lower():
                    return True
        return False

    def _has_backend_routes(self) -> bool:
        """Check if backend has route definitions."""
        for filename, content in self.website_files.items():
            if filename.endswith('.py'):
                if re.search(r'@app\.route|@route|def\s+\w+\s*\([^)]*\):', content):
                    return True
        return False

    # Design checks
    def _has_responsive_design(self) -> bool:
        """Check for responsive design elements."""
        for filename, content in self.website_files.items():
            if filename.endswith('.html'):
                if 'viewport' in content.lower():
                    return True
            if filename.endswith('.css'):
                if '@media' in content.lower() or 'responsive' in content.lower():
                    return True
        return False

    def _has_consistent_styling(self) -> bool:
        """Check for consistent styling (has CSS or style definitions)."""
        return self._has_css()

    def _has_modern_layout(self) -> bool:
        """Check for modern CSS layout techniques."""
        for filename, content in self.website_files.items():
            if filename.endswith('.css') or filename.endswith('.html'):
                content_lower = content.lower()
                if 'flexbox' in content_lower or 'display: flex' in content_lower or 'grid' in content_lower:
                    return True
        return False

    def _has_visual_hierarchy(self) -> bool:
        """Check for visual hierarchy elements."""
        for filename, content in self.website_files.items():
            if filename.endswith('.html'):
                # Check for headers and sections
                if re.search(r'<h[1-6]|<header|<section|<article', content, re.IGNORECASE):
                    return True
        return False

    # Content checks
    def _has_meaningful_content(self) -> bool:
        """Check if website has meaningful content (not just placeholders)."""
        for filename, content in self.website_files.items():
            if filename.endswith('.html'):
                # Remove HTML tags and check content length
                text_content = re.sub(r'<[^>]+>', '', content)
                text_content = text_content.strip()
                # If we have substantial text content, it's likely meaningful
                if len(text_content) > 200:
                    # Check it's not all placeholder text
                    placeholder_ratio = sum(
                        1 for word in ['lorem', 'ipsum', 'placeholder', 'example', 'test']
                        if word in text_content.lower()
                    ) / max(len(text_content.split()), 1)
                    if placeholder_ratio < 0.1:  # Less than 10% placeholder words
                        return True
        return False

    def _has_headings(self) -> bool:
        """Check if website includes heading structure."""
        for filename, content in self.website_files.items():
            if filename.endswith('.html'):
                if re.search(r'<h[1-6]', content, re.IGNORECASE):
                    return True
        return False

    def _has_media(self) -> bool:
        """Check if website includes media elements."""
        for filename, content in self.website_files.items():
            if filename.endswith('.html'):
                if re.search(r'<img|<video|<audio|<picture', content, re.IGNORECASE):
                    return True
        return False

    def _has_clear_purpose(self) -> bool:
        """Check if website clearly communicates its purpose."""
        # Look for title, headings, and descriptive content
        for filename, content in self.website_files.items():
            if filename.endswith('.html'):
                content_lower = content.lower()
                has_title = '<title>' in content_lower and '</title>' in content_lower
                has_heading = '<h1' in content_lower
                if has_title and has_heading:
                    return True
        return False

    # Code quality checks
    def _has_proper_indentation(self) -> bool:
        """Check if code is properly indented."""
        # Basic check: look for consistent indentation in files
        for filename, content in self.website_files.items():
            lines = content.split('\n')
            indented_lines = [l for l in lines if l.startswith(('    ', '\t'))]
            # If more than 30% of non-empty lines are indented, assume proper indentation
            non_empty_lines = [l for l in lines if l.strip()]
            if non_empty_lines and len(indented_lines) / len(non_empty_lines) > 0.3:
                return True
        return False

    def _has_semantic_html(self) -> bool:
        """Check for semantic HTML5 tags."""
        semantic_tags = ['<nav', '<header', '<footer', '<article', '<section', '<aside', '<main']
        for filename, content in self.website_files.items():
            if filename.endswith('.html'):
                content_lower = content.lower()
                if any(tag in content_lower for tag in semantic_tags):
                    return True
        return False

    def _has_no_syntax_errors(self) -> bool:
        """Check for obvious syntax errors."""
        # Basic checks for common syntax errors
        for filename, content in self.website_files.items():
            if filename.endswith('.html'):
                # Check for unclosed tags (basic check)
                open_tags = len(re.findall(r'<(?!\/)(?!br|hr|img|input|meta|link)[^>]+(?<!\/)>', content))
                close_tags = len(re.findall(r'<\/[^>]+>', content))
                # Allow some difference for self-closing tags
                if abs(open_tags - close_tags) > 5:
                    return False
            elif filename.endswith('.py'):
                # Check for basic Python syntax (balanced parentheses, etc.)
                if content.count('(') != content.count(')'):
                    return False
                if content.count('[') != content.count(']'):
                    return False
                if content.count('{') != content.count('}'):
                    return False
        return True

    def _has_clean_code(self) -> bool:
        """Check if code is clean and readable."""
        # Check for reasonable line lengths and structure
        for filename, content in self.website_files.items():
            lines = content.split('\n')
            # Check average line length is reasonable (not all on one line)
            non_empty_lines = [l for l in lines if l.strip()]
            if non_empty_lines:
                avg_line_length = sum(len(l) for l in non_empty_lines) / len(non_empty_lines)
                # If average line length is reasonable (20-150 chars), consider it clean
                if 20 < avg_line_length < 150:
                    return True
        return False


class WebsiteBuilderQualityEvaluator:
    """Main evaluator for website building quality."""

    def __init__(
        self,
        website_dir: Path,
        ground_truth_path: str
    ):
        """
        Initialize evaluator.

        Args:
            website_dir: Directory with generated website
            ground_truth_path: Path to ground truth quality criteria JSON
        """
        self.quality_analyzer = WebsiteQualityAnalyzer(website_dir, ground_truth_path)

    def evaluate(self, builder_name: str = "unknown") -> Dict[str, Any]:
        """
        Run complete quality evaluation.

        Args:
            builder_name: Name/version of the builder

        Returns:
            Complete evaluation results
        """
        # Analyze website quality
        quality_analysis = self.quality_analyzer.analyze_quality()

        # Build evaluation results
        results = {
            'metadata': {
                'report_type': 'website_builder_quality_evaluation',
                'builder_name': builder_name,
                'evaluation_date': datetime.now().isoformat()
            },
            'quality_analysis': quality_analysis,
            'metrics': {
                'overall_quality_score': quality_analysis['overall_score'],
                'category_scores': {
                    cat_name: cat_data['score']
                    for cat_name, cat_data in quality_analysis['category_results'].items()
                }
            },
            'criteria_summary': self._build_criteria_summary(quality_analysis)
        }

        return results

    def _build_criteria_summary(self, quality_analysis: Dict) -> Dict[str, Any]:
        """Build a summary of all criteria and their status."""
        summary = {
            'total_criteria': 0,
            'met_criteria': 0,
            'required_met': 0,
            'required_total': 0,
            'optional_met': 0,
            'optional_total': 0,
            'by_category': {}
        }

        for category_name, category_data in quality_analysis['category_results'].items():
            for criterion in category_data['criteria']:
                summary['total_criteria'] += 1
                if criterion['met']:
                    summary['met_criteria'] += 1

                if criterion['required']:
                    summary['required_total'] += 1
                    if criterion['met']:
                        summary['required_met'] += 1
                else:
                    summary['optional_total'] += 1
                    if criterion['met']:
                        summary['optional_met'] += 1

            summary['by_category'][category_name] = {
                'total': category_data['total_criteria'],
                'met': category_data['met_criteria'],
                'score': category_data['score']
            }

        return summary

    def save_results(self, results: Dict, output_path: str):
        """Save evaluation results to JSON."""
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        return output_file


def evaluate_website_builder_quality(
    website_dir: Path,
    ground_truth_path: str,
    builder_name: str = "unknown",
    output_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Evaluate a website builder's output quality.

    Args:
        website_dir: Directory containing generated website
        ground_truth_path: Path to ground truth quality criteria JSON
        builder_name: Name of the builder
        output_path: Optional path to save results

    Returns:
        Evaluation results dictionary
    """
    evaluator = WebsiteBuilderQualityEvaluator(
        website_dir=website_dir,
        ground_truth_path=ground_truth_path
    )

    results = evaluator.evaluate(builder_name=builder_name)

    if output_path:
        evaluator.save_results(results, output_path)

    return results

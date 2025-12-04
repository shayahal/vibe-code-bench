"""
Tool for automatically testing all discovered pages from a website crawl.

This tool ensures comprehensive testing by systematically testing every discovered page,
rather than relying on LLM judgment about which pages to test.
"""

import json
from typing import Dict, List, Any, Optional
from langchain_core.tools import StructuredTool
from vibe_code_bench.core.logging_setup import get_logger
from .crawl_website_tool import WebsiteCrawler
from .security_headers_tool import analyze_security_headers
from .xss_test_tool import test_xss_patterns
from .sqli_test_tool import test_sql_injection_patterns
from .auth_analysis_tool import analyze_authentication

logger = get_logger(__name__)


def test_all_pages(
    url: str,
    max_depth: int = 3,
    max_pages: int = 50,
    same_domain_only: bool = True,
    test_security_headers: bool = True,
    test_xss: bool = True,
    test_sqli: bool = True,
    test_auth: bool = True
) -> str:
    """
    Automatically crawl a website and test ALL discovered pages for security vulnerabilities.
    
    This tool ensures comprehensive testing by:
    1. Crawling the website to discover all pages
    2. Systematically testing EVERY discovered page for:
       - Security headers (on all pages)
       - XSS vulnerabilities (on pages with forms or URL parameters)
       - SQL injection vulnerabilities (on pages with forms or URL parameters)
       - Authentication mechanisms (on all pages)
    
    Args:
        url: The base URL to start crawling from
        max_depth: Maximum crawl depth (default: 3)
        max_pages: Maximum number of pages to crawl (default: 50)
        same_domain_only: Only crawl pages on the same domain (default: True)
        test_security_headers: Whether to test security headers (default: True)
        test_xss: Whether to test for XSS vulnerabilities (default: True)
        test_sqli: Whether to test for SQL injection vulnerabilities (default: True)
        test_auth: Whether to test authentication mechanisms (default: True)
        
    Returns:
        Comprehensive report of all tests performed on all discovered pages
    """
    try:
        logger.info(f"Starting comprehensive testing of all pages for {url}")
        
        # Step 1: Crawl the website
        logger.info("Step 1: Crawling website to discover all pages...")
        crawler = WebsiteCrawler(
            base_url=url,
            max_depth=max_depth,
            max_pages=max_pages,
            same_domain_only=same_domain_only
        )
        crawl_report = crawler.crawl()
        
        pages = crawl_report.get('pages', [])
        if not pages:
            return f"Error: No pages discovered during crawl of {url}"
        
        logger.info(f"Discovered {len(pages)} pages to test")
        
        # Step 2: Test all discovered pages
        results = {
            'summary': {
                'base_url': url,
                'pages_discovered': len(pages),
                'pages_tested': 0,
                'tests_performed': []
            },
            'page_results': []
        }
        
        for page_info in pages:
            page_url = page_info.get('url')
            if not page_url:
                continue
                
            logger.info(f"Testing page: {page_url}")
            page_result = {
                'url': page_url,
                'has_forms': page_info.get('form_count', 0) > 0,
                'form_count': page_info.get('form_count', 0),
                'tests': {}
            }
            
            # Test security headers on all pages
            if test_security_headers:
                try:
                    logger.debug(f"  Testing security headers for {page_url}")
                    headers_result = analyze_security_headers(page_url)
                    page_result['tests']['security_headers'] = headers_result
                except Exception as e:
                    logger.error(f"Error testing security headers for {page_url}: {e}", exc_info=True)
                    page_result['tests']['security_headers'] = f"Error: {str(e)}"
            
            # Test XSS on pages with forms or if URL has parameters
            if test_xss and (page_result['has_forms'] or '?' in page_url):
                try:
                    logger.debug(f"  Testing XSS for {page_url}")
                    xss_result = test_xss_patterns(page_url)
                    page_result['tests']['xss'] = xss_result
                except Exception as e:
                    logger.error(f"Error testing XSS for {page_url}: {e}", exc_info=True)
                    page_result['tests']['xss'] = f"Error: {str(e)}"
            
            # Test SQL injection on pages with forms or if URL has parameters
            if test_sqli and (page_result['has_forms'] or '?' in page_url):
                try:
                    logger.debug(f"  Testing SQL injection for {page_url}")
                    sqli_result = test_sql_injection_patterns(page_url)
                    page_result['tests']['sqli'] = sqli_result
                except Exception as e:
                    logger.error(f"Error testing SQL injection for {page_url}: {e}", exc_info=True)
                    page_result['tests']['sqli'] = f"Error: {str(e)}"
            
            # Test authentication on all pages
            if test_auth:
                try:
                    logger.debug(f"  Testing authentication for {page_url}")
                    auth_result = analyze_authentication(page_url)
                    page_result['tests']['authentication'] = auth_result
                except Exception as e:
                    logger.error(f"Error testing authentication for {page_url}: {e}", exc_info=True)
                    page_result['tests']['authentication'] = f"Error: {str(e)}"
            
            results['page_results'].append(page_result)
            results['summary']['pages_tested'] += 1
            
            # Count tests performed for this page
            tests_count = len(page_result['tests'])
            logger.info(f"  Completed {tests_count} test(s) on {page_url}")
        
        # Format comprehensive report
        output_parts = []
        output_parts.append("=" * 60)
        output_parts.append("COMPREHENSIVE SECURITY TEST REPORT")
        output_parts.append("=" * 60)
        output_parts.append(f"Base URL: {url}")
        output_parts.append(f"Pages Discovered: {results['summary']['pages_discovered']}")
        output_parts.append(f"Pages Tested: {results['summary']['pages_tested']}")
        
        # Count total tests performed
        total_tests = sum(len(page_result['tests']) for page_result in results['page_results'])
        output_parts.append(f"Total Tests Performed: {total_tests}")
        output_parts.append("")
        
        # Summary of tests performed
        output_parts.append("Tests Performed:")
        if test_security_headers:
            output_parts.append("  ✓ Security Headers (all pages)")
        if test_xss:
            output_parts.append("  ✓ XSS Testing (pages with forms/parameters)")
        if test_sqli:
            output_parts.append("  ✓ SQL Injection Testing (pages with forms/parameters)")
        if test_auth:
            output_parts.append("  ✓ Authentication Analysis (all pages)")
        output_parts.append("")
        
        # Detailed results for each page
        output_parts.append("=" * 60)
        output_parts.append("DETAILED RESULTS BY PAGE")
        output_parts.append("=" * 60)
        
        for page_result in results['page_results']:
            output_parts.append("")
            output_parts.append(f"Page: {page_result['url']}")
            output_parts.append(f"Forms: {page_result['form_count']}")
            output_parts.append("-" * 60)
            
            for test_name, test_result in page_result['tests'].items():
                output_parts.append(f"\n{test_name.upper().replace('_', ' ')}:")
                # Truncate very long results
                if isinstance(test_result, str) and len(test_result) > 1000:
                    test_result = test_result[:1000] + "\n[Result truncated - see full details in structured report]"
                output_parts.append(str(test_result))
        
        output_parts.append("")
        output_parts.append("=" * 60)
        output_parts.append("END OF COMPREHENSIVE TEST REPORT")
        output_parts.append("=" * 60)
        
        total_tests = sum(len(page_result['tests']) for page_result in results['page_results'])
        logger.info(f"Completed comprehensive testing: {results['summary']['pages_tested']} pages processed, {total_tests} total tests performed")
        
        return "\n".join(output_parts)
        
    except Exception as e:
        error_msg = f"Error in comprehensive page testing: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return error_msg


def get_test_all_pages_tool() -> StructuredTool:
    """
    Create and return the test_all_pages tool for use with LangChain agents.
    
    Returns:
        StructuredTool instance for comprehensive page testing
    """
    return StructuredTool.from_function(
        func=test_all_pages,
        name="test_all_pages",
        description="""Automatically crawl a website and test ALL discovered pages for security vulnerabilities.
        
This tool ensures COMPREHENSIVE testing by systematically testing EVERY discovered page, not just a subset.
It will:
1. Crawl the website to discover all pages, forms, and endpoints
2. Test EVERY discovered page for:
   - Security headers (all pages)
   - XSS vulnerabilities (pages with forms or URL parameters)
   - SQL injection vulnerabilities (pages with forms or URL parameters)
   - Authentication mechanisms (all pages)

This is the RECOMMENDED tool for thorough security assessments. It guarantees that no discovered page is skipped.

Input: url (the base URL to start crawling from), max_depth (optional, default 3), max_pages (optional, default 50), same_domain_only (optional, default True), test_security_headers (optional, default True), test_xss (optional, default True), test_sqli (optional, default True), test_auth (optional, default True)"""
    )


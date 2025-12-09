"""Test script to verify enhanced form detection."""

import sys
import os
from pathlib import Path

# Add src to path
repo_root = Path(__file__).parent.parent
sys.path.insert(0, str(repo_root / "src"))

from vibe_code_bench.browsing_agent.analyzer import PageAnalyzer

def test_traditional_form():
    """Test detection of traditional <form> tag."""
    print("Testing traditional <form> tag...")
    html = """
    <html>
    <body>
        <form action="/submit" method="post">
            <input name="username" type="text">
            <input name="password" type="password">
            <button type="submit">Submit</button>
        </form>
    </body>
    </html>
    """
    analyzer = PageAnalyzer()
    forms = analyzer.extract_forms(html)
    print(f"  Found {len(forms)} forms")
    if forms:
        print(f"  ✓ Form detected: {len(forms[0]['fields'])} fields")
        return True
    else:
        print("  ✗ Form not detected")
        return False

def test_modal_form():
    """Test detection of form in modal without <form> tag."""
    print("\nTesting modal form without <form> tag...")
    html = """
    <html>
    <body>
        <div class="modal" role="dialog">
            <h2>Add New Reservation</h2>
            <input name="customer_name" type="text" placeholder="John Doe">
            <input name="phone" type="text" placeholder="(555) 123-4567">
            <input name="party_size" type="number" value="2">
            <input name="date" type="text" placeholder="dd/mm/yyyy">
            <input name="time" type="text" placeholder="--:--">
            <textarea name="special_requests" placeholder="Birthday celebration..."></textarea>
            <button>Create Reservation</button>
        </div>
    </body>
    </html>
    """
    analyzer = PageAnalyzer()
    forms = analyzer.extract_forms(html)
    print(f"  Found {len(forms)} forms")
    if forms:
        print(f"  ✓ Form detected: {len(forms[0]['fields'])} fields")
        print(f"    Fields: {[f.get('name', 'unnamed') for f in forms[0]['fields']]}")
        return True
    else:
        print("  ✗ Form not detected")
        return False

def test_input_group_form():
    """Test detection of input group that functions as a form."""
    print("\nTesting input group form...")
    html = """
    <html>
    <body>
        <div class="reservation-form">
            <input name="customer_name" type="text">
            <input name="phone" type="tel">
            <input name="party_size" type="number">
            <button type="submit">Book Table</button>
        </div>
    </body>
    </html>
    """
    analyzer = PageAnalyzer()
    forms = analyzer.extract_forms(html)
    print(f"  Found {len(forms)} forms")
    if forms:
        print(f"  ✓ Form detected: {len(forms[0]['fields'])} fields")
        return True
    else:
        print("  ✗ Form not detected")
        return False

def test_hidden_modal_form():
    """Test detection of form in hidden modal."""
    print("\nTesting hidden modal form...")
    html = """
    <html>
    <body>
        <div class="modal" style="display: none;" aria-modal="true">
            <div class="form-container">
                <input name="customer_name" type="text">
                <input name="phone" type="text">
                <input name="date" type="date">
                <button>Save</button>
            </div>
        </div>
    </body>
    </html>
    """
    analyzer = PageAnalyzer()
    forms = analyzer.extract_forms(html)
    print(f"  Found {len(forms)} forms")
    if forms:
        print(f"  ✓ Form detected: {len(forms[0]['fields'])} fields")
        return True
    else:
        print("  ✗ Form not detected")
        return False

def main():
    """Run all tests."""
    print("=" * 60)
    print("Enhanced Form Detection Tests")
    print("=" * 60)
    
    results = []
    results.append(("Traditional Form", test_traditional_form()))
    results.append(("Modal Form", test_modal_form()))
    results.append(("Input Group Form", test_input_group_form()))
    results.append(("Hidden Modal Form", test_hidden_modal_form()))
    
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    
    for name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status}: {name}")
    
    all_passed = all(result[1] for result in results)
    
    print("\n" + "=" * 60)
    if all_passed:
        print("✓ All form detection tests passed!")
    else:
        print("✗ Some tests failed. Check the output above.")
    print("=" * 60)
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())

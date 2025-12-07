"""
Scenario-Based Vulnerability Guidance

Provides scenario-based vulnerability mapping to guide the red team agent
on which vulnerabilities to prioritize based on detected website components.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from vibe_code_bench.core.paths import get_resources_dir, get_repo_root
from vibe_code_bench.core.logging_setup import get_logger

logger = get_logger(__name__)


def load_scenario_mapping() -> Dict[str, Any]:
    """
    Load the scenario vulnerability mapping from JSON file.
    
    Returns:
        Dictionary containing scenario definitions with components and vulnerability expectations
        
    Raises:
        FileNotFoundError: If the mapping file doesn't exist
        json.JSONDecodeError: If the JSON is invalid
    """
    resources_dir = get_resources_dir()
    mapping_file = resources_dir / "scenario_vulnerability_mapping.json"
    
    if not mapping_file.exists():
        # Try repo root as fallback
        repo_root = get_repo_root()
        mapping_file = repo_root / "data" / "resources" / "scenario_vulnerability_mapping.json"
        
        if not mapping_file.exists():
            logger.warning(f"Scenario mapping file not found at {mapping_file}")
            return {}
    
    try:
        with open(mapping_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        logger.debug(f"Loaded scenario mapping from {mapping_file}")
        return data.get("scenarios", {})
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in scenario mapping file: {e}")
        raise
    except Exception as e:
        logger.error(f"Error loading scenario mapping: {e}")
        return {}


def generate_scenario_guidance_text(scenarios: Optional[Dict[str, Any]] = None) -> str:
    """
    Generate guidance text for the agent based on scenario vulnerability mapping.
    
    Args:
        scenarios: Optional pre-loaded scenarios dict. If None, loads from file.
        
    Returns:
        Formatted guidance text to include in agent prompt
    """
    if scenarios is None:
        scenarios = load_scenario_mapping()
    
    if not scenarios:
        return ""
    
    guidance_lines = [
        "",
        "=" * 70,
        "SCENARIO-BASED VULNERABILITY GUIDANCE",
        "=" * 70,
        "",
        "As you discover components and features on the website, match them to scenarios",
        "below to prioritize your vulnerability testing. This will help you focus on",
        "the most likely vulnerabilities for each component type.",
        "",
        "SCENARIO DEFINITIONS:",
        ""
    ]
    
    # Add each scenario with its components and vulnerability expectations
    for scenario_name, scenario_data in scenarios.items():
        components_data = scenario_data.get("components", {})
        vulnerabilities = scenario_data.get("vulnerabilities", {})
        
        # Handle both old format (list) and new format (object with nested keys)
        if isinstance(components_data, list):
            # Old format: components is a list
            components_list = components_data
        else:
            # New format: components is an object with keys like "general", "routes", etc.
            components_list = []
            if "general" in components_data:
                components_list.extend(components_data["general"])
            if "routes" in components_data:
                components_list.extend([f"route: {r}" for r in components_data["routes"]])
            if "inputs" in components_data:
                components_list.extend([f"input: {i}" for i in components_data["inputs"]])
            if "auth" in components_data:
                components_list.extend([f"auth: {a}" for a in components_data["auth"]])
            if "db" in components_data:
                components_list.extend([f"db: {d}" for d in components_data["db"]])
        
        # Format scenario name - use "name" field if available, otherwise format from key
        scenario_display = scenario_data.get("name", scenario_name.replace("_", " ").title())
        
        guidance_lines.append(f"  {scenario_display}:")
        if components_list:
            guidance_lines.append(f"    Components: {', '.join(components_list[:10])}")  # Limit to first 10
            if len(components_list) > 10:
                guidance_lines.append(f"      ... and {len(components_list) - 10} more")
        
        # Group vulnerabilities by expectation level
        expected = []
        possible = []
        na = []
        
        for vuln_name, expectation in vulnerabilities.items():
            vuln_display = vuln_name.replace("_", " ").title()
            if expectation == "expected":
                expected.append(vuln_display)
            elif expectation == "possible":
                possible.append(vuln_display)
            elif expectation == "na":
                na.append(vuln_display)
        
        if expected:
            guidance_lines.append(f"    EXPECTED vulnerabilities (test these first):")
            for vuln in expected:
                guidance_lines.append(f"      • {vuln}")
        
        if possible:
            guidance_lines.append(f"    POSSIBLE vulnerabilities (test if applicable):")
            for vuln in possible:
                guidance_lines.append(f"      • {vuln}")
        
        if na:
            guidance_lines.append(f"    NOT APPLICABLE (skip these):")
            for vuln in na:
                guidance_lines.append(f"      • {vuln}")
        
        guidance_lines.append("")
    
    guidance_lines.extend([
        "HOW TO USE THIS GUIDANCE:",
        "",
        "1. As you browse and discover website features, identify which scenarios match:",
        "   - Login forms → login_form scenario",
        "   - Contact forms → contact_form scenario",
        "   - Comment sections → comment_system scenario",
        "   - Admin areas → admin_panel scenario",
        "   - File uploads → file_upload_portal scenario",
        "   - CRUD applications → todo_app scenario",
        "   - Static content sites → static_blog scenario",
        "   - E-commerce sites → ecommerce_store scenario",
        "   - Chat/messaging apps → multi_user_chat scenario",
        "",
        "2. For each matching scenario:",
        "   - PRIORITIZE testing vulnerabilities marked as 'expected'",
        "   - TEST vulnerabilities marked as 'possible' if time/resources allow",
        "   - SKIP vulnerabilities marked as 'na' (not applicable)",
        "",
        "3. You may discover multiple scenarios on a single website:",
        "   - Test all applicable scenarios",
        "   - Combine vulnerability findings into comprehensive report",
        "",
        "4. Even if a scenario isn't listed, still perform comprehensive testing",
        "   - This guidance is a prioritization tool, not a restriction",
        "",
        "=" * 70,
        ""
    ])
    
    return "\n".join(guidance_lines)


def match_scenario_to_features(
    detected_components: List[str],
    scenarios: Optional[Dict[str, Any]] = None
) -> List[tuple[str, float]]:
    """
    Match detected website features/components to scenarios.
    
    Args:
        detected_components: List of detected component types (e.g., ["form", "authentication"])
        scenarios: Optional pre-loaded scenarios dict. If None, loads from file.
        
    Returns:
        List of tuples (scenario_name, match_score) sorted by score descending.
        Score is number of matching components / total components in scenario.
    """
    if scenarios is None:
        scenarios = load_scenario_mapping()
    
    if not scenarios or not detected_components:
        return []
    
    matches = []
    detected_lower = [c.lower() for c in detected_components]
    
    for scenario_name, scenario_data in scenarios.items():
        components_data = scenario_data.get("components", {})
        
        # Handle both old format (list) and new format (object with nested keys)
        if isinstance(components_data, list):
            scenario_components = components_data
        else:
            # New format: extract all components
            scenario_components = []
            if "general" in components_data:
                scenario_components.extend(components_data["general"])
            if "routes" in components_data:
                scenario_components.extend(components_data["routes"])
            if "inputs" in components_data:
                scenario_components.extend(components_data["inputs"])
            if "auth" in components_data:
                scenario_components.extend(components_data["auth"])
            if "db" in components_data:
                scenario_components.extend(components_data["db"])
        
        scenario_components_lower = [c.lower() for c in scenario_components]
        
        # Count matching components
        matches_count = sum(1 for comp in detected_lower if comp in scenario_components_lower)
        
        if matches_count > 0:
            # Calculate match score (percentage of scenario components found)
            score = matches_count / len(scenario_components) if scenario_components else 0
            matches.append((scenario_name, score))
    
    # Sort by score descending
    matches.sort(key=lambda x: x[1], reverse=True)
    return matches


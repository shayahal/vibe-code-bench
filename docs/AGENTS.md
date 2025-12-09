# Orchestrator Agents Overview

This document provides a simple overview of all agents in the orchestrator workflow.

## Agents

### 1. Website Builder Agent
**Role:** Website Builder  
**Goal:** Generate complete, functional website code from prompts including HTML, CSS, JavaScript, and Flask backend

**Responsibilities:**
- Creates complete website codebases
- Generates HTML pages, CSS styling, JavaScript functionality
- Creates Flask backend with proper routing
- Ensures code follows best practices
- Includes main.py Flask server file

**Model:** Claude 3 Haiku (default)  
**Temperature:** 0.7  
**Max Tokens:** 8192

---

### 2. Static Analysis Agent
**Role:** Static Code Analyst  
**Goal:** Perform comprehensive static code analysis to identify security vulnerabilities and code quality issues

**Responsibilities:**
- Runs Bandit (Python security linter)
- Runs Semgrep (general static analysis)
- Runs npm audit (Node.js dependency vulnerabilities)
- Analyzes code for security issues
- Provides detailed reports with severity classifications

**Model:** Claude 3 Haiku (default)  
**Temperature:** 0.3  
**Max Tokens:** 4096

---

### 3. Red Team Agent
**Role:** Security Tester (Red Team)  
**Goal:** Perform comprehensive security testing on web applications to identify vulnerabilities including XSS, SQL injection, authentication flaws, and security header issues

**Responsibilities:**
- Performs penetration testing
- Tests for XSS vulnerabilities
- Tests for SQL injection flaws
- Analyzes authentication weaknesses
- Checks security header misconfigurations
- Provides detailed security assessment reports

**Tools:** 
- Browse Tool
- Crawl Website Tool
- XSS Test Tool
- SQL Injection Test Tool
- Authentication Analysis Tool
- Security Headers Tool
- Security Report Tool
- Test All Pages Tool

**Model:** Claude 3 Haiku (default)  
**Temperature:** 0.7  
**Max Tokens:** 4096

---

### 4. Website Builder Evaluator Agent
**Role:** Website Quality Evaluator  
**Goal:** Evaluate website builder output against ground truth criteria to assess quality, completeness, and correctness

**Responsibilities:**
- Compares generated websites against ground truth specifications
- Checks for completeness and correctness
- Validates functionality
- Verifies adherence to requirements
- Provides detailed evaluation reports with metrics and scores

**Model:** Claude 3 Haiku (default)  
**Temperature:** 0.3  
**Max Tokens:** 4096

---

### 5. Red Team Evaluator Agent
**Role:** Security Findings Evaluator  
**Goal:** Evaluate red team security findings against ground truth vulnerabilities to assess detection accuracy and completeness

**Responsibilities:**
- Compares security testing findings against known ground truth vulnerabilities
- Calculates detection rates
- Identifies false positives and false negatives
- Provides comprehensive evaluation metrics

**Model:** Claude 3 Haiku (default)  
**Temperature:** 0.3  
**Max Tokens:** 4096

---

### 6. Final Report Agent
**Role:** Report Generator  
**Goal:** Generate comprehensive final reports that consolidate all evaluation results, findings, and metrics into clear, actionable documentation

**Responsibilities:**
- Synthesizes complex evaluation data from multiple sources
- Creates well-structured markdown and JSON reports
- Includes all relevant metrics, findings, and recommendations
- Consolidates all agent outputs into unified reports

**Model:** Claude 3 Haiku (default)  
**Temperature:** 0.5  
**Max Tokens:** 8192

---

## Workflow

The agents execute in the following order:

1. **Website Builder** → Builds the website
2. **Static Analysis** → Analyzes the code statically
3. **Server Manager** → Starts the website server (utility, not an agent)
4. **Red Team** → Tests the running website
5. **Server Manager** → Stops the website server (utility, not an agent)
6. **Website Builder Evaluator** → Evaluates website quality (optional)
7. **Red Team Evaluator** → Evaluates red team findings (optional)
8. **Final Report** → Generates consolidated reports

## Report Organization

All reports are organized by agent in the `reports/` directory:

```
reports/
├── static_analysis/         # Static analysis results
├── red_team/                # Red team testing results
├── website_builder_evaluator/  # Website builder evaluation
├── red_team_evaluator/      # Red team evaluation
└── final/                   # Final consolidated reports
```

Main consolidated reports are also available in the run root:
- `run.json` - Complete run data
- `report.md` - Human-readable summary



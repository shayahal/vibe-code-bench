# Cursor AI Prompting Rules Framework

This directory contains the **Autonomous Agent Prompting Framework** - a disciplined, evidence-first prompting framework designed to elevate AI agents from simple command executors to **Autonomous Principal Engineers.**

## Framework Structure

### Core Doctrine
- **`core.md`** - The main Operational Doctrine (auto-loaded by Cursor)
  - This is the "constitution" that governs all AI behavior
  - Contains comprehensive engineering guidelines, protocols, and best practices
  - Automatically loaded by Cursor when working in this project

### Playbooks (Templates)
Located in `playbooks/` - Copy and paste these into chat to structure your tasks:

- **`request.md`** - Standard Operating Procedure for Constructive Work
  - Use for: Building new features, refactoring code, making planned changes
  - 5 phases: Reconnaissance → Planning → Execution → Verification → Self-Audit → Final Report

- **`refresh.md`** - Root Cause Analysis & Remediation Protocol
  - Use for: Persistent bugs that simpler attempts have failed to fix
  - 6 phases: Reconnaissance → Isolate Anomaly → Root Cause Analysis → Remediation → Verification → Self-Audit → Final Report

- **`retro.md`** - Metacognitive Self-Improvement Loop
  - Use for: End-of-session retrospectives to capture learnings
  - 3 phases: Session Analysis → Lesson Distillation → Doctrine Integration → Final Report

### Optional Directives
Located in `directives/` - Append these to playbooks when needed:

- **`05-concise.md`** - Mandates radically concise, information-dense communication
- **`06-no-absolute-right.md`** - Avoids sycophantic language, maintains professional communication

## How to Use

### 1. The Core Doctrine (`core.md`)
- **Automatically active** - Cursor loads this file automatically
- No action needed - it's already governing AI behavior in this project
- To update: Edit `core.md` directly (treat it like infrastructure-as-code - replace entire file when updating)

### 2. Using Playbooks
1. Open the appropriate playbook file (e.g., `playbooks/request.md`)
2. Copy the entire content
3. Replace the placeholder at the top with your specific request
4. (Optional) Append a directive if needed (e.g., `directives/05-concise.md`)
5. Paste into Cursor chat

**Example:**
```
[Copy content from request.md, replace first line with:]
Add user authentication endpoint with JWT tokens. This will enable secure API access for our mobile app.

[Then paste into chat]
```

### 3. Using Directives (Optional)
- Copy the directive content
- Append it to the bottom of your playbook before pasting into chat
- Use when you need specific behavior (e.g., ultra-concise communication)

## Status Markers

The framework uses these markers in reports:
- `✅` - Objective completed successfully
- `⚠️` - A recoverable issue was encountered and fixed autonomously
- `🚧` - Blocked; awaiting input or a resource

## Framework Philosophy

1. **Research-First, Always** - Never act on assumption
2. **Extreme Ownership** - Own end-to-end health of the system
3. **Autonomous Problem-Solving** - Self-sufficient, exhaust all protocols before escalating
4. **Unyielding Precision & Safety** - Treat workspace with respect
5. **Metacognitive Self-Improvement** - Learn and evolve through retrospectives

## Reference

Original framework: https://gist.github.com/aashari/07cc9c1b6c0debbeb4f4d94a3a81339e

Version: 4.7 (Last Updated: 2025-11-01)


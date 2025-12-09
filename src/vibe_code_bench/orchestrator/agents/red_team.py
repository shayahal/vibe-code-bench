"""
Red Team Agent Node

Runs the red team agent to perform security testing on a website (evaluation happens separately).
"""

from pathlib import Path

from vibe_code_bench.orchestrator.state import OrchestratorState
from vibe_code_bench.core.logging_setup import get_logger
from vibe_code_bench.red_team_agent.agent_common import (
    initialize_langfuse,
    initialize_llm,
    create_and_run_agent,
    save_report
)
from vibe_code_bench.red_team_agent.tools import get_all_tools
from vibe_code_bench.red_team_agent.report_generator import generate_run_report
from vibe_code_bench.red_team_agent.red_team_prompt import RED_TEAM_AGENT_PROMPT

logger = get_logger(__name__)


def red_team_node(state: OrchestratorState) -> OrchestratorState:
    """
    Run red team agent on the website.
    
    Args:
        state: Current orchestrator state
        
    Returns:
        Updated state with red_team_result
    """
    logger.info("="*60)
    logger.info("STEP 3: Running Red Team Agent")
    logger.info("="*60)
    
    url = state.get("url")
    if not url:
        logger.error("url not set in state - cannot run red team agent")
        raise ValueError("url not set in state - cannot run red team agent")
    
    run_id = state.get("run_id")
    if not run_id:
        logger.error("run_id not set in state")
        raise ValueError("run_id not set in state")
    
    red_team_model = state.get("red_team_model", "anthropic/claude-3-haiku")
    output_dir = state.get("output_dir")
    
    # Initialize LangFuse
    langfuse_client, langfuse_handler = initialize_langfuse()
    
    # Initialize LLM
    llm = initialize_llm(
        model_name=red_team_model,
        api_key=None,
        langfuse_handler=langfuse_handler,
        title="Red Team Agent"
    )
    
    logger.info(f"Using model: {red_team_model}")
    
    # Get tools
    all_tools = get_all_tools()
    logger.info(f"Loaded {len(all_tools)} security testing tools")
    logger.debug(f"Tools: {[tool.name for tool in all_tools]}")
    
    # Run agent
    red_team_run_id = f"{run_id}_redteam"
    logger.info(f"Starting security assessment for {url}")
    output, execution_time, trace_id = create_and_run_agent(
        llm=llm,
        all_tools=all_tools,
        system_prompt=RED_TEAM_AGENT_PROMPT,
        url=url,
        langfuse_handler=langfuse_handler,
        langfuse_client=langfuse_client,
        model_name=red_team_model,
        run_id=red_team_run_id
    )
    
    # Generate report (both markdown and structured)
    logger.info("Generating security assessment report")
    report, structured_report = generate_run_report(
        llm=llm,
        langfuse_client=langfuse_client,
        url=url,
        output=output,
        execution_time=execution_time,
        langfuse_handler=langfuse_handler,
        run_id=red_team_run_id,
        model_name=red_team_model
    )
    
    # Save reports to run directory
    run_dir = state.get("run_dir")
    # Save reports to agent-specific directory
    run_dir = state.get("run_dir")
    if run_dir:
        run_dir = Path(run_dir)
        agent_dir = run_dir / "reports" / "red_team"
        agent_dir.mkdir(parents=True, exist_ok=True)
        
        # Save markdown report
        md_file = agent_dir / "red_team_report.md"
        with open(md_file, 'w', encoding='utf-8') as f:
            f.write(report)
        logger.info(f"Red team report saved: {md_file}")

        # Also save structured JSON if available
        json_file = None
        if structured_report:
            import json
            json_file = agent_dir / "red_team_structured.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(structured_report, f, indent=2, ensure_ascii=False)
            logger.info(f"Red team structured JSON saved: {json_file}")
        
        # Update state with new report file path
        state['red_team_report_file'] = md_file
    else:
        # Fallback to daily directory for backward compatibility
        from vibe_code_bench.core.paths import get_daily_reports_dir
        daily_reports_dir = get_daily_reports_dir(run_id)
        md_file, json_file = save_report(
            report,
            red_team_run_id,
            report_dir_path=str(daily_reports_dir),
            structured_report=structured_report
        )
    
    logger.info("Red team assessment completed")
    logger.info(f"Execution time: {execution_time:.2f}s")
    logger.info(f"Markdown report saved: {md_file}")
    if json_file:
        logger.info(f"Structured JSON report saved: {json_file}")
    
    # Update state with red team result
    red_team_result = {
        'output': output,
        'report': report,
        'structured_report': structured_report,
        'report_file': md_file,
        'json_report_file': json_file,
        'execution_time': execution_time,
        'trace_id': trace_id
    }
    
    # Return updated state (evaluation will happen later)
    return {
        **state,
        'red_team_result': red_team_result,
        'next': 'server_manager'  # Next step is to stop the server
    }


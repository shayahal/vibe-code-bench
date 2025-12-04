"""
Red Team Agent Node

Runs the red team agent to perform security testing on a website.
"""

from vibe_code_bench.orchestrator.state import OrchestratorState
from vibe_code_bench.red_team_agent.agent_common import (
    initialize_langfuse,
    initialize_llm,
    create_and_run_agent,
    flush_langfuse,
    save_report
)
from vibe_code_bench.red_team_agent.tools import get_all_tools
from vibe_code_bench.red_team_agent.report_generator import generate_run_report
from vibe_code_bench.red_team_agent.red_team_prompt import RED_TEAM_AGENT_PROMPT


def red_team_node(state: OrchestratorState) -> OrchestratorState:
    """
    Run red team agent on the website.
    
    Args:
        state: Current orchestrator state
        
    Returns:
        Updated state with red_team_result
    """
    print("\n" + "="*60)
    print("STEP 3: Running Red Team Agent")
    print("="*60)
    
    url = state.get("url")
    if not url:
        raise ValueError("url not set in state - cannot run red team agent")
    
    run_id = state.get("run_id")
    if not run_id:
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
    
    print(f"✓ Using model: {red_team_model}")
    
    # Get tools
    all_tools = get_all_tools()
    print(f"✓ Loaded {len(all_tools)} security testing tools")
    
    # Run agent
    red_team_run_id = f"{run_id}_redteam"
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
    
    # Generate report
    report = generate_run_report(
        llm=llm,
        langfuse_client=langfuse_client,
        url=url,
        output=output,
        execution_time=execution_time,
        langfuse_handler=langfuse_handler,
        run_id=red_team_run_id,
        model_name=red_team_model
    )
    
    # Save report (uses standard reports directory)
    report_file = save_report(report, red_team_run_id)
    
    print(f"✓ Red team assessment completed")
    print(f"  Execution time: {execution_time:.2f}s")
    print(f"  Report saved: {report_file}")
    
    # Update state
    red_team_result = {
        'output': output,
        'report': report,
        'report_file': report_file,
        'execution_time': execution_time,
        'trace_id': trace_id
    }
    
    return {
        **state,
        'red_team_result': red_team_result,
        'next': 'server_manager'  # Next step is to stop the server
    }


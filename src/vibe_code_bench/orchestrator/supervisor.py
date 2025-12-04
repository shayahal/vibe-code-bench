"""
Supervisor agent for routing tasks in the hierarchical orchestrator.

The supervisor coordinates the workflow by routing to appropriate agents.
"""

from typing import Literal
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_openai import ChatOpenAI
import os

from vibe_code_bench.orchestrator.state import OrchestratorState


# System prompt for the supervisor
SUPERVISOR_PROMPT = """You are a supervisor managing a security evaluation workflow.

Your job is to route tasks to the appropriate agent based on the current state of the workflow.

Available agents:
1. **website_builder**: Builds a website from a prompt. Use when website_dir is None or build_result is None.
2. **server_manager**: Manages the Flask server lifecycle (start/stop). Use when:
   - website_dir exists but url is None (need to start server)
   - url exists but need to stop server (after red team testing)
3. **red_team_agent**: Performs security testing on a website. Use when url exists and red_team_result is None.
4. **evaluator**: Evaluates red team findings against ground truth. Use when red_team_result exists but eval_results is None.
5. **__end__**: End the workflow when evaluation is complete (eval_results exists).

Workflow order:
1. website_builder (if not built)
2. server_manager start (if not started)
3. red_team_agent (if not tested)
4. server_manager stop (after testing)
5. evaluator (if not evaluated)
6. __end__ (when complete)

Based on the current state, determine the next agent to execute.
Respond with ONLY the agent name: website_builder, server_manager, red_team_agent, evaluator, or __end__
"""


def create_supervisor_chain(model_name: str = "anthropic/claude-3-haiku"):
    """
    Create the supervisor LLM chain.
    
    Args:
        model_name: Model to use for supervisor
        
    Returns:
        LLM chain for routing decisions
    """
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise Exception("OPENROUTER_API_KEY not found")
    
    llm = ChatOpenAI(
        model=model_name,
        api_key=api_key,
        base_url="https://openrouter.ai/api/v1",
        temperature=0,
        max_tokens=50,  # Very short responses
        default_headers={
            "HTTP-Referer": "https://github.com/shayahal/vibe-code-bench",
            "X-Title": "Orchestrator Supervisor"
        }
    )
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", SUPERVISOR_PROMPT),
        MessagesPlaceholder(variable_name="messages"),
        ("human", "What is the next agent to execute? Current state:\n- website_dir: {website_dir}\n- url: {url}\n- build_result: {build_result}\n- red_team_result: {red_team_result}\n- eval_results: {eval_results}"),
    ])
    
    return prompt | llm


def supervisor_node(state: OrchestratorState) -> OrchestratorState:
    """
    Supervisor node that routes to the next agent.
    
    Args:
        state: Current orchestrator state
        
    Returns:
        Updated state with next agent set
    """
    next_agent = route_supervisor(state)
    return {
        **state,
        'next': next_agent
    }


def route_supervisor(state: OrchestratorState) -> Literal["website_builder", "server_manager", "red_team_agent", "evaluator", "__end__"]:
    """
    Route to the next agent based on state.
    
    This function implements deterministic routing logic based on the workflow state.
    It checks what has been completed and routes to the next step.
    
    Args:
        state: Current orchestrator state
        
    Returns:
        Name of the next agent to execute
    """
    # Check if website is built
    if not state.get("website_dir") or not state.get("build_result"):
        return "website_builder"
    
    # Check if server needs to be started
    if not state.get("url") and state.get("website_dir"):
        # Check if we need to start (server not started yet)
        return "server_manager"
    
    # Check if red team testing is done
    if state.get("url") and not state.get("red_team_result"):
        return "red_team_agent"
    
    # Check if server needs to be stopped (after red team testing)
    if state.get("red_team_result") and state.get("url") and state.get("server"):
        # Server is still running, need to stop it
        return "server_manager"
    
    # Check if evaluation is done
    if state.get("red_team_result") and not state.get("eval_results"):
        return "evaluator"
    
    # Everything is complete
    return "__end__"


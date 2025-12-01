"""
Example usage of the LangChain Orchestrator.

This script demonstrates how to use the orchestrator to coordinate
multiple agents and execute tasks.
"""

import asyncio
import os
from dotenv import load_dotenv
from orchestrator import LangChainOrchestrator
from example_agents import setup_example_agents

# Load environment variables
load_dotenv()


async def basic_example():
    """Basic example of using the orchestrator."""
    print("=" * 60)
    print("Basic Orchestrator Example")
    print("=" * 60)
    
    # Initialize orchestrator
    orchestrator = LangChainOrchestrator(verbose=True)
    
    # Setup example agents
    setup_example_agents(orchestrator)
    
    # Create tasks
    task1_id = orchestrator.create_task(
        description="Calculate (25 * 4) + (100 / 2)",
        agent_name="math_agent"
    )
    
    task2_id = orchestrator.create_task(
        description="Analyze this text: 'The quick brown fox jumps over the lazy dog. This is a test sentence.'",
        agent_name="analysis_agent"
    )
    
    # Execute tasks sequentially
    print("\n--- Executing tasks sequentially ---")
    results = await orchestrator.execute_tasks(parallel=False)
    
    # Display results
    print("\n--- Results ---")
    for task_id, result in results.items():
        task = orchestrator.tasks[task_id]
        print(f"\nTask: {task.description}")
        print(f"Status: {task.status.value}")
        print(f"Result: {result}")
    
    return orchestrator


async def parallel_example():
    """Example of parallel task execution."""
    print("\n" + "=" * 60)
    print("Parallel Execution Example")
    print("=" * 60)
    
    orchestrator = LangChainOrchestrator(verbose=True)
    setup_example_agents(orchestrator)
    
    # Create multiple tasks
    tasks = [
        "Calculate 2^10",
        "Calculate 15 * 23",
        "Calculate 1000 / 25"
    ]
    
    task_ids = []
    for task_desc in tasks:
        task_id = orchestrator.create_task(
            description=task_desc,
            agent_name="math_agent"
        )
        task_ids.append(task_id)
    
    # Execute in parallel
    print("\n--- Executing tasks in parallel ---")
    results = await orchestrator.execute_tasks(task_ids=task_ids, parallel=True)
    
    print("\n--- Results ---")
    for task_id, result in results.items():
        task = orchestrator.tasks[task_id]
        print(f"{task.description}: {result}")
    
    return orchestrator


async def shared_state_example():
    """Example using shared state."""
    print("\n" + "=" * 60)
    print("Shared State Example")
    print("=" * 60)
    
    orchestrator = LangChainOrchestrator(verbose=True)
    setup_example_agents(orchestrator)
    
    # Set shared state
    orchestrator.set_shared_state("user_name", "Alice")
    orchestrator.set_shared_state("project", "LangChain Orchestrator")
    
    # Create task that can use shared state
    task_id = orchestrator.create_task(
        description="Greet the user and mention the project they're working on",
        agent_name="general_agent"
    )
    
    print("\n--- Executing task with shared state ---")
    result = await orchestrator.execute_task(task_id)
    
    print(f"\nResult: {result}")
    print(f"\nShared State: {orchestrator.shared_state}")
    
    return orchestrator


async def agent_selection_example():
    """Example of automatic agent selection."""
    print("\n" + "=" * 60)
    print("Automatic Agent Selection Example")
    print("=" * 60)
    
    orchestrator = LangChainOrchestrator(verbose=True)
    setup_example_agents(orchestrator)
    
    # Create tasks without specifying agent
    tasks = [
        "What is 50 * 30?",
        "Analyze the text: 'Hello world, this is a test.'",
        "Help me understand how to use the orchestrator"
    ]
    
    task_ids = []
    for task_desc in tasks:
        task_id = orchestrator.create_task(description=task_desc)
        task_ids.append(task_id)
    
    print("\n--- Executing tasks with auto-selected agents ---")
    results = await orchestrator.execute_tasks(task_ids=task_ids, parallel=False)
    
    print("\n--- Results ---")
    for task_id, result in results.items():
        task = orchestrator.tasks[task_id]
        selected_agent = task.agent_name or "auto-selected"
        print(f"\nTask: {task.description}")
        print(f"Agent: {selected_agent}")
        print(f"Result: {result}")
    
    return orchestrator


async def main():
    """Run all examples."""
    # Check for OpenAI API key
    if not os.getenv("OPENAI_API_KEY"):
        print("Warning: OPENAI_API_KEY not found in environment variables.")
        print("Please set it in a .env file or export it.")
        return
    
    try:
        # Run examples
        await basic_example()
        await parallel_example()
        await shared_state_example()
        await agent_selection_example()
        
        print("\n" + "=" * 60)
        print("All examples completed!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\nError: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())

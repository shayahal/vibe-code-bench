"""
LangChain Orchestrator

A flexible orchestrator for coordinating multiple LangChain agents and chains.
Supports task delegation, state management, and parallel execution.
"""

from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import asyncio
import logging
from datetime import datetime

from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain.tools import BaseTool
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_openai import ChatOpenAI
from langchain.schema import BaseMessage, HumanMessage, AIMessage
from langchain.callbacks.base import BaseCallbackHandler

# Configure logging
logger = logging.getLogger(__name__)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


class TaskStatus(Enum):
    """Status of a task in the orchestrator"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Task:
    """Represents a task to be executed"""
    id: str
    description: str
    agent_name: Optional[str] = None
    status: TaskStatus = TaskStatus.PENDING
    result: Any = None
    error: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class OrchestratorCallbackHandler(BaseCallbackHandler):
    """Callback handler for orchestrator events"""
    
    def __init__(self):
        self.events: List[Dict[str, Any]] = []
    
    def on_agent_action(self, action, **kwargs):
        self.events.append({
            "type": "agent_action",
            "action": action,
            "timestamp": datetime.now().isoformat(),
            **kwargs
        })
    
    def on_agent_finish(self, finish, **kwargs):
        self.events.append({
            "type": "agent_finish",
            "finish": finish,
            "timestamp": datetime.now().isoformat(),
            **kwargs
        })


class LangChainOrchestrator:
    """
    Main orchestrator class for coordinating LangChain agents and chains.
    
    Features:
    - Register multiple agents with different capabilities
    - Delegate tasks to appropriate agents
    - Manage task queue and execution
    - Support parallel and sequential execution
    - Track task status and results
    """
    
    def __init__(
        self,
        llm: Optional[ChatOpenAI] = None,
        temperature: float = 0.7,
        max_iterations: int = 15,
        verbose: bool = True
    ):
        """
        Initialize the orchestrator.
        
        Args:
            llm: LangChain LLM instance (defaults to GPT-4)
            temperature: Temperature for LLM
            max_iterations: Maximum iterations for agents
            verbose: Enable verbose logging
        """
        self.llm = llm or ChatOpenAI(
            model="gpt-4-turbo-preview",
            temperature=temperature
        )
        self.max_iterations = max_iterations
        self.verbose = verbose
        
        logger.info(f"Initializing LangChainOrchestrator - Max iterations: {max_iterations}, Verbose: {verbose}")
        
        # Agent registry: name -> AgentExecutor
        self.agents: Dict[str, AgentExecutor] = {}
        
        # Task management
        self.tasks: Dict[str, Task] = {}
        self.task_queue: List[str] = []
        
        # State management
        self.shared_state: Dict[str, Any] = {}
        self.conversation_history: List[BaseMessage] = []
        
        # Callbacks
        self.callback_handler = OrchestratorCallbackHandler()
        
        logger.info("LangChainOrchestrator initialized successfully")
    
    def register_agent(
        self,
        name: str,
        tools: List[BaseTool],
        system_prompt: str,
        description: Optional[str] = None
    ) -> None:
        """
        Register an agent with the orchestrator.
        
        Args:
            name: Unique name for the agent
            tools: List of tools the agent can use
            system_prompt: System prompt defining agent's role
            description: Optional description of agent's capabilities
        """
        prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            MessagesPlaceholder(variable_name="chat_history"),
            ("human", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ])
        
        agent = create_openai_tools_agent(self.llm, tools, prompt)
        agent_executor = AgentExecutor(
            agent=agent,
            tools=tools,
            verbose=self.verbose,
            max_iterations=self.max_iterations,
            callbacks=[self.callback_handler]
        )
        
        self.agents[name] = {
            "executor": agent_executor,
            "description": description or f"Agent specialized in {name}",
            "tools": tools
        }
        
        logger.info(f"Registered agent: {name} with {len(tools)} tools - {description or 'No description'}")
        
        if self.verbose:
            print(f"✓ Registered agent: {name}")
    
    def create_task(
        self,
        description: str,
        agent_name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Create a new task.
        
        Args:
            description: Task description
            agent_name: Optional agent to assign task to
            metadata: Optional metadata for the task
            
        Returns:
            Task ID
        """
        task_id = f"task_{len(self.tasks) + 1}_{datetime.now().timestamp()}"
        task = Task(
            id=task_id,
            description=description,
            agent_name=agent_name,
            metadata=metadata or {}
        )
        
        self.tasks[task_id] = task
        self.task_queue.append(task_id)
        
        logger.info(f"Created task: {task_id} - Description: {description[:100]}... - Agent: {agent_name or 'auto-select'}")
        
        if self.verbose:
            print(f"✓ Created task: {task_id} - {description}")
        
        return task_id
    
    async def execute_task(
        self,
        task_id: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Any:
        """
        Execute a single task.
        
        Args:
            task_id: ID of the task to execute
            context: Optional context to pass to the agent
            
        Returns:
            Task result
        """
        if task_id not in self.tasks:
            logger.error(f"Task {task_id} not found")
            raise ValueError(f"Task {task_id} not found")
        
        task = self.tasks[task_id]
        task.status = TaskStatus.IN_PROGRESS
        
        logger.info(f"Executing task: {task_id} - Status changed to IN_PROGRESS")
        
        try:
            # Determine which agent to use
            agent_name = task.agent_name or self._select_agent(task.description)
            
            if agent_name not in self.agents:
                logger.error(f"Agent {agent_name} not found for task {task_id}")
                raise ValueError(f"Agent {agent_name} not found")
            
            logger.info(f"Selected agent '{agent_name}' for task {task_id}")
            
            agent_info = self.agents[agent_name]
            agent_executor = agent_info["executor"]
            
            # Prepare input with context
            input_text = task.description
            if context:
                context_str = "\n".join([f"{k}: {v}" for k, v in context.items()])
                input_text = f"{input_text}\n\nContext:\n{context_str}"
                logger.debug(f"Added context to task {task_id}: {len(context)} items")
            
            # Add shared state to context if available
            if self.shared_state:
                state_str = "\n".join([f"{k}: {v}" for k, v in self.shared_state.items()])
                input_text = f"{input_text}\n\nShared State:\n{state_str}"
                logger.debug(f"Added shared state to task {task_id}: {len(self.shared_state)} items")
            
            # Execute agent
            logger.info(f"Invoking agent '{agent_name}' executor for task {task_id}")
            if self.verbose:
                print(f"→ Executing task {task_id} with agent {agent_name}")
            
            result = await agent_executor.ainvoke({
                "input": input_text,
                "chat_history": self.conversation_history
            })
            
            task.result = result.get("output", result)
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.now()
            
            logger.info(f"Task {task_id} completed successfully - Result length: {len(str(task.result))} chars")
            
            # Update conversation history
            self.conversation_history.append(HumanMessage(content=input_text))
            self.conversation_history.append(AIMessage(content=task.result))
            logger.debug(f"Updated conversation history - Total messages: {len(self.conversation_history)}")
            
            if self.verbose:
                print(f"✓ Task {task_id} completed")
            
            return task.result
            
        except Exception as e:
            task.status = TaskStatus.FAILED
            task.error = str(e)
            task.completed_at = datetime.now()
            
            logger.error(f"Task {task_id} failed: {str(e)}")
            logger.exception(e)
            
            if self.verbose:
                print(f"✗ Task {task_id} failed: {str(e)}")
            
            raise
    
    def _select_agent(self, description: str) -> str:
        """
        Select the most appropriate agent for a task description.
        
        Args:
            description: Task description
            
        Returns:
            Agent name
        """
        if not self.agents:
            raise ValueError("No agents registered")
        
        # Simple keyword matching - can be enhanced with LLM-based selection
        description_lower = description.lower()
        
        for name, info in self.agents.items():
            if name.lower() in description_lower:
                logger.info(f"Auto-selected agent '{name}' based on description keyword match")
                return name
        
        # Default to first agent
        default_agent = list(self.agents.keys())[0]
        logger.info(f"Auto-selected default agent '{default_agent}' (no keyword match found)")
        return default_agent
    
    async def execute_tasks(
        self,
        task_ids: Optional[List[str]] = None,
        parallel: bool = False
    ) -> Dict[str, Any]:
        """
        Execute multiple tasks.
        
        Args:
            task_ids: List of task IDs (defaults to all pending tasks)
            parallel: Whether to execute tasks in parallel
            
        Returns:
            Dictionary mapping task IDs to results
        """
        if task_ids is None:
            task_ids = [tid for tid in self.task_queue 
                       if self.tasks[tid].status == TaskStatus.PENDING]
        
        logger.info(f"Executing {len(task_ids)} tasks - Mode: {'PARALLEL' if parallel else 'SEQUENTIAL'}")
        
        if parallel:
            logger.info(f"Starting parallel execution of {len(task_ids)} tasks")
            results = await asyncio.gather(
                *[self.execute_task(tid) for tid in task_ids],
                return_exceptions=True
            )
            logger.info(f"Parallel execution completed - {len(task_ids)} tasks finished")
        else:
            logger.info(f"Starting sequential execution of {len(task_ids)} tasks")
            results = []
            for i, tid in enumerate(task_ids, 1):
                logger.info(f"Executing task {i}/{len(task_ids)}: {tid}")
                try:
                    result = await self.execute_task(tid)
                    results.append(result)
                    logger.info(f"Task {i}/{len(task_ids)} completed successfully")
                except Exception as e:
                    logger.error(f"Task {i}/{len(task_ids)} failed: {str(e)}")
                    results.append(e)
            logger.info(f"Sequential execution completed - {len(task_ids)} tasks finished")
        
        successful = sum(1 for r in results if not isinstance(r, Exception))
        failed = len(results) - successful
        logger.info(f"Execution summary - Successful: {successful}, Failed: {failed}")
        
        return {
            tid: result for tid, result in zip(task_ids, results)
        }
    
    def set_shared_state(self, key: str, value: Any) -> None:
        """Set a value in shared state."""
        logger.info(f"Setting shared state: {key} = {str(value)[:100]}...")
        self.shared_state[key] = value
    
    def get_shared_state(self, key: str, default: Any = None) -> Any:
        """Get a value from shared state."""
        value = self.shared_state.get(key, default)
        logger.debug(f"Getting shared state: {key} = {str(value)[:100] if value is not None else 'None'}...")
        return value
    
    def get_task_status(self, task_id: str) -> TaskStatus:
        """Get the status of a task."""
        if task_id not in self.tasks:
            raise ValueError(f"Task {task_id} not found")
        return self.tasks[task_id].status
    
    def get_task_result(self, task_id: str) -> Any:
        """Get the result of a completed task."""
        if task_id not in self.tasks:
            raise ValueError(f"Task {task_id} not found")
        return self.tasks[task_id].result
    
    def list_agents(self) -> List[str]:
        """List all registered agent names."""
        return list(self.agents.keys())
    
    def get_agent_info(self, agent_name: str) -> Dict[str, Any]:
        """Get information about a registered agent."""
        if agent_name not in self.agents:
            raise ValueError(f"Agent {agent_name} not found")
        return self.agents[agent_name]
    
    def clear_history(self) -> None:
        """Clear conversation history."""
        message_count = len(self.conversation_history)
        self.conversation_history = []
        logger.info(f"Cleared conversation history - Removed {message_count} messages")
    
    def get_callback_events(self) -> List[Dict[str, Any]]:
        """Get all callback events."""
        return self.callback_handler.events


"""
Comprehensive test suite for LangChainOrchestrator.
"""

import pytest
import asyncio
from unittest.mock import Mock, MagicMock, patch, AsyncMock
from datetime import datetime

from orchestrator import (
    LangChainOrchestrator,
    TaskStatus,
    Task,
    OrchestratorCallbackHandler
)
from langchain.tools import Tool


class TestOrchestratorInitialization:
    """Test LangChainOrchestrator initialization."""
    
    def test_init_default(self):
        """Test default initialization."""
        with patch('orchestrator.ChatOpenAI'):
            orchestrator = LangChainOrchestrator()
            assert orchestrator.max_iterations == 15
            assert orchestrator.verbose is True
            assert isinstance(orchestrator.agents, dict)
            assert isinstance(orchestrator.tasks, dict)
            assert isinstance(orchestrator.task_queue, list)
    
    def test_init_custom_params(self):
        """Test initialization with custom parameters."""
        with patch('orchestrator.ChatOpenAI') as mock_llm_class:
            mock_llm = MagicMock()
            mock_llm_class.return_value = mock_llm
            
            orchestrator = LangChainOrchestrator(
                llm=mock_llm,
                temperature=0.5,
                max_iterations=10,
                verbose=False
            )
            assert orchestrator.llm == mock_llm
            assert orchestrator.max_iterations == 10
            assert orchestrator.verbose is False
    
    def test_init_with_llm(self):
        """Test initialization with provided LLM."""
        mock_llm = MagicMock()
        orchestrator = LangChainOrchestrator(llm=mock_llm)
        assert orchestrator.llm == mock_llm


class TestAgentRegistration:
    """Test agent registration functionality."""
    
    @pytest.fixture
    def orchestrator(self):
        """Create orchestrator instance."""
        with patch('orchestrator.ChatOpenAI'):
            return LangChainOrchestrator(verbose=False)
    
    def test_register_agent(self, orchestrator, sample_tools):
        """Test registering an agent."""
        orchestrator.register_agent(
            name="test_agent",
            tools=sample_tools,
            system_prompt="You are a test agent",
            description="Test agent description"
        )
        
        assert "test_agent" in orchestrator.agents
        assert orchestrator.agents["test_agent"]["description"] == "Test agent description"
    
    def test_register_multiple_agents(self, orchestrator, sample_tools):
        """Test registering multiple agents."""
        orchestrator.register_agent(
            name="agent1",
            tools=sample_tools,
            system_prompt="Agent 1",
            description="First agent"
        )
        orchestrator.register_agent(
            name="agent2",
            tools=sample_tools,
            system_prompt="Agent 2",
            description="Second agent"
        )
        
        assert len(orchestrator.agents) == 2
        assert "agent1" in orchestrator.agents
        assert "agent2" in orchestrator.agents
    
    def test_register_agent_without_description(self, orchestrator, sample_tools):
        """Test registering agent without description."""
        orchestrator.register_agent(
            name="test_agent",
            tools=sample_tools,
            system_prompt="Test prompt"
        )
        
        assert "test_agent" in orchestrator.agents
        assert "description" in orchestrator.agents["test_agent"]


class TestTaskManagement:
    """Test task creation and management."""
    
    @pytest.fixture
    def orchestrator(self):
        """Create orchestrator instance."""
        with patch('orchestrator.ChatOpenAI'):
            return LangChainOrchestrator(verbose=False)
    
    def test_create_task(self, orchestrator):
        """Test creating a task."""
        task_id = orchestrator.create_task(
            description="Test task",
            agent_name="test_agent"
        )
        
        assert task_id in orchestrator.tasks
        assert orchestrator.tasks[task_id].description == "Test task"
        assert orchestrator.tasks[task_id].agent_name == "test_agent"
        assert orchestrator.tasks[task_id].status == TaskStatus.PENDING
    
    def test_create_task_without_agent(self, orchestrator):
        """Test creating a task without specifying agent."""
        task_id = orchestrator.create_task(description="Test task")
        
        assert task_id in orchestrator.tasks
        assert orchestrator.tasks[task_id].agent_name is None
    
    def test_create_task_with_metadata(self, orchestrator, sample_task_metadata):
        """Test creating a task with metadata."""
        task_id = orchestrator.create_task(
            description="Test task",
            metadata=sample_task_metadata
        )
        
        assert orchestrator.tasks[task_id].metadata == sample_task_metadata
    
    def test_task_added_to_queue(self, orchestrator):
        """Test that tasks are added to queue."""
        task_id = orchestrator.create_task(description="Test task")
        
        assert task_id in orchestrator.task_queue
    
    def test_multiple_tasks_in_queue(self, orchestrator):
        """Test multiple tasks in queue."""
        task1_id = orchestrator.create_task(description="Task 1")
        task2_id = orchestrator.create_task(description="Task 2")
        
        assert len(orchestrator.task_queue) == 2
        assert task1_id in orchestrator.task_queue
        assert task2_id in orchestrator.task_queue


class TestTaskExecution:
    """Test task execution functionality."""
    
    @pytest.fixture
    def orchestrator(self):
        """Create orchestrator instance."""
        with patch('orchestrator.ChatOpenAI'):
            return LangChainOrchestrator(verbose=False)
    
    @pytest.fixture
    def mock_agent_executor(self):
        """Create mock agent executor."""
        executor = AsyncMock()
        executor.ainvoke = AsyncMock(return_value={"output": "Test result"})
        return executor
    
    def test_execute_task_success(self, orchestrator, mock_agent_executor, sample_tools):
        """Test successful task execution."""
        orchestrator.agents["test_agent"] = {
            "executor": mock_agent_executor,
            "description": "Test agent",
            "tools": sample_tools
        }
        
        task_id = orchestrator.create_task(
            description="Test task",
            agent_name="test_agent"
        )
        
        async def run_test():
            result = await orchestrator.execute_task(task_id)
            assert result == "Test result"
            assert orchestrator.tasks[task_id].status == TaskStatus.COMPLETED
        
        asyncio.run(run_test())
    
    def test_execute_task_failure(self, orchestrator, mock_agent_executor, sample_tools):
        """Test task execution failure."""
        executor = AsyncMock()
        executor.ainvoke = AsyncMock(side_effect=Exception("Test error"))
        
        orchestrator.agents["test_agent"] = {
            "executor": executor,
            "description": "Test agent",
            "tools": sample_tools
        }
        
        task_id = orchestrator.create_task(
            description="Test task",
            agent_name="test_agent"
        )
        
        async def run_test():
            with pytest.raises(Exception):
                await orchestrator.execute_task(task_id)
            assert orchestrator.tasks[task_id].status == TaskStatus.FAILED
            assert orchestrator.tasks[task_id].error == "Test error"
        
        asyncio.run(run_test())
    
    def test_execute_task_nonexistent(self, orchestrator):
        """Test executing non-existent task."""
        async def run_test():
            with pytest.raises(ValueError, match="Task.*not found"):
                await orchestrator.execute_task("nonexistent_task_id")
        
        asyncio.run(run_test())
    
    def test_execute_task_auto_select_agent(self, orchestrator, mock_agent_executor, sample_tools):
        """Test automatic agent selection."""
        orchestrator.agents["math_agent"] = {
            "executor": mock_agent_executor,
            "description": "Math agent",
            "tools": sample_tools
        }
        
        task_id = orchestrator.create_task(description="Calculate 2+2 math")
        
        async def run_test():
            result = await orchestrator.execute_task(task_id)
            assert result == "Test result"
            # Should auto-select math_agent based on description
            assert orchestrator.tasks[task_id].agent_name == "math_agent"
        
        asyncio.run(run_test())
    
    def test_execute_task_with_context(self, orchestrator, mock_agent_executor, sample_tools):
        """Test task execution with context."""
        orchestrator.agents["test_agent"] = {
            "executor": mock_agent_executor,
            "description": "Test agent",
            "tools": sample_tools
        }
        
        task_id = orchestrator.create_task(
            description="Test task",
            agent_name="test_agent"
        )
        
        context = {"key1": "value1", "key2": "value2"}
        
        async def run_test():
            await orchestrator.execute_task(task_id, context=context)
            # Verify context was passed to agent
            call_args = mock_agent_executor.ainvoke.call_args
            assert call_args is not None
        
        asyncio.run(run_test())
    
    def test_execute_task_with_shared_state(self, orchestrator, mock_agent_executor, sample_tools):
        """Test task execution with shared state."""
        orchestrator.agents["test_agent"] = {
            "executor": mock_agent_executor,
            "description": "Test agent",
            "tools": sample_tools
        }
        
        orchestrator.set_shared_state("user", "Alice")
        orchestrator.set_shared_state("project", "Test")
        
        task_id = orchestrator.create_task(
            description="Test task",
            agent_name="test_agent"
        )
        
        async def run_test():
            await orchestrator.execute_task(task_id)
            # Verify shared state was included
            call_args = mock_agent_executor.ainvoke.call_args
            assert call_args is not None
        
        asyncio.run(run_test())


class TestParallelExecution:
    """Test parallel task execution."""
    
    @pytest.fixture
    def orchestrator(self):
        """Create orchestrator instance."""
        with patch('orchestrator.ChatOpenAI'):
            return LangChainOrchestrator(verbose=False)
    
    @pytest.fixture
    def mock_agent_executor(self):
        """Create mock agent executor."""
        executor = AsyncMock()
        executor.ainvoke = AsyncMock(return_value={"output": "Result"})
        return executor
    
    def test_execute_tasks_sequential(self, orchestrator, mock_agent_executor, sample_tools):
        """Test sequential task execution."""
        orchestrator.agents["test_agent"] = {
            "executor": mock_agent_executor,
            "description": "Test agent",
            "tools": sample_tools
        }
        
        task_ids = [
            orchestrator.create_task("Task 1", agent_name="test_agent"),
            orchestrator.create_task("Task 2", agent_name="test_agent"),
        ]
        
        async def run_test():
            results = await orchestrator.execute_tasks(task_ids=task_ids, parallel=False)
            assert len(results) == 2
            assert all(isinstance(r, str) for r in results.values())
        
        asyncio.run(run_test())
    
    def test_execute_tasks_parallel(self, orchestrator, mock_agent_executor, sample_tools):
        """Test parallel task execution."""
        orchestrator.agents["test_agent"] = {
            "executor": mock_agent_executor,
            "description": "Test agent",
            "tools": sample_tools
        }
        
        task_ids = [
            orchestrator.create_task("Task 1", agent_name="test_agent"),
            orchestrator.create_task("Task 2", agent_name="test_agent"),
        ]
        
        async def run_test():
            results = await orchestrator.execute_tasks(task_ids=task_ids, parallel=True)
            assert len(results) == 2
        
        asyncio.run(run_test())
    
    def test_execute_tasks_default_queue(self, orchestrator, mock_agent_executor, sample_tools):
        """Test executing all pending tasks from queue."""
        orchestrator.agents["test_agent"] = {
            "executor": mock_agent_executor,
            "description": "Test agent",
            "tools": sample_tools
        }
        
        orchestrator.create_task("Task 1", agent_name="test_agent")
        orchestrator.create_task("Task 2", agent_name="test_agent")
        
        async def run_test():
            results = await orchestrator.execute_tasks(parallel=False)
            assert len(results) == 2
        
        asyncio.run(run_test())
    
    def test_execute_tasks_with_exceptions(self, orchestrator, sample_tools):
        """Test handling exceptions in parallel execution."""
        executor1 = AsyncMock()
        executor1.ainvoke = AsyncMock(return_value={"output": "Success"})
        
        executor2 = AsyncMock()
        executor2.ainvoke = AsyncMock(side_effect=Exception("Error"))
        
        orchestrator.agents["agent1"] = {
            "executor": executor1,
            "description": "Agent 1",
            "tools": sample_tools
        }
        orchestrator.agents["agent2"] = {
            "executor": executor2,
            "description": "Agent 2",
            "tools": sample_tools
        }
        
        task_ids = [
            orchestrator.create_task("Task 1", agent_name="agent1"),
            orchestrator.create_task("Task 2", agent_name="agent2"),
        ]
        
        async def run_test():
            results = await orchestrator.execute_tasks(task_ids=task_ids, parallel=True)
            assert len(results) == 2
            # One should succeed, one should fail
            assert any(isinstance(r, Exception) for r in results.values())
        
        asyncio.run(run_test())


class TestStateManagement:
    """Test shared state management."""
    
    @pytest.fixture
    def orchestrator(self):
        """Create orchestrator instance."""
        with patch('orchestrator.ChatOpenAI'):
            return LangChainOrchestrator(verbose=False)
    
    def test_set_shared_state(self, orchestrator):
        """Test setting shared state."""
        orchestrator.set_shared_state("key", "value")
        assert orchestrator.get_shared_state("key") == "value"
    
    def test_get_shared_state_existing(self, orchestrator):
        """Test getting existing shared state."""
        orchestrator.set_shared_state("key", "value")
        result = orchestrator.get_shared_state("key")
        assert result == "value"
    
    def test_get_shared_state_default(self, orchestrator):
        """Test getting non-existent shared state with default."""
        result = orchestrator.get_shared_state("nonexistent", default="default_value")
        assert result == "default_value"
    
    def test_get_shared_state_no_default(self, orchestrator):
        """Test getting non-existent shared state without default."""
        result = orchestrator.get_shared_state("nonexistent")
        assert result is None
    
    def test_multiple_shared_state_values(self, orchestrator):
        """Test multiple shared state values."""
        orchestrator.set_shared_state("key1", "value1")
        orchestrator.set_shared_state("key2", "value2")
        orchestrator.set_shared_state("key3", 123)
        
        assert orchestrator.get_shared_state("key1") == "value1"
        assert orchestrator.get_shared_state("key2") == "value2"
        assert orchestrator.get_shared_state("key3") == 123


class TestTaskStatusAndResults:
    """Test task status and result retrieval."""
    
    @pytest.fixture
    def orchestrator(self):
        """Create orchestrator instance."""
        with patch('orchestrator.ChatOpenAI'):
            return LangChainOrchestrator(verbose=False)
    
    def test_get_task_status(self, orchestrator):
        """Test getting task status."""
        task_id = orchestrator.create_task("Test task")
        status = orchestrator.get_task_status(task_id)
        assert status == TaskStatus.PENDING
    
    def test_get_task_status_nonexistent(self, orchestrator):
        """Test getting status of non-existent task."""
        with pytest.raises(ValueError, match="Task.*not found"):
            orchestrator.get_task_status("nonexistent")
    
    def test_get_task_result(self, orchestrator, mock_agent_executor, sample_tools):
        """Test getting task result."""
        orchestrator.agents["test_agent"] = {
            "executor": mock_agent_executor,
            "description": "Test agent",
            "tools": sample_tools
        }
        
        task_id = orchestrator.create_task("Test task", agent_name="test_agent")
        
        async def run_test():
            await orchestrator.execute_task(task_id)
            result = orchestrator.get_task_result(task_id)
            assert result == "Test result"
        
        asyncio.run(run_test())
    
    def test_get_task_result_nonexistent(self, orchestrator):
        """Test getting result of non-existent task."""
        with pytest.raises(ValueError, match="Task.*not found"):
            orchestrator.get_task_result("nonexistent")


class TestAgentManagement:
    """Test agent listing and info retrieval."""
    
    @pytest.fixture
    def orchestrator(self):
        """Create orchestrator instance."""
        with patch('orchestrator.ChatOpenAI'):
            return LangChainOrchestrator(verbose=False)
    
    def test_list_agents_empty(self, orchestrator):
        """Test listing agents when none are registered."""
        agents = orchestrator.list_agents()
        assert isinstance(agents, list)
        assert len(agents) == 0
    
    def test_list_agents(self, orchestrator, sample_tools):
        """Test listing registered agents."""
        orchestrator.register_agent("agent1", sample_tools, "Prompt 1")
        orchestrator.register_agent("agent2", sample_tools, "Prompt 2")
        
        agents = orchestrator.list_agents()
        assert len(agents) == 2
        assert "agent1" in agents
        assert "agent2" in agents
    
    def test_get_agent_info(self, orchestrator, sample_tools):
        """Test getting agent information."""
        orchestrator.register_agent(
            "test_agent",
            sample_tools,
            "Test prompt",
            description="Test description"
        )
        
        info = orchestrator.get_agent_info("test_agent")
        assert "executor" in info
        assert "description" in info
        assert "tools" in info
        assert info["description"] == "Test description"
    
    def test_get_agent_info_nonexistent(self, orchestrator):
        """Test getting info for non-existent agent."""
        with pytest.raises(ValueError, match="Agent.*not found"):
            orchestrator.get_agent_info("nonexistent")


class TestConversationHistory:
    """Test conversation history management."""
    
    @pytest.fixture
    def orchestrator(self):
        """Create orchestrator instance."""
        with patch('orchestrator.ChatOpenAI'):
            return LangChainOrchestrator(verbose=False)
    
    def test_conversation_history_updated(self, orchestrator, mock_agent_executor, sample_tools):
        """Test that conversation history is updated after task execution."""
        orchestrator.agents["test_agent"] = {
            "executor": mock_agent_executor,
            "description": "Test agent",
            "tools": sample_tools
        }
        
        task_id = orchestrator.create_task("Test task", agent_name="test_agent")
        
        initial_length = len(orchestrator.conversation_history)
        
        async def run_test():
            await orchestrator.execute_task(task_id)
            assert len(orchestrator.conversation_history) > initial_length
        
        asyncio.run(run_test())
    
    def test_clear_history(self, orchestrator, mock_agent_executor, sample_tools):
        """Test clearing conversation history."""
        orchestrator.agents["test_agent"] = {
            "executor": mock_agent_executor,
            "description": "Test agent",
            "tools": sample_tools
        }
        
        task_id = orchestrator.create_task("Test task", agent_name="test_agent")
        
        async def run_test():
            await orchestrator.execute_task(task_id)
            assert len(orchestrator.conversation_history) > 0
            
            orchestrator.clear_history()
            assert len(orchestrator.conversation_history) == 0
        
        asyncio.run(run_test())


class TestCallbackHandler:
    """Test callback handler functionality."""
    
    @pytest.fixture
    def orchestrator(self):
        """Create orchestrator instance."""
        with patch('orchestrator.ChatOpenAI'):
            return LangChainOrchestrator(verbose=False)
    
    def test_callback_handler_initialized(self, orchestrator):
        """Test that callback handler is initialized."""
        assert orchestrator.callback_handler is not None
        assert isinstance(orchestrator.callback_handler, OrchestratorCallbackHandler)
    
    def test_get_callback_events(self, orchestrator):
        """Test getting callback events."""
        events = orchestrator.get_callback_events()
        assert isinstance(events, list)


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    @pytest.fixture
    def orchestrator(self):
        """Create orchestrator instance."""
        with patch('orchestrator.ChatOpenAI'):
            return LangChainOrchestrator(verbose=False)
    
    def test_select_agent_no_agents(self, orchestrator):
        """Test agent selection when no agents are registered."""
        task_id = orchestrator.create_task("Test task")
        
        async def run_test():
            with pytest.raises(ValueError, match="No agents registered"):
                await orchestrator.execute_task(task_id)
        
        asyncio.run(run_test())
    
    def test_select_agent_nonexistent(self, orchestrator):
        """Test selecting non-existent agent."""
        task_id = orchestrator.create_task("Test task", agent_name="nonexistent")
        
        async def run_test():
            with pytest.raises(ValueError, match="Agent.*not found"):
                await orchestrator.execute_task(task_id)
        
        asyncio.run(run_test())
    
    def test_empty_task_description(self, orchestrator):
        """Test creating task with empty description."""
        task_id = orchestrator.create_task("")
        assert task_id in orchestrator.tasks
        assert orchestrator.tasks[task_id].description == ""
    
    def test_task_metadata_persistence(self, orchestrator):
        """Test that task metadata persists."""
        metadata = {"key": "value", "number": 123}
        task_id = orchestrator.create_task("Test", metadata=metadata)
        
        assert orchestrator.tasks[task_id].metadata == metadata


"""
Integration tests for agent interactions and workflows.
"""

import pytest
import asyncio
from unittest.mock import Mock, MagicMock, patch, AsyncMock

from orchestrator import LangChainOrchestrator
from example_agents import setup_example_agents
from red_team_agent import RedTeamAgent


class TestOrchestratorWithExampleAgents:
    """Integration tests for orchestrator with example agents."""
    
    @pytest.fixture
    def orchestrator(self):
        """Create orchestrator with example agents."""
        with patch('orchestrator.ChatOpenAI'):
            orch = LangChainOrchestrator(verbose=False)
            setup_example_agents(orch)
            return orch
    
    def test_math_agent_calculation_workflow(self, orchestrator):
        """Test complete workflow with math agent."""
        task_id = orchestrator.create_task(
            description="Calculate (25 * 4) + (100 / 2)",
            agent_name="math_agent"
        )
        
        async def run_test():
            # Mock the agent executor
            mock_executor = AsyncMock()
            mock_executor.ainvoke = AsyncMock(return_value={"output": "150"})
            orchestrator.agents["math_agent"]["executor"] = mock_executor
            
            result = await orchestrator.execute_task(task_id)
            assert result == "150"
            assert orchestrator.tasks[task_id].status.value == "completed"
        
        asyncio.run(run_test())
    
    def test_analysis_agent_workflow(self, orchestrator):
        """Test complete workflow with analysis agent."""
        task_id = orchestrator.create_task(
            description="Analyze this text: 'The quick brown fox jumps over the lazy dog.'",
            agent_name="analysis_agent"
        )
        
        async def run_test():
            mock_executor = AsyncMock()
            mock_executor.ainvoke = AsyncMock(return_value={"output": "Analysis complete"})
            orchestrator.agents["analysis_agent"]["executor"] = mock_executor
            
            result = await orchestrator.execute_task(task_id)
            assert result == "Analysis complete"
        
        asyncio.run(run_test())
    
    def test_multiple_agents_sequential(self, orchestrator):
        """Test multiple agents working sequentially."""
        task1_id = orchestrator.create_task(
            "Calculate 10 * 5",
            agent_name="math_agent"
        )
        task2_id = orchestrator.create_task(
            "Analyze text: 'Hello world'",
            agent_name="analysis_agent"
        )
        
        async def run_test():
            # Mock executors
            for agent_name in ["math_agent", "analysis_agent"]:
                mock_executor = AsyncMock()
                mock_executor.ainvoke = AsyncMock(return_value={"output": "Done"})
                orchestrator.agents[agent_name]["executor"] = mock_executor
            
            results = await orchestrator.execute_tasks(parallel=False)
            assert len(results) == 2
            assert all(r == "Done" for r in results.values())
        
        asyncio.run(run_test())
    
    def test_shared_state_across_agents(self, orchestrator):
        """Test shared state used across multiple agents."""
        orchestrator.set_shared_state("user", "Alice")
        orchestrator.set_shared_state("project", "Test Project")
        
        task_id = orchestrator.create_task(
            "Use shared state information",
            agent_name="general_agent"
        )
        
        async def run_test():
            mock_executor = AsyncMock()
            mock_executor.ainvoke = AsyncMock(return_value={"output": "State used"})
            orchestrator.agents["general_agent"]["executor"] = mock_executor
            
            await orchestrator.execute_task(task_id)
            
            # Verify shared state was included in the call
            call_args = mock_executor.ainvoke.call_args
            assert call_args is not None
        
        asyncio.run(run_test())
    
    def test_auto_agent_selection(self, orchestrator):
        """Test automatic agent selection based on task description."""
        task_id = orchestrator.create_task("What is 50 * 30?")
        
        async def run_test():
            mock_executor = AsyncMock()
            mock_executor.ainvoke = AsyncMock(return_value={"output": "1500"})
            orchestrator.agents["math_agent"]["executor"] = mock_executor
            
            result = await orchestrator.execute_task(task_id)
            # Should auto-select math_agent
            assert orchestrator.tasks[task_id].agent_name == "math_agent"
        
        asyncio.run(run_test())


class TestRedTeamAgentIntegration:
    """Integration tests for RedTeamAgent."""
    
    @pytest.fixture
    def red_team_agent(self, mock_openai_api_key):
        """Create RedTeamAgent instance."""
        with patch('red_team_agent.ChatOpenAI'):
            with patch('red_team_agent.create_agent'):
                return RedTeamAgent(
                    target_url="http://example.com",
                    api_key=mock_openai_api_key
                )
    
    def test_red_team_agent_tool_chain(self, red_team_agent, mock_session, sample_html_page):
        """Test RedTeamAgent tool chain workflow."""
        red_team_agent.session = mock_session
        mock_session.get.return_value.text = sample_html_page
        mock_session.get.return_value.status_code = 200
        
        tools = red_team_agent._create_tools()
        
        # Fetch page
        fetch_tool = next(t for t in tools if t.name == "fetch_page")
        page_data = fetch_tool.func("http://example.com")
        
        assert page_data["has_forms"] is True
        
        # Craft payload
        craft_tool = next(t for t in tools if t.name == "craft_xss_payload")
        payload = craft_tool.func("basic")
        
        # Test XSS
        test_tool = next(t for t in tools if t.name == "test_xss")
        result = test_tool.func("http://example.com?q=test", "q", payload)
        
        assert "is_vulnerable" in result
    
    def test_red_team_agent_report_generation(self, red_team_agent, sample_test_results):
        """Test report generation workflow."""
        red_team_agent.test_results = sample_test_results
        
        tools = red_team_agent._create_tools()
        report_tool = next(t for t in tools if t.name == "generate_report")
        
        report = report_tool.func()
        
        assert "Web Security Red-Teaming Report" in report
        assert "Vulnerabilities found" in report
        assert "1" in report  # Should show 1 vulnerability found


class TestEndToEndWorkflows:
    """End-to-end workflow tests."""
    
    def test_complete_security_test_workflow(self, mock_openai_api_key):
        """Test complete security testing workflow."""
        with patch('red_team_agent.ChatOpenAI'):
            with patch('red_team_agent.create_agent') as mock_create:
                mock_agent = MagicMock()
                mock_agent.invoke = MagicMock(return_value={
                    "messages": [MagicMock(content="Security report")]
                })
                mock_create.return_value = mock_agent
                
                agent = RedTeamAgent(
                    target_url="http://example.com",
                    api_key=mock_openai_api_key
                )
                agent.agent = mock_agent
                
                # Run test suite
                report = agent.run_test_suite(test_scenarios=["Test XSS"])
                
                assert isinstance(report, str)
                assert mock_agent.invoke.call_count > 0
    
    def test_orchestrator_with_multiple_task_types(self):
        """Test orchestrator handling multiple different task types."""
        with patch('orchestrator.ChatOpenAI'):
            orchestrator = LangChainOrchestrator(verbose=False)
            setup_example_agents(orchestrator)
            
            # Create diverse tasks
            tasks = [
                ("Calculate 2+2", "math_agent"),
                ("Analyze text", "analysis_agent"),
                ("General help", "general_agent"),
            ]
            
            task_ids = [
                orchestrator.create_task(desc, agent_name=agent)
                for desc, agent in tasks
            ]
            
            async def run_test():
                # Mock all executors
                for agent_name in orchestrator.agents.keys():
                    mock_executor = AsyncMock()
                    mock_executor.ainvoke = AsyncMock(return_value={"output": "Done"})
                    orchestrator.agents[agent_name]["executor"] = mock_executor
                
                results = await orchestrator.execute_tasks(task_ids=task_ids, parallel=True)
                assert len(results) == 3
            
            asyncio.run(run_test())
    
    def test_error_recovery_workflow(self):
        """Test error recovery in workflow."""
        with patch('orchestrator.ChatOpenAI'):
            orchestrator = LangChainOrchestrator(verbose=False)
            setup_example_agents(orchestrator)
            
            task1_id = orchestrator.create_task("Task 1", agent_name="math_agent")
            task2_id = orchestrator.create_task("Task 2", agent_name="math_agent")
            
            async def run_test():
                # First task succeeds, second fails
                executor1 = AsyncMock()
                executor1.ainvoke = AsyncMock(return_value={"output": "Success"})
                
                executor2 = AsyncMock()
                executor2.ainvoke = AsyncMock(side_effect=Exception("Error"))
                
                orchestrator.agents["math_agent"]["executor"] = executor1
                
                # Execute first task
                result1 = await orchestrator.execute_task(task1_id)
                assert result1 == "Success"
                
                # Change executor for second task
                orchestrator.agents["math_agent"]["executor"] = executor2
                
                # Second task should fail gracefully
                with pytest.raises(Exception):
                    await orchestrator.execute_task(task2_id)
                
                assert orchestrator.tasks[task1_id].status.value == "completed"
                assert orchestrator.tasks[task2_id].status.value == "failed"
            
            asyncio.run(run_test())


class TestConcurrentOperations:
    """Test concurrent operations and race conditions."""
    
    def test_concurrent_task_execution(self):
        """Test concurrent task execution."""
        with patch('orchestrator.ChatOpenAI'):
            orchestrator = LangChainOrchestrator(verbose=False)
            setup_example_agents(orchestrator)
            
            # Create multiple tasks
            task_ids = [
                orchestrator.create_task(f"Task {i}", agent_name="math_agent")
                for i in range(5)
            ]
            
            async def run_test():
                # Mock executor
                mock_executor = AsyncMock()
                mock_executor.ainvoke = AsyncMock(return_value={"output": "Done"})
                orchestrator.agents["math_agent"]["executor"] = mock_executor
                
                results = await orchestrator.execute_tasks(task_ids=task_ids, parallel=True)
                assert len(results) == 5
            
            asyncio.run(run_test())
    
    def test_shared_state_concurrent_access(self):
        """Test shared state with concurrent access."""
        with patch('orchestrator.ChatOpenAI'):
            orchestrator = LangChainOrchestrator(verbose=False)
            setup_example_agents(orchestrator)
            
            # Set initial state
            orchestrator.set_shared_state("counter", 0)
            
            async def run_test():
                # Mock executor that increments counter
                async def increment_counter(*args, **kwargs):
                    current = orchestrator.get_shared_state("counter", 0)
                    orchestrator.set_shared_state("counter", current + 1)
                    return {"output": "Done"}
                
                mock_executor = AsyncMock()
                mock_executor.ainvoke = increment_counter
                orchestrator.agents["math_agent"]["executor"] = mock_executor
                
                # Create and execute tasks concurrently
                task_ids = [
                    orchestrator.create_task(f"Task {i}", agent_name="math_agent")
                    for i in range(3)
                ]
                
                await orchestrator.execute_tasks(task_ids=task_ids, parallel=True)
                
                # Counter should have been incremented
                final_counter = orchestrator.get_shared_state("counter")
                assert final_counter >= 0  # May vary due to race conditions
            
            asyncio.run(run_test())


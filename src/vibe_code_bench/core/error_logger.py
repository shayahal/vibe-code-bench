"""Error logging utility to capture all exceptions and errors during agent execution."""

import traceback
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
import json


class ErrorLogger:
    """Captures and logs all errors and exceptions during execution."""
    
    def __init__(self, log_file_path: Optional[Path] = None):
        """
        Initialize error logger.
        
        Args:
            log_file_path: Optional path to error log file. If None, errors are only stored in memory.
        """
        self.log_file_path = log_file_path
        self.errors: List[Dict[str, Any]] = []
        self.original_excepthook = sys.excepthook
        
        # Set up global exception handler
        sys.excepthook = self._global_exception_handler
        
        # Create log file if path provided
        if self.log_file_path:
            self.log_file_path.parent.mkdir(parents=True, exist_ok=True)
            self._write_header()
    
    def _write_header(self):
        """Write header to error log file."""
        if self.log_file_path:
            with open(self.log_file_path, "w", encoding="utf-8") as f:
                f.write("=" * 80 + "\n")
                f.write("ERROR LOG\n")
                f.write(f"Started: {datetime.now().isoformat()}\n")
                f.write("=" * 80 + "\n\n")
    
    def _global_exception_handler(self, exc_type, exc_value, exc_traceback):
        """Global exception handler to catch unhandled exceptions."""
        if issubclass(exc_type, KeyboardInterrupt):
            # Don't log keyboard interrupts
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        
        self.log_error(
            error_type=exc_type.__name__,
            error_message=str(exc_value),
            traceback=traceback.format_exception(exc_type, exc_value, exc_traceback),
            context="unhandled_exception"
        )
        
        # Call original exception handler
        self.original_excepthook(exc_type, exc_value, exc_traceback)
    
    def log_error(
        self,
        error_type: str,
        error_message: str,
        traceback: Optional[str] = None,
        context: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """
        Log an error.
        
        Args:
            error_type: Type of error (e.g., "ValueError", "ConnectionError")
            error_message: Error message
            traceback: Optional traceback string
            context: Optional context where error occurred (e.g., "browsing_agent.discover", "red_team_agent.test")
            metadata: Optional additional metadata about the error
        """
        error_entry = {
            "timestamp": datetime.now().isoformat(),
            "error_type": error_type,
            "error_message": error_message,
            "context": context,
            "traceback": traceback,
            "metadata": metadata or {},
        }
        
        self.errors.append(error_entry)
        
        # Write to log file if available
        if self.log_file_path:
            self._write_error_entry(error_entry)
    
    def log_exception(
        self,
        exception: Exception,
        context: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """
        Log an exception with full traceback.
        
        Args:
            exception: Exception object
            context: Optional context where error occurred
            metadata: Optional additional metadata
        """
        exc_type = type(exception).__name__
        exc_message = str(exception)
        exc_traceback = traceback.format_exc()
        
        self.log_error(
            error_type=exc_type,
            error_message=exc_message,
            traceback=exc_traceback,
            context=context,
            metadata=metadata,
        )
    
    def _write_error_entry(self, error_entry: Dict[str, Any]):
        """Write error entry to log file."""
        if not self.log_file_path:
            return
        
        try:
            with open(self.log_file_path, "a", encoding="utf-8") as f:
                f.write(f"\n[{error_entry['timestamp']}] {error_entry['error_type']}\n")
                f.write(f"Context: {error_entry.get('context', 'unknown')}\n")
                f.write(f"Message: {error_entry['error_message']}\n")
                
                if error_entry.get('metadata'):
                    f.write(f"Metadata: {json.dumps(error_entry['metadata'], indent=2)}\n")
                
                if error_entry.get('traceback'):
                    f.write("Traceback:\n")
                    f.write(error_entry['traceback'])
                
                f.write("\n" + "-" * 80 + "\n")
        except Exception as e:
            # Don't fail if we can't write to log file
            print(f"Failed to write error log entry: {e}")
    
    def get_errors_summary(self) -> Dict[str, Any]:
        """
        Get summary of all logged errors.
        
        Returns:
            Dictionary with error summary statistics
        """
        if not self.errors:
            return {
                "total_errors": 0,
                "errors_by_type": {},
                "errors_by_context": {},
            }
        
        errors_by_type = {}
        errors_by_context = {}
        
        for error in self.errors:
            error_type = error["error_type"]
            context = error.get("context", "unknown")
            
            errors_by_type[error_type] = errors_by_type.get(error_type, 0) + 1
            errors_by_context[context] = errors_by_context.get(context, 0) + 1
        
        return {
            "total_errors": len(self.errors),
            "errors_by_type": errors_by_type,
            "errors_by_context": errors_by_context,
            "errors": self.errors,
        }
    
    def save_summary(self, output_path: Path):
        """
        Save error summary to JSON file.
        
        Args:
            output_path: Path to save summary JSON file
        """
        summary = self.get_errors_summary()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
    
    def cleanup(self):
        """Cleanup: restore original exception handler."""
        sys.excepthook = self.original_excepthook


# Global error logger instance (can be set per run)
_global_error_logger: Optional[ErrorLogger] = None


def get_error_logger() -> Optional[ErrorLogger]:
    """Get the global error logger instance."""
    return _global_error_logger


def setup_error_logging(log_file_path: Optional[Path] = None) -> ErrorLogger:
    """
    Setup error logging for a run.
    
    Args:
        log_file_path: Path to error log file
        
    Returns:
        ErrorLogger instance
    """
    global _global_error_logger
    _global_error_logger = ErrorLogger(log_file_path)
    return _global_error_logger


def teardown_error_logging():
    """Teardown error logging and restore original exception handler."""
    global _global_error_logger
    if _global_error_logger:
        _global_error_logger.cleanup()
        _global_error_logger = None


def log_error(
    error_type: str,
    error_message: str,
    traceback: Optional[str] = None,
    context: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
):
    """
    Convenience function to log an error using the global error logger.
    
    Args:
        error_type: Type of error
        error_message: Error message
        traceback: Optional traceback string
        context: Optional context
        metadata: Optional metadata
    """
    if _global_error_logger:
        _global_error_logger.log_error(error_type, error_message, traceback, context, metadata)


def log_exception(
    exception: Exception,
    context: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
):
    """
    Convenience function to log an exception using the global error logger.
    
    Args:
        exception: Exception object
        context: Optional context
        metadata: Optional metadata
    """
    if _global_error_logger:
        _global_error_logger.log_exception(exception, context, metadata)

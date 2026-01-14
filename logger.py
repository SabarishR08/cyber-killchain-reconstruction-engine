"""
Structured logging and audit trail module.
Provides centralized logging with correlation IDs and audit tracking.
"""
import logging
import logging.handlers
import os
import json
from datetime import datetime
from typing import Optional, Dict, Any
from uuid import uuid4


class CorrelationIdFilter(logging.Filter):
    """Add correlation ID to log records."""
    
    def __init__(self):
        super().__init__()
        self.correlation_id = None
    
    def filter(self, record):
        record.correlation_id = self.correlation_id or "N/A"
        return True


class StructuredLogger:
    """Structured logging with audit trails."""
    
    _instance = None
    _correlation_id_filter = CorrelationIdFilter()
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(StructuredLogger, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        """Initialize structured logger."""
        if self._initialized:
            return
        
        self.logger = logging.getLogger("killchain")
        self.audit_logger = logging.getLogger("killchain.audit")
        self._setup_handlers()
        self._initialized = True
    
    def _setup_handlers(self):
        """Set up logging handlers."""
        # Create logs directory if it doesn't exist
        os.makedirs("logs", exist_ok=True)
        
        # Main logger format
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(correlation_id)s] - %(message)s'
        )
        
        # Add correlation ID filter
        self.logger.addFilter(self._correlation_id_filter)
        self.audit_logger.addFilter(self._correlation_id_filter)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # File handler with rotation
        file_handler = logging.handlers.RotatingFileHandler(
            "logs/killchain.log",
            maxBytes=10485760,  # 10 MB
            backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # Audit logger (file only)
        audit_handler = logging.handlers.RotatingFileHandler(
            "logs/audit.log",
            maxBytes=10485760,
            backupCount=10
        )
        audit_formatter = logging.Formatter(
            '%(asctime)s - [%(correlation_id)s] - %(message)s'
        )
        audit_handler.setFormatter(audit_formatter)
        self.audit_logger.addHandler(audit_handler)
        
        # Set levels
        self.logger.setLevel(logging.DEBUG)
        self.audit_logger.setLevel(logging.INFO)
    
    def set_correlation_id(self, correlation_id: Optional[str] = None):
        """Set correlation ID for request tracking."""
        self._correlation_id_filter.correlation_id = correlation_id or str(uuid4())
    
    def get_correlation_id(self) -> str:
        """Get current correlation ID."""
        return self._correlation_id_filter.correlation_id or "N/A"
    
    def info(self, message: str, **kwargs):
        """Log info level message."""
        if kwargs:
            message = f"{message} | {json.dumps(kwargs)}"
        self.logger.info(message)
    
    def debug(self, message: str, **kwargs):
        """Log debug level message."""
        if kwargs:
            message = f"{message} | {json.dumps(kwargs)}"
        self.logger.debug(message)
    
    def warning(self, message: str, **kwargs):
        """Log warning level message."""
        if kwargs:
            message = f"{message} | {json.dumps(kwargs)}"
        self.logger.warning(message)
    
    def error(self, message: str, **kwargs):
        """Log error level message."""
        if kwargs:
            message = f"{message} | {json.dumps(kwargs)}"
        self.logger.error(message)
    
    def critical(self, message: str, **kwargs):
        """Log critical level message."""
        if kwargs:
            message = f"{message} | {json.dumps(kwargs)}"
        self.logger.critical(message)
    
    def audit(self, event_type: str, details: Dict[str, Any]):
        """
        Log audit trail event.
        
        Args:
            event_type: Type of event (e.g., 'incident_detected', 'event_ingested')
            details: Event details dictionary
        """
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "details": details
        }
        self.audit_logger.info(json.dumps(audit_entry))


def get_logger() -> StructuredLogger:
    """Get global logger instance."""
    return StructuredLogger()


def set_correlation_id(correlation_id: Optional[str] = None):
    """Set correlation ID for tracking."""
    get_logger().set_correlation_id(correlation_id)


def get_correlation_id() -> str:
    """Get current correlation ID."""
    return get_logger().get_correlation_id()

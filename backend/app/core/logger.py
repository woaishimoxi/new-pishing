"""
Logging System Module
Enterprise-grade logging with structured output
"""
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
import json
from logging.handlers import RotatingFileHandler


class StructuredFormatter(logging.Formatter):
    """Structured JSON formatter for logs"""
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        
        if hasattr(record, 'extra_data') and record.extra_data:
            log_data['extra'] = record.extra_data
        
        return json.dumps(log_data, ensure_ascii=False)


class ColoredFormatter(logging.Formatter):
    """Colored formatter for console output"""
    
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
    }
    RESET = '\033[0m'
    
    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


class LoggerAdapter(logging.LoggerAdapter):
    """Custom logger adapter with extra context support"""
    
    def process(self, msg: str, kwargs: Dict) -> tuple:
        if 'extra_data' in kwargs:
            if not hasattr(self, 'extra'):
                self.extra = {}
            self.extra.update(kwargs.pop('extra_data'))
        return msg, kwargs


class LoggerManager:
    """Logger manager for centralized logging configuration"""
    
    _loggers: Dict[str, logging.Logger] = {}
    _configured: bool = False
    
    @classmethod
    def setup(
        cls,
        level: str = "INFO",
        log_file: Optional[str] = None,
        max_bytes: int = 10 * 1024 * 1024,
        backup_count: int = 5,
        console_output: bool = True,
        json_format: bool = False
    ) -> None:
        """
        Setup logging configuration
        
        Args:
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Path to log file
            max_bytes: Maximum size of each log file
            backup_count: Number of backup files to keep
            console_output: Whether to output to console
            json_format: Whether to use JSON format for file logs
        """
        if cls._configured:
            return
        
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        
        root_logger.handlers.clear()
        
        if console_output:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.DEBUG)
            console_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            console_handler.setFormatter(ColoredFormatter(console_format))
            root_logger.addHandler(console_handler)
        
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding='utf-8'
            )
            file_handler.setLevel(logging.DEBUG)
            
            if json_format:
                file_handler.setFormatter(StructuredFormatter())
            else:
                file_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                file_handler.setFormatter(logging.Formatter(file_format))
            
            root_logger.addHandler(file_handler)
        
        cls._configured = True
    
    @classmethod
    def get_logger(cls, name: str) -> logging.Logger:
        """
        Get or create a logger by name
        
        Args:
            name: Logger name (usually __name__)
            
        Returns:
            Logger instance
        """
        if name not in cls._loggers:
            cls._loggers[name] = logging.getLogger(name)
        return cls._loggers[name]


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = "logs/app.log",
    **kwargs
) -> None:
    """
    Setup logging configuration (convenience function)
    
    Args:
        level: Log level
        log_file: Path to log file
        **kwargs: Additional options for LoggerManager.setup
    """
    LoggerManager.setup(level=level, log_file=log_file, **kwargs)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance (convenience function)
    
    Args:
        name: Logger name (usually __name__)
        
    Returns:
        Logger instance
    """
    return LoggerManager.get_logger(name)


class LogContext:
    """Context manager for logging with timing"""
    
    def __init__(self, logger: logging.Logger, operation: str, **extra_data):
        self.logger = logger
        self.operation = operation
        self.extra_data = extra_data
        self.start_time: Optional[float] = None
    
    def __enter__(self):
        self.start_time = datetime.now().timestamp()
        self.logger.info(f"Starting {self.operation}", extra={'extra_data': self.extra_data})
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = datetime.now().timestamp() - self.start_time
        extra = {**self.extra_data, 'duration_ms': round(duration * 1000, 2)}
        
        if exc_type:
            self.logger.error(
                f"Failed {self.operation}: {exc_val}",
                extra={'extra_data': extra},
                exc_info=True
            )
        else:
            self.logger.info(f"Completed {self.operation}", extra={'extra_data': extra})
        
        return False

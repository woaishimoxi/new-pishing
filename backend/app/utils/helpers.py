"""
Helpers Module
General helper functions
"""
from datetime import datetime
from typing import Optional, Any


def format_timestamp(timestamp: Optional[str] = None, format_str: str = '%Y-%m-%d %H:%M:%S') -> str:
    """
    Format timestamp string
    
    Args:
        timestamp: ISO format timestamp string
        format_str: Output format string
        
    Returns:
        Formatted timestamp string
    """
    if not timestamp:
        return ''
    
    try:
        if 'T' in timestamp:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        else:
            dt = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
        
        return dt.strftime(format_str)
    except Exception:
        return timestamp


def truncate_text(text: str, max_length: int = 100, suffix: str = '...') -> str:
    """
    Truncate text to specified length
    
    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to append when truncated
        
    Returns:
        Truncated text
    """
    if not text:
        return ''
    
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human readable format
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Formatted size string
    """
    if size_bytes < 0:
        return '0 B'
    
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    size = float(size_bytes)
    
    for unit in units:
        if size < 1024:
            return f'{size:.1f} {unit}'
        size /= 1024
    
    return f'{size:.1f} PB'


def safe_json_serialize(obj: Any) -> Any:
    """
    Safely serialize object to JSON compatible format
    
    Args:
        obj: Object to serialize
        
    Returns:
        JSON serializable object
    """
    if obj is None:
        return None
    
    if isinstance(obj, (str, int, float, bool)):
        return obj
    
    if isinstance(obj, bytes):
        return obj.decode('utf-8', errors='ignore')
    
    if isinstance(obj, dict):
        return {k: safe_json_serialize(v) for k, v in obj.items()}
    
    if isinstance(obj, (list, tuple)):
        return [safe_json_serialize(item) for item in obj]
    
    if hasattr(obj, '__dict__'):
        return safe_json_serialize(obj.__dict__)
    
    return str(obj)


def calculate_percentage(value: float, total: float) -> float:
    """
    Calculate percentage
    
    Args:
        value: Value
        total: Total
        
    Returns:
        Percentage (0-100)
    """
    if total == 0:
        return 0.0
    
    return min(100.0, max(0.0, (value / total) * 100))

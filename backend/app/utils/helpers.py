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


def sanitize_ai_api_key(api_key: str) -> str:
    """Strip whitespace and invisible Unicode that often breaks HTTP headers."""
    if not api_key:
        return ''
    key = api_key.strip().replace('\ufeff', '')
    for ch in ('\u200b', '\u200c', '\u200d', '\u00a0'):
        key = key.replace(ch, '')
    return key


def normalize_ai_api_url(url: str) -> str:
    """
    Encode URL for HTTP clients: percent-escape non-ASCII in path/query, punycode IDN host.
    Avoids urllib3/http.client 'latin-1' codec errors on outbound requests.
    """
    url = (url or '').strip()
    if not url:
        return url
    try:
        from requests.utils import requote_uri
        url = requote_uri(url)
    except Exception:
        pass
    from urllib.parse import urlparse, urlunparse, quote
    parsed = urlparse(url)
    path = parsed.path
    if path and not path.isascii():
        path = quote(path, safe='/:~%.-_+')
    netloc = parsed.netloc
    hn = parsed.hostname
    if hn and not hn.isascii():
        try:
            ascii_h = hn.encode('idna').decode('ascii')
            netloc = netloc.replace(hn, ascii_h, 1)
        except Exception:
            pass
    query = parsed.query
    if query and not query.isascii():
        query = quote(query, safe='=&/:+,%?@~$!*\'()')
    return urlunparse((parsed.scheme, netloc, path, parsed.params, query, parsed.fragment))


def require_http_header_latin1(value: str, field_desc: str) -> None:
    """Raise ValueError if value cannot be encoded as latin-1 (required for HTTP headers)."""
    try:
        value.encode('latin-1')
    except UnicodeEncodeError as e:
        raise ValueError(
            f'{field_desc} 含有 HTTP 协议不允许的字符（如中文、部分 Emoji）。'
            f'请使用纯 ASCII 的 API Key，并确认 API 地址为英文 URL。'
        ) from e

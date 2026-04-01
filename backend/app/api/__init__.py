"""
API Module - Flask Blueprints
"""
from .detection import detection_bp
from .alerts import alerts_bp
from .config import config_bp
from .stats import stats_bp
from .email import email_bp
from .system import system_bp
from .domains import domains_bp
from .settings import settings_bp
from .attachment import attachment_bp
from .docs import api_docs, api
from .monitor import monitor_bp

__all__ = [
    'detection_bp',
    'alerts_bp',
    'config_bp',
    'stats_bp',
    'email_bp',
    'system_bp',
    'domains_bp',
    'settings_bp',
    'attachment_bp',
    'api_docs',
    'api',
    'monitor_bp'
]

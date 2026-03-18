"""
API Module - Flask Blueprints
"""
from .detection import detection_bp
from .alerts import alerts_bp
from .config import config_bp
from .stats import stats_bp
from .email import email_bp
from .docs import api_docs, api

__all__ = [
    'detection_bp',
    'alerts_bp',
    'config_bp',
    'stats_bp',
    'email_bp',
    'api_docs',
    'api'
]

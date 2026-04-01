#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Monitor API Routes
Email monitoring control endpoints
"""
from flask import Blueprint, jsonify, request

monitor_bp = Blueprint('monitor', __name__)


@monitor_bp.route('/start', methods=['POST'])
def start_monitor():
    """
    Start email monitor
    
    POST /api/monitor/start
    """
    from app.services.email_monitor import email_monitor
    
    result = email_monitor.start()
    
    if result['success']:
        return jsonify({
            'status': 'success',
            'message': result['message'],
            'running': email_monitor.is_running
        })
    else:
        return jsonify({
            'status': 'error',
            'message': result['message'],
            'running': email_monitor.is_running
        }), 400


@monitor_bp.route('/stop', methods=['POST'])
def stop_monitor():
    """
    Stop email monitor
    
    POST /api/monitor/stop
    """
    from app.services.email_monitor import email_monitor
    
    result = email_monitor.stop()
    
    if result['success']:
        return jsonify({
            'status': 'success',
            'message': result['message'],
            'running': email_monitor.is_running
        })
    else:
        return jsonify({
            'status': 'error',
            'message': result['message'],
            'running': email_monitor.is_running
        }), 400


@monitor_bp.route('/status', methods=['GET'])
def get_monitor_status():
    """
    Get monitor status
    
    GET /api/monitor/status
    """
    from app.services.email_monitor import email_monitor
    
    status = email_monitor.get_status()
    
    return jsonify({
        'status': 'success',
        'data': status
    })


@monitor_bp.route('/toggle', methods=['POST'])
def toggle_monitor():
    """
    Toggle monitor on/off
    
    POST /api/monitor/toggle
    """
    from app.services.email_monitor import email_monitor
    
    if email_monitor.is_running:
        result = email_monitor.stop()
    else:
        result = email_monitor.start()
    
    return jsonify({
        'status': 'success' if result['success'] else 'error',
        'message': result['message'],
        'running': email_monitor.is_running
    })


@monitor_bp.route('/config', methods=['GET'])
def get_monitor_config():
    """
    Get monitor configuration
    
    GET /api/monitor/config
    """
    from app.core.config import get_config
    
    config = get_config()
    
    return jsonify({
        'status': 'success',
        'data': {
            'auto_monitor': getattr(config.email, 'auto_monitor', False),
            'interval': getattr(config.email, 'monitor_interval', 30),
            'email_configured': bool(
                config.email.address and
                config.email.password and
                config.email.server
            )
        }
    })


@monitor_bp.route('/config', methods=['POST'])
def update_monitor_config():
    """
    Update monitor configuration
    
    POST /api/monitor/config
    Body: { "interval": 60, "auto_start": true }
    """
    from app.core.config import get_config
    from app.services.email_monitor import email_monitor
    
    data = request.get_json() or {}
    config = get_config()
    
    if 'interval' in data:
        interval = int(data['interval'])
        if interval < 10:
            return jsonify({
                'status': 'error',
                'message': 'Interval must be at least 10 seconds'
            }), 400
        
        config.email.monitor_interval = interval
    
    return jsonify({
        'status': 'success',
        'message': 'Configuration updated',
        'data': {
            'interval': getattr(config.email, 'monitor_interval', 30)
        }
    })

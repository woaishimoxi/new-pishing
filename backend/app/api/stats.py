"""
Stats API Routes
"""
from flask import Blueprint, jsonify, request
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.core import get_logger
from app.models.database import DatabaseRepository

stats_bp = Blueprint('stats', __name__)
logger = get_logger(__name__)
db = DatabaseRepository()


@stats_bp.route('/overview', methods=['GET'])
def get_overview_stats():
    """Get overview statistics"""
    stats = db.get_stats()
    
    return jsonify({
        'total': stats['total'],
        'phishing': stats['phishing'],
        'suspicious': stats['suspicious'],
        'normal': stats['normal'],
        'today': stats['today'],
        'trend': stats['trend']
    })


@stats_bp.route('/daily', methods=['GET'])
def get_daily_stats():
    """Get daily statistics"""
    days = request.args.get('days', 7, type=int)
    
    stats = db.get_stats()
    
    daily_data = []
    for item in stats.get('trend', []):
        daily_data.append({
            'day': item.get('day'),
            'total': item.get('count', 0),
            'phishing': item.get('phish_count', 0),
            'suspicious': item.get('suspicious_count', 0),
            'normal': item.get('safe_count', 0)
        })
    
    return jsonify(daily_data)

#!/usr/bin/env python3
"""
系统管理API
提供智能配置、性能监控等功能
"""
from flask import Blueprint, jsonify, request
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.services import auto_tuner, monitor

system_bp = Blueprint('system', __name__)


@system_bp.route('/api/system/auto-tune', methods=['POST'])
def auto_tune():
    """
    智能参数调优
    
    POST /api/system/auto-tune
    """
    try:
        result = auto_tuner.auto_tune()
        return jsonify(result), 200 if result['success'] else 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@system_bp.route('/api/system/performance', methods=['GET'])
def get_performance():
    """
    获取性能指标
    
    GET /api/system/performance
    """
    try:
        summary = monitor.get_performance_summary()
        return jsonify(summary), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@system_bp.route('/api/system/performance/daily', methods=['GET'])
def get_daily_performance():
    """
    获取每日性能统计
    
    GET /api/system/performance/daily?days=7
    """
    try:
        days = request.args.get('days', 7, type=int)
        daily_stats = monitor.get_daily_stats(days)
        return jsonify({'daily_stats': daily_stats}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@system_bp.route('/api/system/performance/report', methods=['GET'])
def get_performance_report():
    """
    获取性能报告
    
    GET /api/system/performance/report
    """
    try:
        report = monitor.generate_report()
        return jsonify({'report': report}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@system_bp.route('/api/system/performance/export', methods=['POST'])
def export_performance_report():
    """
    导出性能报告
    
    POST /api/system/performance/export
    """
    try:
        filepath = monitor.export_report()
        return jsonify({'success': True, 'filepath': filepath}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

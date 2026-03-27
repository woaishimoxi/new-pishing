#!/usr/bin/env python3
"""
附件深度分析API
使用微步在线进行沙箱检测
"""
from flask import Blueprint, jsonify, request
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.core import get_logger
from app.services.threatbook import threatbook_service
from app.models.database import DatabaseRepository

attachment_bp = Blueprint('attachment', __name__)
logger = get_logger(__name__)
db = DatabaseRepository()


@attachment_bp.route('/api/attachment/analyze', methods=['POST'])
def analyze_attachment():
    """
    附件深度分析
    
    POST /api/attachment/analyze
    Body: {
        "alert_id": 123,
        "attachment_index": 0
    }
    """
    data = request.get_json() or {}
    alert_id = data.get('alert_id')
    attachment_index = data.get('attachment_index', 0)
    
    if not alert_id:
        return jsonify({'error': '未提供告警ID'}), 400
    
    # 获取告警信息
    alert = db.get_alert(alert_id)
    if not alert:
        return jsonify({'error': '告警不存在'}), 404
    
    # 获取附件信息
    attachments = alert.get('attachments', [])
    if not attachments:
        return jsonify({'error': '该邮件没有附件'}), 400
    
    if attachment_index >= len(attachments):
        return jsonify({'error': '附件索引无效'}), 400
    
    attachment = attachments[attachment_index]
    filename = attachment.get('filename', 'unknown')
    
    # 使用微步分析
    # 注意：由于附件内容未保存在数据库，这里使用文件哈希查询
    md5 = attachment.get('md5', '')
    sha256 = attachment.get('sha256', '')
    
    if md5:
        # 查询已有分析结果
        result = threatbook_service.analyze_file(b'', filename)
        result['md5'] = md5
        result['sha256'] = sha256
    else:
        result = {
            'filename': filename,
            'error': '附件哈希未保存，无法进行深度分析',
            'threat_level': 'unknown',
            'threat_score': 50
        }
    
    return jsonify(result)


@attachment_bp.route('/api/attachment/upload-analyze', methods=['POST'])
def upload_and_analyze():
    """
    上传附件进行深度分析
    
    POST /api/attachment/upload-analyze
    Body: multipart/form-data with 'file' field
    """
    if 'file' not in request.files:
        return jsonify({'error': '未上传文件'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': '文件名为空'}), 400
    
    try:
        file_content = file.read()
        result = threatbook_service.analyze_file(file_content, file.filename)
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"附件分析失败: {e}")
        return jsonify({'error': str(e)}), 500


@attachment_bp.route('/api/attachment/report/<md5>', methods=['GET'])
def get_attachment_report(md5):
    """
    查询附件分析报告
    
    GET /api/attachment/report/{md5}
    """
    try:
        result = threatbook_service._query_file_report(md5)
        
        if result:
            parsed = threatbook_service._parse_report(result)
            parsed['md5'] = md5
            return jsonify(parsed)
        else:
            return jsonify({'error': '未找到分析报告', 'md5': md5}), 404
    
    except Exception as e:
        logger.error(f"查询附件报告失败: {e}")
        return jsonify({'error': str(e)}), 500

"""
Alerts API Routes
"""
from flask import Blueprint, jsonify, request
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.core import get_logger
from app.models.database import DatabaseRepository

alerts_bp = Blueprint('alerts', __name__)
logger = get_logger(__name__)
db = DatabaseRepository()


@alerts_bp.route('', methods=['GET'])
def get_alerts():
    """Get paginated alerts"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    label_filter = request.args.get('label', None)
    
    result = db.get_alerts(page, per_page, label_filter)
    
    return jsonify(result)


@alerts_bp.route('/<int:alert_id>', methods=['GET'])
def get_alert_detail(alert_id: int):
    """Get single alert detail"""
    alert = db.get_alert(alert_id)
    
    if not alert:
        return jsonify({'error': '邮件不存在'}), 404
    
    return jsonify(alert)


@alerts_bp.route('/<int:alert_id>', methods=['DELETE'])
def delete_alert(alert_id: int):
    """Delete single alert"""
    if not db.delete_alert(alert_id):
        return jsonify({'error': '报告不存在'}), 404
    
    return jsonify({'status': 'success', 'message': '报告已删除'})


@alerts_bp.route('/batch', methods=['DELETE'])
def batch_delete_alerts():
    """Batch delete alerts"""
    data = request.get_json()
    alert_ids = data.get('ids', [])
    
    if not alert_ids:
        return jsonify({'error': '未提供要删除的报告ID'}), 400
    
    deleted_count = db.batch_delete_alerts(alert_ids)
    
    return jsonify({
        'status': 'success',
        'message': f'成功删除 {deleted_count} 条报告',
        'deleted_count': deleted_count
    })


@alerts_bp.route('/<int:alert_id>/export', methods=['GET'])
def export_raw_email(alert_id):
    """
    Export raw email as .eml file
    
    GET /api/alerts/{alert_id}/export
    """
    alert = db.get_alert(alert_id)
    if not alert:
        return jsonify({'error': '报告不存在'}), 404
    
    raw_email = alert.get('raw_email', '')
    if not raw_email:
        return jsonify({'error': '原始邮件未保存'}), 404
    
    # 生成文件名
    subject = alert.get('subject', 'email')
    # 清理文件名中的特殊字符
    safe_subject = ''.join(c for c in subject if c.isalnum() or c in ' _-')[:50]
    filename = f"{safe_subject}.eml"
    
    from flask import Response
    return Response(
        raw_email,
        mimetype='message/rfc822',
        headers={
            'Content-Disposition': f'attachment; filename="{filename}"',
            'Content-Type': 'message/rfc822; charset=utf-8'
        }
    )


@alerts_bp.route('/<int:alert_id>/export/json', methods=['GET'])
def export_report_json(alert_id):
    """
    Export full report as JSON file
    
    GET /api/alerts/{alert_id}/export/json
    """
    alert = db.get_alert(alert_id)
    if not alert:
        return jsonify({'error': '报告不存在'}), 404
    
    # 构建完整报告
    report = {
        'report_id': f"PHISH-{alert.get('id', 'unknown')}",
        'detection_time': alert.get('detection_time'),
        'result': alert
    }
    
    from flask import Response
    return Response(
        json.dumps(report, ensure_ascii=False, indent=2),
        mimetype='application/json',
        headers={
            'Content-Disposition': f'attachment; filename="report_{alert_id}.json"',
            'Content-Type': 'application/json; charset=utf-8'
        }
    )


@alerts_bp.route('/<int:alert_id>/ai-analyze', methods=['POST'])
def ai_analyze(alert_id):
    """
    AI analysis for email (预留接口，为接入大模型做准备)
    
    POST /api/alerts/{alert_id}/ai-analyze
    Body: {"model": "gpt-4", "prompt": "分析这封邮件是否为钓鱼邮件"}
    """
    alert = db.get_alert(alert_id)
    if not alert:
        return jsonify({'error': '报告不存在'}), 404
    
    data = request.get_json() or {}
    model = data.get('model', 'default')
    prompt = data.get('prompt', '请分析这封邮件是否为钓鱼邮件，并说明原因。')
    
    # 准备邮件数据
    email_data = {
        'subject': alert.get('subject', ''),
        'from_email': alert.get('from_email', ''),
        'from_display_name': alert.get('from_display_name', ''),
        'to': alert.get('to_addr', ''),
        'body': alert.get('body', ''),
        'urls': alert.get('urls', []),
        'current_label': alert.get('label', ''),
        'current_confidence': alert.get('confidence', 0)
    }
    
    # TODO: 接入AI大模型API
    # 这里预留接口，后续可以接入以下服务：
    # - OpenAI GPT-4
    # - 文心一言
    # - 通义千问
    # - Claude
    
    # 目前返回模拟响应
    ai_response = {
        'status': 'placeholder',
        'message': 'AI分析功能预留接口',
        'model': model,
        'prompt': prompt,
        'email_summary': {
            'subject': email_data['subject'],
            'from': email_data['from_email'],
            'url_count': len(email_data['urls']),
            'current_analysis': {
                'label': email_data['current_label'],
                'confidence': email_data['current_confidence']
            }
        },
        'ai_suggestion': '此接口已预留，可接入OpenAI GPT-4、文心一言等大模型进行深度分析。',
        'integration_guide': {
            'step1': '获取AI服务API Key',
            'step2': '在config/api_config.json中添加ai_api_key配置',
            'step3': '实现AI服务调用逻辑',
            'step4': '解析AI返回结果并更新邮件分析'
        }
    }
    
    return jsonify(ai_response)


@alerts_bp.route('/<int:alert_id>/analyze-detail', methods=['GET'])
def get_analysis_detail(alert_id):
    """
    Get detailed analysis with feature breakdown
    
    GET /api/alerts/{alert_id}/analyze-detail
    """
    alert = db.get_alert(alert_id)
    if not alert:
        return jsonify({'error': '报告不存在'}), 404
    
    # 解析特征数据
    features = {}
    if alert.get('features'):
        try:
            if isinstance(alert['features'], str):
                features = json.loads(alert['features'])
            else:
                features = alert['features']
        except:
            features = {}
    
    # 解析溯源数据
    traceback_data = {}
    if alert.get('traceback_data'):
        try:
            if isinstance(alert['traceback_data'], str):
                traceback_data = json.loads(alert['traceback_data'])
            else:
                traceback_data = alert['traceback_data']
        except:
            traceback_data = {}
    
    # 构建详细分析报告
    detail = {
        'basic_info': {
            'id': alert.get('id'),
            'subject': alert.get('subject'),
            'from_email': alert.get('from_email'),
            'from_display_name': alert.get('from_display_name'),
            'to': alert.get('to_addr'),
            'detection_time': alert.get('detection_time'),
            'label': alert.get('label'),
            'confidence': alert.get('confidence'),
            'source': alert.get('source')
        },
        'header_analysis': {
            'spf_result': alert.get('spf_result', 'none'),
            'dkim_result': alert.get('dkim_result', 'none'),
            'dmarc_result': alert.get('dmarc_result', 'none'),
            'x_mailer': alert.get('x_mailer', ''),
            'is_forwarded': '转发' in (alert.get('subject') or '')
        },
        'features': features,
        'url_analysis': traceback_data.get('url_analysis', []),
        'attack_chain': traceback_data.get('correlation_analysis', {}).get('attack_chain', []),
        'ioc_matches': traceback_data.get('ioc_matches', {}),
        'risk_indicators': traceback_data.get('risk_indicators', []),
        'threat_score': traceback_data.get('correlation_analysis', {}).get('threat_score', 0),
        'raw_email_available': bool(alert.get('raw_email'))
    }
    
    return jsonify(detail)

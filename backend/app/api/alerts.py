"""
Alerts API Routes
"""
from flask import Blueprint, jsonify, request
import sys
import os
import json
import requests
from typing import Dict
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
    
    # 生成文件名（只使用ASCII字符，避免HTTP头编码问题）
    filename = f"email_{alert_id}.eml"
    
    from flask import Response
    from urllib.parse import quote
    
    # 获取原始主题用于中文文件名
    subject = alert.get('subject', '')
    if subject:
        # URL编码中文文件名
        encoded_subject = quote(subject[:30], safe='')
        content_disposition = f'attachment; filename="{filename}"; filename*=UTF-8\'\'{encoded_subject}.eml'
    else:
        content_disposition = f'attachment; filename="{filename}"'
    
    return Response(
        raw_email,
        mimetype='message/rfc822',
        headers={
            'Content-Disposition': content_disposition,
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
    
    # 读取AI配置
    config_file = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        'config', 'api_config.json'
    )
    
    ai_config = {}
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                all_config = json.load(f)
                ai_config = all_config.get('ai', {})
        except:
            pass
    
    # 检查AI配置是否完整
    if not ai_config.get('enabled') or not ai_config.get('api_key'):
        return jsonify({
            'status': 'placeholder',
            'message': 'AI分析未配置',
            'ai_suggestion': '请在系统配置中设置AI服务',
            'integration_guide': {
                'step1': '获取AI服务API Key',
                'step2': '在系统配置中填写API配置',
                'step3': '启用AI分析功能'
            }
        })
    
    # 准备邮件信息
    email_summary = f"""
邮件主题: {email_data['subject']}
发件人: {email_data['from_display_name']} <{email_data['from_email']}>
收件人: {email_data['to']}
URL数量: {len(email_data['urls'])}
当前检测结果: {email_data['current_label']} (置信度: {email_data['current_confidence']:.2%})

邮件内容摘要:
{(alert.get('body') or '')[:500]}
"""
    
    # 调用AI服务
    try:
        ai_result = call_ai_service(ai_config, email_summary, prompt)
        return jsonify({
            'status': 'success',
            'ai_result': ai_result
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'AI分析失败: {str(e)}'
        }), 500


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


def call_ai_service(ai_config: Dict, email_content: str, prompt: str) -> Dict:
    """
    调用AI服务进行邮件分析
    
    支持：OpenAI、文心一言、通义千问、智谱AI、月之暗面
    """
    provider = ai_config.get('provider', 'openai')
    api_key = ai_config.get('api_key', '')
    api_url = ai_config.get('api_url', '')
    model = ai_config.get('model', 'gpt-4')
    
    # 构建系统提示
    system_prompt = """你是一个专业的邮件安全分析师。请分析以下邮件是否为钓鱼邮件，并提供详细的分析报告。

请按以下格式返回JSON：
{
    "is_phishing": true/false,
    "risk_score": 0-100,
    "conclusion": "简短结论",
    "analysis": "详细分析（从发件人、内容、链接、语气等方面分析）",
    "suggestions": ["建议1", "建议2", ...]
}"""
    
    # 构建用户消息
    user_message = f"""请分析以下邮件：

{email_content}

分析要求：{prompt}"""
    
    # 根据不同提供商调用API
    if provider == 'openai' or provider == 'moonshot' or provider == 'custom':
        # OpenAI兼容格式
        if not api_url:
            api_url = 'https://api.openai.com/v1/chat/completions'
        
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        
        data = {
            'model': model,
            'messages': [
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': user_message}
            ],
            'temperature': 0.3
        }
        
        response = requests.post(api_url, headers=headers, json=data, timeout=60)
        result = response.json()
        
        if 'choices' in result and len(result['choices']) > 0:
            ai_text = result['choices'][0]['message']['content']
        else:
            raise Exception(f"AI返回异常: {result}")
    
    elif provider == 'baidu':
        # 百度文心一言
        url = f"{api_url}?access_token={api_key}"
        
        data = {
            'messages': [
                {'role': 'user', 'content': system_prompt + '\n\n' + user_message}
            ]
        }
        
        response = requests.post(url, json=data, timeout=60)
        result = response.json()
        
        if 'result' in result:
            ai_text = result['result']
        else:
            raise Exception(f"文心一言返回异常: {result}")
    
    elif provider == 'alibaba':
        # 阿里通义千问
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        
        data = {
            'model': model,
            'input': {
                'messages': [
                    {'role': 'system', 'content': system_prompt},
                    {'role': 'user', 'content': user_message}
                ]
            },
            'parameters': {
                'temperature': 0.3
            }
        }
        
        response = requests.post(api_url, headers=headers, json=data, timeout=60)
        result = response.json()
        
        if 'output' in result and 'text' in result['output']:
            ai_text = result['output']['text']
        else:
            raise Exception(f"通义千问返回异常: {result}")
    
    elif provider == 'zhipu':
        # 智谱ChatGLM
        import jwt
        import time
        
        # 生成JWT token
        api_key_parts = api_key.split('.')
        if len(api_key_parts) != 2:
            raise Exception("智谱API Key格式错误")
        
        id, secret = api_key_parts
        payload = {
            "api_key": id,
            "exp": int(round(time.time() * 1000)) + 3600 * 1000,
            "timestamp": int(round(time.time() * 1000))
        }
        token = jwt.encode(payload, secret, algorithm="HS256")
        
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        data = {
            'model': model,
            'messages': [
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': user_message}
            ]
        }
        
        response = requests.post(api_url, headers=headers, json=data, timeout=60)
        result = response.json()
        
        if 'choices' in result and len(result['choices']) > 0:
            ai_text = result['choices'][0]['message']['content']
        else:
            raise Exception(f"智谱AI返回异常: {result}")
    
    else:
        raise Exception(f"不支持的AI提供商: {provider}")
    
    # 解析AI返回的JSON
    try:
        # 尝试从返回文本中提取JSON
        import re
        json_match = re.search(r'\{[\s\S]*\}', ai_text)
        if json_match:
            ai_result = json.loads(json_match.group())
        else:
            # 如果没有JSON，构建一个基本结果
            ai_result = {
                'is_phishing': '钓鱼' in ai_text or 'phishing' in ai_text.lower(),
                'risk_score': 50 if '风险' in ai_text else 20,
                'conclusion': ai_text[:200],
                'analysis': ai_text,
                'suggestions': ['请仔细核实发件人身份', '不要点击可疑链接']
            }
    except json.JSONDecodeError:
        ai_result = {
            'is_phishing': False,
            'risk_score': 30,
            'conclusion': 'AI分析完成',
            'analysis': ai_text,
            'suggestions': ['请人工复核']
        }
    
    return ai_result

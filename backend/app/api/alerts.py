"""
Alerts API Routes
"""
from flask import Blueprint, jsonify, request
import sys
import os
import re
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
    
    # 添加reason字段（数据库中没有这个字段）
    if 'reason' not in alert or not alert.get('reason'):
        label = alert.get('label', 'UNKNOWN')
        confidence = alert.get('confidence', 0)
        
        if label == 'PHISHING':
            alert['reason'] = '检测到高置信度钓鱼邮件特征'
        elif label == 'SUSPICIOUS':
            alert['reason'] = '检测到可疑特征，建议人工复核'
        elif label == 'SAFE':
            alert['reason'] = '未检测到显著威胁'
        else:
            alert['reason'] = '检测完成'
    
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
    AI deep analysis for email
    
    POST /api/alerts/{alert_id}/ai-analyze
    """
    alert = db.get_alert(alert_id)
    if not alert:
        return jsonify({'error': '报告不存在'}), 404
    
    config_file = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
        'config', 'api_config.json'
    )
    
    ai_config = {}
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                all_config = json.load(f)
                ai_config = all_config.get('ai', {})
        except Exception as e:
            logger.error(f"Failed to load AI config: {e}")
    
    if not ai_config.get('api_key'):
        return jsonify({
            'status': 'error',
            'message': 'AI分析未配置',
            'ai_suggestion': '请在系统配置中设置AI服务的API Key',
            'integration_guide': {
                'step1': '获取AI服务API Key（推荐智谱AI）',
                'step2': '在系统配置中填写API配置',
                'step3': '保存配置后再次尝试AI分析'
            }
        })
    
    traceback_data = {}
    if alert.get('traceback_data'):
        try:
            if isinstance(alert['traceback_data'], str):
                traceback_data = json.loads(alert['traceback_data'])
            else:
                traceback_data = alert['traceback_data']
        except:
            pass
    
    urls = []
    if alert.get('url_data'):
        try:
            if isinstance(alert['url_data'], str):
                urls = json.loads(alert['url_data'])
            else:
                urls = alert['url_data']
        except:
            pass
    
    attachments = []
    if alert.get('attachment_data'):
        try:
            if isinstance(alert['attachment_data'], str):
                attachments = json.loads(alert['attachment_data'])
            else:
                attachments = alert['attachment_data']
        except:
            pass
    
    body = alert.get('body', '') or ''
    html_body = alert.get('html_body', '') or ''
    
    # 构建处理后的邮件内容（与detection.py保持一致）
    # 这样AI分析的是用户看到的实际内容，而非原始编码数据
    email_content = f"""发件人: {alert.get('from_display_name', '')} <{alert.get('from_email', '')}>
收件人: {alert.get('to_addr', '')}
主题: {alert.get('subject', '')}

邮件正文:
{body or html_body or '[无正文内容]'}

包含的URL:
{chr(10).join('- ' + url for url in urls[:10]) if urls else '[无URL]'}

附件信息:
{chr(10).join('- ' + att.get('filename', '未知') for att in attachments[:5]) if attachments else '[无附件]'}
"""
    
    try:
        ai_result = call_ai_service(ai_config, email_content)
        return jsonify({
            'status': 'success',
            'ai_result': ai_result
        })
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
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


@alerts_bp.route('/<int:alert_id>/traceback', methods=['GET'])
def get_enhanced_traceback(alert_id):
    """
    获取增强版溯源分析报告
    
    GET /api/alerts/{alert_id}/traceback
    返回5个维度的深度分析：
    1. 攻击目标
    2. IP来源与传播链
    3. 攻击特性（社会工程学）
    4. 攻击载体
    5. 攻击动机
    """
    alert = db.get_alert(alert_id)
    if not alert:
        return jsonify({'error': '报告不存在'}), 404
    
    from app.services.traceback_enhanced import traceback_analyzer
    
    # 优先使用数据库中已保存的溯源数据（包含已提取的IP信息）
    saved_traceback = None
    if alert.get('traceback_data'):
        try:
            saved_traceback = json.loads(alert['traceback_data']) if isinstance(alert['traceback_data'], str) else alert['traceback_data']
        except:
            pass
    
    # 构建解析后的邮件数据
    parsed = {
        'subject': alert.get('subject', '') or '',
        'from': alert.get('from_addr', '') or '',
        'from_email': alert.get('from_email', '') or '',
        'to': alert.get('to_addr', '') or '',
        'cc': '',
        'body': alert.get('body', '') or '',
        'html_body': alert.get('html_body', '') or '',
        'urls': [],
        'attachments': [],
        'headers': {},
        'received_chain': []
    }
    
    # 解析URL
    if alert.get('url_data'):
        try:
            parsed['urls'] = json.loads(alert['url_data']) if isinstance(alert['url_data'], str) else alert['url_data']
        except:
            pass
    
    # 解析附件
    if alert.get('attachment_data'):
        try:
            parsed['attachments'] = json.loads(alert['attachment_data']) if isinstance(alert['attachment_data'], str) else alert['attachment_data']
        except:
            pass
    
    # 解析邮件头
    if alert.get('header_data'):
        try:
            parsed['headers'] = json.loads(alert['header_data']) if isinstance(alert['header_data'], str) else alert['header_data']
        except:
            pass
    
    # 执行增强版溯源分析，传入已保存的溯源数据
    traceback_report = traceback_analyzer.analyze(parsed, saved_traceback)
    
    return jsonify(traceback_report)


def call_ai_service(ai_config: Dict, email_content: str) -> Dict:
    """
    调用AI服务进行邮件深度分析
    
    参考LLMphish项目的语义分析逻辑，提供多维度分析：
    - 钓鱼意图识别
    - 紧急程度分析
    - 情感分析
    - 可疑语言检测
    
    支持：通义千问(阿里百炼)、智谱AI、DeepSeek、月之暗面
    """
    provider = ai_config.get('provider', 'alibaba')
    api_key = ai_config.get('api_key', '').strip()
    api_url = ai_config.get('api_url', '')
    model = ai_config.get('model', '')
    
    logger.info(f"AI Service Call - Provider: {provider}, Model: {model}")
    
    if not api_key:
        raise Exception("AI API Key未配置")
    
    system_prompt = """你是一个专业的钓鱼邮件检测专家，擅长分析邮件的语义特征、意图和可疑性。"""
    
    analysis_prompt = f"""请分析以下邮件的语义特征，返回JSON格式结果：

邮件内容：
{email_content[:3000]}

请从以下维度进行分析并返回JSON：

1. 钓鱼意图分析 (phishing_intent_score: 0.0-1.0)
   - 是否冒充知名品牌或机构
   - 是否诱导点击链接或下载附件
   - 是否要求提供敏感信息

2. 紧急程度分析 (urgency_score: 0.0-1.0)
   - 是否使用紧迫性词汇（立即、紧急、24小时内等）
   - 是否制造恐慌或威胁
   - 是否要求立即行动

3. 情感分析 (sentiment_score: -1.0到1.0)
   - 邮件整体情感倾向
   - 是否使用诱导性情感语言

4. 可疑语言检测 (suspicious_language_score: 0.0-1.0)
   - 是否包含拼写错误或语法问题
   - 是否使用模糊或不专业的表述
   - 是否有异常的称呼方式

5. 综合判定
   - is_phishing: true/false
   - risk_score: 0-100
   - attack_type: traditional(传统钓鱼)/llm_generated(AI生成)/hybrid(混合)/benign(正常)
   - conclusion: 一句话结论
   - key_indicators: 关键风险指标数组
   - suggestions: 安全建议数组

返回JSON格式：
{{
    "phishing_intent_score": 0.0,
    "urgency_score": 0.0,
    "sentiment_score": 0.0,
    "suspicious_language_score": 0.0,
    "confidence_level": 0.0,
    "is_phishing": true/false,
    "risk_score": 0,
    "attack_type": "类型",
    "conclusion": "结论",
    "analysis": "详细分析",
    "key_indicators": ["指标1", "指标2"],
    "suggestions": ["建议1", "建议2"]
}}

只返回JSON，不要其他文字。"""

    def make_openai_compatible_request(url: str, api_key: str, model: str, 
                                        system_prompt: str, user_message: str) -> Dict:
        """通用的OpenAI兼容接口调用"""
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json; charset=utf-8'
        }
        
        data = {
            'model': model,
            'messages': [
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': user_message}
            ],
            'temperature': 0.3,
            'max_tokens': 2000
        }
        
        try:
            logger.debug(f"AI Request URL: {url}")
            logger.debug(f"AI Request Model: {model}")
            
            response = requests.post(url, headers=headers, json=data, timeout=60)
            
            logger.info(f"AI API Response Status: {response.status_code}")
            
            if response.status_code == 400:
                try:
                    error_detail = response.json()
                    error_msg = error_detail.get('error', {}).get('message', str(error_detail))
                except:
                    error_msg = response.text[:500]
                logger.error(f"AI API 400 Error: {error_msg}")
                raise Exception(f"API请求参数错误(400): {error_msg}")
            
            elif response.status_code == 401:
                logger.error("AI API 401 Error: Invalid API Key")
                raise Exception("API Key无效或已过期")
            
            elif response.status_code == 403:
                logger.error("AI API 403 Error: Forbidden")
                raise Exception("API访问被拒绝，请检查权限")
            
            elif response.status_code == 429:
                logger.warning("AI API 429 Error: Rate Limited")
                raise Exception("API调用频率超限，请稍后重试")
            
            elif response.status_code != 200:
                logger.error(f"AI API Error: HTTP {response.status_code}")
                raise Exception(f"API请求失败: HTTP {response.status_code}")
            
            result = response.json()
            
            if 'choices' in result and len(result['choices']) > 0:
                message = result['choices'][0].get('message', {})
                if 'content' in message:
                    return message['content']
                else:
                    raise Exception("API响应格式异常: 缺少content字段")
            elif 'error' in result:
                error_msg = result['error'].get('message', str(result['error']))
                logger.error(f"AI API Response Error: {error_msg}")
                raise Exception(f"API返回错误: {error_msg}")
            else:
                logger.error(f"AI API Unexpected Response: {result}")
                raise Exception(f"API返回格式异常")
                
        except requests.exceptions.Timeout:
            logger.error("AI API Timeout")
            raise Exception("API调用超时，请检查网络连接")
        except requests.exceptions.ConnectionError:
            logger.error("AI API Connection Error")
            raise Exception("无法连接到API服务器")
        except requests.exceptions.RequestException as e:
            logger.error(f"AI API Request Exception: {e}")
            raise Exception(f"网络请求异常: {str(e)}")

    ai_text = None
    
    if provider == 'alibaba':
        if not api_url:
            api_url = 'https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions'
        if not model:
            model = 'qwen-turbo'
        
        ai_text = make_openai_compatible_request(api_url, api_key, model, system_prompt, analysis_prompt)
    
    elif provider == 'zhipu':
        if not api_url:
            api_url = 'https://open.bigmodel.cn/api/paas/v4/chat/completions'
        if not model:
            model = 'glm-4-flash'
        
        ai_text = make_openai_compatible_request(api_url, api_key, model, system_prompt, analysis_prompt)
    
    elif provider == 'deepseek':
        if not api_url:
            api_url = 'https://api.deepseek.com/v1/chat/completions'
        if not model:
            model = 'deepseek-chat'
        
        ai_text = make_openai_compatible_request(api_url, api_key, model, system_prompt, analysis_prompt)
    
    elif provider == 'moonshot':
        if not api_url:
            api_url = 'https://api.moonshot.cn/v1/chat/completions'
        if not model:
            model = 'moonshot-v1-8k'
        
        ai_text = make_openai_compatible_request(api_url, api_key, model, system_prompt, analysis_prompt)
    
    elif provider == 'openai':
        if not api_url:
            api_url = 'https://api.openai.com/v1/chat/completions'
        if not model:
            model = 'gpt-3.5-turbo'
        
        ai_text = make_openai_compatible_request(api_url, api_key, model, system_prompt, analysis_prompt)
    
    elif provider == 'custom':
        if not api_url:
            raise Exception("自定义API必须提供api_url")
        
        ai_text = make_openai_compatible_request(api_url, api_key, model, system_prompt, analysis_prompt)
    
    else:
        raise Exception(f"不支持的AI提供商: {provider}。支持的提供商: alibaba, zhipu, deepseek, moonshot, openai, custom")
    
    if not ai_text:
        raise Exception("AI返回内容为空")
    
    try:
        json_match = re.search(r'\{[\s\S]*\}', ai_text)
        if json_match:
            ai_result = json.loads(json_match.group())
            logger.info("AI Response parsed as JSON successfully")
        else:
            logger.warning("AI Response is not JSON format, building fallback result")
            ai_result = {
                'is_phishing': '钓鱼' in ai_text or 'phishing' in ai_text.lower(),
                'risk_score': 50 if '风险' in ai_text else 20,
                'phishing_intent_score': 0.5,
                'urgency_score': 0.3,
                'sentiment_score': 0.0,
                'suspicious_language_score': 0.3,
                'conclusion': ai_text[:200],
                'analysis': ai_text,
                'key_indicators': ['需要人工复核'],
                'suggestions': ['请仔细核实发件人身份', '不要点击可疑链接']
            }
    except json.JSONDecodeError as e:
        logger.warning(f"JSON Decode Error: {e}")
        ai_result = {
            'is_phishing': False,
            'risk_score': 30,
            'phishing_intent_score': 0.3,
            'urgency_score': 0.2,
            'sentiment_score': 0.0,
            'suspicious_language_score': 0.2,
            'conclusion': 'AI分析完成',
            'analysis': ai_text,
            'key_indicators': [],
            'suggestions': ['请人工复核']
        }
    
    ai_result['llm_supported'] = True
    ai_result['provider'] = provider
    ai_result['model'] = model
    
    logger.info(f"AI Analysis Complete - is_phishing: {ai_result.get('is_phishing')}, score: {ai_result.get('risk_score')}")
    return ai_result

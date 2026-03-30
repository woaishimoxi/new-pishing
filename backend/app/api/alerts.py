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
    
    # 读取AI配置
    # alerts.py 在 backend/app/api/ 目录
    # 配置文件在 项目根目录/config/ 目录
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
    
    # 解析溯源数据
    traceback_data = {}
    if alert.get('traceback_data'):
        try:
            if isinstance(alert['traceback_data'], str):
                traceback_data = json.loads(alert['traceback_data'])
            else:
                traceback_data = alert['traceback_data']
        except:
            pass
    
    # 解析URL数据
    urls = []
    if alert.get('url_data'):
        try:
            if isinstance(alert['url_data'], str):
                urls = json.loads(alert['url_data'])
            else:
                urls = alert['url_data']
        except:
            pass
    
    # 获取原始邮件内容
    raw_email = alert.get('raw_email', '')
    body = alert.get('body', '') or ''
    
    # 构建发送给AI的邮件内容（优先发送原始邮件）
    if raw_email:
        # 限制长度避免token过多
        email_content = raw_email[:10000] if len(raw_email) > 10000 else raw_email
    else:
        # 如果没有原始邮件，使用解析后的内容
        email_content = f"""
邮件主题: {alert.get('subject', '无')}
发件人: {alert.get('from_display_name', '')} <{alert.get('from_email', '')}>
收件人: {alert.get('to_addr', '')}

邮件正文:
{body[:3000] if body else '无正文内容'}
"""
    
    # 调用AI服务
    try:
        ai_result = call_ai_service(ai_config, email_content)
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
    
    # 从数据库读取已存储的溯源数据
    traceback_data = {}
    if alert.get('traceback_data'):
        try:
            if isinstance(alert['traceback_data'], str):
                traceback_data = json.loads(alert['traceback_data'])
            else:
                traceback_data = alert['traceback_data']
        except:
            traceback_data = {}
    
    # 解析URL数据
    urls = []
    if alert.get('url_data'):
        try:
            urls = json.loads(alert['url_data']) if isinstance(alert['url_data'], str) else alert['url_data']
        except:
            pass
    
    # 解析附件数据
    attachments = []
    if alert.get('attachment_data'):
        try:
            attachments = json.loads(alert['attachment_data']) if isinstance(alert['attachment_data'], str) else alert['attachment_data']
        except:
            pass
    
    # 解析邮件头数据
    headers = {}
    if alert.get('header_data'):
        try:
            headers = json.loads(alert['header_data']) if isinstance(alert['header_data'], str) else alert['header_data']
        except:
            pass
    
    # 构建前端需要的5维度格式（使用已存储的数据）
    email_source = traceback_data.get('email_source', {})
    risk_indicators = traceback_data.get('risk_indicators', [])
    url_analysis = traceback_data.get('url_analysis', [])
    correlation = traceback_data.get('correlation_analysis', {})
    ioc_matches = traceback_data.get('ioc_matches', {})
    
    # 计算风险评分
    threat_score = correlation.get('threat_score', 0)
    risk_score = min(1.0, threat_score / 100) if threat_score > 0 else 0.3 if alert.get('label') == 'SUSPICIOUS' else 0.8 if alert.get('label') == 'PHISHING' else 0.1
    
    # 维度1: 攻击目标
    targets = {
        'recipients': [alert.get('to_addr', '')],
        'total_count': 1,
        'analysis': '单个目标定向攻击' if alert.get('to_addr') else '目标未知',
        'risk_level': 'medium' if alert.get('to_addr') else 'low'
    }
    
    # 维度2: IP来源与传播链（使用已存储的数据）
    hops = email_source.get('hops', [])
    chain = {
        'source_ip': email_source.get('source_ip', 'Unknown'),
        'geolocation': email_source.get('geolocation', {}),
        'hops': [{'ip': hop, 'server': None, 'time': None} for hop in hops] if hops and isinstance(hops[0], str) else hops,
        'full_path': email_source.get('full_path', ''),
        'analysis': f'源IP: {email_source.get("source_ip", "未知")}' if email_source.get('source_ip') else '无法获取IP信息',
        'risk_level': 'high' if any(ind.get('type') == 'BLACKLISTED_IP' for ind in risk_indicators) else 'medium'
    }
    
    # 维度3: 攻击特性（社会工程学）- 从风险指标推断
    se_keywords = []
    se_categories = []
    for ind in risk_indicators:
        desc = ind.get('description', '')
        if '紧急' in desc or 'urgent' in desc.lower():
            se_keywords.append({'keyword': '紧急', 'category': 'urgency'})
            se_categories.append('urgency')
        if '域名' in desc or 'domain' in desc.lower():
            se_keywords.append({'keyword': '可疑域名', 'category': 'fear'})
            se_categories.append('fear')
    
    social_engineering = {
        'detected_keywords': se_keywords,
        'categories': list(set(se_categories)),
        'risk_level': 'high' if len(se_categories) >= 2 else 'medium' if len(se_categories) >= 1 else 'low',
        'analysis': f'检测到{len(se_categories)}类社会工程学特征' if se_categories else '未检测到明显社会工程学特征'
    }
    
    # 维度4: 攻击载体
    malicious_links = []
    for ua in url_analysis:
        if ua.get('risks'):
            malicious_links.append({
                'url': ua.get('url', ''),
                'is_short_url': any('短链接' in str(r.get('description', '')) for r in ua.get('risks', [])),
                'is_ip_url': any('IP' in str(r.get('description', '')) for r in ua.get('risks', [])),
                'domain': ua.get('domain_info', {}).get('domain', '')
            })
    
    suspicious_attachments = []
    for att in attachments:
        if att.get('is_suspicious_type'):
            suspicious_attachments.append({
                'filename': att.get('filename', ''),
                'risk': 'high'
            })
    
    attack_vectors = {
        'malicious_links': malicious_links,
        'suspicious_attachments': suspicious_attachments,
        'qr_codes': 0,
        'info_theft_request': any('密码' in ind.get('description', '') for ind in risk_indicators),
        'risk_level': 'high' if malicious_links or suspicious_attachments else 'low',
        'analysis': f'发现{len(malicious_links)}个可疑链接，{len(suspicious_attachments)}个可疑附件' if malicious_links or suspicious_attachments else '未发现明显攻击载体'
    }
    
    # 维度5: 攻击动机
    motivation_primary = 'unknown'
    motivation_confidence = 0.3
    motivation_analysis = '无法判断动机'
    
    if suspicious_attachments:
        motivation_primary = 'malware_delivery'
        motivation_confidence = 0.7
        motivation_analysis = '包含可疑附件，动机为植入恶意软件'
    elif malicious_links:
        motivation_primary = 'credential_theft'
        motivation_confidence = 0.6
        motivation_analysis = '包含可疑链接，动机为窃取凭证'
    
    motivation_map = {
        'credential_theft': '窃取凭证',
        'malware_delivery': '植入恶意软件',
        'financial_fraud': '财务诈骗',
        'unknown': '未知'
    }
    
    motivation = {
        'primary': motivation_primary,
        'primary_label': motivation_map.get(motivation_primary, '未知'),
        'confidence': motivation_confidence,
        'analysis': motivation_analysis
    }
    
    # 组装最终报告
    report = {
        'dimensions': {
            'targets': targets,
            'source_chain': chain,
            'social_engineering': social_engineering,
            'attack_vectors': attack_vectors,
            'motivation': motivation
        },
        'risk_score': risk_score,
        'summary': f'来源IP: {chain["source_ip"]}；{attack_vectors["analysis"]}；攻击动机: {motivation["primary_label"]}'
    }
    
    return jsonify(report)


def call_ai_service(ai_config: Dict, email_content: str) -> Dict:
    """
    调用AI服务进行邮件深度分析
    
    支持：OpenAI、文心一言、通义千问、智谱AI、月之暗面
    """
    provider = ai_config.get('provider', 'openai')
    api_key = ai_config.get('api_key', '')
    api_url = ai_config.get('api_url', '')
    model = ai_config.get('model', 'gpt-4')
    
    # 构建系统提示（中文版，支持多种编码）
    system_prompt = """你是一位邮件安全分析专家，任务是分析原始邮件并判断是否为钓鱼邮件。

一、邮件编码处理指南（必须先解码再分析）：

1. Base64编码
   - 识别：Content-Transfer-Encoding: base64 后的内容
   - 解码：将base64字符串转为原始文本
   - 示例：5L2g5b+r5omT = "你的密码"

2. Quoted-Printable编码  
   - 识别：=XX 格式（如 =E4=BD=A0）
   - 解码：将每个=XX转为对应UTF-8字符
   - 示例：=E4=BD=A0=E5=A5=BD = "你好"

3. MIME主题编码
   - 识别：=?UTF-8?B?...?=（B=base64）或 =?UTF-8?Q?...?=（Q=quoted）
   - 解码：按编码类型解码中间内容
   - 示例：=?UTF-8?B?56eY5a+G?= = "秘密"

4. URL编码
   - 识别：%XX 格式（如 %20 = 空格）
   - 解码：将%XX转为对应字符

5. HTML实体
   - 识别：&#XX; 或 &amp; &lt; &gt; 等
   - 解码：转为对应字符

二、分析要点：

1. 发件人伪造
   - 显示名与邮箱是否匹配
   - SPF/DKIM/DMARC验证结果
   - 是否冒充知名品牌

2. 社会工程学
   - 紧迫感：立即、紧急、24小时内
   - 威胁：账户冻结、数据泄露
   - 利诱：中奖、退款、补贴
   - 权威：管理员、IT部门、财务部

3. 可疑链接
   - 使用IP地址而非域名
   - 短链接（bit.ly等）
   - 域名仿冒（如paypa1.com）

4. 危险附件
   - 可执行文件：.exe, .bat, .ps1
   - 带宏文档：.docm, .xlsm
   - 双重扩展：invoice.pdf.exe

三、返回格式（必须是有效JSON）：

{"is_phishing":true或false,"risk_score":0到100的整数,"conclusion":"一句话结论","analysis":"详细分析","decoded_content":"解码后的邮件正文","key_indicators":["指标1","指标2"],"suggestions":["建议1","建议2"]}"""

    # 构建用户消息
    user_message = f"""请分析以下原始邮件，判断是否为钓鱼邮件。

注意：
1. 先解码邮件中的编码内容（base64、quoted-printable等）
2. 然后分析解码后的内容
3. 返回JSON格式结果

原始邮件：
{email_content}"""
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

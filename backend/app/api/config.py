"""
Config API Routes
"""
from flask import Blueprint, jsonify, request
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.core import get_logger, get_config
from app.services import EmailFetcherService

config_bp = Blueprint('config', __name__)
logger = get_logger(__name__)
config = get_config()


@config_bp.route('', methods=['GET'])
def get_api_config():
    """Get API configuration"""
    return jsonify({
        'threatbook': {
            'api_key': config.api.threatbook_api_key,
            'api_url': config.api.threatbook_api_url,
            'sandbox_enabled': getattr(config.api, 'sandbox_enabled', True),
            'ioc_enabled': getattr(config.api, 'ioc_remote_enabled', True)
        },
        'ipapi': {
            'api_url': config.api.ip_api_url
        },
        'email': {
            'email': config.email.address,
            'password': config.email.password,
            'server': config.email.server,
            'protocol': config.email.protocol,
            'port': config.email.port,
            'enabled': config.email.enabled
        }
    })


@config_bp.route('', methods=['POST'])
def update_api_config():
    """Update API configuration"""
    try:
        new_config = request.get_json()
        
        if 'threatbook' in new_config:
            tb = new_config['threatbook']
            if 'api_key' in tb:
                config.api.threatbook_api_key = tb['api_key']
            if 'api_url' in tb:
                config.api.threatbook_api_url = tb['api_url']
            if 'sandbox_enabled' in tb:
                config.api.sandbox_enabled = tb['sandbox_enabled']
            if 'ioc_enabled' in tb:
                config.api.ioc_remote_enabled = tb['ioc_enabled']
        
        if 'ipapi' in new_config and 'api_url' in new_config['ipapi']:
            config.api.ip_api_url = new_config['ipapi']['api_url']
        
        if 'email' in new_config:
            email = new_config['email']
            if 'email' in email:
                config.email.address = email['email']
            if 'password' in email:
                config.email.password = email['password']
            if 'server' in email:
                config.email.server = email['server']
            if 'protocol' in email:
                config.email.protocol = email['protocol']
            if 'port' in email:
                config.email.port = email['port']
            if 'enabled' in email:
                config.email.enabled = email['enabled']
        
        config.save_api_config()
        
        return jsonify({'status': 'success', 'message': '配置已保存'})
        
    except Exception as e:
        logger.error(f"Update config error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@config_bp.route('/test', methods=['GET'])
def test_api_connection():
    """Test ThreatBook API connection"""
    try:
        from app.services.feature_extractor import FeatureExtractionService
        feature_extractor = FeatureExtractionService()
        result = feature_extractor._query_threatbook('https://www.google.com')
        
        if result >= 0:
            return jsonify({'status': 'success', 'message': '微步在线 API 连接成功'})
        else:
            return jsonify({'status': 'error', 'message': '微步在线 API 连接失败'}), 400
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'测试失败: {str(e)}'}), 500


@config_bp.route('/test-ai', methods=['POST'])
def test_ai_connection():
    """Test AI API connection"""
    import requests
    
    try:
        data = request.get_json()
        provider = data.get('provider', 'zhipu')
        api_key = data.get('api_key', '')
        api_url = data.get('api_url', '')
        model = data.get('model', 'glm-4-flash')
        
        if not api_key:
            return jsonify({'status': 'error', 'message': '请填写API Key'}), 400
        
        if not api_url:
            if provider == 'zhipu':
                api_url = 'https://open.bigmodel.cn/api/paas/v4/chat/completions'
            elif provider == 'moonshot':
                api_url = 'https://api.moonshot.cn/v1/chat/completions'
            elif provider == 'deepseek':
                api_url = 'https://api.deepseek.com/v1/chat/completions'
            elif provider == 'openai':
                api_url = 'https://api.openai.com/v1/chat/completions'
            else:
                api_url = 'https://open.bigmodel.cn/api/paas/v4/chat/completions'
        
        test_message = "你好，这是一个测试消息，请回复'测试成功'。"
        
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            'model': model,
            'messages': [
                {'role': 'user', 'content': test_message}
            ],
            'max_tokens': 50,
            'temperature': 0.1
        }
        
        response = requests.post(api_url, headers=headers, json=payload, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            if 'choices' in result or 'result' in result:
                return jsonify({'status': 'success', 'message': 'AI连接测试成功'})
            else:
                return jsonify({'status': 'error', 'message': f'AI返回格式异常: {result}'}), 400
        elif response.status_code == 401:
            return jsonify({'status': 'error', 'message': 'API Key无效或已过期'}), 400
        elif response.status_code == 429:
            return jsonify({'status': 'error', 'message': 'API调用频率超限，请稍后重试'}), 400
        else:
            error_msg = f'API返回错误 (状态码: {response.status_code})'
            try:
                error_data = response.json()
                if 'error' in error_data:
                    error_msg = error_data['error'].get('message', error_msg)
            except:
                pass
            return jsonify({'status': 'error', 'message': error_msg}), 400
            
    except requests.exceptions.Timeout:
        return jsonify({'status': 'error', 'message': 'AI连接超时，请检查网络'}), 500
    except requests.exceptions.ConnectionError:
        return jsonify({'status': 'error', 'message': '无法连接到AI服务，请检查网络或API地址'}), 500
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'测试失败: {str(e)}'}), 500


@config_bp.route('/test-email', methods=['GET'])
def test_email_connection():
    """Test email server connection"""
    try:
        import json
        from pathlib import Path
        
        config_file = Path(__file__).resolve().parent.parent.parent / 'config' / 'api_config.json'
        email_config = {}
        
        if config_file.exists():
            with open(config_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                email_config = data.get('email', {})
        
        email_address = email_config.get('email') or config.email.address
        email_password = email_config.get('password') or config.email.password
        email_server = email_config.get('server') or config.email.server
        email_protocol = email_config.get('protocol') or config.email.protocol
        email_port = email_config.get('port') or config.email.port
        
        if not email_address or not email_password or not email_server:
            return jsonify({'status': 'error', 'message': '邮箱配置不完整'}), 400
        
        fetcher = EmailFetcherService()
        
        if fetcher.connect(
            email_address,
            email_password,
            email_server,
            email_protocol,
            email_port
        ):
            fetcher.disconnect()
            return jsonify({'status': 'success', 'message': '邮箱连接成功'})
        else:
            return jsonify({'status': 'error', 'message': '邮箱连接失败'}), 400
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'测试失败: {str(e)}'}), 500

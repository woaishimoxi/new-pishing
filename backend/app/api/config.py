"""
Config API Routes
"""
from flask import Blueprint, jsonify, request
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.core import get_logger, get_config
from app.services import EmailFetcherService
from app.services.url_analyzer import URLAnalyzerService

config_bp = Blueprint('config', __name__)
logger = get_logger(__name__)
config = get_config()


@config_bp.route('', methods=['GET'])
def get_api_config():
    """Get API configuration"""
    return jsonify({
        'virustotal': {
            'api_key': config.api.virustotal_api_key,
            'api_url': config.api.virustotal_api_url
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
        
        if 'virustotal' in new_config:
            vt = new_config['virustotal']
            if 'api_key' in vt:
                config.api.virustotal_api_key = vt['api_key']
            if 'api_url' in vt:
                config.api.virustotal_api_url = vt['api_url']
        
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
    """Test VirusTotal API connection"""
    try:
        from app.services.feature_extractor import FeatureExtractionService
        feature_extractor = FeatureExtractionService()
        result = feature_extractor._query_virustotal(
            'https://www.google.com',
            config.api.virustotal_api_key,
            config.api.virustotal_api_url
        )
        
        if result >= 0:
            return jsonify({'status': 'success', 'message': 'VirusTotal API 连接成功'})
        else:
            return jsonify({'status': 'error', 'message': 'VirusTotal API 连接失败'}), 400
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'测试失败: {str(e)}'}), 500


@config_bp.route('/test-email', methods=['GET'])
def test_email_connection():
    """Test email server connection"""
    try:
        # 从文件读取最新配置
        import json
        from pathlib import Path
        
        config_file = Path(__file__).resolve().parent.parent.parent / 'config' / 'api_config.json'
        email_config = {}
        
        if config_file.exists():
            with open(config_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                email_config = data.get('email', {})
        
        # 使用文件配置或内存配置
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

#!/usr/bin/env python3
"""
配置管理中心API
提供所有配置文件的Web编辑功能
"""
from flask import Blueprint, jsonify, request
import json
import os
import sys
from typing import Dict
from datetime import datetime
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.core import get_logger

settings_bp = Blueprint('settings', __name__)
logger = get_logger(__name__)

# 配置文件路径
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
CONFIG_DIR = os.path.join(BASE_DIR, 'config')


@settings_bp.route('/api/settings/files', methods=['GET'])
def list_config_files():
    """
    列出所有配置文件
    
    GET /api/settings/files
    """
    try:
        files = []
        for filename in os.listdir(CONFIG_DIR):
            if filename.endswith('.json'):
                filepath = os.path.join(CONFIG_DIR, filename)
                stat = os.stat(filepath)
                files.append({
                    'name': filename,
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'description': _get_file_description(filename)
                })
        
        return jsonify({'files': files}), 200
    except Exception as e:
        logger.error(f"List config files error: {e}")
        return jsonify({'error': str(e)}), 500


@settings_bp.route('/api/settings/file/<filename>', methods=['GET'])
def get_config_file(filename):
    """
    获取配置文件内容
    
    GET /api/settings/file/{filename}
    """
    try:
        # 安全检查
        if not filename.endswith('.json') or '/' in filename or '\\' in filename:
            return jsonify({'error': '无效的文件名'}), 400
        
        filepath = os.path.join(CONFIG_DIR, filename)
        if not os.path.exists(filepath):
            return jsonify({'error': '文件不存在'}), 404
        
        with open(filepath, 'r', encoding='utf-8') as f:
            content = json.load(f)
        
        return jsonify({
            'filename': filename,
            'content': content,
            'description': _get_file_description(filename)
        }), 200
    except Exception as e:
        logger.error(f"Get config file error: {e}")
        return jsonify({'error': str(e)}), 500


@settings_bp.route('/api/settings/file/<filename>', methods=['PUT'])
def update_config_file(filename):
    """
    更新配置文件内容
    
    PUT /api/settings/file/{filename}
    Body: {"content": {...}}
    """
    try:
        # 安全检查
        if not filename.endswith('.json') or '/' in filename or '\\' in filename:
            return jsonify({'error': '无效的文件名'}), 400
        
        filepath = os.path.join(CONFIG_DIR, filename)
        
        data = request.get_json()
        content = data.get('content')
        
        if content is None:
            return jsonify({'error': '未提供内容'}), 400
        
        # 验证JSON格式
        try:
            if isinstance(content, str):
                content = json.loads(content)
        except json.JSONDecodeError:
            return jsonify({'error': '无效的JSON格式'}), 400
        
        # 备份原文件
        if os.path.exists(filepath):
            backup_path = filepath + '.bak'
            with open(filepath, 'r', encoding='utf-8') as f:
                with open(backup_path, 'w', encoding='utf-8') as bf:
                    bf.write(f.read())
        
        # 写入新内容
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(content, f, indent=2, ensure_ascii=False)
        
        # 如果是API配置文件，同步到系统配置
        if filename == 'api_config.json':
            _sync_api_config(content)
        
        return jsonify({
            'success': True,
            'message': f'{filename} 已更新'
        }), 200
    except Exception as e:
        logger.error(f"Update config file error: {e}")
        return jsonify({'error': str(e)}), 500


def _sync_api_config(content: Dict):
    """同步API配置到系统配置"""
    try:
        from app.core.config import get_config
        config = get_config()
        
        if 'threatbook' in content:
            tb = content['threatbook']
            if 'api_key' in tb:
                config.api.threatbook_api_key = tb['api_key']
            if 'api_url' in tb:
                config.api.threatbook_api_url = tb['api_url']
            if 'sandbox_enabled' in tb:
                config.api.sandbox_enabled = tb['sandbox_enabled']
            if 'ioc_enabled' in tb:
                config.api.ioc_remote_enabled = tb['ioc_enabled']
        
        if 'email' in content:
            email = content['email']
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
        
        logger.info("API config synced to system")
    except Exception as e:
        logger.error(f"Failed to sync API config: {e}")


@settings_bp.route('/api/settings/file/<filename>/backup', methods=['POST'])
def restore_backup(filename):
    """
    恢复备份文件
    
    POST /api/settings/file/{filename}/backup
    """
    try:
        filepath = os.path.join(CONFIG_DIR, filename)
        backup_path = filepath + '.bak'
        
        if not os.path.exists(backup_path):
            return jsonify({'error': '没有备份文件'}), 404
        
        with open(backup_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return jsonify({
            'success': True,
            'message': f'{filename} 已恢复备份'
        }), 200
    except Exception as e:
        logger.error(f"Restore backup error: {e}")
        return jsonify({'error': str(e)}), 500


@settings_bp.route('/api/settings/whitelist/add', methods=['POST'])
def add_to_whitelist():
    """
    添加到白名单
    
    POST /api/settings/whitelist/add
    Body: {"domains": ["example.com"]}
    """
    try:
        data = request.get_json()
        domains = data.get('domains', [])
        
        if not domains:
            return jsonify({'error': '未提供域名'}), 400
        
        filepath = os.path.join(CONFIG_DIR, 'whitelist.json')
        with open(filepath, 'r', encoding='utf-8') as f:
            whitelist = json.load(f)
        
        current_domains = set(whitelist.get('trusted_domains', []))
        cleaned = [_clean_domain(d) for d in domains if _clean_domain(d)]
        current_domains.update(cleaned)
        
        whitelist['trusted_domains'] = sorted(list(current_domains))
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(whitelist, f, indent=2, ensure_ascii=False)
        
        return jsonify({
            'success': True,
            'message': f'已添加 {len(cleaned)} 个域名',
            'total': len(current_domains)
        }), 200
    except Exception as e:
        logger.error(f"Add whitelist error: {e}")
        return jsonify({'error': str(e)}), 500


@settings_bp.route('/api/settings/whitelist/remove', methods=['POST'])
def remove_from_whitelist():
    """
    从白名单删除
    
    POST /api/settings/whitelist/remove
    Body: {"domains": ["example.com"]}
    """
    try:
        data = request.get_json()
        domains = data.get('domains', [])
        
        filepath = os.path.join(CONFIG_DIR, 'whitelist.json')
        with open(filepath, 'r', encoding='utf-8') as f:
            whitelist = json.load(f)
        
        current_domains = set(whitelist.get('trusted_domains', []))
        current_domains.difference_update(domains)
        
        whitelist['trusted_domains'] = sorted(list(current_domains))
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(whitelist, f, indent=2, ensure_ascii=False)
        
        return jsonify({
            'success': True,
            'message': f'已删除',
            'total': len(current_domains)
        }), 200
    except Exception as e:
        logger.error(f"Remove whitelist error: {e}")
        return jsonify({'error': str(e)}), 500


@settings_bp.route('/api/settings/blacklist/add', methods=['POST'])
def add_to_blacklist():
    """
    添加到黑名单
    
    POST /api/settings/blacklist/add
    Body: {"domains": ["bad.com"], "ips": ["1.2.3.4"]}
    """
    try:
        data = request.get_json()
        domains = data.get('domains', [])
        ips = data.get('ips', [])
        
        filepath = os.path.join(CONFIG_DIR, 'blacklist.json')
        with open(filepath, 'r', encoding='utf-8') as f:
            blacklist = json.load(f)
        
        current_domains = set(blacklist.get('domains', []))
        current_ips = set(blacklist.get('ips', []))
        
        cleaned_domains = [_clean_domain(d) for d in domains if _clean_domain(d)]
        current_domains.update(cleaned_domains)
        current_ips.update(ips)
        
        blacklist['domains'] = sorted(list(current_domains))
        blacklist['ips'] = sorted(list(current_ips))
        blacklist['last_updated'] = datetime.now().isoformat()
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(blacklist, f, indent=2, ensure_ascii=False)
        
        return jsonify({
            'success': True,
            'message': f'已添加',
            'total_domains': len(current_domains),
            'total_ips': len(current_ips)
        }), 200
    except Exception as e:
        logger.error(f"Add blacklist error: {e}")
        return jsonify({'error': str(e)}), 500


@settings_bp.route('/api/settings/blacklist/remove', methods=['POST'])
def remove_from_blacklist():
    """
    从黑名单删除
    
    POST /api/settings/blacklist/remove
    Body: {"domains": ["bad.com"], "ips": ["1.2.3.4"]}
    """
    try:
        data = request.get_json()
        domains = data.get('domains', [])
        ips = data.get('ips', [])
        
        filepath = os.path.join(CONFIG_DIR, 'blacklist.json')
        with open(filepath, 'r', encoding='utf-8') as f:
            blacklist = json.load(f)
        
        current_domains = set(blacklist.get('domains', []))
        current_ips = set(blacklist.get('ips', []))
        
        current_domains.difference_update(domains)
        current_ips.difference_update(ips)
        
        blacklist['domains'] = sorted(list(current_domains))
        blacklist['ips'] = sorted(list(current_ips))
        blacklist['last_updated'] = datetime.now().isoformat()
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(blacklist, f, indent=2, ensure_ascii=False)
        
        return jsonify({
            'success': True,
            'message': '已删除',
            'total_domains': len(current_domains),
            'total_ips': len(current_ips)
        }), 200
    except Exception as e:
        logger.error(f"Remove blacklist error: {e}")
        return jsonify({'error': str(e)}), 500


@settings_bp.route('/api/settings/ioc/add', methods=['POST'])
def add_to_ioc():
    """
    添加IOC条目
    
    POST /api/settings/ioc/add
    Body: {
        "type": "malicious_ips" | "malicious_domains" | "malicious_urls" | "malicious_ip_patterns" | ...,
        "items": ["item1", "item2"]
    }
    """
    try:
        data = request.get_json()
        ioc_type = data.get('type')
        items = data.get('items', [])
        
        valid_types = [
            'malicious_ips', 'malicious_domains', 'malicious_urls', 'malicious_hashes',
            'malicious_ip_patterns', 'malicious_domain_patterns', 'malicious_url_patterns',
            'known_phishing_keywords', 'suspicious_attachment_extensions', 'suspicious_attachment_names'
        ]
        
        if ioc_type not in valid_types:
            return jsonify({'error': f'无效的类型，支持: {", ".join(valid_types)}'}), 400
        
        filepath = os.path.join(CONFIG_DIR, 'ioc_database.json')
        with open(filepath, 'r', encoding='utf-8') as f:
            ioc_db = json.load(f)
        
        current_items = set(ioc_db.get(ioc_type, []))
        current_items.update(items)
        ioc_db[ioc_type] = sorted(list(current_items))
        ioc_db['last_updated'] = datetime.now().isoformat()
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(ioc_db, f, indent=2, ensure_ascii=False)
        
        return jsonify({
            'success': True,
            'message': f'已添加 {len(items)} 个条目到 {ioc_type}',
            'total': len(current_items)
        }), 200
    except Exception as e:
        logger.error(f"Add IOC error: {e}")
        return jsonify({'error': str(e)}), 500


@settings_bp.route('/api/settings/ioc/remove', methods=['POST'])
def remove_from_ioc():
    """
    删除IOC条目
    
    POST /api/settings/ioc/remove
    Body: {"type": "malicious_ips", "items": ["1.2.3.4"]}
    """
    try:
        data = request.get_json()
        ioc_type = data.get('type')
        items = data.get('items', [])
        
        filepath = os.path.join(CONFIG_DIR, 'ioc_database.json')
        with open(filepath, 'r', encoding='utf-8') as f:
            ioc_db = json.load(f)
        
        current_items = set(ioc_db.get(ioc_type, []))
        current_items.difference_update(items)
        ioc_db[ioc_type] = sorted(list(current_items))
        ioc_db['last_updated'] = datetime.now().isoformat()
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(ioc_db, f, indent=2, ensure_ascii=False)
        
        return jsonify({
            'success': True,
            'message': '已删除',
            'total': len(current_items)
        }), 200
    except Exception as e:
        logger.error(f"Remove IOC error: {e}")
        return jsonify({'error': str(e)}), 500


def _get_file_description(filename):
    """获取配置文件描述"""
    descriptions = {
        'api_config.json': 'API配置（微步在线、邮箱服务器）',
        'whitelist.json': '白名单（可信域名列表）',
        'blacklist.json': '黑名单（恶意域名/IP列表）',
        'ioc_database.json': 'IOC威胁情报库（恶意模式、钓鱼关键词）'
    }
    return descriptions.get(filename, '配置文件')


def _clean_domain(domain):
    """清理域名格式"""
    domain = domain.strip().lower()
    if domain.startswith('http://'):
        domain = domain[7:]
    elif domain.startswith('https://'):
        domain = domain[8:]
    domain = domain.split('/')[0]
    return domain

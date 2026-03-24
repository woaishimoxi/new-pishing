#!/usr/bin/env python3
"""
域名管理API
提供白名单和黑名单管理功能
"""
from flask import Blueprint, jsonify, request
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.core import get_logger
from app.services.traceback import (
    get_config_stats, reload_config,
    add_to_whitelist, remove_from_whitelist,
    add_to_blacklist, remove_from_blacklist
)

domains_bp = Blueprint('domains', __name__)
logger = get_logger(__name__)


@domains_bp.route('/api/domains/stats', methods=['GET'])
def get_domains_stats():
    """
    获取域名配置统计
    
    GET /api/domains/stats
    """
    try:
        stats = get_config_stats()
        return jsonify(stats), 200
    except Exception as e:
        logger.error(f"Get domains stats error: {e}")
        return jsonify({'error': str(e)}), 500


@domains_bp.route('/api/domains/reload', methods=['POST'])
def reload_domains_config():
    """
    重新加载配置
    
    POST /api/domains/reload
    """
    try:
        stats = reload_config()
        return jsonify({
            'success': True,
            'message': '配置已重新加载',
            'stats': stats
        }), 200
    except Exception as e:
        logger.error(f"Reload config error: {e}")
        return jsonify({'error': str(e)}), 500


@domains_bp.route('/api/domains/whitelist', methods=['GET'])
def get_whitelist():
    """
    获取白名单
    
    GET /api/domains/whitelist
    """
    try:
        stats = get_config_stats()
        return jsonify({
            'domains': stats.get('trusted_domains_list', []),
            'total': stats.get('trusted_domains', 0)
        }), 200
    except Exception as e:
        logger.error(f"Get whitelist error: {e}")
        return jsonify({'error': str(e)}), 500


@domains_bp.route('/api/domains/whitelist', methods=['POST'])
def add_whitelist():
    """
    添加白名单
    
    POST /api/domains/whitelist
    Body: {"domains": ["example.com", "test.com"]}
    """
    try:
        data = request.get_json()
        domains = data.get('domains', [])
        
        if not domains:
            return jsonify({'error': '未提供域名'}), 400
        
        # 清理域名格式
        cleaned_domains = []
        for domain in domains:
            domain = domain.strip().lower()
            # 移除协议前缀
            if domain.startswith('http://'):
                domain = domain[7:]
            elif domain.startswith('https://'):
                domain = domain[8:]
            # 移除路径
            domain = domain.split('/')[0]
            if domain:
                cleaned_domains.append(domain)
        
        add_to_whitelist(cleaned_domains)
        
        return jsonify({
            'success': True,
            'message': f'已添加 {len(cleaned_domains)} 个域名到白名单',
            'domains': cleaned_domains
        }), 200
    except Exception as e:
        logger.error(f"Add whitelist error: {e}")
        return jsonify({'error': str(e)}), 500


@domains_bp.route('/api/domains/whitelist', methods=['DELETE'])
def delete_whitelist():
    """
    删除白名单
    
    DELETE /api/domains/whitelist
    Body: {"domains": ["example.com"]}
    """
    try:
        data = request.get_json()
        domains = data.get('domains', [])
        
        if not domains:
            return jsonify({'error': '未提供域名'}), 400
        
        remove_from_whitelist(domains)
        
        return jsonify({
            'success': True,
            'message': f'已从白名单删除 {len(domains)} 个域名'
        }), 200
    except Exception as e:
        logger.error(f"Delete whitelist error: {e}")
        return jsonify({'error': str(e)}), 500


@domains_bp.route('/api/domains/blacklist', methods=['GET'])
def get_blacklist():
    """
    获取黑名单
    
    GET /api/domains/blacklist
    """
    try:
        stats = get_config_stats()
        return jsonify({
            'domains': stats.get('blacklisted_domains_list', []),
            'ips': stats.get('blacklisted_ips_list', []),
            'total_domains': stats.get('blacklisted_domains', 0),
            'total_ips': stats.get('blacklisted_ips', 0)
        }), 200
    except Exception as e:
        logger.error(f"Get blacklist error: {e}")
        return jsonify({'error': str(e)}), 500


@domains_bp.route('/api/domains/blacklist', methods=['POST'])
def add_blacklist():
    """
    添加黑名单
    
    POST /api/domains/blacklist
    Body: {"domains": ["malicious.com"], "ips": ["1.2.3.4"]}
    """
    try:
        data = request.get_json()
        domains = data.get('domains', [])
        ips = data.get('ips', [])
        
        if not domains and not ips:
            return jsonify({'error': '未提供域名或IP'}), 400
        
        # 清理域名
        cleaned_domains = []
        for domain in domains:
            domain = domain.strip().lower()
            if domain.startswith('http://'):
                domain = domain[7:]
            elif domain.startswith('https://'):
                domain = domain[8:]
            domain = domain.split('/')[0]
            if domain:
                cleaned_domains.append(domain)
        
        # 清理IP
        cleaned_ips = [ip.strip() for ip in ips if ip.strip()]
        
        add_to_blacklist(domains=cleaned_domains, ips=cleaned_ips)
        
        return jsonify({
            'success': True,
            'message': f'已添加 {len(cleaned_domains)} 个域名和 {len(cleaned_ips)} 个IP到黑名单',
            'domains': cleaned_domains,
            'ips': cleaned_ips
        }), 200
    except Exception as e:
        logger.error(f"Add blacklist error: {e}")
        return jsonify({'error': str(e)}), 500


@domains_bp.route('/api/domains/blacklist', methods=['DELETE'])
def delete_blacklist():
    """
    删除黑名单
    
    DELETE /api/domains/blacklist
    Body: {"domains": ["malicious.com"], "ips": ["1.2.3.4"]}
    """
    try:
        data = request.get_json()
        domains = data.get('domains', [])
        ips = data.get('ips', [])
        
        if not domains and not ips:
            return jsonify({'error': '未提供域名或IP'}), 400
        
        remove_from_blacklist(domains=domains, ips=ips)
        
        return jsonify({
            'success': True,
            'message': '已从黑名单删除'
        }), 200
    except Exception as e:
        logger.error(f"Delete blacklist error: {e}")
        return jsonify({'error': str(e)}), 500


@domains_bp.route('/api/domains/batch', methods=['POST'])
def batch_add_domains():
    """
    批量添加域名
    
    POST /api/domains/batch
    Body: {
        "type": "whitelist" 或 "blacklist",
        "domains": ["domain1.com", "domain2.com"],
        "ips": ["1.2.3.4"] (仅黑名单)
    }
    """
    try:
        data = request.get_json()
        list_type = data.get('type', 'whitelist')
        domains = data.get('domains', [])
        ips = data.get('ips', [])
        
        # 清理域名
        cleaned_domains = []
        for domain in domains:
            domain = domain.strip().lower()
            if domain.startswith('http://'):
                domain = domain[7:]
            elif domain.startswith('https://'):
                domain = domain[8:]
            domain = domain.split('/')[0]
            if domain:
                cleaned_domains.append(domain)
        
        cleaned_ips = [ip.strip() for ip in ips if ip.strip()]
        
        if list_type == 'whitelist':
            add_to_whitelist(cleaned_domains)
            message = f'已添加 {len(cleaned_domains)} 个域名到白名单'
        else:
            add_to_blacklist(domains=cleaned_domains, ips=cleaned_ips)
            message = f'已添加 {len(cleaned_domains)} 个域名和 {len(cleaned_ips)} 个IP到黑名单'
        
        return jsonify({
            'success': True,
            'message': message
        }), 200
    except Exception as e:
        logger.error(f"Batch add error: {e}")
        return jsonify({'error': str(e)}), 500

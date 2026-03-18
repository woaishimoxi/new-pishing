"""
Email API Routes
"""
from flask import Blueprint, jsonify, request
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.core import get_logger, get_config
from app.services import EmailFetcherService
from app.models.database import DatabaseRepository

email_bp = Blueprint('email', __name__)
logger = get_logger(__name__)
config = get_config()
db = DatabaseRepository()


@email_bp.route('/fetch', methods=['POST'])
def fetch_emails():
    """Fetch emails from configured mail server"""
    try:
        if not config.email.address or not config.email.password or not config.email.server:
            return jsonify({'status': 'error', 'message': '邮箱配置不完整，请先配置邮箱'}), 400
        
        fetcher = EmailFetcherService()
        
        if not fetcher.connect(
            config.email.address,
            config.email.password,
            config.email.server,
            config.email.protocol,
            config.email.port
        ):
            return jsonify({'status': 'error', 'message': '连接邮箱服务器失败'}), 400
        
        try:
            emails = fetcher.fetch_emails(limit=10, only_unseen=True)
            
            if not emails:
                return jsonify({'status': 'success', 'message': '没有新邮件', 'emails': []})
            
            processed_hashes = db.get_processed_hashes()
            processed_uids = db.get_processed_uids()
            
            new_emails = []
            seen_hashes = set()
            
            for email_item in emails:
                raw_email = email_item.get('raw', '')
                email_uid = email_item.get('uid')
                
                if raw_email:
                    email_hash = hashlib.md5(raw_email.encode('utf-8')).hexdigest()
                    if (email_hash not in processed_hashes and 
                        email_hash not in seen_hashes and 
                        (not email_uid or email_uid not in processed_uids)):
                        seen_hashes.add(email_hash)
                        email_item['hash'] = email_hash
                        new_emails.append(email_item)
                        
                        if email_item.get('id'):
                            fetcher.mark_as_seen(email_item['id'])
            
            if not new_emails:
                return jsonify({'status': 'success', 'message': '没有新邮件', 'emails': []})
            
            return jsonify({
                'status': 'success',
                'message': f'成功获取 {len(new_emails)} 封新邮件',
                'emails': new_emails
            })
        finally:
            fetcher.disconnect()
            
    except Exception as e:
        logger.error(f"Fetch emails error: {e}")
        return jsonify({'status': 'error', 'message': f'获取邮件失败: {str(e)}'}), 500


import hashlib

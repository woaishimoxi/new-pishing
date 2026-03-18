"""
Database Repository
Centralized database operations
"""
import sqlite3
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.core import get_logger, get_config, DatabaseError
from app.models import Alert, ProcessedUID


class DatabaseRepository:
    """
    Database Repository
    Centralized database operations
    """
    
    def __init__(self, db_path: str = None):
        self.logger = get_logger(__name__)
        self.config = get_config()
        self.db_path = db_path or self.config.database.path
        self._ensure_database()
    
    def _ensure_database(self) -> None:
        """Ensure database and tables exist"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("PRAGMA table_info(alerts)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'is_phish' in columns:
            cursor.execute('DROP TABLE IF EXISTS alerts')
            columns = []
        
        if not columns:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    from_addr TEXT,
                    from_display_name TEXT,
                    from_email TEXT,
                    to_addr TEXT,
                    subject TEXT,
                    detection_time TEXT,
                    label TEXT,
                    confidence REAL,
                    source_ip TEXT,
                    risk_indicators TEXT,
                    raw_email TEXT,
                    traceback_data TEXT,
                    attachment_data TEXT,
                    url_data TEXT,
                    header_data TEXT,
                    source TEXT,
                    email_hash TEXT
                )
            ''')
        else:
            if 'source' not in columns:
                cursor.execute('ALTER TABLE alerts ADD COLUMN source TEXT')
            if 'email_hash' not in columns:
                cursor.execute('ALTER TABLE alerts ADD COLUMN email_hash TEXT')
            if 'raw_email' not in columns:
                cursor.execute('ALTER TABLE alerts ADD COLUMN raw_email TEXT')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS processed_uids (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uid TEXT UNIQUE,
                processed_at TEXT
            )
        ''')
        
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_detection_time ON alerts(detection_time)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_label ON alerts(label)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_from_email ON alerts(from_email)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_email_hash ON alerts(email_hash)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_uid ON processed_uids(uid)')
        
        conn.commit()
        conn.close()
        
        self.logger.info(f"Database initialized: {self.db_path}")
    
    def save_alert(
        self,
        parsed: Dict,
        label: str,
        confidence: float,
        traceback_report: Dict,
        source: str = '手动输入',
        raw_email: str = '',
        email_uid: str = ''
    ) -> int:
        """Save detection result to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        attachments = parsed.get('attachments', [])
        safe_attachments = []
        for att in attachments:
            safe_att = {**att}
            if 'content' in safe_att:
                del safe_att['content']
            safe_attachments.append(safe_att)
        
        email_hash = ''
        if raw_email:
            email_hash = hashlib.md5(raw_email.encode('utf-8')).hexdigest()
        
        cursor.execute('''
            INSERT INTO alerts (from_addr, from_display_name, from_email, to_addr, subject, detection_time,
                               label, confidence, source_ip, risk_indicators,
                               raw_email, traceback_data, attachment_data, url_data, header_data, source, email_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            parsed.get('from', ''),
            parsed.get('from_display_name', ''),
            parsed.get('from_email', ''),
            parsed.get('to', ''),
            parsed.get('subject', ''),
            datetime.now().isoformat(),
            label,
            confidence,
            traceback_report.get('email_source', {}).get('source_ip', ''),
            json.dumps(traceback_report.get('risk_indicators', [])),
            raw_email,
            json.dumps(traceback_report),
            json.dumps(safe_attachments),
            json.dumps(parsed.get('urls', [])),
            json.dumps(parsed.get('headers', {})),
            source,
            email_hash
        ))
        
        alert_id = cursor.lastrowid
        
        if email_uid:
            try:
                cursor.execute('''
                    INSERT OR IGNORE INTO processed_uids (uid, processed_at)
                    VALUES (?, ?)
                ''', (email_uid, datetime.now().isoformat()))
            except:
                pass
        
        conn.commit()
        conn.close()
        
        return alert_id
    
    def get_alert(self, alert_id: int) -> Optional[Dict]:
        """Get single alert by ID"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM alerts WHERE id = ?', (alert_id,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        alert = dict(row)
        self._parse_json_fields(alert)
        
        return alert
    
    def get_alerts(
        self,
        page: int = 1,
        per_page: int = 20,
        label_filter: str = None
    ) -> Dict[str, Any]:
        """Get paginated alerts"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        base_query = "SELECT * FROM alerts"
        count_query = "SELECT COUNT(*) FROM alerts"
        params = []
        
        if label_filter is not None:
            base_query += " WHERE label = ?"
            count_query += " WHERE label = ?"
            params = [label_filter]
        
        cursor.execute(count_query, params)
        total = cursor.fetchone()[0]
        
        offset = (page - 1) * per_page
        cursor.execute(f"{base_query} ORDER BY detection_time DESC LIMIT ? OFFSET ?",
                       params + [per_page, offset])
        
        alerts = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        for alert in alerts:
            self._parse_json_fields(alert)
        
        return {
            'alerts': alerts,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page
        }
    
    def delete_alert(self, alert_id: int) -> bool:
        """Delete single alert"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT id FROM alerts WHERE id = ?", (alert_id,))
        if not cursor.fetchone():
            conn.close()
            return False
        
        cursor.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
        conn.commit()
        conn.close()
        
        return True
    
    def batch_delete_alerts(self, alert_ids: List[int]) -> int:
        """Batch delete alerts"""
        if not alert_ids:
            return 0
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        placeholders = ','.join(['?' for _ in alert_ids])
        cursor.execute(f"DELETE FROM alerts WHERE id IN ({placeholders})", alert_ids)
        
        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()
        
        return deleted_count
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detection statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM alerts")
        total = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE label = 'PHISHING'")
        phish_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE label = 'SUSPICIOUS'")
        suspicious_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE label = 'SAFE'")
        normal_count = cursor.fetchone()[0]
        
        today = datetime.now().strftime('%Y-%m-%d')
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE date(detection_time) = ?", (today,))
        today_count = cursor.fetchone()[0]
        
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT date(detection_time) as day,
                   COUNT(*) as count,
                   SUM(CASE WHEN label = 'PHISHING' THEN 1 ELSE 0 END) as phish_count,
                   SUM(CASE WHEN label = 'SUSPICIOUS' THEN 1 ELSE 0 END) as suspicious_count,
                   SUM(CASE WHEN label = 'SAFE' THEN 1 ELSE 0 END) as safe_count
            FROM alerts
            WHERE detection_time >= datetime('now', '-7 days')
            GROUP BY day
            ORDER BY day
        """)
        trend_data = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            'total': total,
            'phishing': phish_count,
            'suspicious': suspicious_count,
            'normal': normal_count,
            'today': today_count,
            'trend': trend_data
        }
    
    def get_processed_hashes(self) -> set:
        """Get all processed email hashes"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT DISTINCT email_hash FROM alerts WHERE email_hash IS NOT NULL')
        processed_hashes = set(row[0] for row in cursor.fetchall() if row[0])
        
        conn.close()
        
        return processed_hashes
    
    def get_processed_uids(self) -> set:
        """Get all processed UIDs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT DISTINCT uid FROM processed_uids')
        processed_uids = set(row[0] for row in cursor.fetchall() if row[0])
        
        conn.close()
        
        return processed_uids
    
    def _parse_json_fields(self, alert: Dict) -> None:
        """Parse JSON fields in alert dict"""
        if alert.get('traceback_data'):
            try:
                alert['traceback'] = json.loads(alert['traceback_data'])
            except:
                alert['traceback'] = {}
        
        if alert.get('attachment_data'):
            try:
                alert['attachments'] = json.loads(alert['attachment_data'])
            except:
                alert['attachments'] = []
        
        if alert.get('url_data'):
            try:
                alert['urls'] = json.loads(alert['url_data'])
            except:
                alert['urls'] = []
        
        if alert.get('header_data'):
            try:
                alert['headers'] = json.loads(alert['header_data'])
            except:
                alert['headers'] = {}
        
        if alert.get('risk_indicators'):
            try:
                if isinstance(alert['risk_indicators'], str):
                    alert['risk_indicators'] = json.loads(alert['risk_indicators'])
            except:
                alert['risk_indicators'] = []
        
        alert['parsed'] = {
            'from': alert.get('from_addr', ''),
            'from_display_name': alert.get('from_display_name', ''),
            'from_email': alert.get('from_email', ''),
            'to': alert.get('to_addr', ''),
            'subject': alert.get('subject', ''),
            'url_count': len(alert.get('urls', [])),
            'attachment_count': len(alert.get('attachments', []))
        }

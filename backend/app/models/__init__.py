"""
Models Module - Database Models
"""
import json
from datetime import datetime
from typing import Optional, Dict, List, Any
from dataclasses import dataclass


@dataclass
class Alert:
    """Alert model for phishing detection results"""
    id: int
    from_addr: str
    from_display_name: str
    from_email: str
    to_addr: str
    subject: str
    detection_time: str
    label: str
    confidence: float
    source_ip: str
    risk_indicators: str
    raw_email: str
    traceback_data: str
    attachment_data: str
    url_data: str
    header_data: str
    source: str
    email_hash: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'from_addr': self.from_addr,
            'from_display_name': self.from_display_name,
            'from_email': self.from_email,
            'to_addr': self.to_addr,
            'subject': self.subject,
            'detection_time': self.detection_time,
            'label': self.label,
            'confidence': self.confidence,
            'source_ip': self.source_ip,
            'risk_indicators': json.loads(self.risk_indicators) if self.risk_indicators else [],
            'source': self.source,
            'email_hash': self.email_hash
        }


@dataclass
class ProcessedUID:
    """Model for processed email UIDs"""
    id: int
    uid: str
    processed_at: str


@dataclass
class EmailAnalysis:
    """Model for detailed email analysis results"""
    id: int
    alert_id: int
    module_scores: str
    features: str
    url_analysis: str
    sandbox_results: str
    created_at: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'alert_id': self.alert_id,
            'module_scores': json.loads(self.module_scores) if self.module_scores else {},
            'features': json.loads(self.features) if self.features else {},
            'url_analysis': json.loads(self.url_analysis) if self.url_analysis else {},
            'sandbox_results': json.loads(self.sandbox_results) if self.sandbox_results else None,
            'created_at': self.created_at
        }


@dataclass
class SystemConfig:
    """Model for system configuration"""
    id: int
    config_key: str
    config_value: str
    updated_at: str


@dataclass
class APILog:
    """Model for API call logs"""
    id: int
    api_name: str
    endpoint: str
    request_time: float
    status_code: int
    response_time: float
    error_message: str
    created_at: str

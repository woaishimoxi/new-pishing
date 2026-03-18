"""
Test Detection Service
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services import DetectionService, EmailParserService
from app.core import get_config


class TestDetectionService:
    """Test cases for DetectionService"""
    
    @pytest.fixture
    def detector(self):
        return DetectionService()
    
    @pytest.fixture
    def parser(self):
        return EmailParserService()
    
    def test_detector_initialization(self, detector):
        """Test detector initialization"""
        assert detector is not None
        assert detector.config is not None
    
    def test_safe_email_detection(self, detector, parser):
        """Test detection of safe email"""
        raw_email = """From: test@example.com
To: recipient@example.com
Subject: Normal Email
Date: Mon, 1 Jan 2024 12:00:00 +0000

This is a normal email content.
"""
        parsed = parser.parse(raw_email)
        features = {
            'is_suspicious_from_domain': 0,
            'spf_fail': 0,
            'dkim_fail': 0,
            'dmarc_fail': 0,
            'from_display_name_mismatch': 0,
            'url_count': 0,
            'attachment_count': 0
        }
        
        label, confidence, reason = detector.analyze(parsed, features)
        
        assert label in ['SAFE', 'SUSPICIOUS', 'PHISHING']
        assert 0 <= confidence <= 1
        assert isinstance(reason, str)


class TestEmailParserService:
    """Test cases for EmailParserService"""
    
    @pytest.fixture
    def parser(self):
        return EmailParserService()
    
    def test_parser_initialization(self, parser):
        """Test parser initialization"""
        assert parser is not None
    
    def test_parse_simple_email(self, parser):
        """Test parsing simple email"""
        raw_email = """From: sender@example.com
To: recipient@example.com
Subject: Test Subject
Date: Mon, 1 Jan 2024 12:00:00 +0000

This is the email body.
"""
        result = parser.parse(raw_email)
        
        assert result is not None
        assert 'from' in result
        assert 'subject' in result
        assert 'body' in result
        assert result['subject'] == 'Test Subject'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

"""
Test Email Parser Service
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services import EmailParserService


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
    
    def test_parse_email_with_url(self, parser):
        """Test parsing email with URL"""
        raw_email = """From: sender@example.com
To: recipient@example.com
Subject: Test with URL

Please visit https://example.com for more info.
"""
        result = parser.parse(raw_email)
        
        assert result is not None
        assert 'urls' in result
        assert len(result['urls']) > 0
        assert 'https://example.com' in result['urls']
    
    def test_parse_email_with_multiple_urls(self, parser):
        """Test parsing email with multiple URLs"""
        raw_email = """From: sender@example.com
To: recipient@example.com
Subject: Test with Multiple URLs

Visit https://google.com and http://example.org for details.
Also check www.test-site.com
"""
        result = parser.parse(raw_email)
        
        assert result is not None
        assert len(result['urls']) >= 2
    
    def test_parse_email_from_header(self, parser):
        """Test parsing From header"""
        raw_email = """From: "John Doe" <john.doe@example.com>
To: recipient@example.com
Subject: Test

Body content.
"""
        result = parser.parse(raw_email)
        
        assert result is not None
        assert 'from_display_name' in result
        assert 'from_email' in result
        assert result['from_display_name'] == 'John Doe'
        assert result['from_email'] == 'john.doe@example.com'
    
    def test_parse_email_with_mime_encoded_header(self, parser):
        """Test parsing MIME encoded header"""
        raw_email = """From: =?utf-8?B?5byg5LiJ?= <sender@example.com>
To: recipient@example.com
Subject: =?utf-8?B?5rWL6K+V6YKu5Lu2?=

Body content.
"""
        result = parser.parse(raw_email)
        
        assert result is not None
        assert result['from'] is not None
        assert result['subject'] is not None


class TestURLAnalyzerService:
    """Test cases for URLAnalyzerService"""
    
    @pytest.fixture
    def url_analyzer(self):
        from app.services import URLAnalyzerService
        return URLAnalyzerService()
    
    def test_url_analyzer_initialization(self, url_analyzer):
        """Test URL analyzer initialization"""
        assert url_analyzer is not None
    
    def test_is_valid_http_url(self, url_analyzer):
        """Test URL validation"""
        assert url_analyzer.is_valid_http_url('https://example.com') == True
        assert url_analyzer.is_valid_http_url('http://example.com') == True
        assert url_analyzer.is_valid_http_url('example.com') == True
        assert url_analyzer.is_valid_http_url('mailto:test@example.com') == False
        assert url_analyzer.is_valid_http_url('javascript:alert(1)') == False
    
    def test_is_trusted_domain(self, url_analyzer):
        """Test trusted domain check"""
        assert url_analyzer.is_trusted_domain('qq.com') == True
        assert url_analyzer.is_trusted_domain('mail.qq.com') == True
        assert url_analyzer.is_trusted_domain('google.com') == True
        assert url_analyzer.is_trusted_domain('phishing-site.com') == False
    
    def test_get_registered_domain(self, url_analyzer):
        """Test registered domain extraction"""
        assert url_analyzer.get_registered_domain('mail.qq.com') == 'qq.com'
        assert url_analyzer.get_registered_domain('www.google.com') == 'google.com'
        assert url_analyzer.get_registered_domain('sub.domain.example.com') == 'example.com'


class TestFeatureExtractionService:
    """Test cases for FeatureExtractionService"""
    
    @pytest.fixture
    def feature_extractor(self):
        from app.services import FeatureExtractionService
        return FeatureExtractionService()
    
    @pytest.fixture
    def parser(self):
        from app.services import EmailParserService
        return EmailParserService()
    
    def test_feature_extractor_initialization(self, feature_extractor):
        """Test feature extractor initialization"""
        assert feature_extractor is not None
    
    def test_extract_text_features(self, feature_extractor):
        """Test text feature extraction"""
        body = "紧急！您的账户需要立即验证！请点击链接确认。"
        subject = "重要通知"
        
        features = feature_extractor._extract_text_features(body, subject)
        
        assert 'urgent_keywords_count' in features
        assert 'financial_keywords_count' in features
        assert 'text_length' in features
        assert features['urgent_keywords_count'] > 0
    
    def test_extract_header_features(self, feature_extractor, parser):
        """Test header feature extraction"""
        raw_email = """From: sender@example.com
To: recipient@example.com
Subject: Test
Received: from mail.example.com ([192.168.1.1])
Authentication-Results: spf=pass dkim=pass dmarc=pass

Body content.
"""
        parsed = parser.parse(raw_email)
        features = feature_extractor._extract_header_features(parsed)
        
        assert 'is_suspicious_from_domain' in features
        assert 'spf_fail' in features
        assert 'dkim_fail' in features
        assert 'dmarc_fail' in features


class TestDatabaseRepository:
    """Test cases for DatabaseRepository"""
    
    @pytest.fixture
    def db(self, tmp_path):
        from app.models.database import DatabaseRepository
        db_path = str(tmp_path / "test.db")
        return DatabaseRepository(db_path)
    
    def test_database_initialization(self, db):
        """Test database initialization"""
        assert db is not None
    
    def test_save_and_get_alert(self, db):
        """Test saving and retrieving alert"""
        parsed = {
            'from': 'sender@example.com',
            'from_display_name': 'Sender',
            'from_email': 'sender@example.com',
            'to': 'recipient@example.com',
            'subject': 'Test Subject',
            'urls': ['https://example.com'],
            'attachments': [],
            'headers': {}
        }
        
        traceback_report = {
            'email_source': {'source_ip': '192.168.1.1'},
            'risk_indicators': []
        }
        
        alert_id = db.save_alert(
            parsed=parsed,
            label='SAFE',
            confidence=0.1,
            traceback_report=traceback_report,
            source='Test'
        )
        
        assert alert_id > 0
        
        alert = db.get_alert(alert_id)
        assert alert is not None
        assert alert['label'] == 'SAFE'
    
    def test_get_stats(self, db):
        """Test getting statistics"""
        stats = db.get_stats()
        
        assert 'total' in stats
        assert 'phishing' in stats
        assert 'suspicious' in stats
        assert 'normal' in stats
        assert 'today' in stats
    
    def test_delete_alert(self, db):
        """Test deleting alert"""
        parsed = {
            'from': 'sender@example.com',
            'from_email': 'sender@example.com',
            'to': 'recipient@example.com',
            'subject': 'Test',
            'urls': [],
            'attachments': [],
            'headers': {}
        }
        
        traceback_report = {'email_source': {}, 'risk_indicators': []}
        
        alert_id = db.save_alert(
            parsed=parsed,
            label='SAFE',
            confidence=0.1,
            traceback_report=traceback_report,
            source='Test'
        )
        
        result = db.delete_alert(alert_id)
        assert result == True
        
        alert = db.get_alert(alert_id)
        assert alert is None


class TestConfig:
    """Test cases for configuration"""
    
    def test_config_singleton(self):
        """Test config singleton pattern"""
        from app.core import get_config, reset_config
        
        reset_config()
        config1 = get_config()
        config2 = get_config()
        
        assert config1 is config2
        
        reset_config()
    
    def test_config_default_values(self):
        """Test config default values"""
        from app.core import get_config, reset_config
        
        reset_config()
        config = get_config()
        
        assert config.detection.phishing_threshold == 0.70
        assert config.detection.suspicious_threshold == 0.40
        
        reset_config()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

"""
Test Exception Handling
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.exceptions import (
    PhishingDetectionError,
    EmailParseError,
    FeatureExtractionError,
    DetectionError,
    ConfigurationError,
    DatabaseError,
    APIError,
    ValidationError,
    handle_exception
)


class TestExceptions:
    """Test cases for exception classes"""
    
    def test_base_exception(self):
        """Test base exception"""
        exc = PhishingDetectionError("Test error")
        assert exc.message == "Test error"
        assert exc.error_code == "UNKNOWN_ERROR"
        assert exc.details == {}
    
    def test_base_exception_with_details(self):
        """Test base exception with details"""
        details = {'key': 'value'}
        exc = PhishingDetectionError("Test error", "CUSTOM_ERROR", details)
        assert exc.message == "Test error"
        assert exc.error_code == "CUSTOM_ERROR"
        assert exc.details == details
    
    def test_exception_to_dict(self):
        """Test exception to_dict method"""
        exc = PhishingDetectionError("Test error", "TEST_ERROR", {'key': 'value'})
        result = exc.to_dict()
        
        assert result['error'] == "TEST_ERROR"
        assert result['message'] == "Test error"
        assert result['details'] == {'key': 'value'}
    
    def test_email_parse_error(self):
        """Test EmailParseError"""
        exc = EmailParseError("Parse failed")
        assert exc.message == "Parse failed"
        assert exc.error_code == "EMAIL_PARSE_ERROR"
    
    def test_feature_extraction_error(self):
        """Test FeatureExtractionError"""
        exc = FeatureExtractionError("Extraction failed")
        assert exc.message == "Extraction failed"
        assert exc.error_code == "FEATURE_EXTRACTION_ERROR"
    
    def test_detection_error(self):
        """Test DetectionError"""
        exc = DetectionError("Detection failed")
        assert exc.message == "Detection failed"
        assert exc.error_code == "DETECTION_ERROR"
    
    def test_configuration_error(self):
        """Test ConfigurationError"""
        exc = ConfigurationError("Config error")
        assert exc.message == "Config error"
        assert exc.error_code == "CONFIGURATION_ERROR"
    
    def test_database_error(self):
        """Test DatabaseError"""
        exc = DatabaseError("DB error")
        assert exc.message == "DB error"
        assert exc.error_code == "DATABASE_ERROR"
    
    def test_api_error(self):
        """Test APIError"""
        exc = APIError("API error", api_name="TestAPI", status_code=500)
        assert exc.message == "API error"
        assert exc.error_code == "API_ERROR"
        assert exc.details['api_name'] == "TestAPI"
        assert exc.details['status_code'] == 500
    
    def test_validation_error(self):
        """Test ValidationError"""
        exc = ValidationError("Invalid field", field="email")
        assert exc.message == "Invalid field"
        assert exc.error_code == "VALIDATION_ERROR"
        assert exc.details['field'] == "email"
    
    def test_handle_exception(self):
        """Test handle_exception function"""
        exc = PhishingDetectionError("Test error", "TEST_ERROR")
        result = handle_exception(exc)
        
        assert result['error'] == "TEST_ERROR"
        assert result['message'] == "Test error"
    
    def test_handle_unknown_exception(self):
        """Test handle_exception with unknown exception"""
        exc = ValueError("Unknown error")
        result = handle_exception(exc)
        
        assert result['error'] == "INTERNAL_ERROR"
        assert "Unknown error" in result['message']


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

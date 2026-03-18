"""
Test Utility Functions
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.utils.validators import (
    validate_email,
    validate_url,
    validate_ip_address,
    validate_file_extension,
    sanitize_filename
)
from app.utils.helpers import (
    format_timestamp,
    truncate_text,
    format_file_size,
    safe_json_serialize,
    calculate_percentage
)


class TestValidators:
    """Test cases for validators"""
    
    def test_validate_email_valid(self):
        """Test valid email validation"""
        assert validate_email("test@example.com") == True
        assert validate_email("user.name@domain.org") == True
        assert validate_email("user+tag@example.co.uk") == True
    
    def test_validate_email_invalid(self):
        """Test invalid email validation"""
        assert validate_email("") == False
        assert validate_email("invalid") == False
        assert validate_email("invalid@") == False
        assert validate_email("@example.com") == False
        assert validate_email("user@") == False
    
    def test_validate_url_valid(self):
        """Test valid URL validation"""
        assert validate_url("https://example.com") == True
        assert validate_url("http://example.com") == True
        assert validate_url("https://www.example.com/path") == True
    
    def test_validate_url_invalid(self):
        """Test invalid URL validation"""
        assert validate_url("") == False
        assert validate_url("invalid") == False
        assert validate_url("ftp://example.com") == False
    
    def test_validate_ip_address_valid(self):
        """Test valid IP address validation"""
        assert validate_ip_address("192.168.1.1") == True
        assert validate_ip_address("0.0.0.0") == True
        assert validate_ip_address("255.255.255.255") == True
    
    def test_validate_ip_address_invalid(self):
        """Test invalid IP address validation"""
        assert validate_ip_address("") == False
        assert validate_ip_address("invalid") == False
        assert validate_ip_address("256.1.1.1") == False
        assert validate_ip_address("1.1.1") == False
    
    def test_validate_file_extension(self):
        """Test file extension validation"""
        assert validate_file_extension("test.eml", {"eml", "msg"}) == True
        assert validate_file_extension("test.txt", {"eml", "msg"}) == False
        assert validate_file_extension("", {"eml"}) == False
    
    def test_sanitize_filename(self):
        """Test filename sanitization"""
        assert sanitize_filename("test.txt") == "test.txt"
        assert sanitize_filename("test<>file.txt") == "test__file.txt"
        assert sanitize_filename("test<>:file.txt") == "test___file.txt"
        assert sanitize_filename("") == ""
        assert sanitize_filename("   ") == "unnamed"
        assert sanitize_filename("test..file.txt") == "test_file.txt"


class TestHelpers:
    """Test cases for helper functions"""
    
    def test_format_timestamp_valid(self):
        """Test valid timestamp formatting"""
        result = format_timestamp("2024-01-01T12:00:00")
        assert "2024" in result
        assert "01" in result
    
    def test_format_timestamp_empty(self):
        """Test empty timestamp formatting"""
        assert format_timestamp("") == ""
        assert format_timestamp(None) == ""
    
    def test_truncate_text_short(self):
        """Test truncate short text"""
        assert truncate_text("short") == "short"
    
    def test_truncate_text_long(self):
        """Test truncate long text"""
        long_text = "a" * 200
        result = truncate_text(long_text, max_length=50)
        assert len(result) == 50
        assert result.endswith("...")
    
    def test_truncate_text_empty(self):
        """Test truncate empty text"""
        assert truncate_text("") == ""
    
    def test_format_file_size(self):
        """Test file size formatting"""
        assert format_file_size(0) == "0.0 B"
        assert format_file_size(1024) == "1.0 KB"
        assert format_file_size(1024 * 1024) == "1.0 MB"
    
    def test_safe_json_serialize_string(self):
        """Test safe JSON serialize string"""
        assert safe_json_serialize("test") == "test"
    
    def test_safe_json_serialize_bytes(self):
        """Test safe JSON serialize bytes"""
        result = safe_json_serialize(b"test")
        assert result == "test"
    
    def test_safe_json_serialize_dict(self):
        """Test safe JSON serialize dict"""
        result = safe_json_serialize({"key": "value"})
        assert result == {"key": "value"}
    
    def test_safe_json_serialize_none(self):
        """Test safe JSON serialize None"""
        assert safe_json_serialize(None) is None
    
    def test_calculate_percentage(self):
        """Test percentage calculation"""
        assert calculate_percentage(50, 100) == 50.0
        assert calculate_percentage(1, 3) == pytest.approx(33.33, rel=0.01)
        assert calculate_percentage(0, 100) == 0.0
        assert calculate_percentage(100, 0) == 0.0
        assert calculate_percentage(150, 100) == 100.0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

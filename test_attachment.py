#!/usr/bin/env python3
"""
Test script to verify attachment detection improvements work correctly
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backend'))

from app.services.email_parser import EmailParserService

def test_php_extension_detection():
    """Test that PHP extensions are detected even when masked"""
    
    parser = EmailParserService()
    
    # Test cases: (filename, expected_suspicious)
    test_cases = [
        # Direct PHP extensions
        ("test.php", True),
        ("test.php3", True),
        ("test.php5", True),
        ("test.phtml", True),
        
        # Other dangerous extensions
        ("test.jsp", True),
        ("test.asp", True),
        ("test.aspx", True),
        ("test.sh", True),
        ("test.py", True),
        ("test.pl", True),
        ("test.cgi", True),
        
        # Masked extensions (safe extension + dangerous extension)
        ("test.txt.php", True),
        ("test.jpg.php", True),
        ("test.pdf.php", True),
        ("test.doc.php", True),
        ("test.zip.php", True),
        
        # Normal safe files
        ("test.txt", False),
        ("test.jpg", False),
        ("test.pdf", False),
        ("test.doc", False),
        ("test.zip", False),
        
        # Double extension with safe extensions (should not be suspicious)
        ("test.pdf.txt", False),
        ("test.jpg.txt", False),
    ]
    
    print("Testing attachment extension detection...")
    print("=" * 50)
    
    success = True
    for filename, expected in test_cases:
        # Mock attachment part
        class MockPart:
            def get_filename(self):
                return filename
            
            def get_content_type(self):
                return "application/octet-stream"
            
            def get(self, key, default=None):
                if key == "Content-Disposition":
                    return "attachment"
                return default
            
            def get_payload(self, decode=True):
                return b"test content"
        
        part = MockPart()
        attachment_info = parser._parse_attachment(part)
        
        if attachment_info:
            is_suspicious = attachment_info.get('is_suspicious_type', False)
            if is_suspicious == expected:
                print(f"PASS: {filename}: {'SUSPICIOUS' if is_suspicious else 'SAFE'}")
            else:
                print(f"FAIL: {filename}: Expected {'SUSPICIOUS' if expected else 'SAFE'}, got {'SUSPICIOUS' if is_suspicious else 'SAFE'}")
                success = False
        else:
            print(f"❌ {filename}: Failed to parse attachment")
            success = False
    
    return success

def test_php_content_detection():
    """Test that PHP content is detected even in non-PHP files"""
    
    parser = EmailParserService()
    
    # Test PHP web shell content
    php_content = b"""PD9waHANCiRhID0gJ3RzZSfvvJs...
    <?php
    $a = 'tse}; 
    $b = 'xe}; 
    $c = base64_decode('...');
    eval($c);
    ?>
    """
    
    # Mock attachment part with PHP content but .txt extension
    class MockPart:
        def get_filename(self):
            return "test.txt"
        
        def get_content_type(self):
            return "text/plain"
        
        def get(self, key, default=None):
            if key == "Content-Disposition":
                return "attachment"
            return default
        
        def get_payload(self, decode=True):
            return php_content
    
    print("\nTesting attachment content detection...")
    print("=" * 50)
    
    part = MockPart()
    attachment_info = parser._parse_attachment(part)
    
    if attachment_info:
        is_suspicious = attachment_info.get('is_suspicious_type', False)
        if is_suspicious:
            print("PASS: PHP content detected in .txt file")
            return True
        else:
            print("FAIL: PHP content NOT detected in .txt file")
            return False
    else:
        print("❌ Failed to parse attachment")
        return False

if __name__ == "__main__":
    print("Testing attachment detection improvements...")
    print("=" * 50)
    
    success = True
    success &= test_php_extension_detection()
    success &= test_php_content_detection()
    
    print("=" * 50)
    if success:
        print("All tests passed!")
        sys.exit(0)
    else:
        print("Some tests failed!")
        sys.exit(1)
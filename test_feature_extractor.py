#!/usr/bin/env python3
"""
Test script to verify feature extraction improvements work correctly
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backend'))

from app.services.feature_extractor import FeatureExtractionService

def test_double_extension_detection():
    """Test that double extension detection works correctly"""
    
    extractor = FeatureExtractionService()
    
    # Test cases: (filename, expected_has_double_extension)
    test_cases = [
        # Should be detected as double extension
        ("test.txt.php", 1),
        ("test.jpg.php", 1),
        ("test.pdf.php", 1),
        ("test.doc.php", 1),
        ("test.zip.php", 1),
        ("test.txt.jsp", 1),
        ("test.jpg.asp", 1),
        
        # Should NOT be detected as double extension (safe extensions)
        ("test.txt.txt", 0),
        ("test.jpg.jpg", 0),
        ("test.pdf.pdf", 0),
        ("test.doc.doc", 0),
        ("test.zip.zip", 0),
        
        # Normal files
        ("test.txt", 0),
        ("test.jpg", 0),
        ("test.pdf", 0),
        ("test.doc", 0),
        ("test.php", 0),  # Single extension, caught by other checks
        
        # Edge cases
        ("test", 0),  # No extension
        ("test.", 0),  # Empty extension
    ]
    
    print("Testing double extension detection...")
    print("=" * 50)
    
    success = True
    for filename, expected in test_cases:
        # Mock attachment
        attachment = {
            'filename': filename,
            'content_type': 'application/octet-stream',
            'size': 100,
            'is_suspicious_type': False
        }
        
        # Create a mock parsed_email with this attachment
        parsed_email = {
            'attachments': [attachment]
        }
        
        # Extract features
        features = extractor._extract_attachment_features(parsed_email)
        
        actual = features.get('has_double_extension', 0)
        if actual == expected:
            print(f"PASS: {filename}: {actual}")
        else:
            print(f"FAIL: {filename}: Expected {expected}, got {actual}")
            success = False
    
    return success

def test_dangerous_extension_detection():
    """Test that dangerous extensions are detected in feature extraction"""
    
    extractor = FeatureExtractionService()
    
    # Test cases: (filename, expected_has_executable_attachment)
    test_cases = [
        # Direct dangerous extensions
        ("test.php", 1),
        ("test.php3", 1),
        ("test.php5", 1),
        ("test.phtml", 1),
        ("test.jsp", 1),
        ("test.asp", 1),
        ("test.aspx", 1),
        ("test.sh", 1),
        ("test.py", 1),
        ("test.pl", 1),
        ("test.cgi", 1),
        
        # Masked dangerous extensions
        ("test.txt.php", 1),
        ("test.jpg.php", 1),
        ("test.pdf.php", 1),
        ("test.doc.php", 1),
        ("test.zip.php", 1),
        
        # Normal safe files
        ("test.txt", 0),
        ("test.jpg", 0),
        ("test.pdf", 0),
        ("test.doc", 0),
        ("test.zip", 0),
    ]
    
    print("\nTesting dangerous extension detection in features...")
    print("=" * 50)
    
    success = True
    for filename, expected in test_cases:
        # Mock attachment
        attachment = {
            'filename': filename,
            'content_type': 'application/octet-stream',
            'size': 100,
            'is_suspicious_type': False
        }
        
        # Create a mock parsed_email with this attachment
        parsed_email = {
            'attachments': [attachment]
        }
        
        # Extract features
        features = extractor._extract_attachment_features(parsed_email)
        
        actual = features.get('has_executable_attachment', 0)
        if actual == expected:
            print(f"PASS: {filename}: {actual}")
        else:
            print(f"FAIL: {filename}: Expected {expected}, got {actual}")
            success = False
    
    return success

if __name__ == "__main__":
    print("Testing feature extraction improvements...")
    print("=" * 50)
    
    success = True
    success &= test_double_extension_detection()
    success &= test_dangerous_extension_detection()
    
    print("=" * 50)
    if success:
        print("All tests passed!")
        sys.exit(0)
    else:
        print("Some tests failed!")
        sys.exit(1)
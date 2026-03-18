"""
Exception Handling Module
Centralized exception definitions for the application
"""
from typing import Optional, Dict, Any


class PhishingDetectionError(Exception):
    """Base exception for all phishing detection errors"""
    
    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or "UNKNOWN_ERROR"
        self.details = details or {}
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'error': self.error_code,
            'message': self.message,
            'details': self.details
        }


class EmailParseError(PhishingDetectionError):
    """Exception raised when email parsing fails"""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "EMAIL_PARSE_ERROR", details)


class FeatureExtractionError(PhishingDetectionError):
    """Exception raised when feature extraction fails"""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "FEATURE_EXTRACTION_ERROR", details)


class DetectionError(PhishingDetectionError):
    """Exception raised when detection fails"""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "DETECTION_ERROR", details)


class ConfigurationError(PhishingDetectionError):
    """Exception raised for configuration errors"""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "CONFIGURATION_ERROR", details)


class DatabaseError(PhishingDetectionError):
    """Exception raised for database errors"""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "DATABASE_ERROR", details)


class APIError(PhishingDetectionError):
    """Exception raised for external API errors"""
    
    def __init__(
        self,
        message: str,
        api_name: Optional[str] = None,
        status_code: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        details = details or {}
        if api_name:
            details['api_name'] = api_name
        if status_code:
            details['status_code'] = status_code
        super().__init__(message, "API_ERROR", details)


class ValidationError(PhishingDetectionError):
    """Exception raised for validation errors"""
    
    def __init__(self, message: str, field: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        details = details or {}
        if field:
            details['field'] = field
        super().__init__(message, "VALIDATION_ERROR", details)


class FileUploadError(PhishingDetectionError):
    """Exception raised for file upload errors"""
    
    def __init__(self, message: str, filename: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        details = details or {}
        if filename:
            details['filename'] = filename
        super().__init__(message, "FILE_UPLOAD_ERROR", details)


class AuthenticationError(PhishingDetectionError):
    """Exception raised for authentication errors"""
    
    def __init__(self, message: str = "Authentication failed", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "AUTHENTICATION_ERROR", details)


class RateLimitError(PhishingDetectionError):
    """Exception raised when rate limit is exceeded"""
    
    def __init__(self, message: str = "Rate limit exceeded", retry_after: Optional[int] = None):
        details = {}
        if retry_after:
            details['retry_after'] = retry_after
        super().__init__(message, "RATE_LIMIT_ERROR", details)


class ModelNotFoundError(PhishingDetectionError):
    """Exception raised when model file is not found"""
    
    def __init__(self, model_path: str):
        super().__init__(
            f"Model file not found: {model_path}",
            "MODEL_NOT_FOUND",
            {'model_path': model_path}
        )


class ServiceUnavailableError(PhishingDetectionError):
    """Exception raised when a service is unavailable"""
    
    def __init__(self, service_name: str, message: Optional[str] = None):
        msg = message or f"Service '{service_name}' is unavailable"
        super().__init__(msg, "SERVICE_UNAVAILABLE", {'service': service_name})


def handle_exception(exc: Exception) -> Dict[str, Any]:
    """
    Convert exception to error response dict
    
    Args:
        exc: Exception instance
        
    Returns:
        Dict with error information
    """
    if isinstance(exc, PhishingDetectionError):
        return exc.to_dict()
    
    return {
        'error': 'INTERNAL_ERROR',
        'message': str(exc),
        'details': {}
    }

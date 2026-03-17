# 面向中小型企业的轻量化钓鱼邮件检测与溯源系统
# 系统初始化文件

from .parse_email import parse_email
from .features import build_feature_vector
from .detector import PhishingDetector, analyze_phishing_risk
from .email_traceback import generate_traceback_report
from .email_fetcher import EmailFetcher

__all__ = [
    'parse_email',
    'build_feature_vector',
    'PhishingDetector',
    'analyze_phishing_risk',
    'generate_traceback_report',
    'EmailFetcher'
]


"""
Configuration Management Module
Enterprise-grade configuration with environment variables support
"""
import os
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum


class Environment(Enum):
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"


@dataclass
class DatabaseConfig:
    """Database configuration"""
    type: str = "sqlite"
    path: str = "data/alerts.db"
    host: str = "localhost"
    port: int = 5432
    name: str = "phishing_detection"
    user: str = ""
    password: str = ""
    pool_size: int = 5
    echo: bool = False
    
    @property
    def connection_string(self) -> str:
        if self.type == "sqlite":
            return f"sqlite:///{self.path}"
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"


@dataclass
class APIConfig:
    """External API configuration"""
    threatbook_api_key: str = ""
    threatbook_api_url: str = "https://api.threatbook.cn/v3"
    ip_api_url: str = "https://opendata.baidu.com/api.php?query={ip}&co=&resource_id=6006&oe=utf8"
    sandbox_enabled: bool = True
    ioc_remote_enabled: bool = True
    request_timeout: int = 10
    max_retries: int = 3
    
    # AI配置
    ai_provider: str = "alibaba"
    ai_api_key: str = ""
    ai_api_url: str = ""
    ai_model: str = "qwen-turbo"
    ai_enabled: bool = False


@dataclass
class EmailConfig:
    """Email server configuration"""
    address: str = ""
    password: str = ""
    server: str = ""
    protocol: str = "imap"
    port: Optional[int] = None
    enabled: bool = False
    fetch_limit: int = 10
    auto_monitor: bool = False
    monitor_interval: int = 30


@dataclass
class DetectionConfig:
    """Detection engine configuration"""
    phishing_threshold: float = 0.70
    suspicious_threshold: float = 0.40
    url_risk_weight: float = 0.4
    text_risk_weight: float = 0.3
    header_risk_weight: float = 0.3
    feature_count: int = 39
    model_path: str = "models/phish_detector.txt"
    use_sandbox: bool = True
    max_file_size: int = 50 * 1024 * 1024


@dataclass
class WhitelistConfig:
    """Whitelist configuration"""
    trusted_domains: List[str] = field(default_factory=lambda: [
        "qq.com", "qlogo.cn", "mail.qq.com", "weixin.qq.com",
        "steampowered.com", "google.com", "microsoft.com",
        "facebook.com", "baidu.com", "taobao.com", "jd.com",
        "aliyun.com", "alipay.com", "wechat.com", "163.com",
        "126.com", "sina.com", "sohu.com"
    ])
    trusted_senders: List[str] = field(default_factory=list)
    verification_indicators: List[str] = field(default_factory=lambda: [
        "验证码", "verification", "verify", "code",
        "confirm", "激活码", "校验码", "动态密码"
    ])
    suspicious_keywords: List[str] = field(default_factory=lambda: [
        "paypa1.com", "g0ogle.com", "micros0ft.com", "amaz0n.com",
        "secure-login.net", "account-verify.com", "bank-security.net"
    ])


@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_path: str = "logs/app.log"
    max_bytes: int = 10 * 1024 * 1024
    backup_count: int = 5
    console_output: bool = True


@dataclass
class SecurityConfig:
    """Security configuration"""
    secret_key: str = ""  # 将在初始化时生成
    session_timeout: int = 3600
    max_content_length: int = 50 * 1024 * 1024
    allowed_extensions: List[str] = field(default_factory=lambda: ["eml", "msg"])
    cors_origins: List[str] = field(default_factory=lambda: ["*"])


class Config:
    """
    Main configuration class
    Supports environment variables and config files
    """
    
    _instance: Optional['Config'] = None
    
    def __new__(cls, *args, **kwargs) -> 'Config':
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(
        self,
        env: Environment = Environment.DEVELOPMENT,
        config_dir: str = None,  # 修改为None，自动检测路径
        data_dir: str = "data",
        models_dir: str = "models",
        logs_dir: str = "logs"
    ):
        if self._initialized:
            return
        
        # 自动检测项目根目录
        if config_dir is None:
            # 从当前文件位置向上查找项目根目录
            current_file = Path(__file__).resolve()
            # backend/app/core/config.py -> 项目根目录
            project_root = current_file.parent.parent.parent.parent
            config_dir = project_root / "config"
        
        self.env = env
        self.config_dir = Path(config_dir)
        self.data_dir = Path(data_dir)
        self.models_dir = Path(models_dir)
        self.logs_dir = Path(logs_dir)
        
        # 确保路径是绝对路径
        if not self.config_dir.is_absolute():
            # 如果是相对路径，基于项目根目录解析
            current_file = Path(__file__).resolve()
            project_root = current_file.parent.parent.parent.parent
            self.config_dir = project_root / self.config_dir
        
        self.database = DatabaseConfig()
        self.api = APIConfig()
        self.email = EmailConfig()
        self.detection = DetectionConfig()
        self.whitelist = WhitelistConfig()
        self.logging = LoggingConfig()
        
        # 生成安全的secret_key（优先使用环境变量）
        import secrets
        self.security = SecurityConfig()
        self.security.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(32))
        
        self._load_from_env()
        self._load_from_files()
        self._ensure_directories()
        
        self._initialized = True
    
    def _load_from_env(self) -> None:
        """Load configuration from environment variables"""
        self.database.type = os.getenv("DB_TYPE", self.database.type)
        self.database.path = os.getenv("DB_PATH", self.database.path)
        self.database.host = os.getenv("DB_HOST", self.database.host)
        self.database.port = int(os.getenv("DB_PORT", self.database.port))
        self.database.name = os.getenv("DB_NAME", self.database.name)
        self.database.user = os.getenv("DB_USER", self.database.user)
        self.database.password = os.getenv("DB_PASSWORD", self.database.password)
        
        self.api.threatbook_api_key = os.getenv("THREATBOOK_API_KEY", self.api.threatbook_api_key)
        self.api.threatbook_api_url = os.getenv("THREATBOOK_API_URL", self.api.threatbook_api_url)
        self.api.ip_api_url = os.getenv("IP_API_URL", self.api.ip_api_url)
        
        self.email.address = os.getenv("EMAIL_ADDRESS", self.email.address)
        self.email.password = os.getenv("EMAIL_PASSWORD", self.email.password)
        self.email.server = os.getenv("EMAIL_SERVER", self.email.server)
        self.email.protocol = os.getenv("EMAIL_PROTOCOL", self.email.protocol)
        
        self.detection.phishing_threshold = float(os.getenv("PHISHING_THRESHOLD", self.detection.phishing_threshold))
        self.detection.suspicious_threshold = float(os.getenv("SUSPICIOUS_THRESHOLD", self.detection.suspicious_threshold))
        
        self.security.secret_key = os.getenv("SECRET_KEY", self.security.secret_key)
        
        self.logging.level = os.getenv("LOG_LEVEL", self.logging.level)
    
    def _load_from_files(self) -> None:
        """Load configuration from JSON files"""
        self._load_api_config()
        self._load_whitelist_config()
    
    def _load_api_config(self) -> None:
        """Load API configuration from file"""
        config_file = self.config_dir / "api_config.json"
        if config_file.exists():
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                if 'threatbook' in data:
                    tb = data['threatbook']
                    if tb.get('api_key'):
                        self.api.threatbook_api_key = tb['api_key']
                    if tb.get('api_url'):
                        self.api.threatbook_api_url = tb['api_url']
                    if 'sandbox_enabled' in tb:
                        self.api.sandbox_enabled = tb['sandbox_enabled']
                    if 'ioc_enabled' in tb:
                        self.api.ioc_remote_enabled = tb['ioc_enabled']
                
                if 'ipapi' in data and data['ipapi'].get('api_url'):
                    self.api.ip_api_url = data['ipapi']['api_url']
                
                if 'email' in data:
                    email = data['email']
                    if email.get('email'):
                        self.email.address = email['email']
                    if email.get('password'):
                        self.email.password = email['password']
                    if email.get('server'):
                        self.email.server = email['server']
                    if email.get('protocol'):
                        self.email.protocol = email['protocol']
                    if email.get('port'):
                        self.email.port = email['port']
                    if 'enabled' in email:
                        self.email.enabled = email['enabled']
                
                # 加载AI配置
                if 'ai' in data:
                    ai = data['ai']
                    if ai.get('provider'):
                        self.api.ai_provider = ai['provider']
                    if ai.get('api_key'):
                        self.api.ai_api_key = ai['api_key']
                    if ai.get('api_url'):
                        self.api.ai_api_url = ai['api_url']
                    if ai.get('model'):
                        self.api.ai_model = ai['model']
                    if 'enabled' in ai:
                        self.api.ai_enabled = ai['enabled']

                if 'detection' in data:
                    det = data['detection']
                    if 'phishing_threshold' in det:
                        self.detection.phishing_threshold = float(det['phishing_threshold'])
                    if 'suspicious_threshold' in det:
                        self.detection.suspicious_threshold = float(det['suspicious_threshold'])
                    if 'url_risk_weight' in det:
                        self.detection.url_risk_weight = float(det['url_risk_weight'])
                    if 'text_risk_weight' in det:
                        self.detection.text_risk_weight = float(det['text_risk_weight'])
                    if 'header_risk_weight' in det:
                        self.detection.header_risk_weight = float(det['header_risk_weight'])

                if 'monitor' in data:
                    mon = data['monitor']
                    if 'interval' in mon:
                        self.email.monitor_interval = int(mon['interval'])
                    if 'max_attachment_size' in mon:
                        self.detection.max_file_size = int(mon['max_attachment_size'])
                        
            except Exception as e:
                print(f"Warning: Failed to load API config: {e}")
    
    def _load_whitelist_config(self) -> None:
        """Load whitelist configuration from file"""
        config_file = self.config_dir / "whitelist.json"
        if config_file.exists():
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                if 'trusted_domains' in data:
                    self.whitelist.trusted_domains = data['trusted_domains']
                if 'trusted_senders' in data:
                    self.whitelist.trusted_senders = data['trusted_senders']
                if 'verification_email_indicators' in data:
                    self.whitelist.verification_indicators = data['verification_email_indicators']
                if 'suspicious_domain_keywords' in data:
                    self.whitelist.suspicious_keywords = data['suspicious_domain_keywords']
                    
            except Exception as e:
                print(f"Warning: Failed to load whitelist config: {e}")
    
    def _ensure_directories(self) -> None:
        """Ensure all required directories exist"""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.config_dir.mkdir(parents=True, exist_ok=True)
    
    def save_api_config(self) -> bool:
        """Save API configuration to file"""
        config_file = self.config_dir / "api_config.json"
        try:
            # 读取现有配置（保留 detection / monitor / last_tuned 等扩展段）
            existing_data = {}
            if config_file.exists():
                with open(config_file, 'r', encoding='utf-8') as f:
                    existing_data = json.load(f)
            
            data = {**existing_data}
            data['threatbook'] = {
                'api_key': self.api.threatbook_api_key,
                'api_url': self.api.threatbook_api_url,
                'sandbox_enabled': self.api.sandbox_enabled,
                'ioc_enabled': self.api.ioc_remote_enabled
            }
            data['ipapi'] = {
                'api_url': self.api.ip_api_url
            }
            data['email'] = {
                'email': self.email.address,
                'password': self.email.password,
                'server': self.email.server,
                'protocol': self.email.protocol,
                'port': self.email.port,
                'enabled': self.email.enabled
            }
            data['ai'] = {
                'provider': self.api.ai_provider,
                'api_key': self.api.ai_api_key,
                'api_url': self.api.ai_api_url,
                'model': self.api.ai_model,
                'enabled': self.api.ai_enabled
            }
            data['detection'] = {
                'phishing_threshold': self.detection.phishing_threshold,
                'suspicious_threshold': self.detection.suspicious_threshold,
                'url_risk_weight': self.detection.url_risk_weight,
                'text_risk_weight': self.detection.text_risk_weight,
                'header_risk_weight': self.detection.header_risk_weight,
            }
            data['monitor'] = {
                'interval': self.email.monitor_interval,
                'max_attachment_size': self.detection.max_file_size,
                'enable_sandbox': self.api.sandbox_enabled,
            }

            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Error saving API config: {e}")
            return False
    
    @property
    def is_production(self) -> bool:
        return self.env == Environment.PRODUCTION
    
    @property
    def is_development(self) -> bool:
        return self.env == Environment.DEVELOPMENT
    
    @property
    def is_testing(self) -> bool:
        return self.env == Environment.TESTING
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            'env': self.env.value,
            'database': {
                'type': self.database.type,
                'path': self.database.path,
                'host': self.database.host,
                'port': self.database.port,
                'name': self.database.name
            },
            'api': {
                'threatbook_api_key': '***' if self.api.threatbook_api_key else '',
                'threatbook_api_url': self.api.threatbook_api_url,
                'ip_api_url': self.api.ip_api_url
            },
            'email': {
                'address': self.email.address,
                'server': self.email.server,
                'protocol': self.email.protocol,
                'enabled': self.email.enabled
            },
            'detection': {
                'phishing_threshold': self.detection.phishing_threshold,
                'suspicious_threshold': self.detection.suspicious_threshold,
                'model_path': self.detection.model_path
            }
        }


_config_instance: Optional[Config] = None


def get_config(
    env: Environment = Environment.DEVELOPMENT,
    **kwargs
) -> Config:
    """
    Get configuration instance (singleton pattern)
    
    Args:
        env: Environment type
        **kwargs: Additional configuration options
        
    Returns:
        Config instance
    """
    global _config_instance
    
    if _config_instance is None:
        env_str = os.getenv("APP_ENV", env.value)
        try:
            env = Environment(env_str)
        except ValueError:
            env = Environment.DEVELOPMENT
        
        _config_instance = Config(env=env, **kwargs)
    
    return _config_instance


def reset_config() -> None:
    """Reset configuration instance (useful for testing)"""
    global _config_instance
    _config_instance = None
    Config._instance = None

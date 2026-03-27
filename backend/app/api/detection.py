"""
Detection API Routes
"""
from flask import Blueprint, jsonify, request
from werkzeug.utils import secure_filename
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.core import get_logger, get_config
from app.services import (
    EmailParserService,
    DetectionService,
    FeatureExtractionService,
    TracebackService,
    URLAnalyzerService,
    SandboxAnalyzerService
)
from app.models.database import DatabaseRepository

detection_bp = Blueprint('detection', __name__)
logger = get_logger(__name__)
config = get_config()
db = DatabaseRepository()

ALLOWED_EXTENSIONS = {'eml', 'msg'}


@detection_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Phishing Detection System',
        'version': '2.0.0'
    })


@detection_bp.route('/analyze', methods=['POST'])
def analyze_email():
    """
    Analy email API
    Accept raw email string and return detection result
    """
    try:
        data = request.get_json()
        raw_email = data.get('email', '')
        source = data.get('source', '手动输入')
        email_uid = data.get('email_uid', '')
        
        if not raw_email:
            return jsonify({'error': 'No email content provided'}), 400
        
        return process_email(raw_email, source, email_uid)
        
    except Exception as e:
        logger.error(f"Analyze email error: {e}")
        return jsonify({'error': str(e)}), 500


@detection_bp.route('/upload', methods=['POST'])
def upload_email():
    """
    Upload email file API
    Support .eml and .msg formats
    """
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': '不支持的文件格式，请上传 .eml 或 .msg 文件'}), 400
        
        filename = secure_filename(file.filename)
        upload_dir = os.path.join(config.data_dir, 'uploads')
        os.makedirs(upload_dir, exist_ok=True)
        filepath = os.path.join(upload_dir, filename)
        file.save(filepath)
        
        raw_email = read_email_file(filepath)
        
        try:
            os.remove(filepath)
        except:
            pass
        
        return process_email(raw_email, '上传邮件')
        
    except Exception as e:
        logger.error(f"Upload email error: {e}")
        return jsonify({'error': str(e)}), 500


def process_email(raw_email: str, source: str = '手动输入', email_uid: str = ''):
    """Process email and return detection result"""
    parser = EmailParserService()
    detector = DetectionService()
    feature_extractor = FeatureExtractionService()
    traceback = TracebackService()
    url_analyzer = URLAnalyzerService()
    sandbox_analyzer = SandboxAnalyzerService()  # 添加沙箱分析器
    
    parsed = parser.parse(raw_email)
    
    max_raw_size = 500 * 1024
    raw_email_stored = raw_email[:max_raw_size] if len(raw_email) > max_raw_size else raw_email
    
    # 附件沙箱分析
    sandbox_results = []
    attachments = parsed.get('attachments', [])
    
    for att in attachments:
        att_result = {
            'filename': att.get('filename', ''),
            'content_type': att.get('content_type', ''),
            'size': att.get('size', 0),
            'sandbox_detected': False,
            'sandbox_report': None
        }
        
        # 检查是否需要分析
        if sandbox_analyzer.should_analyze(
            att.get('filename', ''),
            att.get('content_type', ''),
            att.get('size', 0)
        ):
            try:
                # 如果有VirusTotal API Key，进行沙箱分析
                if config.api.virustotal_api_key:
                    sandbox_result = sandbox_analyzer.analyze_attachment(
                        att, 
                        config.api.virustotal_api_key
                    )
                    att_result['sandbox_detected'] = sandbox_result.get('sandbox_detected', False)
                    att_result['sandbox_report'] = sandbox_result.get('sandbox_report')
            except Exception as e:
                logger.warning(f"Sandbox analysis failed for {att.get('filename')}: {e}")
        
        sandbox_results.append(att_result)
    
    # 更新parsed中的沙箱结果
    parsed['sandbox_results'] = sandbox_results
    
    features = feature_extractor.extract_features(
        parsed, 
        config.api.virustotal_api_key,
        config.api.virustotal_api_url
    )
    
    # 更新特征中的沙箱检测结果
    if any(r.get('sandbox_detected') for r in sandbox_results):
        features['sandbox_detected'] = 1
    
    # 先进行URL分析，然后传入检测器
    url_analysis = url_analyzer.analyze_urls(parsed.get('urls', []))
    url_risk_level = url_analysis.get('max_risk_level', 'UNKNOWN')
    url_risk_score = url_analysis.get('max_risk_score', 0)
    
    label, confidence, reason = detector.analyze(
        parsed, features, 
        url_risk_level=url_risk_level,
        url_risk_score=url_risk_score,
        url_analysis=url_analysis
    )
    
    traceback_report = traceback.generate_report(
        parsed, 
        config.api.virustotal_api_key,
        config.api.ip_api_url
    )
    
    alert_id = db.save_alert(
        parsed, label, confidence, traceback_report, source, raw_email_stored, email_uid
    )
    
    # 处理附件信息（包含沙箱分析结果）
    attachments_with_analysis = []
    for i, att in enumerate(attachments):
        att_with_analysis = {**att}
        if 'content' in att_with_analysis:
            del att_with_analysis['content']
        # 添加沙箱分析结果
        if i < len(sandbox_results):
            att_with_analysis['sandbox_detected'] = sandbox_results[i].get('sandbox_detected', False)
            att_with_analysis['sandbox_report'] = sandbox_results[i].get('sandbox_report')
        attachments_with_analysis.append(att_with_analysis)
    
    safe_features = {}
    for key, value in features.items():
        if isinstance(value, bytes):
            safe_features[key] = str(value)
        else:
            safe_features[key] = value
    
    module_scores = calculate_module_scores(features)
    
    return jsonify({
        'id': alert_id,
        'label': label,
        'confidence': round(confidence, 4),
        'reason': reason,
        'module_scores': module_scores,
        'parsed': {
            'from': parsed.get('from'),
            'from_display_name': parsed.get('from_display_name'),
            'from_email': parsed.get('from_email'),
            'to': parsed.get('to'),
            'subject': parsed.get('subject'),
            'body': parsed.get('body', ''),
            'html_body': parsed.get('html_body', ''),
            'urls': parsed.get('urls', []),
            'url_count': len(parsed.get('urls', [])),
            'attachment_count': len(parsed.get('attachments', [])),
            'has_html_body': 1 if parsed.get('html_body') else 0
        },
        'features': safe_features,
        'attachments': attachments_with_analysis,
        'html_links': parsed.get('html_links', []),
        'html_forms': parsed.get('html_forms', []),
        'headers': parsed.get('headers', {}),
        'traceback': traceback_report,
        'url_analysis': url_analysis,
        'sandbox_analysis': {
            'enabled': bool(config.api.virustotal_api_key),
            'has_sandbox_analysis': features.get('has_sandbox_analysis', 0) == 1,
            'sandbox_detected': features.get('sandbox_detected', 0) == 1,
            'max_detection_ratio': features.get('max_sandbox_detection_ratio', 0.0)
        }
    })


def allowed_file(filename: str) -> bool:
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def read_email_file(filepath: str) -> str:
    """Read email file content, support .eml and .msg formats"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except UnicodeDecodeError:
        try:
            with open(filepath, 'r', encoding='gbk') as f:
                return f.read()
        except:
            pass
        try:
            with open(filepath, 'rb') as f:
                return f.read().decode('utf-8', errors='ignore')
        except:
            pass
    except Exception as e:
        raise Exception(f"读取邮件文件失败： {e}")
    
    raise Exception("无法解析邮件文件编码")


def calculate_module_scores(features: dict) -> dict:
    """Calculate module scores"""
    module_scores = {
        'header': 0.0,
        'url': 0.0,
        'text': 0.0,
        'attachment': 0.0,
        'html': 0.0
    }
    
    header_features = [
        'is_suspicious_from_domain', 'spf_fail', 'dkim_fail', 'dmarc_fail',
        'from_display_name_mismatch', 'from_domain_in_subject'
    ]
    for feat in header_features:
        if features.get(feat, 0):
            module_scores['header'] += 0.2
    
    url_features = [
        'ip_address_count', 'port_count', 'at_symbol_count', 'subdomain_count',
        'suspicious_param_count', 'short_url_count'
    ]
    for feat in url_features:
        if features.get(feat, 0) > 0:
            module_scores['url'] += 0.167
    
    text_features = [
        'urgent_keywords_count', 'financial_keywords_count', 'exclamation_count',
        'caps_ratio', 'urgency_score'
    ]
    for feat in text_features:
        value = features.get(feat, 0)
        if feat == 'urgency_score':
            module_scores['text'] += value * 0.2
        else:
            if value > 0:
                module_scores['text'] += 0.2
    
    attachment_features = [
        'has_suspicious_attachment', 'has_executable_attachment',
        'has_double_extension', 'sandbox_detected'
    ]
    for feat in attachment_features:
        if features.get(feat, 0):
            module_scores['attachment'] += 0.25
    
    html_features = [
        'has_hidden_links', 'has_form', 'has_iframe', 'has_external_script'
    ]
    for feat in html_features:
        if features.get(feat, 0):
            module_scores['html'] += 0.25
    
    for key in module_scores:
        module_scores[key] = min(1.0, module_scores[key])
    
    return module_scores

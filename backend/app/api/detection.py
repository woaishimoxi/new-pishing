"""
Detection API Routes
"""
from flask import Blueprint, jsonify, request
from werkzeug.utils import secure_filename
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.core import get_logger, get_config
from app.services.analysis_pipeline import AnalysisPipeline
from app.models.database import DatabaseRepository


detection_bp = Blueprint('detection', __name__)
logger = get_logger(__name__)
config = get_config()
db = DatabaseRepository()
pipeline = AnalysisPipeline()

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
    Analyze email API
    Accept raw email string and return detection result
    """
    try:
        data = request.get_json() or {}
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
        except Exception:
            pass

        return process_email(raw_email, '上传邮件')

    except Exception as e:
        logger.error(f"Upload email error: {e}")
        return jsonify({'error': str(e)}), 500


def process_email(raw_email: str, source: str = '手动输入', email_uid: str = ''):
    """兼容旧接口：统一转给分析管线"""
    result = pipeline.analyze(raw_email, source=source, email_uid=email_uid, include_sandbox=True)

    # 对抗测试不写入主报告列表，避免污染真实告警数据
    if source == '对抗测试':
        result['saved'] = False
        result['id'] = None
        result['message'] = '对抗测试结果已返回，但未写入报告列表'
        return jsonify(result)

    alert_id = db.save_alert(
        result['parsed'],
        result['label'],
        result['confidence'],
        result['traceback'],
        source,
        raw_email,
        email_uid,
        result.get('ai_analysis')
    )
    result['id'] = alert_id
    result['saved'] = True
    return jsonify(result)


def allowed_file(filename: str) -> bool:
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def read_email_file(filepath: str) -> str:
    """Read email file content, support .eml and .msg formats"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except UnicodeDecodeError:
        try:
            with open(filepath, 'r', encoding='gbk') as f:
                return f.read()
        except Exception:
            pass
        try:
            with open(filepath, 'rb') as f:
                return f.read().decode('utf-8', errors='ignore')
        except Exception:
            pass
    except Exception as e:
        raise Exception(f"读取邮件文件失败： {e}")

    raise Exception("无法解析邮件文件编码")

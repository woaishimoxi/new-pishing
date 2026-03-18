"""
Application Factory
Creates Flask application with configured blueprints
"""
import os
import sys
from flask import Flask, jsonify, render_template
from flask_cors import CORS
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(BASE_DIR / 'backend'))

from app.core.config import get_config
from app.core.logger import setup_logging, get_logger
from app.api.detection import detection_bp
from app.api.alerts import alerts_bp
from app.api.config import config_bp
from app.api.stats import stats_bp
from app.api.email import email_bp
from app.api.docs import api_docs


def create_app(config_name: str = 'development') -> Flask:
    """
    Application factory pattern
    
    Args:
        config_name: Configuration environment name
        
    Returns:
        Configured Flask application
    """
    template_dir = BASE_DIR / 'src' / 'templates'
    static_dir = BASE_DIR / 'static'
    
    app = Flask(
        __name__,
        template_folder=str(template_dir),
        static_folder=str(static_dir)
    )
    
    config = get_config()
    
    setup_logging(
        level=config.logging.level,
        log_file=config.logging.file_path,
        max_bytes=config.logging.max_bytes,
        backup_count=config.logging.backup_count,
        console_output=config.logging.console_output
    )
    
    logger = get_logger(__name__)
    
    app.config['SECRET_KEY'] = config.security.secret_key
    app.config['MAX_CONTENT_LENGTH'] = config.security.max_content_length
    
    CORS(app, origins=config.security.cors_origins)
    
    app.register_blueprint(detection_bp, url_prefix='/api/detection')
    app.register_blueprint(alerts_bp, url_prefix='/api/alerts')
    app.register_blueprint(config_bp, url_prefix='/api/config')
    app.register_blueprint(stats_bp, url_prefix='/api/stats')
    app.register_blueprint(email_bp, url_prefix='/api/email')
    app.register_blueprint(api_docs)
    
    register_error_handlers(app)
    
    register_template_routes(app)
    
    logger.info("Application initialized successfully")
    
    return app


def register_error_handlers(app: Flask) -> None:
    """Register global error handlers"""
    
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({'error': 'Bad Request', 'message': str(error)}), 400
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Not Found', 'message': str(error)}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({'error': 'Internal Server Error', 'message': str(error)}), 500
    
    @app.errorhandler(Exception)
    def handle_exception(error):
        logger = get_logger(__name__)
        logger.error(f"Unhandled exception: {error}")
        return jsonify({'error': 'Internal Error', 'message': str(error)}), 500


def register_template_routes(app: Flask) -> None:
    """Register template routes for frontend pages"""
    
    @app.route('/')
    def index():
        return render_template('dashboard.html')
    
    @app.route('/dashboard')
    def dashboard():
        return render_template('dashboard.html')
    
    @app.route('/detection')
    def detection():
        return render_template('detection.html')
    
    @app.route('/alerts')
    def alerts():
        return render_template('alerts.html')
    
    @app.route('/config')
    def config_page():
        return render_template('config.html')
    
    @app.route('/history')
    def history():
        return render_template('history.html')
    
    @app.route('/report.html')
    def report():
        return render_template('report.html')


app = create_app()


if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )

"""
Unified email analysis pipeline.
All email sources should pass through this entry to keep results consistent.
"""
import os
import json
from typing import Dict

from app.core import get_logger, get_config
from app.services.email_parser import EmailParserService
from app.services.detector import DetectionService
from app.services.traceback import TracebackService
from app.services.feature_extractor import FeatureExtractionService
from app.services.url_analyzer import URLAnalyzerService
from app.services.sandbox_analyzer import SandboxAnalyzerService

logger = get_logger(__name__)


class AnalysisPipeline:
    def __init__(self):
        self.parser = EmailParserService()
        self.detector = DetectionService()
        self.feature_extractor = FeatureExtractionService()
        self.traceback = TracebackService()
        self.url_analyzer = URLAnalyzerService()
        self.sandbox_analyzer = SandboxAnalyzerService()

    def _get_config(self):
        """每次获取最新的配置实例，避免缓存旧配置"""
        return get_config()

    def analyze(self, raw_email: str, source: str = 'manual', email_uid: str = '', include_sandbox: bool = True) -> Dict:
        logger.info(f"[Pipeline] 开始分析 - source={source}, email_uid={email_uid}, include_sandbox={include_sandbox}")
        
        # 每次分析都获取最新配置
        config = self._get_config()
        logger.info(f"[Pipeline] AI配置: ai_enabled={getattr(config.api, 'ai_enabled', None)}, api_key={'已配置' if getattr(config.api, 'ai_api_key', '') else '未配置'}")

        parsed = self.parser.parse(raw_email)
        parsed['analysis_source'] = source
        if email_uid:
            parsed['email_uid'] = email_uid

        sandbox_results = []
        if include_sandbox:
            attachments = parsed.get('attachments', []) or []
            for att in attachments:
                att_result = {
                    'filename': att.get('filename', ''),
                    'content_type': att.get('content_type', ''),
                    'size': att.get('size', 0),
                    'sandbox_detected': False,
                    'sandbox_report': None
                }
                if self.sandbox_analyzer.should_analyze(att.get('filename', ''), att.get('content_type', ''), att.get('size', 0)):
                    try:
                        if getattr(config.api, 'threatbook_api_key', ''):
                            try:
                                from app.services.threatbook import threatbook_service
                                sandbox_result = threatbook_service.analyze_file(att.get('content', b''), att.get('filename', ''))
                                att_result['sandbox_detected'] = sandbox_result.get('threat_level') in ['malicious', 'suspicious']
                                att_result['sandbox_report'] = sandbox_result
                            except Exception as e:
                                logger.warning(f"Sandbox service unavailable for {att.get('filename')}: {e}")
                    except Exception as e:
                        logger.warning(f"Sandbox analysis failed {att.get('filename')}: {e}")
                sandbox_results.append(att_result)
            parsed['sandbox_results'] = sandbox_results

        urls = parsed.get('urls', []) or []
        url_analysis = self.url_analyzer.analyze_urls(urls) if urls else None
        features = self.feature_extractor.extract_features(parsed)
        if sandbox_results and any(r.get('sandbox_detected') for r in sandbox_results):
            features['sandbox_detected'] = 1

        ai_analysis = None
        try:
            if getattr(config.api, 'ai_enabled', False) and getattr(config.api, 'ai_api_key', ''):
                body_text = parsed.get('body', '') or parsed.get('html_body', '') or '[无正文内容]'
                email_content_for_ai = f"""发件人: {parsed.get('from_display_name', '')} <{parsed.get('from_email', '')}>
收件人: {parsed.get('to', '')}
主题: {parsed.get('subject', '')}

邮件正文:
{body_text}

包含的URL:
{chr(10).join('- ' + url for url in parsed.get('urls', [])[:10]) if parsed.get('urls') else '[无URL]'}

附件信息:
{chr(10).join('- ' + att.get('filename', '未知') for att in (parsed.get('attachments', []) or [])[:5]) if parsed.get('attachments') else '[无附件]'}
"""
                try:
                    from app.api.alerts import call_ai_service
                    ai_analysis = call_ai_service({
                        'provider': getattr(config.api, 'ai_provider', 'alibaba'),
                        'api_key': getattr(config.api, 'ai_api_key', ''),
                        'api_url': getattr(config.api, 'ai_api_url', ''),
                        'model': getattr(config.api, 'ai_model', 'qwen-turbo'),
                    }, email_content_for_ai[:6000])
                except Exception as e:
                    logger.warning(f"AI service unavailable, skip AI analysis: {e}")
        except Exception as e:
            logger.warning(f"AI analysis config load failed: {e}")

        label, confidence, reason, model_scores = self.detector.analyze(parsed, features, ai_analysis, url_analysis)
        traceback_report = self.traceback.generate_report(parsed)

        attachments = parsed.get('attachments', []) or []
        attachments_with_analysis = []
        for i, att in enumerate(attachments):
            item = {**att}
            item.pop('content', None)
            if i < len(sandbox_results):
                item['sandbox_detected'] = sandbox_results[i].get('sandbox_detected', False)
                item['sandbox_report'] = sandbox_results[i].get('sandbox_report')
            attachments_with_analysis.append(item)

        safe_features = {}
        for key, value in features.items():
            safe_features[key] = str(value) if isinstance(value, bytes) else value

        return {
            'label': label,
            'confidence': round(confidence, 4),
            'reason': reason,
            'model_scores': model_scores,
            'module_scores': calculate_module_scores(features),
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
            'traceback': traceback_report,
            'url_analysis': url_analysis,
            'ai_analysis': ai_analysis,
            'source': source,
            'email_uid': email_uid
        }


def calculate_module_scores(features: Dict) -> Dict:
    weights = {
        'header_score': 0.20,
        'url_score': 0.30,
        'body_score': 0.20,
        'attachment_score': 0.15,
        'html_score': 0.10,
        'suspicion_score': 0.05
    }
    return {k: float(features.get(k, 0)) * w for k, w in weights.items()}

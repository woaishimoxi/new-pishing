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
        # 每次分析都获取最新配置
        config = self._get_config()
        logger.info(f"[诊断] ===== 开始分析邮件 ===== source={source}")

        parsed = self.parser.parse(raw_email)
        logger.info(f"[诊断] 邮件解析完成: from={parsed.get('from_email', '')}, subject={parsed.get('subject', '')[:50]}")
        
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
        logger.info(f"[诊断] URL分析执行: source={source}, url_count={len(urls)}, url_analysis={'存在' if url_analysis else 'None'}")

        features = self.feature_extractor.extract_features(parsed)
        if sandbox_results and any(r.get('sandbox_detected') for r in sandbox_results):
            features['sandbox_detected'] = 1

        ai_analysis = None
        try:
            ai_enabled = getattr(config.api, 'ai_enabled', False)
            ai_api_key = getattr(config.api, 'ai_api_key', '')
            logger.info(f"[诊断] AI配置检查: ai_enabled={ai_enabled}, api_key={'已配置' if ai_api_key else '未配置'}, source={source}")
            
            if ai_enabled and ai_api_key:
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
                    logger.info(f"[诊断] AI分析成功: source={source}")
                except Exception as e:
                    logger.warning(f"AI service unavailable, skip AI analysis: {e}")
            else:
                logger.warning(f"[诊断] AI分析未激活: ai_enabled={ai_enabled}, api_key={'已配置' if ai_api_key else '未配置'}, source={source}")
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
    """计算模块分数 - 增强版，处理头部信息缺失的情况"""
    weights = {
        'header_score': 0.20,
        'url_score': 0.30,
        'body_score': 0.20,
        'attachment_score': 0.15,
        'html_score': 0.10,
        'suspicion_score': 0.05
    }
    
    # 计算各个模块的分数
    scores = {}
    
    # 头部分数：基于可用的头部特征
    header_score = 0.0
    if features.get('has_source_ip') == 0:
        # 没有源IP，增加一些风险分数
        header_score += 0.2
    if features.get('has_authentication_results') == 0:
        # 没有认证结果，增加一些风险分数
        header_score += 0.2
    if features.get('spf_fail') == 1:
        header_score += 0.3
    if features.get('dkim_fail') == 1:
        header_score += 0.2
    if features.get('dmarc_fail') == 1:
        header_score += 0.1
    scores['header_score'] = min(1.0, header_score)
    
    # URL分数
    url_score = 0.0
    if features.get('url_count', 0) > 0:
        # 有URL时计算URL风险
        if features.get('max_vt_detection_ratio', 0) > 0:
            url_score = features.get('max_vt_detection_ratio', 0)
        elif features.get('max_threat_detection_ratio', 0) > 0:
            url_score = features.get('max_threat_detection_ratio', 0)
        else:
            # 基于其他URL特征计算
            url_score = min(1.0, (
                features.get('short_url_count', 0) * 0.2 +
                features.get('ip_address_count', 0) * 0.3 +
                features.get('at_symbol_count', 0) * 0.2 +
                features.get('suspicious_param_count', 0) * 0.1
            ))
    scores['url_score'] = url_score
    
    # 正文分数
    body_score = 0.0
    if features.get('urgent_keywords_count', 0) > 0:
        body_score += min(0.3, features.get('urgent_keywords_count', 0) * 0.1)
    if features.get('financial_keywords_count', 0) > 0:
        body_score += min(0.3, features.get('financial_keywords_count', 0) * 0.1)
    if features.get('urgency_score', 0) > 0:
        body_score += features.get('urgency_score', 0) * 0.4
    scores['body_score'] = min(1.0, body_score)
    
    # 附件分数
    attachment_score = 0.0
    if features.get('attachment_count', 0) > 0:
        if features.get('has_suspicious_attachment') == 1:
            attachment_score += 0.5
        if features.get('has_executable_attachment') == 1:
            attachment_score += 0.3
        if features.get('has_double_extension') == 1:
            attachment_score += 0.2
        if features.get('sandbox_detected') == 1:
            attachment_score += 0.5
    scores['attachment_score'] = min(1.0, attachment_score)
    
    # HTML分数
    html_score = 0.0
    if features.get('has_html_body') == 1:
        html_score += 0.1
    if features.get('has_hidden_links') == 1:
        html_score += 0.3
    if features.get('has_form') == 1:
        html_score += 0.3
    if features.get('has_iframe') == 1:
        html_score += 0.2
    if features.get('has_external_script') == 1:
        html_score += 0.1
    scores['html_score'] = min(1.0, html_score)
    
    # 可疑分数
    suspicion_score = 0.0
    if features.get('is_suspicious_from_domain') == 1:
        suspicion_score += 0.3
    if features.get('from_display_name_mismatch') == 1:
        suspicion_score += 0.3
    if features.get('caps_ratio', 0) > 0.5:
        suspicion_score += 0.2
    if features.get('exclamation_count', 0) > 3:
        suspicion_score += 0.2
    scores['suspicion_score'] = min(1.0, suspicion_score)
    
    # 应用权重
    return {k: scores.get(k, 0) * w for k, w in weights.items()}

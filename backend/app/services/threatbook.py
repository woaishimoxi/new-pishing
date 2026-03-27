#!/usr/bin/env python3
"""
微步在线沙箱检测服务
用于附件深度分析
"""
import os
import json
import time
import base64
import hashlib
import requests
from typing import Dict, Optional
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.core import get_logger, get_config


class ThreatBookService:
    """
    微步在线威胁分析服务
    支持文件沙箱分析、URL检测、IP查询
    """
    
    # 微步在线API地址
    BASE_URL = "https://api.threatbook.cn/v3"
    
    # 文件分析接口
    FILE_SCAN_URL = f"{BASE_URL}/file/upload"
    FILE_REPORT_URL = f"{BASE_URL}/file/report"
    
    # URL分析接口
    URL_SCAN_URL = f"{BASE_URL}/url/scan"
    URL_REPORT_URL = f"{BASE_URL}/url/report"
    
    # IP查询接口
    IP_QUERY_URL = f"{BASE_URL}/ip/query"
    
    # 威胁等级映射
    THREAT_LEVELS = {
        'malicious': {'level': 'high', 'score': 90, 'label': '恶意'},
        'suspicious': {'level': 'medium', 'score': 60, 'label': '可疑'},
        'clean': {'level': 'low', 'score': 10, 'label': '安全'},
        'unknown': {'level': 'unknown', 'score': 50, 'label': '未知'}
    }
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config = get_config()
        self.api_key = self._get_api_key()
    
    def _get_api_key(self) -> str:
        """获取微步API Key"""
        config_file = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
            'config', 'api_config.json'
        )
        
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    return config.get('threatbook', {}).get('api_key', '')
            except:
                pass
        return ''
    
    def analyze_file(self, file_content: bytes, filename: str) -> Dict:
        """
        分析文件（附件深度分析）
        
        Args:
            file_content: 文件内容
            filename: 文件名
            
        Returns:
            分析结果
        """
        result = {
            'filename': filename,
            'analyzed': False,
            'threat_level': 'unknown',
            'threat_score': 50,
            'threat_label': '未知',
            'scan_time': None,
            'engines': {},
            'behavior': [],
            'network': [],
            'registry': [],
            'error': None
        }
        
        if not self.api_key:
            result['error'] = '微步API Key未配置'
            return result
        
        try:
            # 计算文件哈希
            md5 = hashlib.md5(file_content).hexdigest()
            sha256 = hashlib.sha256(file_content).hexdigest()
            
            result['md5'] = md5
            result['sha256'] = sha256
            
            # 首先查询是否已有分析结果
            report = self._query_file_report(md5)
            
            if report:
                result.update(self._parse_report(report))
                result['analyzed'] = True
            else:
                # 上传文件进行分析
                upload_result = self._upload_file(file_content, filename)
                
                if upload_result.get('response_code') == 0:
                    # 等待分析完成
                    time.sleep(3)
                    report = self._query_file_report(md5)
                    
                    if report:
                        result.update(self._parse_report(report))
                        result['analyzed'] = True
                    else:
                        result['error'] = '分析中，请稍后查询'
                else:
                    result['error'] = upload_result.get('verbose_msg', '上传失败')
        
        except Exception as e:
            result['error'] = str(e)
            self.logger.error(f"微步文件分析失败: {e}")
        
        return result
    
    def analyze_url(self, url: str) -> Dict:
        """
        分析URL
        
        Args:
            url: 待分析的URL
            
        Returns:
            分析结果
        """
        result = {
            'url': url,
            'analyzed': False,
            'threat_level': 'unknown',
            'threat_score': 50,
            'threat_label': '未知',
            'engines': {},
            'categories': [],
            'error': None
        }
        
        if not self.api_key:
            result['error'] = '微步API Key未配置'
            return result
        
        try:
            # 查询URL
            params = {
                'apikey': self.api_key,
                'url': url
            }
            
            response = requests.get(self.URL_REPORT_URL, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('response_code') == 0:
                    report = data.get('data', {}).get(url, {})
                    result.update(self._parse_url_report(report))
                    result['analyzed'] = True
                else:
                    result['error'] = data.get('verbose_msg', '查询失败')
            else:
                result['error'] = f'HTTP {response.status_code}'
        
        except Exception as e:
            result['error'] = str(e)
            self.logger.error(f"微步URL分析失败: {e}")
        
        return result
    
    def query_ip(self, ip: str) -> Dict:
        """
        查询IP信息
        
        Args:
            ip: IP地址
            
        Returns:
            IP信息
        """
        result = {
            'ip': ip,
            'threat_level': 'unknown',
            'threat_score': 0,
            'location': {},
            'asn': {},
            'tags': [],
            'error': None
        }
        
        if not self.api_key:
            result['error'] = '微步API Key未配置'
            return result
        
        try:
            params = {
                'apikey': self.api_key,
                'resource': ip
            }
            
            response = requests.get(self.IP_QUERY_URL, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('response_code') == 0:
                    ip_data = data.get('data', {}).get(ip, {})
                    result.update(self._parse_ip_report(ip_data))
                else:
                    result['error'] = data.get('verbose_msg', '查询失败')
            else:
                result['error'] = f'HTTP {response.status_code}'
        
        except Exception as e:
            result['error'] = str(e)
            self.logger.error(f"微步IP查询失败: {e}")
        
        return result
    
    def _upload_file(self, file_content: bytes, filename: str) -> Dict:
        """上传文件到微步进行分析"""
        try:
            files = {'file': (filename, file_content)}
            params = {'apikey': self.api_key}
            
            response = requests.post(
                self.FILE_SCAN_URL,
                files=files,
                params=params,
                timeout=30
            )
            
            return response.json()
        
        except Exception as e:
            return {'response_code': -1, 'verbose_msg': str(e)}
    
    def _query_file_report(self, md5: str) -> Optional[Dict]:
        """查询文件分析报告"""
        try:
            params = {
                'apikey': self.api_key,
                'resource': md5
            }
            
            response = requests.get(self.FILE_REPORT_URL, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('response_code') == 0:
                    return data.get('data', {}).get(md5, {})
            
            return None
        
        except Exception as e:
            self.logger.error(f"查询文件报告失败: {e}")
            return None
    
    def _parse_report(self, report: Dict) -> Dict:
        """解析微步报告"""
        result = {
            'scan_time': report.get('scan_time'),
            'engines': {},
            'behavior': [],
            'network': [],
            'registry': []
        }
        
        # 解析多引擎检测结果
        scans = report.get('scans', {})
        detected_count = 0
        total_count = 0
        
        for engine, info in scans.items():
            total_count += 1
            detected = info.get('detected', False)
            result_name = info.get('result', '')
            
            result['engines'][engine] = {
                'detected': detected,
                'result': result_name
            }
            
            if detected:
                detected_count += 1
        
        # 计算威胁等级
        if total_count > 0:
            detection_ratio = detected_count / total_count
            
            if detection_ratio > 0.3:
                result['threat_level'] = 'malicious'
                result['threat_score'] = min(95, int(detection_ratio * 100))
                result['threat_label'] = '恶意'
            elif detection_ratio > 0.1:
                result['threat_level'] = 'suspicious'
                result['threat_score'] = int(detection_ratio * 100)
                result['threat_label'] = '可疑'
            else:
                result['threat_level'] = 'clean'
                result['threat_score'] = max(5, int(detection_ratio * 100))
                result['threat_label'] = '安全'
        
        # 解析行为分析
        behavior = report.get('behaviour', {})
        if behavior:
            result['behavior'] = behavior.get('summary', [])
            result['network'] = behavior.get('network', [])
            result['registry'] = behavior.get('registry', [])
        
        return result
    
    def _parse_url_report(self, report: Dict) -> Dict:
        """解析URL报告"""
        result = {
            'engines': {},
            'categories': []
        }
        
        # 解析检测结果
        scans = report.get('scans', {})
        detected_count = 0
        
        for engine, info in scans.items():
            detected = info.get('detected', False)
            result['engines'][engine] = {
                'detected': detected,
                'result': info.get('result', '')
            }
            if detected:
                detected_count += 1
        
        # 解析分类
        result['categories'] = report.get('categories', [])
        
        # 计算威胁等级
        if detected_count > 2:
            result['threat_level'] = 'malicious'
            result['threat_score'] = 90
            result['threat_label'] = '恶意'
        elif detected_count > 0:
            result['threat_level'] = 'suspicious'
            result['threat_score'] = 60
            result['threat_label'] = '可疑'
        else:
            result['threat_level'] = 'clean'
            result['threat_score'] = 10
            result['threat_label'] = '安全'
        
        return result
    
    def _parse_ip_report(self, report: Dict) -> Dict:
        """解析IP报告"""
        result = {
            'location': report.get('location', {}),
            'asn': report.get('asn', {}),
            'tags': report.get('tags_basic', [])
        }
        
        # 计算威胁等级
        severity = report.get('severity', 'info')
        
        if severity == 'critical':
            result['threat_level'] = 'malicious'
            result['threat_score'] = 95
        elif severity == 'high':
            result['threat_level'] = 'malicious'
            result['threat_score'] = 85
        elif severity == 'medium':
            result['threat_level'] = 'suspicious'
            result['threat_score'] = 60
        else:
            result['threat_level'] = 'clean'
            result['threat_score'] = 10
        
        return result


# 创建全局实例
threatbook_service = ThreatBookService()

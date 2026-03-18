"""
Sandbox Analyzer Service
Dynamic analysis of attachments using VirusTotal
"""
import time
import hashlib
import requests
from typing import Dict, Optional
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.core import get_logger, get_config


class SandboxAnalyzerService:
    """
    Sandbox Analyzer Service
    Dynamic analysis of attachments using VirusTotal
    """
    
    VT_FILE_REPORT_URL = "https://www.virustotal.com/vtapi/v2/file/report"
    VT_FILE_SCAN_URL = "https://www.virustotal.com/vtapi/v2/file/scan"
    
    HIGH_RISK_EXTENSIONS = [
        ".exe", ".bat", ".cmd", ".com", ".scr", ".vbs", ".vbe",
        ".js", ".jse", ".wsf", ".wsh", ".ps1", ".msi", ".msp", ".hta",
        ".cpl", ".msc", ".jar", ".dll", ".reg", ".lnk",
        ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm", ".ppam", ".sldm",
        ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz"
    ]
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config = get_config()
    
    def get_file_hash(self, file_content: bytes) -> Dict[str, str]:
        """Calculate file hashes"""
        return {
            "md5": hashlib.md5(file_content).hexdigest(),
            "sha1": hashlib.sha1(file_content).hexdigest(),
            "sha256": hashlib.sha256(file_content).hexdigest()
        }
    
    def should_analyze(self, filename: str, content_type: str, file_size: int) -> bool:
        """Check if file should be analyzed"""
        if file_size > 10 * 1024 * 1024:
            return False
        
        image_extensions = [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff"]
        text_extensions = [".txt", ".csv", ".log"]
        
        ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        
        if ext in image_extensions or ext in text_extensions:
            return False
        
        if ext in self.HIGH_RISK_EXTENSIONS:
            return True
        
        if not ext and content_type.startswith("application/"):
            return True
        
        return False
    
    def query_virustotal_hash(
        self,
        file_hash: str,
        vt_api_key: str
    ) -> Optional[Dict]:
        """Query VirusTotal for existing hash"""
        try:
            params = {"apikey": vt_api_key, "resource": file_hash}
            response = requests.get(self.VT_FILE_REPORT_URL, params=params, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get("response_code") == 1:
                    return result
        except Exception as e:
            self.logger.error(f"VirusTotal hash query error: {e}")
        
        return None
    
    def scan_file_virustotal(
        self,
        file_content: bytes,
        filename: str,
        vt_api_key: str
    ) -> Optional[Dict]:
        """Upload file to VirusTotal for analysis"""
        try:
            files = {"file": (filename, file_content)}
            params = {"apikey": vt_api_key}
            response = requests.post(
                self.VT_FILE_SCAN_URL,
                files=files,
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            self.logger.error(f"VirusTotal file scan error: {e}")
        
        return None
    
    def get_virustotal_report(
        self,
        scan_id: str,
        vt_api_key: str,
        max_retries: int = 5,
        retry_interval: int = 10
    ) -> Optional[Dict]:
        """Get VirusTotal scan report"""
        for i in range(max_retries):
            try:
                params = {"apikey": vt_api_key, "resource": scan_id}
                response = requests.get(self.VT_FILE_REPORT_URL, params=params, timeout=10)
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get("response_code") == 1:
                        return result
            except Exception as e:
                self.logger.error(f"VirusTotal report error: {e}")
            
            if i < max_retries - 1:
                time.sleep(retry_interval)
        
        return None
    
    def analyze_file(
        self,
        file_content: bytes,
        filename: str,
        content_type: str,
        vt_api_key: str
    ) -> Dict:
        """Analyze file with VirusTotal"""
        result = {
            "analysis_type": "none",
            "detected": False,
            "detection_ratio": 0.0,
            "scanner_count": 0,
            "malicious_scanners": 0,
            "sandbox_report": None,
            "error": None
        }
        
        hashes = self.get_file_hash(file_content)
        
        vt_report = self.query_virustotal_hash(hashes["sha256"], vt_api_key)
        
        if vt_report:
            result["analysis_type"] = "hash_lookup"
            result["scanner_count"] = vt_report.get("total", 0)
            result["malicious_scanners"] = vt_report.get("positives", 0)
            result["detection_ratio"] = vt_report.get("positives", 0) / vt_report.get("total", 1)
            result["detected"] = vt_report.get("positives", 0) > 0
            result["sandbox_report"] = vt_report
            return result
        
        scan_response = self.scan_file_virustotal(file_content, filename, vt_api_key)
        
        if scan_response and scan_response.get("response_code") == 1:
            scan_id = scan_response.get("scan_id")
            if scan_id:
                vt_report = self.get_virustotal_report(scan_id, vt_api_key)
                if vt_report:
                    result["analysis_type"] = "file_scan"
                    result["scanner_count"] = vt_report.get("total", 0)
                    result["malicious_scanners"] = vt_report.get("positives", 0)
                    result["detection_ratio"] = vt_report.get("positives", 0) / vt_report.get("total", 1)
                    result["detected"] = vt_report.get("positives", 0) > 0
                    result["sandbox_report"] = vt_report
                    return result
        
        return result
    
    def analyze_attachment(
        self,
        attachment: Dict,
        vt_api_key: str = ""
    ) -> Dict:
        """Analyze single attachment"""
        filename = attachment.get("filename", "")
        content_type = attachment.get("content_type", "")
        file_size = attachment.get("size", 0)
        
        if not self.should_analyze(filename, content_type, file_size):
            return {
                "analyzed": False,
                "reason": "low_risk",
                "result": None
            }
        
        file_content = attachment.get("content")
        if not file_content:
            return {
                "analyzed": False,
                "reason": "no_content",
                "result": None
            }
        
        try:
            result = self.analyze_file(file_content, filename, content_type, vt_api_key)
            return {
                "analyzed": True,
                "reason": "analyzed",
                "result": result
            }
        except Exception as e:
            return {
                "analyzed": False,
                "reason": "error",
                "error": str(e),
                "result": None
            }

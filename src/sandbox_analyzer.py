"""
在线沙箱分析模块
该模块负责将可疑附件提交到在线沙箱服务进行动态分析，作为静态分析的第二道防线。

支持的沙箱服务：
- VirusTotal API (首选)
- Hybrid Analysis (可选)
"""
import time
import hashlib
import requests
from typing import Dict, Optional, Tuple


class SandboxAnalyzer:
    """
    沙箱分析器类，负责与在线沙箱服务交互
    """
    
    def __init__(self, vt_api_key: str = "", ha_api_key: str = ""):
        """
        初始化沙箱分析器
        
        Args:
            vt_api_key: VirusTotal API 密钥
            ha_api_key: Hybrid Analysis API 密钥
        """
        self.vt_api_key = vt_api_key
        self.ha_api_key = ha_api_key
        
        # API 端点
        self.VT_FILE_REPORT_URL = "https://www.virustotal.com/vtapi/v2/file/report"
        self.VT_FILE_SCAN_URL = "https://www.virustotal.com/vtapi/v2/file/scan"
        self.HA_API_URL = "https://www.hybrid-analysis.com/api/v2"
    
    def get_file_hash(self, file_content: bytes) -> Dict[str, str]:
        """
        计算文件的哈希值
        
        Args:
            file_content: 文件内容
            
        Returns:
            包含 MD5、SHA1、SHA256 哈希值的字典
        """
        return {
            "md5": hashlib.md5(file_content).hexdigest(),
            "sha1": hashlib.sha1(file_content).hexdigest(),
            "sha256": hashlib.sha256(file_content).hexdigest()
        }
    
    def query_virustotal_hash(self, file_hash: str) -> Optional[Dict]:
        """
        查询 VirusTotal 已知哈希
        
        Args:
            file_hash: 文件哈希值 (MD5, SHA1 或 SHA256)
            
        Returns:
            VirusTotal 报告，如果未找到或 API 失败则返回 None
        """
        if not self.vt_api_key:
            return None
        
        try:
            params = {"apikey": self.vt_api_key, "resource": file_hash}
            response = requests.get(self.VT_FILE_REPORT_URL, params=params, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get("response_code") == 1:
                    return result
        except Exception as e:
            print(f"VirusTotal hash query error: {e}")
        
        return None
    
    def scan_file_virustotal(self, file_content: bytes, filename: str) -> Optional[Dict]:
        """
        上传文件到 VirusTotal 进行分析
        
        Args:
            file_content: 文件内容
            filename: 文件名
            
        Returns:
            VirusTotal 扫描响应，如果失败则返回 None
        """
        if not self.vt_api_key:
            return None
        
        try:
            files = {"file": (filename, file_content)}
            params = {"apikey": self.vt_api_key}
            response = requests.post(self.VT_FILE_SCAN_URL, files=files, params=params, timeout=30)
            
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"VirusTotal file scan error: {e}")
        
        return None
    
    def get_virustotal_report(self, scan_id: str, max_retries: int = 5, retry_interval: int = 10) -> Optional[Dict]:
        """
        获取 VirusTotal 扫描报告
        
        Args:
            scan_id: 扫描 ID
            max_retries: 最大重试次数
            retry_interval: 重试间隔（秒）
            
        Returns:
            VirusTotal 报告，如果失败则返回 None
        """
        if not self.vt_api_key:
            return None
        
        for i in range(max_retries):
            try:
                params = {"apikey": self.vt_api_key, "resource": scan_id}
                response = requests.get(self.VT_FILE_REPORT_URL, params=params, timeout=10)
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get("response_code") == 1:
                        return result
            except Exception as e:
                print(f"VirusTotal report error: {e}")
            
            if i < max_retries - 1:
                time.sleep(retry_interval)
        
        return None
    
    def analyze_file(self, file_content: bytes, filename: str, content_type: str) -> Dict:
        """
        分析文件，先查哈希，再上传分析
        
        Args:
            file_content: 文件内容
            filename: 文件名
            content_type: 内容类型
            
        Returns:
            分析结果字典
        """
        result = {
            "analysis_type": "none",
            "detected": False,
            "detection_ratio": 0.0,
            "scanner_count": 0,
            "malicious_scanners": 0,
            "sandbox_report": None,
            "error": None
        }
        
        # 计算哈希
        hashes = self.get_file_hash(file_content)
        
        # 先查询 VirusTotal 已知哈希
        vt_report = self.query_virustotal_hash(hashes["sha256"])
        
        if vt_report:
            result["analysis_type"] = "hash_lookup"
            result["scanner_count"] = vt_report.get("total", 0)
            result["malicious_scanners"] = vt_report.get("positives", 0)
            result["detection_ratio"] = vt_report.get("positives", 0) / vt_report.get("total", 1)
            result["detected"] = vt_report.get("positives", 0) > 0
            result["sandbox_report"] = vt_report
            return result
        
        # 如果哈希未找到，上传文件进行分析
        scan_response = self.scan_file_virustotal(file_content, filename)
        
        if scan_response and scan_response.get("response_code") == 1:
            scan_id = scan_response.get("scan_id")
            if scan_id:
                # 等待并获取报告
                vt_report = self.get_virustotal_report(scan_id)
                if vt_report:
                    result["analysis_type"] = "file_scan"
                    result["scanner_count"] = vt_report.get("total", 0)
                    result["malicious_scanners"] = vt_report.get("positives", 0)
                    result["detection_ratio"] = vt_report.get("positives", 0) / vt_report.get("total", 1)
                    result["detected"] = vt_report.get("positives", 0) > 0
                    result["sandbox_report"] = vt_report
                    return result
        
        return result
    
    def should_analyze(self, filename: str, content_type: str, file_size: int) -> bool:
        """
        判断是否应该进行沙箱分析
        
        Args:
            filename: 文件名
            content_type: 内容类型
            file_size: 文件大小（字节）
            
        Returns:
            是否应该进行分析
        """
        # 文件大小限制：>10MB 跳过
        if file_size > 10 * 1024 * 1024:
            return False
        
        # 纯图片/纯文本跳过
        image_extensions = [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff"]
        text_extensions = [".txt", ".csv", ".log"]
        
        ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        
        if ext in image_extensions or ext in text_extensions:
            return False
        
        # 需要分析的高风险文件类型
        high_risk_extensions = [
            ".exe", ".bat", ".cmd", ".com", ".scr", ".vbs", ".vbe",
            ".js", ".jse", ".wsf", ".wsh", ".ps1", ".msi", ".msp", ".hta",
            ".cpl", ".msc", ".jar", ".dll", ".reg", ".lnk",
            ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm", ".ppam", ".sldm",
            ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz"
        ]
        
        if ext in high_risk_extensions:
            return True
        
        # 无扩展名的二进制文件
        if not ext and content_type.startswith("application/"):
            return True
        
        return False


def analyze_attachment(attachment: Dict, vt_api_key: str = "") -> Dict:
    """
    分析单个附件
    
    Args:
        attachment: 附件信息字典
        vt_api_key: VirusTotal API 密钥
        
    Returns:
        分析结果字典
    """
    analyzer = SandboxAnalyzer(vt_api_key=vt_api_key)
    
    # 检查是否需要分析
    filename = attachment.get("filename", "")
    content_type = attachment.get("content_type", "")
    file_size = attachment.get("size", 0)
    
    if not analyzer.should_analyze(filename, content_type, file_size):
        return {
            "analyzed": False,
            "reason": "low_risk",
            "result": None
        }
    
    # 获取文件内容（如果有）
    file_content = attachment.get("content")
    if not file_content:
        return {
            "analyzed": False,
            "reason": "no_content",
            "result": None
        }
    
    # 进行分析
    try:
        result = analyzer.analyze_file(file_content, filename, content_type)
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


if __name__ == "__main__":
    # 测试示例
    test_content = b"# Test file"
    test_attachment = {
        "filename": "test.js",
        "content_type": "application/javascript",
        "size": len(test_content),
        "content": test_content
    }
    
    # 注意：需要设置有效的 API 密钥才能测试
    result = analyze_attachment(test_attachment, vt_api_key="")
    print("沙箱分析结果:")
    print(result)

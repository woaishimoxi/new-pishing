#!/usr/bin/env python3
"""
性能监控模块
记录系统运行指标，生成性能报告
"""
import os
import json
import time
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from functools import wraps
import statistics
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core import get_logger


class PerformanceMonitor:
    """
    性能监控器
    记录检测响应时间、溯源耗时等指标
    """
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.metrics_file = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            'data', 'performance_metrics.json'
        )
        self.metrics = self._load_metrics()
    
    def _load_metrics(self) -> Dict:
        """加载历史性能指标"""
        if os.path.exists(self.metrics_file):
            try:
                with open(self.metrics_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.warning(f"加载性能指标失败: {e}")
        
        return {
            'detection_times': [],
            'traceback_times': [],
            'total_detections': 0,
            'successful_detections': 0,
            'failed_detections': 0,
            'phishing_detected': 0,
            'safe_detected': 0,
            'suspicious_detected': 0,
            'daily_stats': {},
            'last_updated': None
        }
    
    def _save_metrics(self):
        """保存性能指标"""
        try:
            os.makedirs(os.path.dirname(self.metrics_file), exist_ok=True)
            with open(self.metrics_file, 'w', encoding='utf-8') as f:
                json.dump(self.metrics, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.error(f"保存性能指标失败: {e}")
    
    def record_detection(self, detection_time: float, label: str, success: bool = True):
        """
        记录一次检测
        
        Args:
            detection_time: 检测耗时（秒）
            label: 检测结果标签
            success: 是否成功
        """
        self.metrics['detection_times'].append({
            'time': detection_time,
            'timestamp': datetime.now().isoformat(),
            'label': label,
            'success': success
        })
        
        # 只保留最近1000条记录
        if len(self.metrics['detection_times']) > 1000:
            self.metrics['detection_times'] = self.metrics['detection_times'][-1000:]
        
        self.metrics['total_detections'] += 1
        
        if success:
            self.metrics['successful_detections'] += 1
            if label == 'PHISHING':
                self.metrics['phishing_detected'] += 1
            elif label == 'SAFE':
                self.metrics['safe_detected'] += 1
            elif label == 'SUSPICIOUS':
                self.metrics['suspicious_detected'] += 1
        else:
            self.metrics['failed_detections'] += 1
        
        # 更新每日统计
        today = datetime.now().strftime('%Y-%m-%d')
        if today not in self.metrics['daily_stats']:
            self.metrics['daily_stats'][today] = {
                'total': 0,
                'phishing': 0,
                'safe': 0,
                'suspicious': 0,
                'avg_time': 0
            }
        
        daily = self.metrics['daily_stats'][today]
        daily['total'] += 1
        if label == 'PHISHING':
            daily['phishing'] += 1
        elif label == 'SAFE':
            daily['safe'] += 1
        elif label == 'SUSPICIOUS':
            daily['suspicious'] += 1
        
        self.metrics['last_updated'] = datetime.now().isoformat()
        self._save_metrics()
    
    def record_traceback(self, traceback_time: float, success: bool = True):
        """
        记录一次溯源
        
        Args:
            traceback_time: 溯源耗时（秒）
            success: 是否成功
        """
        self.metrics['traceback_times'].append({
            'time': traceback_time,
            'timestamp': datetime.now().isoformat(),
            'success': success
        })
        
        # 只保留最近500条记录
        if len(self.metrics['traceback_times']) > 500:
            self.metrics['traceback_times'] = self.metrics['traceback_times'][-500:]
        
        self.metrics['last_updated'] = datetime.now().isoformat()
        self._save_metrics()
    
    def get_performance_summary(self) -> Dict:
        """
        获取性能摘要
        
        Returns:
            性能指标摘要
        """
        detection_times = [d['time'] for d in self.metrics['detection_times'] if d['success']]
        traceback_times = [t['time'] for t in self.metrics['traceback_times'] if t['success']]
        
        summary = {
            'total_detections': self.metrics['total_detections'],
            'successful_detections': self.metrics['successful_detections'],
            'failed_detections': self.metrics['failed_detections'],
            'success_rate': 0,
            
            'phishing_detected': self.metrics['phishing_detected'],
            'safe_detected': self.metrics['safe_detected'],
            'suspicious_detected': self.metrics['suspicious_detected'],
            
            'detection_time': {
                'avg': 0,
                'min': 0,
                'max': 0,
                'median': 0,
                'p95': 0
            },
            
            'traceback_time': {
                'avg': 0,
                'min': 0,
                'max': 0,
                'median': 0,
                'p95': 0
            },
            
            'last_updated': self.metrics['last_updated']
        }
        
        # 计算成功率
        if self.metrics['total_detections'] > 0:
            summary['success_rate'] = self.metrics['successful_detections'] / self.metrics['total_detections']
        
        # 检测时间统计
        if detection_times:
            summary['detection_time']['avg'] = statistics.mean(detection_times)
            summary['detection_time']['min'] = min(detection_times)
            summary['detection_time']['max'] = max(detection_times)
            summary['detection_time']['median'] = statistics.median(detection_times)
            sorted_times = sorted(detection_times)
            p95_index = int(len(sorted_times) * 0.95)
            summary['detection_time']['p95'] = sorted_times[p95_index] if p95_index < len(sorted_times) else sorted_times[-1]
        
        # 溯源时间统计
        if traceback_times:
            summary['traceback_time']['avg'] = statistics.mean(traceback_times)
            summary['traceback_time']['min'] = min(traceback_times)
            summary['traceback_time']['max'] = max(traceback_times)
            summary['traceback_time']['median'] = statistics.median(traceback_times)
            sorted_times = sorted(traceback_times)
            p95_index = int(len(sorted_times) * 0.95)
            summary['traceback_time']['p95'] = sorted_times[p95_index] if p95_index < len(sorted_times) else sorted_times[-1]
        
        return summary
    
    def get_daily_stats(self, days: int = 7) -> List[Dict]:
        """
        获取每日统计数据
        
        Args:
            days: 天数
            
        Returns:
            每日统计列表
        """
        daily_stats = []
        
        for i in range(days):
            date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
            stats = self.metrics['daily_stats'].get(date, {
                'total': 0,
                'phishing': 0,
                'safe': 0,
                'suspicious': 0
            })
            stats['date'] = date
            daily_stats.append(stats)
        
        return list(reversed(daily_stats))
    
    def generate_report(self) -> str:
        """
        生成性能报告
        
        Returns:
            报告内容（Markdown格式）
        """
        summary = self.get_performance_summary()
        daily_stats = self.get_daily_stats(7)
        
        report = f"""# 系统性能测试报告

生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## 一、总体统计

| 指标 | 数值 |
|------|------|
| 总检测次数 | {summary['total_detections']} |
| 成功次数 | {summary['successful_detections']} |
| 失败次数 | {summary['failed_detections']} |
| 成功率 | {summary['success_rate']*100:.2f}% |

## 二、检测结果分布

| 类型 | 数量 | 占比 |
|------|------|------|
| 钓鱼邮件 | {summary['phishing_detected']} | {summary['phishing_detected']/max(summary['total_detections'],1)*100:.1f}% |
| 安全邮件 | {summary['safe_detected']} | {summary['safe_detected']/max(summary['total_detections'],1)*100:.1f}% |
| 可疑邮件 | {summary['suspicious_detected']} | {summary['suspicious_detected']/max(summary['total_detections'],1)*100:.1f}% |

## 三、响应时间分析

### 检测响应时间
| 指标 | 数值 |
|------|------|
| 平均耗时 | {summary['detection_time']['avg']*1000:.2f} ms |
| 最短耗时 | {summary['detection_time']['min']*1000:.2f} ms |
| 最长耗时 | {summary['detection_time']['max']*1000:.2f} ms |
| 中位数 | {summary['detection_time']['median']*1000:.2f} ms |
| P95 | {summary['detection_time']['p95']*1000:.2f} ms |

### 溯源耗时
| 指标 | 数值 |
|------|------|
| 平均耗时 | {summary['traceback_time']['avg']*1000:.2f} ms |
| 最短耗时 | {summary['traceback_time']['min']*1000:.2f} ms |
| 最长耗时 | {summary['traceback_time']['max']*1000:.2f} ms |

## 四、近7天检测趋势

| 日期 | 总数 | 钓鱼 | 安全 | 可疑 |
|------|------|------|------|------|
"""
        
        for day in daily_stats:
            report += f"| {day['date']} | {day['total']} | {day['phishing']} | {day['safe']} | {day['suspicious']} |\n"
        
        report += f"""
## 五、性能评估结论

1. **响应时间**: 平均检测耗时 {summary['detection_time']['avg']*1000:.2f}ms，满足实时检测需求
2. **系统稳定性**: 成功率 {summary['success_rate']*100:.2f}%，系统运行稳定
3. **检测能力**: 共检测到钓鱼邮件 {summary['phishing_detected']} 封，有效防护率良好

---
*报告由系统自动生成*
"""
        
        return report
    
    def export_report(self, filepath: str = None) -> str:
        """
        导出报告到文件
        
        Args:
            filepath: 文件路径
            
        Returns:
            文件路径
        """
        if not filepath:
            filepath = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                'data', f'performance_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.md'
            )
        
        report = self.generate_report()
        
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report)
        
        self.logger.info(f"性能报告已导出: {filepath}")
        return filepath


# 装饰器：自动记录函数执行时间
def record_execution_time(metric_type: str = 'detection'):
    """
    装饰器：记录函数执行时间
    
    Args:
        metric_type: 指标类型 ('detection' 或 'traceback')
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            success = True
            result = None
            
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                success = False
                raise e
            finally:
                elapsed_time = time.time() - start_time
                
                if metric_type == 'detection':
                    label = 'UNKNOWN'
                    if result and isinstance(result, tuple) and len(result) >= 1:
                        label = result[0]
                    monitor.record_detection(elapsed_time, label, success)
                elif metric_type == 'traceback':
                    monitor.record_traceback(elapsed_time, success)
        
        return wrapper
    return decorator


# 创建全局实例
monitor = PerformanceMonitor()

"""
API Documentation Module
Flask-RESTX based Swagger documentation
"""
from flask import Blueprint
from flask_restx import Api, Resource, fields

api_docs = Blueprint('api_docs', __name__, url_prefix='/api-docs')

api = Api(
    api_docs,
    version='2.0.0',
    title='钓鱼邮件检测与溯源系统 API',
    description='''
## 概述

企业级钓鱼邮件检测系统RESTful API文档。本系统提供以下核心功能：

- **邮件检测**: 分析原始邮件内容，识别钓鱼邮件
- **溯源分析**: 追踪邮件来源，分析风险指标
- **告警管理**: 管理检测结果和历史记录
- **系统配置**: 配置API密钥和邮箱服务器

## 基础URL

```
http://localhost:5000/api
```

## 认证

当前版本无需认证，后续版本将支持Bearer Token认证。

## 响应格式

所有API响应均为JSON格式，包含以下通用字段：

| 字段 | 类型 | 说明 |
|------|------|------|
| status | string | 请求状态 (success/error) |
| message | string | 状态消息 |
| data | object | 响应数据 |

## HTTP状态码

| 状态码 | 说明 |
|--------|------|
| 200 | 请求成功 |
| 201 | 资源创建成功 |
| 400 | 请求参数错误 |
| 404 | 资源不存在 |
| 500 | 服务器内部错误 |

## 错误响应格式

```json
{
    "error": "ERROR_CODE",
    "message": "错误描述信息",
    "details": {}
}
```

## 判定结果说明

| 标签 | 置信度范围 | 说明 |
|------|-----------|------|
| PHISHING | >= 70% | 钓鱼邮件，高风险 |
| SUSPICIOUS | 40% - 70% | 可疑邮件，中等风险 |
| SAFE | < 40% | 正常邮件，低风险 |
    ''',
    doc='/',
    authorizations={
        'Bearer': {
            'type': 'apiKey',
            'in': 'header',
            'name': 'Authorization'
        }
    }
)

ns_detection = api.namespace('detection', description='邮件检测相关接口')
ns_alerts = api.namespace('alerts', description='告警管理相关接口')
ns_config = api.namespace('config', description='系统配置相关接口')
ns_stats = api.namespace('stats', description='统计分析相关接口')
ns_email = api.namespace('email', description='邮件收取相关接口')


email_content_model = api.model('EmailContent', {
    'email': fields.String(
        required=True, 
        description='原始邮件内容（RFC822格式），包含完整的邮件头和邮件体',
        example='From: sender@example.com\nTo: recipient@example.com\nSubject: Urgent: Verify Your Account\nContent-Type: text/plain\n\nDear User, Please click the link to verify your account.'
    ),
    'source': fields.String(
        required=False, 
        description='来源标识，用于标记邮件来源渠道',
        default='手动输入',
        example='手动输入'
    ),
    'email_uid': fields.String(
        required=False, 
        description='邮件唯一标识符，用于防止重复检测（IMAP UID或自定义ID）',
        example='ABC123'
    )
})

parsed_email_model = api.model('ParsedEmail', {
    'from': fields.String(description='发件人原始地址', example='"Bank Security" <security@bank-verify.com>'),
    'from_display_name': fields.String(description='发件人显示名称', example='Bank Security'),
    'from_email': fields.String(description='发件人邮箱地址', example='security@bank-verify.com'),
    'to': fields.String(description='收件人地址', example='user@example.com'),
    'subject': fields.String(description='邮件主题', example='Urgent: Verify Your Account'),
    'body': fields.String(description='纯文本邮件正文'),
    'html_body': fields.String(description='HTML格式邮件正文'),
    'urls': fields.List(fields.String, description='邮件中提取的URL列表'),
    'url_count': fields.Integer(description='URL数量', example=3),
    'attachment_count': fields.Integer(description='附件数量', example=1),
    'has_html_body': fields.Integer(description='是否包含HTML正文 (0/1)', example=1)
})

module_scores_model = api.model('ModuleScores', {
    'header': fields.Float(description='邮件头分析评分 (0-1)', example=0.6),
    'url': fields.Float(description='URL风险分析评分 (0-1)', example=0.8),
    'text': fields.Float(description='文本内容分析评分 (0-1)', example=0.4),
    'attachment': fields.Float(description='附件风险分析评分 (0-1)', example=0.0),
    'html': fields.Float(description='HTML结构分析评分 (0-1)', example=0.5)
})

traceback_model = api.model('TracebackReport', {
    'source_ip': fields.String(description='源IP地址', example='192.168.1.100'),
    'source_domain': fields.String(description='源域名', example='mail.bank-verify.com'),
    'geo_location': fields.String(description='地理位置', example='United States'),
    'isp': fields.String(description='ISP信息', example='CloudFlare Inc.'),
    'hops': fields.List(fields.Raw, description='邮件路由跳转信息'),
    'authentication_results': fields.Raw(description='认证结果 (SPF/DKIM/DMARC)')
})

url_analysis_model = api.model('URLAnalysis', {
    'total_urls': fields.Integer(description='URL总数', example=3),
    'suspicious_urls': fields.Integer(description='可疑URL数', example=2),
    'ip_urls': fields.Integer(description='IP地址形式URL数', example=1),
    'shortened_urls': fields.Integer(description='短链接数', example=0),
    'details': fields.List(fields.Raw, description='各URL详细分析')
})

sandbox_analysis_model = api.model('SandboxAnalysis', {
    'enabled': fields.Boolean(description='沙箱分析是否启用', example=True),
    'has_sandbox_analysis': fields.Boolean(description='是否有沙箱分析结果', example=True),
    'sandbox_detected': fields.Boolean(description='沙箱是否检测到威胁', example=True),
    'max_detection_ratio': fields.Float(description='最大检测率 (0-1)', example=0.75)
})

detection_result_model = api.model('DetectionResult', {
    'id': fields.Integer(description='告警ID，用于后续查询详情', example=1),
    'label': fields.String(
        description='判定结果', 
        enum=['PHISHING', 'SUSPICIOUS', 'SAFE'], 
        example='PHISHING'
    ),
    'confidence': fields.Float(
        description='置信度，范围0-1，值越高表示越可能是钓鱼邮件', 
        example=0.92
    ),
    'reason': fields.String(
        description='判定原因的详细说明', 
        example='邮件认证失败；包含可疑链接；发件人域名与显示名称不匹配'
    ),
    'module_scores': fields.Nested(module_scores_model, description='各模块评分详情'),
    'parsed': fields.Nested(parsed_email_model, description='解析后的邮件信息'),
    'features': fields.Raw(description='提取的特征向量（用于机器学习）'),
    'attachments': fields.List(fields.Raw, description='附件信息列表'),
    'html_links': fields.List(fields.Raw, description='HTML中的链接信息'),
    'html_forms': fields.List(fields.Raw, description='HTML中的表单信息'),
    'headers': fields.Raw(description='原始邮件头信息'),
    'traceback': fields.Nested(traceback_model, description='溯源分析报告'),
    'url_analysis': fields.Nested(url_analysis_model, description='URL分析结果'),
    'sandbox_analysis': fields.Nested(sandbox_analysis_model, description='沙箱分析结果')
})

alert_brief_model = api.model('AlertBrief', {
    'id': fields.Integer(description='告警ID', example=1),
    'from_addr': fields.String(description='发件人地址', example='"Bank Security" <security@bank-verify.com>'),
    'from_email': fields.String(description='发件人邮箱', example='security@bank-verify.com'),
    'to_addr': fields.String(description='收件人地址', example='user@example.com'),
    'subject': fields.String(description='邮件主题', example='Urgent: Verify Your Account'),
    'detection_time': fields.String(description='检测时间 (ISO 8601格式)', example='2024-01-15T10:30:00'),
    'label': fields.String(description='判定结果', enum=['PHISHING', 'SUSPICIOUS', 'SAFE'], example='PHISHING'),
    'confidence': fields.Float(description='置信度', example=0.92),
    'source_ip': fields.String(description='源IP地址', example='192.168.1.100'),
    'source': fields.String(description='来源', example='手动输入'),
    'risk_indicators': fields.List(fields.String, description='风险指标列表')
})

pagination_model = api.model('Pagination', {
    'alerts': fields.List(fields.Nested(alert_brief_model), description='告警列表'),
    'total': fields.Integer(description='总记录数', example=100),
    'page': fields.Integer(description='当前页码', example=1),
    'per_page': fields.Integer(description='每页数量', example=20),
    'total_pages': fields.Integer(description='总页数', example=5)
})

stats_model = api.model('Statistics', {
    'total': fields.Integer(description='总检测数', example=1000),
    'phishing': fields.Integer(description='钓鱼邮件数', example=150),
    'suspicious': fields.Integer(description='可疑邮件数', example=250),
    'normal': fields.Integer(description='正常邮件数', example=600),
    'today': fields.Integer(description='今日新增数', example=25),
    'trend': fields.List(fields.Raw, description='趋势数据（按日期统计）')
})

daily_stats_model = api.model('DailyStats', {
    'day': fields.String(description='日期', example='2024-01-15'),
    'total': fields.Integer(description='当日总检测数', example=25),
    'phishing': fields.Integer(description='当日钓鱼邮件数', example=5),
    'suspicious': fields.Integer(description='当日可疑邮件数', example=8),
    'normal': fields.Integer(description='当日正常邮件数', example=12)
})

virustotal_config_model = api.model('VirusTotalConfig', {
    'api_key': fields.String(description='VirusTotal API密钥', example='your-api-key-here'),
    'api_url': fields.String(description='VirusTotal API地址', example='https://www.virustotal.com/vtapi/v2/url/report')
})

ipapi_config_model = api.model('IPApiConfig', {
    'api_url': fields.String(description='IP查询API地址', example='http://ip-api.com/json/')
})

email_config_model = api.model('EmailConfig', {
    'email': fields.String(description='邮箱地址', example='monitor@example.com'),
    'password': fields.String(description='邮箱密码或应用专用密码', example='your-password'),
    'server': fields.String(description='邮件服务器地址', example='imap.example.com'),
    'protocol': fields.String(description='协议类型', enum=['imap', 'pop3'], example='imap'),
    'port': fields.Integer(description='端口号', example=993),
    'enabled': fields.Boolean(description='是否启用自动收取', example=True)
})

config_model = api.model('Config', {
    'virustotal': fields.Nested(virustotal_config_model, description='VirusTotal API配置'),
    'ipapi': fields.Nested(ipapi_config_model, description='IP API配置'),
    'email': fields.Nested(email_config_model, description='邮箱服务器配置')
})

error_model = api.model('Error', {
    'error': fields.String(description='错误代码', example='VALIDATION_ERROR'),
    'message': fields.String(description='错误信息', example='Invalid email format'),
    'details': fields.Raw(description='详细信息')
})

health_model = api.model('Health', {
    'status': fields.String(description='服务状态', example='healthy'),
    'service': fields.String(description='服务名称', example='Phishing Detection System'),
    'version': fields.String(description='版本号', example='2.0.0')
})

success_model = api.model('Success', {
    'status': fields.String(description='状态', example='success'),
    'message': fields.String(description='消息', example='操作成功')
})

batch_delete_model = api.model('BatchDelete', {
    'ids': fields.List(fields.Integer, description='要删除的告警ID列表', example=[1, 2, 3])
})

batch_delete_result_model = api.model('BatchDeleteResult', {
    'status': fields.String(description='状态', example='success'),
    'message': fields.String(description='消息', example='成功删除 3 条报告'),
    'deleted_count': fields.Integer(description='删除数量', example=3)
})

email_fetch_result_model = api.model('EmailFetchResult', {
    'status': fields.String(description='状态', example='success'),
    'message': fields.String(description='消息', example='成功获取 5 封新邮件'),
    'emails': fields.List(fields.Raw, description='新邮件列表')
})

attachment_model = api.model('Attachment', {
    'filename': fields.String(description='文件名', example='document.pdf'),
    'content_type': fields.String(description='MIME类型', example='application/pdf'),
    'size': fields.Integer(description='文件大小（字节）', example=102400),
    'hash': fields.String(description='文件哈希值', example='abc123...'),
    'is_suspicious': fields.Boolean(description='是否可疑', example=False)
})


@ns_detection.route('/health')
class HealthCheck(Resource):
    @ns_detection.doc('health_check')
    @ns_detection.marshal_with(health_model)
    def get(self):
        """
        健康检查接口
        
        检查服务是否正常运行，用于监控系统健康状态。
        
        **使用场景：**
        - 负载均衡器健康检查
        - 监控系统探测
        - 服务启动确认
        """
        return {
            'status': 'healthy',
            'service': 'Phishing Detection System',
            'version': '2.0.0'
        }


@ns_detection.route('/analyze')
class AnalyzeEmail(Resource):
    @ns_detection.doc('analyze_email')
    @ns_detection.expect(email_content_model)
    @ns_detection.response(200, '分析成功', detection_result_model)
    @ns_detection.response(400, '请求参数错误', error_model)
    @ns_detection.response(500, '服务器内部错误', error_model)
    def post(self):
        """
        分析邮件内容
        
        接收原始邮件内容，进行钓鱼邮件检测分析，返回详细的检测结果。
        
        **请求参数说明：**
        
        | 参数 | 类型 | 必填 | 说明 |
        |------|------|------|------|
        | email | string | 是 | 原始邮件内容，RFC822格式 |
        | source | string | 否 | 来源标识，默认"手动输入" |
        | email_uid | string | 否 | 邮件唯一标识，用于去重 |
        
        **返回字段说明：**
        
        - `label`: 判定结果
          - **PHISHING**: 钓鱼邮件（置信度 >= 70%）
          - **SUSPICIOUS**: 可疑邮件（40% <= 置信度 < 70%）
          - **SAFE**: 正常邮件（置信度 < 40%）
        - `confidence`: 置信度，范围0-1
        - `reason`: 判定原因说明
        - `module_scores`: 各模块评分
          - `header`: 邮件头分析（SPF/DKIM/DMARC验证）
          - `url`: URL风险分析（可疑链接检测）
          - `text`: 文本内容分析（紧急词汇、财务词汇）
          - `attachment`: 附件风险分析
          - `html`: HTML结构分析（隐藏链接、表单）
        
        **请求示例：**
        ```json
        {
            "email": "From: sender@example.com\\nTo: user@example.com\\nSubject: Test\\n\\nBody",
            "source": "手动输入"
        }
        ```
        """
        pass


@ns_detection.route('/upload')
class UploadEmail(Resource):
    @ns_detection.doc('upload_email')
    @ns_detection.response(200, '上传成功', detection_result_model)
    @ns_detection.response(400, '请求参数错误', error_model)
    @ns_detection.response(500, '服务器内部错误', error_model)
    def post(self):
        """
        上传邮件文件进行分析
        
        通过文件上传方式提交邮件进行分析。
        
        **支持的文件格式：**
        - `.eml`: 标准邮件格式（推荐）
        - `.msg`: Outlook邮件格式
        
        **请求格式：**
        - Content-Type: `multipart/form-data`
        - 文件字段名: `file`
        
        **使用示例 (curl)：**
        ```bash
        curl -X POST "http://localhost:5000/api/detection/upload" \\
             -F "file=@suspicious_email.eml"
        ```
        
        **注意事项：**
        - 文件大小限制：10MB
        - 上传后文件会被自动删除
        - 支持UTF-8和GBK编码
        """
        pass


@ns_alerts.route('')
class AlertList(Resource):
    @ns_alerts.doc('list_alerts')
    @ns_alerts.param('page', '页码，从1开始', type=int, default=1, _in='query')
    @ns_alerts.param('per_page', '每页数量，范围1-100', type=int, default=20, _in='query')
    @ns_alerts.param('label', '按判定结果筛选', enum=['PHISHING', 'SUSPICIOUS', 'SAFE'], _in='query')
    @ns_alerts.response(200, '成功', pagination_model)
    def get(self):
        """
        获取告警列表
        
        分页获取告警记录列表，支持按判定结果筛选。
        
        **查询参数：**
        
        | 参数 | 类型 | 默认值 | 说明 |
        |------|------|--------|------|
        | page | int | 1 | 页码，从1开始 |
        | per_page | int | 20 | 每页数量，最大100 |
        | label | string | - | 筛选标签 |
        
        **筛选标签说明：**
        - `PHISHING`: 仅显示钓鱼邮件
        - `SUSPICIOUS`: 仅显示可疑邮件
        - `SAFE`: 仅显示正常邮件
        - 不传此参数则显示全部
        
        **请求示例：**
        ```
        GET /api/alerts?page=1&per_page=20&label=PHISHING
        ```
        """
        pass


@ns_alerts.route('/<int:alert_id>')
class AlertDetail(Resource):
    @ns_alerts.doc('get_alert')
    @ns_alerts.param('alert_id', '告警ID', type=int, required=True)
    @ns_alerts.response(200, '成功', detection_result_model)
    @ns_alerts.response(404, '告警不存在', error_model)
    def get(self, alert_id):
        """
        获取告警详情
        
        获取单个告警的完整详细信息，包括：
        - 邮件基本信息（发件人、收件人、主题等）
        - 检测结果（判定、置信度、原因）
        - 特征分析（各模块评分）
        - 溯源信息（IP地理位置、路由跳转）
        - URL分析（可疑链接详情）
        - 附件分析（文件哈希、风险等级）
        - 原始邮件头
        
        **请求示例：**
        ```
        GET /api/alerts/123
        ```
        """
        pass
    
    @ns_alerts.doc('delete_alert')
    @ns_alerts.param('alert_id', '告警ID', type=int, required=True)
    @ns_alerts.response(200, '删除成功', success_model)
    @ns_alerts.response(404, '告警不存在', error_model)
    def delete(self, alert_id):
        """
        删除单个告警
        
        删除指定的告警记录。删除后无法恢复。
        
        **请求示例：**
        ```
        DELETE /api/alerts/123
        ```
        
        **返回示例：**
        ```json
        {
            "status": "success",
            "message": "报告已删除"
        }
        ```
        """
        pass


@ns_alerts.route('/batch')
class AlertBatch(Resource):
    @ns_alerts.doc('batch_delete_alerts')
    @ns_alerts.expect(batch_delete_model)
    @ns_alerts.response(200, '删除成功', batch_delete_result_model)
    @ns_alerts.response(400, '请求参数错误', error_model)
    def delete(self):
        """
        批量删除告警
        
        批量删除多个告警记录。
        
        **请求参数：**
        
        | 参数 | 类型 | 必填 | 说明 |
        |------|------|------|------|
        | ids | array | 是 | 要删除的告警ID数组 |
        
        **请求示例：**
        ```json
        {
            "ids": [1, 2, 3, 4, 5]
        }
        ```
        
        **返回示例：**
        ```json
        {
            "status": "success",
            "message": "成功删除 5 条报告",
            "deleted_count": 5
        }
        ```
        """
        pass


@ns_stats.route('/overview')
class StatsOverview(Resource):
    @ns_stats.doc('stats_overview')
    @ns_stats.response(200, '成功', stats_model)
    def get(self):
        """
        获取统计概览
        
        获取系统检测统计概览数据，用于仪表盘展示。
        
        **返回数据说明：**
        
        | 字段 | 说明 |
        |------|------|
        | total | 历史总检测数 |
        | phishing | 钓鱼邮件总数 |
        | suspicious | 可疑邮件总数 |
        | normal | 正常邮件总数 |
        | today | 今日新增检测数 |
        | trend | 近7天趋势数据 |
        
        **趋势数据格式：**
        ```json
        {
            "trend": [
                {"day": "2024-01-15", "count": 25, "phish_count": 5, "suspicious_count": 8, "safe_count": 12},
                ...
            ]
        }
        ```
        """
        pass


@ns_stats.route('/daily')
class StatsDaily(Resource):
    @ns_stats.doc('stats_daily')
    @ns_stats.param('days', '统计天数，范围1-30', type=int, default=7, _in='query')
    @ns_stats.response(200, '成功', fields.List(fields.Nested(daily_stats_model)))
    def get(self):
        """
        获取每日统计
        
        获取每日检测统计数据，用于趋势图表展示。
        
        **查询参数：**
        
        | 参数 | 类型 | 默认值 | 说明 |
        |------|------|--------|------|
        | days | int | 7 | 统计天数，最大30 |
        
        **返回示例：**
        ```json
        [
            {
                "day": "2024-01-15",
                "total": 25,
                "phishing": 5,
                "suspicious": 8,
                "normal": 12
            },
            ...
        ]
        ```
        """
        pass


@ns_config.route('')
class ConfigManagement(Resource):
    @ns_config.doc('get_config')
    @ns_config.response(200, '成功', config_model)
    def get(self):
        """
        获取系统配置
        
        获取当前系统所有配置信息，包括：
        - VirusTotal API配置（用于URL安全检测）
        - IP API配置（用于IP地理位置查询）
        - 邮箱服务器配置（用于自动收取邮件）
        
        **注意事项：**
        - 敏感信息（如密码）会部分隐藏显示
        - 用于配置页面的初始化
        """
        pass
    
    @ns_config.doc('update_config')
    @ns_config.expect(config_model)
    @ns_config.response(200, '更新成功', success_model)
    @ns_config.response(500, '更新失败', error_model)
    def post(self):
        """
        更新系统配置
        
        更新系统配置信息，配置会持久化保存到配置文件。
        
        **可更新的配置项：**
        
        **VirusTotal配置：**
        | 字段 | 说明 |
        |------|------|
        | api_key | VirusTotal API密钥 |
        | api_url | API地址（可选） |
        
        **邮箱配置：**
        | 字段 | 说明 |
        |------|------|
        | email | 邮箱地址 |
        | password | 邮箱密码或应用专用密码 |
        | server | 邮件服务器地址 |
        | protocol | 协议类型（imap/pop3） |
        | port | 端口号 |
        | enabled | 是否启用自动收取 |
        
        **请求示例：**
        ```json
        {
            "virustotal": {
                "api_key": "your-api-key"
            },
            "email": {
                "email": "monitor@example.com",
                "password": "your-password",
                "server": "imap.example.com",
                "protocol": "imap",
                "port": 993,
                "enabled": true
            }
        }
        ```
        """
        pass


@ns_config.route('/test')
class ConfigTest(Resource):
    @ns_config.doc('test_virustotal')
    @ns_config.response(200, '连接成功', success_model)
    @ns_config.response(400, '连接失败', error_model)
    def get(self):
        """
        测试VirusTotal API连接
        
        测试VirusTotal API配置是否正确可用。
        
        **测试方法：**
        使用配置的API密钥查询一个已知URL的安全状态。
        
        **返回说明：**
        - 成功：返回 `{"status": "success", "message": "VirusTotal API 连接成功"}`
        - 失败：返回错误原因（如API密钥无效、网络问题等）
        
        **使用场景：**
        - 配置保存前的验证
        - 故障排查
        """
        pass


@ns_config.route('/test-email')
class ConfigTestEmail(Resource):
    @ns_config.doc('test_email')
    @ns_config.response(200, '连接成功', success_model)
    @ns_config.response(400, '连接失败', error_model)
    def get(self):
        """
        测试邮箱服务器连接
        
        测试邮箱服务器配置是否正确可用。
        
        **前置条件：**
        - 需要先配置邮箱地址、密码、服务器
        - 邮箱需要开启IMAP/POP3服务
        
        **测试内容：**
        - 服务器连接性
        - 账号认证
        - 协议兼容性
        
        **常见错误：**
        - "邮箱配置不完整"：缺少必要配置项
        - "连接失败"：服务器地址或端口错误
        - "认证失败"：密码错误或未开启应用专用密码
        """
        pass


@ns_email.route('/fetch')
class EmailFetch(Resource):
    @ns_email.doc('fetch_emails')
    @ns_email.response(200, '获取成功', email_fetch_result_model)
    @ns_email.response(400, '配置不完整', error_model)
    @ns_email.response(500, '获取失败', error_model)
    def post(self):
        """
        从邮箱服务器收取新邮件
        
        从配置的邮箱服务器收取新邮件并返回邮件列表。
        收取的邮件需要手动调用分析接口进行检测。
        
        **前置条件：**
        - 需要先在配置页面设置邮箱服务器信息
        - 邮箱需要开启IMAP/POP3服务
        - 建议先调用 `/api/config/test-email` 测试连接
        
        **收取规则：**
        - 默认只收取未读邮件
        - 每次最多收取10封
        - 自动去重（基于邮件哈希和UID）
        - 已收取的邮件会被标记为已读
        
        **返回数据说明：**
        
        | 字段 | 说明 |
        |------|------|
        | status | 状态（success/error） |
        | message | 状态消息 |
        | emails | 新邮件列表 |
        
        **邮件对象格式：**
        ```json
        {
            "uid": "123",
            "subject": "邮件主题",
            "from": "sender@example.com",
            "date": "2024-01-15T10:30:00",
            "raw": "原始邮件内容（RFC822格式）",
            "hash": "邮件哈希值"
        }
        ```
        
        **后续操作：**
        收取的邮件可以调用 `/api/detection/analyze` 接口进行分析：
        ```json
        {
            "email": "<raw内容>",
            "email_uid": "<uid>",
            "source": "自动收取"
        }
        ```
        """
        pass

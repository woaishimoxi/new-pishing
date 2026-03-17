# 项目更新日志

## 2026-02-26

### 新增功能
1. **邮件文件上传** - 支持 .eml/.msg 格式文件拖拽上传
2. **邮件详情页** - 点击查看原始邮件的完整内容细节
3. **日志优化** - 静默处理网络错误，提升用户体验

### 修复问题
- parse_email.py: from_addr → from_raw
- email_traceback.py: 添加 time 模块导入
- features.py/email_traceback.py: whois API 兼容性修复
- 数据库表结构重新初始化

---

*更多详细记录请查看 progress/updates/CHANGELOG.md*

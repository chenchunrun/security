# 🔒 Security Alert Triage System

基于LangChain的智能安全告警研判系统原型

**✨ 现已支持通义千问(Qwen)、OpenAI等多种LLM！**

## 🎯 功能特性

- ✅ 智能告警解析和路由
- ✅ 多维度风险评估（基于CVSS）
- ✅ 威胁情报关联查询
- ✅ 上下文信息收集
- ✅ 自动生成处置建议
- ✅ 人工审核判断
- ✅ 批量告警处理
- ✅ 完整的日志记录

## 📁 项目结构

```
security_triage/
├── src/
│   ├── agents/           # Agent实现
│   │   └── triage_agent.py
│   ├── tools/            # 工具函数
│   │   ├── context_tools.py
│   │   ├── threat_intel_tools.py
│   │   └── risk_assessment_tools.py
│   ├── models/           # 数据模型
│   │   └── alert.py
│   └── utils/            # 工具类
│       ├── config.py
│       └── logger.py
├── config/               # 配置文件
│   └── config.yaml
├── data/                 # 数据文件
│   └── sample_alerts.json
├── logs/                 # 日志目录
├── tests/                # 测试文件
├── requirements.txt      # 依赖列表
├── .env.example         # 环境变量示例
└── main.py              # 主入口

```

## 🚀 快速开始

### 支持的LLM提供商

- ✅ **通义千问 Qwen** - 推荐国内用户（性价比高）
- ✅ **OpenAI** - GPT-4, GPT-3.5
- ✅ **DeepSeek** - 高性价比
- ✅ **智谱AI GLM** - 国产模型
- ✅ **月之暗面 Kimi** - 长上下文
- ✅ 任何OpenAI兼容的API

详细配置指南: **[LLM_API_CONFIG.md](LLM_API_CONFIG.md)**

### 1. 安装依赖

```bash
cd /Users/newmba/Downloads/CCWorker/security_triage
pip install -r requirements.txt
```

### 2. 配置LLM API

**快速配置（通义千问 - 推荐）:**

```bash
# 复制环境变量模板
cp .env.example .env

# 编辑.env文件
nano .env  # 或使用任何文本编辑器
```

添加以下内容：
```bash
# 通义千问配置
LLM_API_KEY=sk-your-qwen-api-key-here
LLM_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
```

**获取通义千问API密钥**: https://bailian.console.aliyun.com/

**或使用OpenAI:**
```bash
LLM_API_KEY=sk-your-openai-key
LLM_BASE_URL=
```

详细配置说明: 查看 **[LLM_API_CONFIG.md](LLM_API_CONFIG.md)**

### 3. 运行示例

```bash
# 处理示例告警
python main.py --sample

# 交互式模式
python main.py --interactive

# 从文件处理告警
python main.py --file data/sample_alerts.json

# 处理单个告警
python main.py --alert '{"alert_id":"ALT-001","timestamp":"2025-01-04T12:00:00Z","alert_type":"malware","source_ip":"45.33.32.156","target_ip":"10.0.0.50","severity":"high","description":"Test alert"}'
```

## 📊 使用示例

### 示例1：恶意软件告警

```python
{
  "alert_id": "ALT-2025-001",
  "timestamp": "2025-01-04T12:00:00Z",
  "alert_type": "malware",
  "source_ip": "45.33.32.156",
  "target_ip": "10.0.0.50",
  "severity": "high",
  "description": "Detected suspicious file execution",
  "file_hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
}
```

### 示例2：暴力破解告警

```python
{
  "alert_id": "ALT-2025-002",
  "timestamp": "2025-01-04T11:30:00Z",
  "alert_type": "brute_force",
  "source_ip": "192.168.1.200",
  "target_ip": "10.0.0.10",
  "severity": "medium",
  "description": "Multiple failed login attempts detected"
}
```

## 🎨 输出示例

```
================================================================================
🚨 SECURITY ALERT RECEIVED
================================================================================
Alert ID:        ALT-2025-001
Timestamp:       2025-01-04T12:00:00Z
Type:            malware
Severity:        HIGH
Source IP:       45.33.32.156
Target IP:       10.0.0.50
Description:     Detected suspicious file execution
File Hash:       5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
================================================================================

================================================================================
📊 TRIAGE ANALYSIS RESULT
================================================================================

🎯 RISK ASSESSMENT:
   Risk Score:      75.5/100
   Risk Level:      HIGH
   Confidence:      75.0%
   Key Factors:
      • 告警严重级别: high
      • 资产重要性: high
      • 威胁情报评分: 7.0/10

🔍 THREAT INTELLIGENCE:
   • IOC: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
     Type: hash
     Threat Level: high
     ⚠️  MALICIOUS

🌐 CONTEXT INFORMATION:
   Network:
      Source IP Internal: False
   Asset:
      Type: workstation
      Criticality: high

🛠️  REMEDIATION ACTIONS:
   1. [IMMEDIATE] 立即隔离受影响主机 (🤖 AUTO)
   2. [IMMEDIATE] 阻断恶意IP地址 (🤖 AUTO)
   3. [IMMEDIATE] 禁用受损账户 (🤖 AUTO)
   4. [HIGH] 启动应急响应流程 (👤 MANUAL)
      Owner: Security Team

📋 ADDITIONAL INFO:
   Processing Time:  2.34 seconds
   Human Review:     ⚠️  REQUIRED
   Analysis Time:    2025-01-04 12:00:05

================================================================================
✅ ANALYSIS COMPLETED
================================================================================
```

### 3. 测试API连接（推荐）

```bash
python3 test_api.py
```

这会验证你的API配置是否正确。

### 4. 运行示例

### config.yaml

```yaml
# 风险评分阈值
risk_scoring:
  thresholds:
    critical: 90
    high: 70
    medium: 40
    low: 20

# 权重配置
  weights:
    severity: 0.3
    threat_intel: 0.3
    asset_criticality: 0.2
    exploitability: 0.2
```

## 📈 扩展建议

### 生产环境增强

1. **真实威胁情报集成**
   - VirusTotal API
   - Abuse.ch
   - MISP
   - AlienVault OTX

2. **向量数据库**
   - Chroma用于历史告警存储
   - 语义搜索相似事件

3. **消息队列**
   - RabbitMQ/Kafka处理告警流
   - 异步批量处理

4. **监控告警**
   - Prometheus指标导出
   - Grafana仪表板

5. **API接口**
   - FastAPI REST API
   - Webhook通知

## 🧪 测试

```bash
# 运行测试（待实现）
pytest tests/

# 运行示例
python main.py --sample
```

## 📝 注意事项

1. **API密钥**: 需要配置OpenAI API密钥
2. **Mock数据**: 当前使用模拟数据，生产环境需集成真实数据源
3. **性能**: 优化向量检索和LLM调用
4. **安全**: 生产环境需要添加认证和授权

## 🤝 贡献

这是一个原型系统，欢迎改进和扩展！

## 📄 许可

Apache License 2.0 - 详见项目根目录 LICENSE 文件
# Last build test

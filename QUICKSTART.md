# 🚀 快速启动指南

## 第一步：安装依赖

```bash
cd /Users/newmba/Downloads/CCWorker/security_triage

# 安装Python依赖
pip install -r requirements.txt
```

## 第二步：配置API密钥

```bash
# 复制环境变量模板
cp .env.example .env

# 编辑.env文件，添加OpenAI API Key
# OPENAI_API_KEY=sk-your-actual-api-key-here
```

**获取OpenAI API Key：**
1. 访问 https://platform.openai.com/api-keys
2. 创建新的API密钥
3. 复制密钥到.env文件

## 第三步：运行示例

### 方式1：处理示例告警（推荐）

```bash
python main.py --sample
```

这将处理4个示例告警并展示完整的分析流程。

### 方式2：交互式模式

```bash
python main.py --interactive
```

然后可以输入JSON格式的告警数据进行实时分析。

### 方式3：处理单个告警

```bash
python main.py --alert '{
  "alert_id": "ALT-001",
  "timestamp": "2025-01-04T12:00:00Z",
  "alert_type": "malware",
  "source_ip": "45.33.32.156",
  "target_ip": "10.0.0.50",
  "severity": "high",
  "description": "Test alert"
}'
```

## 📊 预期输出

```
================================================================================
🚨 SECURITY ALERT RECEIVED
================================================================================
Alert ID:        ALT-2025-001
Timestamp:       2025-01-04T12:00:00Z
Type:            malware
Severity:        HIGH
...

================================================================================
📊 TRIAGE ANALYSIS RESULT
================================================================================

🎯 RISK ASSESSMENT:
   Risk Score:      75.5/100
   Risk Level:      HIGH
   ...
```

## 🧪 测试不同场景

### 场景1：恶意软件检测
```json
{
  "alert_id": "ALT-001",
  "timestamp": "2025-01-04T12:00:00Z",
  "alert_type": "malware",
  "source_ip": "45.33.32.156",
  "target_ip": "10.0.0.50",
  "severity": "high",
  "description": "Malware detected",
  "file_hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
}
```

### 场景2：暴力破解攻击
```json
{
  "alert_id": "ALT-002",
  "timestamp": "2025-01-04T11:30:00Z",
  "alert_type": "brute_force",
  "source_ip": "192.168.1.200",
  "target_ip": "10.0.0.10",
  "severity": "medium",
  "description": "Brute force attack detected"
}
```

### 场景3：数据泄露
```json
{
  "alert_id": "ALT-003",
  "timestamp": "2025-01-04T10:00:00Z",
  "alert_type": "data_exfiltration",
  "source_ip": "103.224.212.222",
  "target_ip": "10.0.0.30",
  "severity": "critical",
  "description": "Large data transfer to external IP"
}
```

## ⚙️ 自定义配置

编辑 `config/config.yaml` 来自定义系统行为：

```yaml
# 风险评分阈值
risk_scoring:
  thresholds:
    critical: 90  # 修改这里调整critical阈值
    high: 70
    medium: 40

# 权重配置
  weights:
    severity: 0.3      # 告警严重程度权重
    threat_intel: 0.3  # 威胁情报权重
    asset_criticality: 0.2  # 资产重要性权重
    exploitability: 0.2      # 可利用性权重
```

## 📝 查看日志

```bash
# 查看实时日志
tail -f logs/triage.log

# 查看分析结果JSON
ls -la logs/triage_result_*.json
```

## 🐛 故障排除

### 问题1：ImportError
```bash
# 解决方案：重新安装依赖
pip install -r requirements.txt --upgrade
```

### 问题2：API密钥错误
```bash
# 检查.env文件
cat .env

# 确保格式正确（不要有空格和引号）
OPENAI_API_KEY=sk-your-key-here
```

### 问题3：模块找不到
```bash
# 确保在项目根目录运行
cd /Users/newmba/Downloads/CCWorker/security_triage
python main.py --sample
```

## 🎯 下一步

1. **扩展威胁情报源**：集成VirusTotal、Abuse.ch等真实API
2. **添加向量数据库**：使用Chroma存储历史告警
3. **实现Web界面**：使用FastAPI + Streamlit
4. **部署到生产**：容器化并部署到Kubernetes

## 📚 更多信息

- 完整文档：`README.md`
- 系统设计：`../security_alert_triage_system.md`
- 配置说明：`config/config.yaml`

---

**需要帮助？** 查看日志文件 `logs/triage.log` 了解详细错误信息。

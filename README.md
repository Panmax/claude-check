<p align="center">
  <h1 align="center">🤖 Claude Check</h1>
  <p align="center">
    <strong>一条命令，深度检测你的网络环境是否安全适配 Claude AI</strong>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/Python-3.6+-blue?logo=python&logoColor=white" alt="Python 3.6+">
    <img src="https://img.shields.io/badge/依赖-零依赖-brightgreen" alt="Zero Dependencies">
    <img src="https://img.shields.io/badge/平台-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey" alt="Cross Platform">
    <img src="https://img.shields.io/github/license/Panmax/claude-check" alt="License">
  </p>
</p>

---

## ⚡ 一键运行（无需安装）

**macOS / Linux:**

```bash
curl -fsSL https://raw.githubusercontent.com/Panmax/claude-check/main/claude_check.py | python3
```

**Windows PowerShell:**

```powershell
irm https://raw.githubusercontent.com/Panmax/claude-check/main/claude_check.py | python
```

就这么简单。无需 clone、无需 pip install、无需任何依赖。

---

## 🔍 它能检测什么？

| 检测项 | 说明 | 风险等级 |
|--------|------|----------|
| 🔌 **代理环境变量** | 检查 `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` 是否配置 | 提示 |
| 🌐 **IPv6 泄漏** | 多目标探测 IPv6 出口连通性，防止真实 IP 绕过代理裸奔 | 🔴 高危 |
| 🧭 **DNS 泄漏** | 检测 DNS 出口是否泄漏到国内节点 | 🔴 高危 |
| 🕒 **时区匹配** | 对比本机系统时区与代理出口 IP 所在时区，暴露翻墙特征 | 🔴 高危 |
| 📊 **IP 质量** | 判定出口 IP 是家宽/原生 ISP 还是商用机房/代理节点 | 🟡 中危 |
| 🛡️ **Cloudflare WAF** | 探测 claude.ai 是否对当前 IP 发起人机验证拦截 | 🔴 高危 |
| 🔗 **API 连通性** | 逆向探测 Anthropic API 是否对当前 IP 硬封锁 | 🔴 高危 |
| 📋 **综合评估** | 汇总所有检测项，给出风险等级 + 修复建议 | - |

## 📸 输出示例

```
================================================================
       🤖 Claude AI - 终极环境安全深度检测工具 (Pro 版)
================================================================

[*] 1. 本地网络与防泄漏体检 (Local Network & Leak Check)
  ✅ 发现系统代理环境变量:
     - HTTPS_PROXY: http://127.0.0.1:7890
  ✅ IPv6 处于关闭或不可达状态 (安全，无绕过代理泄漏风险)
  ✅ DNS 无国内泄漏。海外出口 DNS 为: 1.1.1.1 (United States)
  🕒 本机系统时区: PST (UTC-8.0)

[*] 2. 落地 IP 质量与时区匹配度 (IP Quality & Timezone Match)
  📍 物理位置: United States (US) - Los Angeles
  🌐 出口 IP : 203.x.x.x
  🏢 归属 ASN: AS12345 Example ISP
  📡 运营商  : Example ISP
  ✅ IP 质量优秀: 检测为 [真实家庭宽带/原生ISP] -> 适合防封
  ✅ 伪装完美：本机时区与代理出口 IP 时区完全一致: America/Los_Angeles (UTC-8.0)

[*] 3. 探测 Claude 前端 Web 盾防御策略 (Cloudflare WAF Check)
  ✅ 网页直连通过: 无 Cloudflare 人机拦截，Web 盾前置放行！

[*] 4. 逆向探测 Anthropic API 底层连通性 (API Hard-Ban Check)
  ✅ API 穿透成功: 流量直达 Anthropic 核心后端，IP 未在硬封锁黑名单中！

====================== 综合风险评估 ================================
  IPv6 泄漏    : ✅ 安全
  DNS 泄漏     : ✅ 安全
  时区匹配     : ✅ 安全
  IP 质量      : ✅ 安全
  Web WAF      : ✅ 安全
  API 连通     : ✅ 安全

  🔒 综合风险等级: 低风险 (LOW)
=====================================================================
```

## ⚙️ 命令行参数

```
用法: python3 claude_check.py [选项]

选项:
  --skip-api     跳过 Anthropic API 连通性检测
  --skip-web     跳过 Cloudflare WAF 检测
  --json         以 JSON 格式输出（适合脚本集成和自动化）
  --no-color     禁用彩色输出（管道输出时自动禁用）
```

**示例：**

```bash
# JSON 输出，方便 jq 处理
curl -fsSL https://raw.githubusercontent.com/Panmax/claude-check/main/claude_check.py | python3 - --json | jq .

# 只检测本地环境和 IP，跳过 Web 和 API 探测
python3 claude_check.py --skip-web --skip-api
```

**退出码：**

| 退出码 | 含义 |
|--------|------|
| `0` | 低风险 (LOW) |
| `1` | 高风险 / 极高风险 (HIGH / CRITICAL) |
| `2` | 中风险 (MEDIUM) |

## 📦 本地运行

```bash
git clone https://github.com/Panmax/claude-check.git
cd claude-check
python3 claude_check.py
```

## 🤝 Contributing

欢迎提交 Issue 和 Pull Request！

## ⚠️ 免责声明

本工具仅用于网络环境自检和安全研究目的。用户应遵守所在地区的法律法规以及 Anthropic 的服务条款。开发者不对使用本工具产生的任何后果负责。

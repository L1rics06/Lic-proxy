#  网络代理程序及检测方案设计与实现

> **总分: 100分 + 加分20分 | 代码行数: 1568行 | 语言: Python 3.12+**

Lic-proxy 是一个用于课程设计的 Python 双端加密代理示例。它由本地客户端 user/ 和远端服务端 server/ 组成：浏览器或 curl 连接本地代理，本地代理再通过加密 TCP 隧道连接远端服务端，远端服务端负责访问真实目标网站并把数据转发回来。

本项目实现的是教学用途的简化协议，不兼容真实 VMess、VLESS 或 Hysteria 客户端。

注：原远端服务器租借于阿里云平台的新加坡服务器，目前已释放实例，若需验证或二次开发，请自行租借或联系开发者。
## 评分对照表

| 评分项 | 分值 | 对应章节 | 状态 | 分工 |
|--------|------|---------|------|------|
| HTTP/HTTPS 代理 | 基础分 | [2.1](#21-httphttps-代理) | ✅ |
| 访问国外网站 | 基础分 | [2.2](#22-访问国外网站) + [附录A](#附录a-实测结果) | ✅ |
| 加密传输(≥2种算法) | 基础分 | [2.3](#23-加密传输) | ✅ AES-GCM + ChaCha20 |
| 代理检测方案 | 基础分 | [3](#3-代理检测方案) | ✅ 7种方法 |
| 防火墙对抗 | 基础分 | [4](#4-防火墙对抗分析) | ✅ |
| SOCKS5 代理 | 加分 | [2.4](#24-socks5-代理加分项) | ✅ |
| 可视化监控面板 | 加分(20分) | [2.5](#25-实时监控面板加分项20分) | ✅ ECharts 6图表 |

## 分工
| 成员 | 主要工作 |
|------|---------|
| 程俊钦 | 本地客户端：HTTP/HTTPS/SOCKS5代理入口实现 |
| 程俊钦 | 项目答辩视频的录制与讲解 |
| 程俊钦 | 项目测试与调试 |
| 谢长君 | 远端服务端：实现加密隧道出口、StatsStore |
| 谢长君 | 实现前端监控面板 |
| 谢长君 | 课程设计报告的撰写 |

---

## 1. 项目概述

Lic-proxy 是一个**双端加密代理系统**，由本地客户端和远端服务端组成。浏览器或系统代理连接本地客户端，客户端通过**加密TCP隧道**将请求转发至远端服务端，由服务端访问目标网站并返回数据。

### 架构图

<img width="960" height="600" alt="image" src="https://github.com/user-attachments/assets/c303782e-af64-4a6d-abb6-21054072f0fa" />


### 技术栈

| 组件 | 技术 |
|------|------|
| 语言 | Python 3.12+ |
| 加密库 | cryptography >= 42.0.0 |
| 加密算法 | AES-256-GCM, ChaCha20-Poly1305 |
| 认证 | HMAC-SHA256 + 时间戳 + Nonce |
| 异步框架 | asyncio (streams) |
| 前端 | HTML5 + CSS3 + ECharts 5.5 (CDN) |

---

## 2. 核心功能实现

### 2.1 HTTP/HTTPS 代理

**HTTP 代理**: 客户端解析浏览器发来的绝对 URL（如 `GET http://example.com/path HTTP/1.1`），提取目标主机和端口，将请求改写为 origin-form 后通过加密隧道转发。

**HTTPS 代理**: 客户端接收 `CONNECT host:443` 请求，建立加密隧道到服务端，服务端连接目标主机后返回 `200 Connection Established`，之后双向透传 TLS 数据。

**关键代码**: `user/client.py:handle_http()` → `server/server.py:handle_tunnel()`

```python
# HTTP 请求解析 (client.py)
def parse_http_request(header_bytes: bytes) -> HttpProxyRequest:
    if method_upper == "CONNECT":       # HTTPS 隧道
        return HttpProxyRequest(host, 443, "https", True, b"")
    parsed = urlsplit(target)           # HTTP 绝对URL
    return HttpProxyRequest(host, port, "http", False, rewritten)
```

### 2.2 访问国外网站

远端服务器部署在境外云服务器（47.84.230.14），国内用户通过加密隧道连接远端服务器，由远端服务器代理访问被墙网站。

**实测验证**（详见[附录A](#附录a-实测结果)）：
- ✅ **Steam**（store.steampowered.com）— 连接成功
- ✅ **YouTube** — 2秒完成加载
- ✅ **Twitter / Reddit / Instagram / Discord** — 全部连通
- ✅ **GitHub / StackOverflow / Medium** — 正常访问

### 2.3 加密传输

#### 算法对比

| 特性 | AES-256-GCM | ChaCha20-Poly1305 |
|------|------------|-------------------|
| 类型 | 分组密码 + AEAD | 流密码 + AEAD |
| 密钥长度 | 256 bits | 256 bits |
| Nonce | 12 bytes (随机) | 12 bytes (随机) |
| 硬件加速 | AES-NI (x86) | 纯软件优化 |
| 适用场景 | 有AES-NI的服务器 | 移动设备/无硬件加速 |
| 安全性 | NIST标准 | RFC 8439 |

#### 握手协议

<img width="650" height="700" alt="image" src="https://github.com/user-attachments/assets/d3e02d1a-5a5b-4f1e-a0aa-960b90cf6f00" />


**密钥派生**: `key = SHA-256(token)` → 32字节固定密钥

**数据帧格式**: `[4字节长度] [12字节Nonce] [AEAD加密载荷+认证标签]`

**安全特性**:
- 不直接传输 token，使用 HMAC 验证
- 时间戳防重放攻击（600秒窗口）
- 每次握手随机 Nonce (16 bytes)
- 每次数据帧随机 Nonce (12 bytes)

**关键代码**: `common/crypto.py:CryptoBox` → `common/protocol.py:write_handshake/read_handshake`

### 2.4 SOCKS5 代理（加分项）

支持 RFC 1928 标准的 SOCKS5 无认证代理，支持三种地址类型：

| 地址类型 | ATYP | 格式 |
|---------|------|------|
| IPv4 | 0x01 | 4 bytes |
| 域名 | 0x03 | 1字节长度 + 域名 |
| IPv6 | 0x04 | 16 bytes |

**握手流程**:
1. 客户端→服务端: `[0x05, nmethods, methods...]`
2. 服务端→客户端: `[0x05, 0x00]`（选择无认证）
3. 客户端→服务端: `[0x05, 0x01, 0x00, ATYP, DST.ADDR, DST.PORT]`
4. 服务端→客户端: `[0x05, 0x00, 0x00, 0x01, 0x00...0x00, 0x00, 0x00]`（连接成功）

**关键代码**: `user/client.py:handle_socks5()`

### 2.5 实时监控面板（加分项·20分）

服务端内置 Web 监控面板（`http://服务器IP:8080`），实时展示所有代理连接和流量数据。

#### 功能特性

- **4个 KPI 卡片**: 活跃连接数、总连接数、上传/下载实时速率
- **6个 ECharts 可视化图表**:

| 图表 | 类型 | 说明 |
|------|------|------|
| 流量速率图 | 双线面积图 | 上传(蓝)/下载(绿)实时速率(bps) |
| 活跃连接图 | 折线面积图 | 活跃连接数随时间变化 |
| 协议分布图 | 环形饼图 | HTTP/HTTPS/SOCKS5 占比 |
| 目标域名排名 | 水平柱状图 | Top 15 访问最多的目标站点 |
| 连接状态图 | 环形饼图 | active/closed/error/failed 分布 |
| 客户端IP排名 | 水平柱状图 | Top 15 客户端IP流量排名 |

- **连接详情表格**: 搜索过滤、状态/协议下拉筛选、列点击排序、分页(20条/页)、状态彩色标签
- **响应式布局**: 支持桌面/平板/手机三档自适应
- **智能轮询**: 1秒自动刷新，切换标签页自动暂停/恢复

#### API 设计

`GET /api/stats` 返回字段：

| 字段 | 类型 | 说明 |
|------|------|------|
| active | int | 当前活跃连接数 |
| total_connections | int | 历史总连接数 |
| total_uploaded / total_downloaded | int | 累计流量(bytes) |
| upload_rate / download_rate | float | 实时速率(bytes/s, 10秒滑动窗口) |
| protocol_stats | dict | {"http":N, "https":N, "socks5":N} |
| target_stats | array | Top 20 目标域名 {host, count, uploaded, downloaded} |
| client_stats | array | Top 20 客户端IP {ip, count, uploaded, downloaded} |
| status_stats | dict | {"active", "connecting", "connected", "closed", "error", "failed"} |
| history | array | 最近120个采样点 {time, active, uploaded, downloaded} |
| connections | array | 最近100条连接详情(含id/client/target/protocol/status/流量/时长/错误) |

---

## 3. 代理检测方案

防火墙或网络管理员可能通过以下7种方法检测代理服务：

### 3.1 端口扫描

**原理**: 扫描常见代理端口（1080/9000/8080等），识别开放服务。

**检测特征**: 本项目的默认端口 9000(tunnel) 和 8080(admin)。

**对策**: 将监听端口改为常见服务端口（如443），或使用端口敲门技术。

### 3.2 主动探测

**原理**: 向可疑端口发送 HTTP 代理请求或 SOCKS5 握手包，观察响应。例如发送 `GET http://test.com HTTP/1.0`，代理返回目标页面而非错误页。

**检测特征**: SOCKS5 握手返回 `0x05 0x00`（方法选择），HTTP CONNECT 返回 `200 Connection Established`。

**对策**: 在未认证的情况下不响应任何探测包，必须先完成加密握手。

### 3.3 流量特征分析

**原理**: 统计长连接比例、上下行流量比、固定远端IP连接数、连接时长分布。代理流量通常是"少量上传 + 大量下载"模式。

**检测特征**: 所有流量发往同一个远端IP(47.84.230.14:9000)，上下行流量比例不对称。

**对策**: 使用多路复用混淆连接模式，或在多个IP间轮换。

### 3.4 TLS/SNI 异常分析

**原理**: 检查 TLS 握手中的 SNI（Server Name Indication）与实际访问行为是否匹配。正常 HTTPS 流量会在 SNI 中声明目标域名。

**检测特征**: 本项目在 CONNECT 隧道中直接透传 TLS，SNI 由浏览器设置，与代理本身无关。但加密隧道的 TLS 特征（如使用自签证书）可能被检测。

**对策**: 使用正规 CA 签发的证书，模拟正常 HTTPS 流量。

### 3.5 DNS 与访问目标关联

**原理**: 分析客户端 DNS 查询和实际 TCP 连接目标。如果 DNS 查询全是国内网站，但TCP连接全是境外IP，则为代理特征。

**检测特征**: 客户端只连接一个远端IP(47.84.230.14)，与该IP的流量远大于DNS查询的域名。

**对策**: 使用 DoH(DNS over HTTPS) 隐藏 DNS 查询，或将DNS查询也通过代理发送。

### 3.6 流量突增监控

**原理**: 代理服务器在特定时段（如晚上）出现大量并发连接和流量突增。单个IP短时间连接多个不同目标。

**检测特征**: 一个客户端IP在短时间内访问几十个不同境外网站。

**对策**: 对连接速率进行限制，分散到多个时间段。

### 3.7 认证失败观察（时延指纹）

**原理**: 向代理端口发送错误的token或协议版本，观察拒绝响应的时间。正常服务通常立即返回错误，而代理可能在完成加密握手后才返回错误，时延特征不同。

**检测特征**: 本项目的握手包含 MAGIC 校验 → 长度校验 → JSON解析 → HMAC校验，每一步失败都会立即断开连接。

**对策**: 在任何校验失败时添加随机延迟（如 100-500ms），使时延特征不可预测。

---

## 4. 防火墙对抗分析

### 当前防护能力

| 攻击方式 | 防护效果 | 说明 |
|---------|---------|------|
| 明文内容检测 | ✅ 有效 | 所有数据经 AEAD 加密，无法识别内容 |
| 简单端口封锁 | ❌ 脆弱 | 固定端口(9000)，可直接封锁 |
| 协议指纹识别 | ⚠️ 部分 | MAGIC 字节(LPX1)可被特征匹配 |
| 流量统计攻击 | ❌ 脆弱 | 单一远端IP + 固定端口 |
| 深度包检测(DPI) | ⚠️ 部分 | 加密但无流量混淆/填充 |

### 已知局限

1. **固定端口**: 默认 9000/8080，容易被端口封锁
2. **流量模式明显**: 所有流量发往单一IP
3. **无协议伪装**: 不像 VMess/VLESS 模拟正常TLS流量
4. **无流量混淆**: 不使用随机填充或流量整形
5. **主动探测响应**: 未认证连接仍返回错误，可被指纹识别

### 改进方向

1. **协议伪装**: 将加密流量伪装成 HTTPS/WebSocket 流量
2. **端口跳跃**: 定期更换监听端口，使用端口范围
3. **流量填充**: 随机填充数据包大小，打破流量特征
4. **多路复用**: 单一连接承载多个代理会话，减少连接数特征
5. **CDN中转**: 通过 CDN(如 Cloudflare) 隐藏真实服务器IP

---

## 5. 快速开始

### 安装

```bash
pip install -r requirements.txt  # 仅依赖 cryptography>=42.0.0
```

Python 3.12+ 推荐。

### 启动

**服务端**（在阿里云平台上租借了新加坡的服务器）:

```bash
ssh root@服务器IP

python -m server.server --listen 0.0.0.0:9000 --admin 0.0.0.0:8080 --token my-token --cipher aesgcm
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| --listen | 0.0.0.0:9000 | 加密隧道监听地址 |
| --admin | 127.0.0.1:8080 | 监控面板地址 |
| --token | 必填 | 共享密钥 |
| --cipher | aesgcm | 加密算法(aesgcm/chacha20) |

**客户端**（在本地机器）:

```bash
python -m user.client --listen 127.0.0.1:1080 --server 服务器IP:9000 --token my-token --cipher aesgcm
```

⚠️ 客户端和服务端的 `--token`、`--cipher` 必须一致。

### 使用

```bash
# HTTP 代理
curl -x http://127.0.0.1:1080 http://example.com/

# HTTPS 代理
curl -x http://127.0.0.1:1080 https://www.youtube.com/

# SOCKS5 代理
curl --socks5 127.0.0.1:1080 https://store.steampowered.com/
```

### 监控面板

```
http://服务器IP:8080
```

若服务端只监听 127.0.0.1，通过 SSH 端口转发访问：
```bash
ssh -L 18080:127.0.0.1:8080 user@服务器IP
# 本地浏览器打开 http://127.0.0.1:18080
```

---

## 6. 项目结构

```
Lic-proxy/
├── common/                 # 共享模块
│   ├── crypto.py           # AES-256-GCM / ChaCha20-Poly1305 加密封装
│   └── protocol.py         # 握手协议、HMAC认证、加密帧读写
├── server/                 # 远端服务端
│   └── server.py           # 加密隧道出口 + 监控面板(API+HTML)
├── user/                   # 本地客户端
│   └── client.py           # HTTP/HTTPS/SOCKS5 代理入口
├── requirements.txt        # Python 依赖
└── README.md              # 本文档
```

| 文件 | 行数 | 职责 |
|------|------|------|
| server/server.py | 1002 | 远端出口代理 + StatsStore聚合 + 监控面板 |
| user/client.py | 375 | 本地代理入口，HTTP/HTTPS/SOCKS5解析 |
| common/protocol.py | 142 | 握手/加密帧协议实现 |
| common/crypto.py | 49 | 加密算法封装 |
| **总计** | **1568** | |

---

---

## 附录A: 实测结果

测试环境：本地客户端(China Mobile) → 加密隧道 → 远端服务器(47.84.230.14, 境外) → 目标网站

测试时间：2026-07-06

| 目标网站 | 协议 | 状态 | 耗时 | 下载量 |
|---------|------|------|------|--------|
| store.steampowered.com | HTTPS | ✅ connected | 9s | — |
| steamcommunity.com | HTTPS | ✅ connected | 3s | — |
| twitter.com | HTTPS | ✅ connected | 1s | 15.3KB |
| reddit.com | HTTPS | ✅ connected | 3s | 5.4KB |
| youtube.com | HTTPS | ✅ closed | 2s | 8.2KB |
| discord.com | HTTPS | ✅ closed | 2s | — |
| instagram.com | HTTPS | ✅ closed | 1s | 4.0KB |
| github.com | HTTPS | ✅ closed | 2s | 579KB |
| stackoverflow.com | HTTPS | ✅ closed | 1s | 12.0KB |
| netflix.com | HTTPS | ✅ closed | 2s | 3.9KB |
| amazon.com | HTTPS | ✅ closed | 1s | 6.8KB |
| wikipedia.org | HTTPS | ✅ closed | 1s | 8.1KB |
| cnn.com | HTTPS | ✅ closed | 1s | 4.5KB |

<img width="900" height="500" alt="image" src="https://github.com/user-attachments/assets/7c98213a-c406-4ccf-9b2c-f7f08b44a9f7" />


<img width="800" height="500" alt="image" src="https://github.com/user-attachments/assets/b6836899-33dc-4ae6-b4d9-4c9f4a941764" />


> 数据来源：监控面板 `/api/stats` 实时记录。Steam/Twitter/Reddit 连接状态为"connected"（TCP连接建立成功，数据持续传输中）。

---

## 附录B: 提交清单

| # | 材料 | 格式 | 说明 |
|---|------|------|------|
| 1 | 课程设计报告 | .doc | 含设计思路、方案说明、测试分析 |
| 2 | 程序源代码 | .rar | 含全部源文件 + 依赖文件 + 可执行说明 |
| 3 | 演示PPT | .ppt/.pptx | 含架构图、功能演示、分工说明 |
| 4 | 演示视频 | .mp4 | ≤10分钟，含功能演示和代码讲解 |
| 5 | Github截图 | 图片 | 仓库首页 + 代码文件截图 |



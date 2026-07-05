# Lic-proxy

Lic-proxy 是一个用于课程设计的 Python 双端加密代理示例。它由本地客户端 `user/` 和远端服务端 `server/` 组成：浏览器或 curl 连接本地代理，本地代理再通过加密 TCP 隧道连接远端服务端，远端服务端负责访问真实目标网站并把数据转发回来。

> 本项目实现的是教学用途的简化协议，不兼容真实 VMess、VLESS 或 Hysteria 客户端。

## 功能

- HTTP 代理：支持 `GET http://host/path HTTP/1.1` 这类普通 HTTP 代理请求。
- HTTPS 代理：支持 `CONNECT host:443` 建立 TCP 隧道。
- SOCKS5 代理：支持无认证 `CONNECT`。
- 加密隧道：支持 `AES-256-GCM` 和 `ChaCha20-Poly1305` 两种认证加密算法。
- 认证握手：握手包含版本、算法、时间戳、随机 nonce 和 HMAC token 校验。
- 监控面板：服务端提供连接表、活跃连接数、上传/下载流量和简单趋势图。

## 安装

```bash
python -m pip install -r requirements.txt
```

建议使用 Python 3.12 或更新版本。

## 启动

在可以访问目标网站的机器上启动服务端：

```bash
python -m server.server --listen 0.0.0.0:9000 --admin 127.0.0.1:8080 --token demo-token --cipher aesgcm
```

在本机启动客户端：

```bash
python -m user.client --listen 127.0.0.1:1080 --server SERVER_IP:9000 --token demo-token --cipher aesgcm
```

`--cipher` 可以设置为：

- `aesgcm`
- `chacha20`

客户端和服务端的 `--token`、`--cipher` 必须一致。

## 使用

HTTP/HTTPS 代理：

```bash
curl -x http://127.0.0.1:1080 http://example.com/
curl -x http://127.0.0.1:1080 https://example.com/
```

SOCKS5 代理：

```bash
curl --socks5 127.0.0.1:1080 http://example.com/
```

监控页面：

```text
http://127.0.0.1:8080
```

如果服务端部署在远端机器，默认 `--admin 127.0.0.1:8080` 只允许远端机器本机访问。需要远程查看时，可以改成内网地址或通过 SSH 端口转发访问。

## 工作流程

1. 浏览器或 curl 连接 `user.client`。
2. `user.client` 判断请求类型：
   - SOCKS5：按 SOCKS5 握手读取目标地址；
   - HTTP：解析绝对 URL 并改写为 origin-form；
   - HTTPS：解析 `CONNECT host:port`。
3. `user.client` 与 `server.server` 建立 TCP 连接并发送认证握手。
4. 握手通过后，客户端发送加密的连接请求帧。
5. 服务端连接目标地址，然后双向转发加密数据帧。

每个代理连接对应一个服务端 TCP 连接。为了保持代码简洁，当前版本不做多路复用。

## 加密设计

共享 token 会通过 SHA-256 派生为 32 字节密钥。

握手阶段不直接发送 token，而是发送：

- 协议版本；
- 加密算法；
- 当前时间戳；
- 随机 nonce；
- HMAC-SHA256 校验值。

数据阶段使用：

```text
4 字节长度前缀 + 12 字节 AEAD nonce + 密文 + 认证标签
```

长度前缀本身不加密，payload 使用 AEAD 加密和认证。

## 代理服务检测方案

可能的网络代理服务检测方法包括：

- 端口扫描：扫描常见代理端口，尝试识别开放服务。
- 主动探测：向可疑端口发送 HTTP、SOCKS5 或自定义探测包，观察是否返回代理特征响应。
- 流量特征分析：统计长连接比例、上下行流量模式、固定远端 IP 连接、连接时长等行为。
- TLS/SNI 异常分析：检查 TLS 握手、SNI 与后续流量行为是否匹配。
- DNS 与访问目标关联：分析客户端 DNS 查询和实际连接目标是否出现代理转发特征。
- 流量突增监控：代理服务器常出现多客户端、多目标站点的集中出口流量。
- 认证失败观察：对疑似代理端口进行错误 token 或错误协议探测，记录连接关闭方式和错误时延。

## 防火墙拦截说明

本项目通过加密隧道避免明文 HTTP 代理内容直接暴露，能够降低被简单内容检测识别的概率。但是它没有实现复杂的抗封锁伪装，也不模拟正常 HTTPS 网站、QUIC 或 Hysteria 流量。面对严格防火墙时，仍可能因为固定端口、流量模式、主动探测或连接行为被识别。

## 项目结构

```text
common/
  crypto.py      # AES-GCM / ChaCha20-Poly1305
  protocol.py    # 握手、HMAC、加密帧
user/
  client.py      # 本地 HTTP/HTTPS/SOCKS5 入口
server/
  server.py      # 远端出口代理与监控面板
requirements.txt
README.md
```


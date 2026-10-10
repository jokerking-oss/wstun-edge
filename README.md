# wstun-edge

一个**零依赖**的 Python 边缘中继：把「客户端 ↔ 边缘」那一跳换成你自己托管的一台机器
（PaaS 免费层 / VPS / 容器都行），出口仍然是你的上游住宅代理。

## 它解决什么问题

原本的链路是：

```
本机 ──(中国 ↔ Cloudflare 边缘)──> Cloudflare Worker ──> 美国住宅代理 ──> 目标站
                ↑
        2026-10 实测：这一段会出现「概率性瞬断」
        （与 SNI 无关、与边缘 IP 无关、换入口/换实例都无效）
```

把 Cloudflare 边缘整个换掉，就是唯一的根治方向。本仓库提供那个替代品。

```
本机 ──(WSS)──> 本服务（Render / VPS）──> 上游住宅代理 ──> 目标站
```

## 为什么不能直接用 `server/server.py`

那是早期草案，按「明文 `host:port` + 明文文本帧」写的，与当前客户端的 WS 语义**三条全不匹配**
（对 base64 串做 `rpartition(":")` 会在 `int()` 上抛异常）。本文件是严格对齐版。

## 协议（勿改，客户端按此实现）

| 方向 | 帧类型 | 载荷 |
|---|---|---|
| 客户端 → 边缘 | 文本帧 `0x1` | `base64(原始字节)`；首帧 = `base64("host:port")`；保活 = `base64("__v1__")` |
| 边缘 → 客户端 · 数据 | **二进制帧** `0x2` | 原始字节（客户端**不解 base64**，直接喂 TCP） |
| 边缘 → 客户端 · 保活应答 | 文本帧 `0x1` | `base64("__v1ok__")` |
| 边缘 → 客户端 · 错误 | 文本帧 `0x1` | `base64("EDGE_ERR ...")` |
| 控制帧 | `0x9` ping | 必须回 `0xA` pong |

客户端连接时用 `?a=<AUTH_TOKEN>` 带鉴权，用 `?m=direct` 可切换为直连（不走住宅代理）。

## 环境变量

**本仓库不含任何凭据**，下面 4 项必须由环境变量（或命令行）提供：

| 变量 | 必填 | 说明 |
|---|---|---|
| `AUTH` | 建议 | 客户端连接用的 token。不设 = 谁都能用这个中继 |
| `UP` | ✅ | 上游住宅代理 `host:port`。缺失则启动即报错退出 |
| `UP_USER` / `UP_PASS` | ✅ | 上游代理的 `Proxy-Authorization: Basic` 凭据。缺失则拨号必被拒 |
| `PORT` / `LISTEN` | — | 监听端口。PaaS 会注入 `PORT`，本程序自动读取并绑 `0.0.0.0` |

拨号预算（可用命令行覆盖，默认已比 Cloudflare Worker 宽）：
`--dial-attempt-ms 6000`、`--dial-attempts 4`、`--dial-gap-ms 250`、`--dial-total-ms 5500`。

## 部署到 Render（免费层，不需要信用卡）

1. Render 控制台 → **New** → **Blueprint** → 选中本仓库 → **Apply**。
   `render.yaml` 已把区域钉在 **virginia**（美东，离住宅出口最近）、计划 `free`。
2. 进入服务 → **Environment** → 填 4 个 Secret：`AUTH`、`UP`、`UP_USER`、`UP_PASS`。
   ⚠️ 只改了环境变量的话记得点 **Save and deploy** —— 环境变量变更需要重新部署才生效。
3. 等状态变绿，访问 `https://<你的服务名>.onrender.com/health`，应返回：

```json
{"ok":true,"svc":"wstun-edge","ts":"..."}
```

4. 客户端入口就是：`wss://<你的服务名>.onrender.com/?a=<AUTH>`

### Render 免费层必须知道的两条

- **休眠**：免费 Web Service 在「15 分钟内既没有收到 HTTP 请求、也没有收到 WebSocket 消息」时休眠。
  **2026-02 起 WebSocket 消息也算活跃**，所以隧道有流量时不会睡。
  但**完全空闲 15 分钟仍会休眠**，下次连接要等约 1 分钟冷启动。
  → 规避：用一个免费定时器每 10 分钟打一次 `/health`（cron-job.org / UptimeRobot）。
  ⚠️ 免费额度是 **750 实例小时/月**，而一个月只有 744 小时 ⇒ **只能保持 1 个服务常醒**，别开第二个。
- **流量**：免费层含 **5 GB/月**出站，超出 $0.15/GB。没有绑卡时**超了会暂停服务**。
  5 GB ≈ 170 MB/天，跑文本类长连接（如 Codex）绰绰有余；**整机全量代理跑视频就不够**。

## 部署到其他平台

- **任何支持 Docker 的平台**：仓库里有 `Dockerfile`，直接用它构建即可（同样读 `PORT`）。
- **自己的 VPS**：`python3 edge_srv.py`，前面挂 Caddy/Nginx 做 TLS 即可。
  也可以让它自带 TLS：`--tls-cert fullchain.pem --tls-key privkey.pem`。

## 本地自检

```bash
python3 edge_srv.py --up 127.0.0.1:1 --auth t --listen 127.0.0.1:8080
curl http://127.0.0.1:8080/health
```

拨号失败时应当看到明确的分级日志，而不是静默断开：

```
dial FAIL attempt=1/4 host:port ms=89 : upstream refused: HTTP/1.1 403 Forbidden
dial GIVEUP host:port tries=4 total=1124ms
```

## 安全提醒

- 不设 `AUTH` 时，任何知道 URL 的人都能把它当免费代理用 —— 请务必设置。
- 凭据只放平台的环境变量面板，不要提交进仓库。

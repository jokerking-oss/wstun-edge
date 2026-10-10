#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wstun 自建边缘端（非 Cloudflare）
==================================
把 Cloudflare Worker / Pages 那一跳换成你自己的 VPS（或任意能跑 Python3 的机器）。

为什么要有它
------------
2026-10-11 定位结论：故障不在「CF -> 住宅」那一跳，而在
「本机 -> CF 边缘」这一段（概率性瞬断；与 SNI 无关、与边缘 IP 无关、换入口无效）。
=> 唯一的根治办法是**换掉 CF 边缘本身**。本文件就是那个替代品。

与现成 server/server.py 的区别（**别混用**）
--------------------------------------------
server/server.py 是早期草案，按「明文 host:port + 明文文本帧」写的，
与当前 client/wstun.py 的协议**三条全不匹配**：
  1) 首帧：客户端发 base64("host:port")，它按明文解析 -> int() 抛异常；
  2) 上行数据：客户端发 base64 文本帧，它当原始字节直接写 TCP -> 数据损坏；
  3) 保活：认不出 base64("__v1__")。
本文件严格对齐 client/wstun.py 的 WS.recv/send 语义，可**零改动**接入。

协议（由 client/wstun.py 逆向确认，勿改）
-----------------------------------------
  客户端 -> 边缘 : 文本帧 base64(原始字节)
                   首帧 = base64("host:port")
                   保活 = base64("__v1__")
  边缘 -> 客户端 : 数据走【二进制帧】，原始字节（客户端不解 base64，直接喂 TCP）
                   保活应答 = 文本帧 base64("__v1ok__")
                   错误     = 文本帧 base64("EDGE_ERR ...")
  客户端 ping(0x9) -> 边缘必须回 pong(0xA)

比 CF Worker 强的地方（这就是选 VPS 的理由）
--------------------------------------------
  * 没有 DIAL_TOTAL_MS=4200 这种被 CF CPU 预算逼出来的紧预算
    -> 默认放宽到 5500ms（仍略快于客户端 6s 首字节看门狗，能给出明确错误）；
  * 没有 CF 的 exceededResources / isolate 生命周期掐断；
  * 长连接不会被 CF 平台层拆；
  * 想调什么调什么，不用重部署。

用法
----
  # A) 明文监听，前面挂 Caddy/Nginx 做 TLS（推荐，证书自动续）
  python3 edge_srv.py --listen 0.0.0.0:8080 --auth <token>

  # B) 自带 TLS（自签或 Let's Encrypt 证书都行）
  python3 edge_srv.py --listen 0.0.0.0:8443 \
      --tls-cert /etc/ssl/fullchain.pem --tls-key /etc/ssl/privkey.pem --auth <token>

  # 探活（非 WS 的普通 GET 会返回健康 JSON）
  curl http://<vps>:8080/health

  # C) PaaS（Render / Koyeb）—— 平台会注入 PORT、并在边缘终结 TLS，
  #    所以既不用买域名也不用配证书，直接：  python3 edge_srv.py
  #    平台健康检查打到 / 或 /health，本文件两个都返回 200 JSON。

环境变量（**本仓库不含任何内置凭据**，AUTH / UP / UP_USER / UP_PASS 必须由环境变量提供）：
  PORT / LISTEN / AUTH / UP / UP_USER / UP_PASS
  ↳ PORT 由平台注入；其余请在平台的 Secret / 环境变量面板里设置，别写进代码。
"""

import argparse
import base64
import hashlib
import os
import socket
import ssl
import struct
import sys
import threading
import time

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# 上行分片（服务端 -> 客户端方向不需要分片，这个只用于内部缓冲）
RECV_CHUNK = 65536
# 下行切片：TCP -> WS 每次最多发这么多（二进制帧，无 base64 膨胀）
DOWN_CHUNK = 65536
# 拨号默认预算（放宽版；worker 线上是 2000/4200，实测太紧）
DEF_ATTEMPT_MS = 6000
DEF_ATTEMPTS = 4
DEF_GAP_MS = 250
DEF_TOTAL_MS = 5500      # 略小于客户端 _SETUP_TIMEOUT=6.0s，保证我方先给出明确错误

_LOGLOCK = threading.Lock()


def log(*a):
    with _LOGLOCK:
        sys.stdout.write(time.strftime("%H:%M:%S") + " " + " ".join(str(x) for x in a) + "\n")
        sys.stdout.flush()


# ----------------------------------------------------------------- 工具
def b64e(b):
    return base64.b64encode(b).decode("ascii")


def b64d(s):
    return base64.b64decode(s)


def parse_hp(s, default_port=None):
    """把 "host:port" / "host" 拆开。IPv6 未考虑（住宅是 IPv4）。"""
    s = s.strip()
    if s.count(":") == 1:
        h, _, p = s.rpartition(":")
        try:
            return h, int(p)
        except ValueError:
            pass
    if default_port:
        return s, default_port
    raise ValueError("bad host:port: %r" % s)


def find_double_crlf(b):
    i = b.find(b"\r\n\r\n")
    return i + 4 if i >= 0 else -1


# ----------------------------------------------------------------- WS
class WSSock:
    """最小 WebSocket 服务端。只实现本隧道用到的子集，但帧解析是完整安全的。"""

    def __init__(self, sock):
        self.sock = sock
        self._buf = b""
        self._wlock = threading.Lock()
        self.closed = False

    # ---- 底层读 ----
    def _readn(self, n):
        while len(self._buf) < n:
            try:
                c = self.sock.recv(max(4096, n - len(self._buf)))
            except socket.timeout:
                raise
            if not c:
                raise ConnectionError("eof")
            self._buf += c
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    # ---- 握手 ----
    def handshake(self):
        """读 HTTP 升级请求，回 101。返回 (path, header_bytes)。非升级请求返回 None。"""
        req = b""
        while b"\r\n\r\n" not in req:
            c = self.sock.recv(4096)
            if not c:
                return None
            req += c
            if len(req) > 65536:
                return None
        head, _, rest = req.partition(b"\r\n\r\n")
        self._buf = rest
        lines = head.decode("latin1").split("\r\n")
        request_line = lines[0] if lines else ""
        parts = request_line.split(" ")
        path = parts[1] if len(parts) >= 2 else "/"
        hdrs = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, _, v = ln.partition(":")
                hdrs[k.strip().lower()] = v.strip()

        if hdrs.get("upgrade", "").lower() != "websocket":
            # 非 WS 请求：交给调用方处理（健康检查等）
            return ("__http__", path, head)

        key = hdrs.get("sec-websocket-key", "")
        accept = base64.b64encode(hashlib.sha1(key.encode() + GUID).digest()).decode()
        self.sock.sendall(
            ("HTTP/1.1 101 Switching Protocols\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Accept: %s\r\n\r\n" % accept).encode()
        )
        return ("__ws__", path, None)

    # ---- 帧 ----
    def _read_frame_raw(self):
        h = self._readn(2)
        b0, b1 = h[0], h[1]
        fin = (b0 >> 7) & 1
        op = b0 & 0x0F
        masked = (b1 >> 7) & 1
        ln = b1 & 0x7F
        if ln == 126:
            ln = struct.unpack(">H", self._readn(2))[0]
        elif ln == 127:
            ln = struct.unpack(">Q", self._readn(8))[0]
        mask = self._readn(4) if masked else b""
        payload = self._readn(ln) if ln else b""
        if masked:
            payload = bytes(x ^ mask[i & 3] for i, x in enumerate(payload))
        return fin, op, payload

    def read_message(self):
        """返回 (opcode, payload)。opcode 0x8 = 关闭。自动回 pong / 处理续帧。"""
        while True:
            fin, op, payload = self._read_frame_raw()
            if op == 0x8:
                return (0x8, payload)
            if op == 0x9:            # ping -> pong
                try:
                    self.send_frame(0xA, payload)
                except Exception:
                    pass
                continue
            if op == 0xA:            # pong，忽略
                continue
            if op == 0x0:            # 续帧：合并
                self._frag += payload
                if fin:
                    op2, data = self._frag_op, self._frag
                    self._frag, self._frag_op = b"", None
                    return (op2, data)
                continue
            if not fin:              # 首片
                self._frag, self._frag_op = payload, op
                continue
            return (op, payload)

    def send_frame(self, op, payload):
        hdr = bytearray()
        hdr.append(0x80 | op)        # FIN + opcode
        n = len(payload)
        if n < 126:
            hdr.append(n)            # 服务端 -> 客户端：不 mask
        elif n < 65536:
            hdr.append(126)
            hdr += struct.pack(">H", n)
        else:
            hdr.append(127)
            hdr += struct.pack(">Q", n)
        with self._wlock:
            if self.closed:
                return
            self.sock.sendall(bytes(hdr) + payload)

    def send_text(self, s):
        self.send_frame(0x1, s.encode("ascii"))

    def send_bin(self, b):
        self.send_frame(0x2, b)

    def send_close(self, code=1000):
        try:
            self.send_frame(0x8, struct.pack(">H", code))
        except Exception:
            pass
        self.closed = True

    def close(self):
        self.closed = True
        try:
            self.sock.close()
        except Exception:
            pass


# ----------------------------------------------------------------- 拨号
def dial_up(up_host, up_port, target, budget_ms, auth_header):
    """TCP connect 上游住宅代理 -> 写 CONNECT -> 读 2xx 应答头。返回 (sock, rest)。"""
    deadline = time.time() + budget_ms / 1000.0
    last = None
    while True:
        remain = deadline - time.time()
        if remain <= 0:
            raise last or TimeoutError("dial budget exhausted")
        try:
            s = socket.create_connection((up_host, up_port), timeout=remain)
            break
        except Exception as e:
            last = e
            # 连接被拒/无路由这类"确定性错误"没必要再等
            raise
    try:
        s.settimeout(max(0.5, deadline - time.time()))
        th = target
        s.sendall(("CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n"
                   % (th, th, auth_header)).encode())
        buf = b""
        while True:
            idx = find_double_crlf(buf)
            if idx >= 0:
                break
            if len(buf) > 16384:
                raise ConnectionError("CONNECT response too big")
            c = s.recv(4096)
            if not c:
                raise ConnectionError("upstream closed during CONNECT")
            buf += c
        head = buf[:idx]
        rest = buf[idx:]
        line0 = head.split(b"\r\n", 1)[0].decode("latin1")
        if not (line0.startswith("HTTP/1.1 2") or line0.startswith("HTTP/1.0 2")):
            raise ConnectionError("upstream refused: " + line0[:80])
        s.settimeout(None)
        return s, rest
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        raise


# ----------------------------------------------------------------- 单连接
class Session:
    def __init__(self, ws, peer, args):
        self.ws = ws
        self.peer = peer
        self.args = args
        self.tcp = None
        self.state = {"up": 0, "down": 0, "err": "", "t0": time.time(), "label": "?"}

    def run(self):
        r = self.ws.handshake()
        if r is None:
            self.ws.close()
            return
        kind, path, head = r
        if kind == "__http__":
            self._http(path, head)
            return

        # 鉴权：客户端带 ?a=<token>
        q = {}
        if "?" in path:
            for kv in path.split("?", 1)[1].split("&"):
                if "=" in kv:
                    k, _, v = kv.partition("=")
                    q[k] = v
        import urllib.parse as _up
        want = self.args.auth
        got = _up.unquote(q.get("a", ""))
        if want and got != want:
            log("AUTH-FAIL", self.peer, "got=%r" % got[:12])
            self.ws.send_close(4003)
            self.ws.close()
            return
        mode = q.get("m", "up")
        if mode != "direct":
            mode = "up"

        # 首帧：base64("host:port")
        try:
            self.ws.sock.settimeout(25.0)
            op, payload = self.ws.read_message()
            if op == 0x8:
                self.ws.close()
                return
            raw = b64d(payload.decode("ascii")) if op == 0x1 else payload
        except Exception as e:
            log("HELLO-FAIL", self.peer, repr(e)[:80])
            self._err("bad hello: %s" % e)
            return

        try:
            host, port = parse_hp(raw.decode("latin1"))
        except Exception as e:
            self._err("bad target: %s" % e)
            return
        self.state["label"] = "%s:%d" % (host, port)
        log("CONN", self.peer, "mode=%s" % mode, self.state["label"])

        # 拨号
        rest = b""
        if mode == "up":
            ok, res = self._dial_upstream(host, port)
            if not ok:
                return
            self.tcp, rest = res
        else:
            try:
                self.tcp = socket.create_connection((host, port), timeout=20)
                self.tcp.settimeout(None)
            except Exception as e:
                self._err("direct dial failed: %s" % e)
                return
        if rest:
            self.ws.send_bin(rest)
            self.state["down"] += len(rest)

        # 双向搬运
        self.ws.sock.settimeout(90.0)   # 90s 内没有任何上行帧 -> 认为死链
        t = threading.Thread(target=self._tcp_to_ws, daemon=True)
        t.start()
        self._ws_to_tcp()
        self._finish()

    def _dial_upstream(self, host, port):
        target = "%s:%d" % (host, port)
        auth_header = self.args.up_auth_header
        deadline = time.time() + self.args.dial_total_ms / 1000.0
        last = None
        for i in range(self.args.dial_attempts):
            if time.time() >= deadline:
                break
            remain_ms = max(200, int((deadline - time.time()) * 1000))
            budget = min(self.args.dial_attempt_ms, remain_ms)
            t0 = time.time()
            try:
                s, rest = dial_up(self.args.up_host, self.args.up_port,
                                  target, budget, auth_header)
                ms = int((time.time() - t0) * 1000)
                log("dial ok", "attempt=%d/%d" % (i + 1, self.args.dial_attempts),
                    target, "ms=%d" % ms)
                self.tcp = s
                return True, (s, rest)
            except Exception as e:
                last = e
                log("dial FAIL", "attempt=%d/%d" % (i + 1, self.args.dial_attempts),
                    target, "ms=%d" % int((time.time() - t0) * 1000), ":", repr(e)[:90])
                if i + 1 < self.args.dial_attempts:
                    time.sleep(self.args.dial_gap_ms / 1000.0)
        log("dial GIVEUP", target, "tries=%d" % self.args.dial_attempts,
            "total=%dms" % int(self.args.dial_total_ms))
        self._err("relay: %s" % (last or "dial failed"))
        return False, None

    def _ws_to_tcp(self):
        while True:
            try:
                op, payload = self.ws.read_message()
            except socket.timeout:
                # 客户端每 ~25s 会发 base64("__v1__")，真死链不会到这里两次
                self.state["err"] = self.state["err"] or "上行 90s 无帧"
                return
            except Exception as e:
                self.state["err"] = self.state["err"] or ("上行异常 %s: %s"
                                                          % (type(e).__name__, str(e)[:60]))
                return
            if op == 0x8:
                self.state["err"] = self.state["err"] or "客户端 close"
                return
            if op == 0x1:
                try:
                    raw = b64d(payload.decode("ascii"))
                except Exception:
                    raw = payload        # 容错：非 base64 的原样处理
            else:
                raw = payload
            # 应用层保活：拦下 base64("__v1__")，回 base64("__v1ok__")，不写上游
            if raw == b"__v1__":
                try:
                    self.ws.send_text(b64e(b"__v1ok__"))
                except Exception:
                    return
                continue
            if not raw:
                continue
            try:
                self.tcp.sendall(raw)
                self.state["up"] += len(raw)
            except Exception as e:
                self.state["err"] = self.state["err"] or ("写上游失败 %s" % str(e)[:60])
                return

    def _tcp_to_ws(self):
        while True:
            try:
                data = self.tcp.recv(DOWN_CHUNK)
            except Exception as e:
                self.state["err"] = self.state["err"] or ("读上游失败 %s" % str(e)[:60])
                break
            if not data:
                self.state["err"] = self.state["err"] or "上游关闭"
                break
            try:
                self.ws.send_bin(data)
                self.state["down"] += len(data)
            except Exception as e:
                self.state["err"] = self.state["err"] or ("写 WS 失败 %s" % str(e)[:60])
                break
        try:
            self.ws.send_close(1000)
        except Exception:
            pass

    def _err(self, msg):
        """与 worker 一致：文本帧 base64("EDGE_ERR ...")，然后干净关闭。"""
        try:
            self.ws.send_text(b64e(("EDGE_ERR " + str(msg)).encode("utf-8")))
        except Exception:
            pass
        try:
            self.ws.send_close(1011)
        except Exception:
            pass
        self.ws.close()

    def _finish(self):
        st = self.state
        log("中继结束", st["label"], "| 时长 %.1fs" % (time.time() - st["t0"]),
            "| 上行 %.1fKB" % (st["up"] / 1024.0),
            "| 下行 %.1fKB" % (st["down"] / 1024.0),
            "|", st["err"] or "正常")
        for x in (self.tcp, self.ws):
            try:
                x.close()
            except Exception:
                pass

    def _http(self, path, head):
        body = ('{"ok":true,"svc":"wstun-edge","up":"%s:%d","ts":"%s"}\n'
                % (self.args.up_host, self.args.up_port,
                   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
        try:
            if path.startswith("/health") or path == "/":
                self.ws.sock.sendall(
                    ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                     "Content-Length: %d\r\nConnection: close\r\n\r\n%s"
                     % (len(body), body)).encode())
            else:
                self.ws.sock.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        except Exception:
            pass
        self.ws.close()


# ----------------------------------------------------------------- 环境变量
def env(name, default=None):
    """PaaS 友好：环境变量优先于内置默认值；空字符串视为未设置。"""
    v = os.environ.get(name)
    return v if v not in (None, "") else default


# ----------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="wstun 自建边缘端（非 CF）")
    # ⚠️ PaaS（Render / Koyeb）会注入 PORT，且只允许监听该端口、必须绑 0.0.0.0。
    #    这里的默认值走环境变量，命令行显式给参仍可覆盖。
    ap.add_argument("--listen", default=env("LISTEN",
                                            "0.0.0.0:" + env("PORT", "8080")))
    # ⚠️ 本仓库不含任何凭据：以下全部为空，必须由环境变量或命令行提供。
    ap.add_argument("--auth", default=env("AUTH", ""))
    ap.add_argument("--up", default=env("UP", ""))
    ap.add_argument("--up-user", default=env("UP_USER", ""))
    ap.add_argument("--up-pass", default=env("UP_PASS", ""))
    ap.add_argument("--dial-attempt-ms", type=int, default=DEF_ATTEMPT_MS)
    ap.add_argument("--dial-attempts", type=int, default=DEF_ATTEMPTS)
    ap.add_argument("--dial-gap-ms", type=int, default=DEF_GAP_MS)
    ap.add_argument("--dial-total-ms", type=int, default=DEF_TOTAL_MS)
    ap.add_argument("--tls-cert", default=None)
    ap.add_argument("--tls-key", default=None)
    args = ap.parse_args()

    h, _, p = args.listen.rpartition(":")
    listen_host, listen_port = (h or "0.0.0.0"), int(p)

    # ---- 配置自检：缺一项就明确报错，别让它以“连不上”的形式表现出来 ----
    if not args.up:
        log("FATAL 未配置上游住宅代理地址。请设置环境变量 UP=host:port （或在平台面板里填 Secret）")
        sys.exit(2)
    if not args.auth:
        log("WARN 未配置 AUTH：任何人都能用这个中继（强烈建议在平台面板里设置 AUTH）")
    if not args.up_user:
        log("WARN 未配置 UP_USER/UP_PASS：上游代理很可能因未授权而拒绝拨号")

    args.up_host, args.up_port = parse_hp(args.up, 50100)
    args.up_auth_header = ""
    if args.up_user:
        tok = base64.b64encode(("%s:%s" % (args.up_user, args.up_pass)).encode()).decode()
        args.up_auth_header = "Proxy-Authorization: Basic %s\r\n" % tok

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((listen_host, listen_port))
    srv.listen(128)

    ctx = None
    if args.tls_cert and args.tls_key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.tls_cert, args.tls_key)
        log("TLS 已启用")

    log("wstun-edge 监听 %s:%d  upstream=%s:%d  auth=%s"
        % (listen_host, listen_port, args.up_host, args.up_port,
           "on" if args.auth else "off"))
    log("拨号预算 attempt=%dms attempts=%d total=%dms"
        % (args.dial_attempt_ms, args.dial_attempts, args.dial_total_ms))

    while True:
        try:
            conn, peer = srv.accept()
        except KeyboardInterrupt:
            break
        except Exception as e:
            log("accept err", repr(e)[:80])
            continue
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if ctx is not None:
            try:
                conn = ctx.wrap_socket(conn, server_side=True)
            except Exception as e:
                log("TLS-HANDSHAKE-FAIL", peer, repr(e)[:70])
                try:
                    conn.close()
                except Exception:
                    pass
                continue
        ws = WSSock(conn)
        t = threading.Thread(target=_safe_run, args=(ws, peer, args), daemon=True)
        t.start()


def _safe_run(ws, peer, args):
    try:
        Session(ws, peer, args).run()
    except Exception as e:
        log("SESSION-ERR", peer, repr(e)[:100])
        try:
            ws.close()
        except Exception:
            pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass

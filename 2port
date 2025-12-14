#!/usr/bin/env python3
import socket
import threading
import struct
import select
import os
from datetime import datetime
import zoneinfo
from urllib.parse import urlparse, parse_qs

try:
    import setproctitle
except ImportError:
    setproctitle = None

# ================== HTTP 服务 ==================
HTTP_PORT = int(os.getenv("HTTP_PORT", "8008"))
COMMON_TIMEZONES = ["UTC", "Asia/Shanghai", "Asia/Tokyo", "America/New_York"]

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><title>HTTP 掩护</title></head>
<body>
<h3>当前 UTC 时间</h3>
<p>{}</p>
</body>
</html>
"""

def handle_http_request(client):
    try:
        client.recv(1024)  # 简单丢弃请求头
        now = datetime.now(zoneinfo.ZoneInfo("UTC"))
        response = HTML_TEMPLATE.format(now.isoformat()).encode("utf-8")
        client.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n"
            b"Connection: close\r\n\r\n" + response
        )
    except:
        pass
    finally:
        client.close()

def start_http():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", HTTP_PORT))
    s.listen(100)
    print(f"[INFO] HTTP listening on {HTTP_PORT}")
    while True:
        client, _ = s.accept()
        threading.Thread(target=handle_http_request, args=(client,), daemon=True).start()


# ================== SOCKS5 服务 ==================
SOCKS5_PORT = int(os.getenv("SOCKS5_PORT", "8009"))
SOCKS5_USER = os.getenv("USER", "admin")
SOCKS5_PASS = os.getenv("PASS", "password123")
SOCKS_VERSION = 5
AUTH_USERPASS = 0x02

class Socks5Server:

    def handle_client(self, client):
        remote = None
        try:
            # ---- 1. 协商（强制用户名密码）----
            header = self._recvn(client, 2)
            if not header:
                return
            ver, nmethods = struct.unpack("!BB", header)
            if ver != SOCKS_VERSION:
                return
            methods = self._recvn(client, nmethods)
            if AUTH_USERPASS not in methods:
                client.sendall(struct.pack("!BB", SOCKS_VERSION, 0xFF))
                return
            client.sendall(struct.pack("!BB", SOCKS_VERSION, AUTH_USERPASS))

            # ---- 2. 用户名密码认证 ----
            if not self._auth_userpass(client):
                return

            # ---- 3. 请求 ----
            req = self._recvn(client, 4)
            if not req:
                return
            ver, cmd, _, atyp = struct.unpack("!BBBB", req)
            if ver != SOCKS_VERSION or cmd != 0x01:
                self._reply(client, 0x07)
                return

            if atyp == 0x01:      # IPv4
                addr = socket.inet_ntoa(self._recvn(client, 4))
            elif atyp == 0x03:    # 域名
                length = self._recvn(client, 1)[0]
                addr = self._recvn(client, length).decode()
            else:
                self._reply(client, 0x08)
                return

            port = struct.unpack("!H", self._recvn(client, 2))[0]

            # ---- 4. 连接目标 ----
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect((addr, port))
            bind_addr, bind_port = remote.getsockname()
            self._reply(client, 0x00, bind_addr, bind_port)

            # ---- 5. 转发 ----
            self._relay(client, remote)

        except:
            pass
        finally:
            try:
                if remote:
                    remote.close()
                client.close()
            except:
                pass

    # ---------- 工具函数 ----------
    def _auth_userpass(self, client):
        data = self._recvn(client, 2)
        if not data:
            return False
        _, ulen = struct.unpack("!BB", data)
        user = self._recvn(client, ulen).decode()
        plen = self._recvn(client, 1)[0]
        pwd = self._recvn(client, plen).decode()
        if user == SOCKS5_USER and pwd == SOCKS5_PASS:
            client.sendall(struct.pack("!BB", 0x01, 0x00))
            return True
        client.sendall(struct.pack("!BB", 0x01, 0x01))
        return False

    def _reply(self, client, rep, addr="0.0.0.0", port=0):
        client.sendall(
            struct.pack("!BBBB4sH",
                        SOCKS_VERSION, rep, 0x00, 0x01,
                        socket.inet_aton(addr), port)
        )

    def _relay(self, a, b):
        while True:
            r, _, _ = select.select([a, b], [], [], 300)
            if not r:
                break
            for s in r:
                data = s.recv(4096)
                if not data:
                    return
                (b if s is a else a).sendall(data)

    def _recvn(self, sock, n):
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

def start_socks5():
    server = Socks5Server()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", SOCKS5_PORT))
    s.listen(100)
    print(f"[INFO] 隐藏 listening on {SOCKS5_PORT}")
    while True:
        client, _ = s.accept()
        threading.Thread(target=server.handle_client, args=(client,), daemon=True).start()


# ================== 主线程 ==================
if __name__ == "__main__":
    if setproctitle:
        setproctitle.setproctitle("system-helper")

    threading.Thread(target=start_http, daemon=True).start()
    threading.Thread(target=start_socks5, daemon=True).start()

    print("[INFO] HTTP + 隐藏 两个服务已启动")
    threading.Event().wait()

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

# ========================== HTTP 配置 ==========================
COMMON_TIMEZONES = [
    "UTC", "Asia/Shanghai", "Asia/Tokyo", "Asia/Dubai", "Asia/Singapore",
    "Europe/London", "Europe/Berlin", "Europe/Paris",
    "America/New_York", "America/Los_Angeles"
]

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><title>时区时间查询</title></head>
<body>
<form method="GET">
<select name="timezone" onchange="this.form.submit()">
<option value="" disabled {init}>-- 选择时区 --</option>
{options}
</select>
</form>
<div>{result}</div>
</body>
</html>
"""

def generate_html(result, selected=None):
    opts = ""
    for tz in COMMON_TIMEZONES:
        sel = " selected" if tz == selected else ""
        opts += f'<option value="{tz}"{sel}>{tz}</option>'
    return HTML_TEMPLATE.format(
        options=opts,
        result=result,
        init="selected" if not selected else ""
    )

def handle_http(client):
    try:
        req = client.recv(4096).decode(errors="ignore")
        if not req:
            return
        path = req.split(" ")[1]
        q = parse_qs(urlparse(path).query)
        tz = q.get("timezone", [None])[0]

        result = "<p>请选择一个时区</p>"
        if tz:
            try:
                now = datetime.now(zoneinfo.ZoneInfo("UTC")).astimezone(
                    zoneinfo.ZoneInfo(tz)
                )
                result = f"<b>{tz}</b><br>{now.strftime('%Y-%m-%d %H:%M:%S %Z')}"
            except Exception as e:
                result = f"<span style='color:red'>{e}</span>"

        html = generate_html(result, tz)
        resp = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(html.encode())}\r\n"
            "Connection: close\r\n\r\n"
            f"{html}"
        )
        client.sendall(resp.encode())
    finally:
        client.close()

# ========================== SOCKS5 ==========================
SOCKS_VERSION = 5

class Socks5Server:
    def __init__(self, users):
        self.users = users

    def handle(self, client):
        try:
            # ---- handshake ----
            ver, nmethods = client.recv(2)
            methods = client.recv(nmethods)

            if 0x02 in methods:
                client.sendall(struct.pack("!BB", 5, 0x02))
                if not self.auth(client):
                    return
            elif 0x00 in methods:
                client.sendall(struct.pack("!BB", 5, 0x00))
            else:
                client.sendall(struct.pack("!BB", 5, 0xFF))
                return

            # ---- request ----
            ver, cmd, _, atyp = struct.unpack("!BBBB", client.recv(4))
            if cmd != 1:
                self.reply(client, 0x07)
                return

            if atyp == 1:   # IPv4
                addr = socket.inet_ntoa(client.recv(4))
            elif atyp == 3: # domain
                l = client.recv(1)[0]
                addr = client.recv(l).decode()
            elif atyp == 4: # IPv6
                addr = socket.inet_ntop(socket.AF_INET6, client.recv(16))
            else:
                self.reply(client, 0x08)
                return

            port = struct.unpack("!H", client.recv(2))[0]

            # ---- connect (IPv4/IPv6 auto) ----
            remote = None
            for af, st, pr, _, sa in socket.getaddrinfo(addr, port, socket.AF_UNSPEC, socket.SOCK_STREAM):
                try:
                    remote = socket.socket(af, st, pr)
                    remote.connect(sa)
                    break
                except Exception:
                    continue

            if not remote:
                self.reply(client, 0x01)
                return

            bind_addr, bind_port = remote.getsockname()[:2]
            self.reply(client, 0x00)

            self.relay(client, remote)

        finally:
            client.close()

    def auth(self, client):
        ver = client.recv(1)[0]
        ulen = client.recv(1)[0]
        user = client.recv(ulen).decode()
        plen = client.recv(1)[0]
        pwd = client.recv(plen).decode()

        if self.users.get(user) == pwd:
            client.sendall(b"\x01\x00")
            return True
        client.sendall(b"\x01\x01")
        return False

    def reply(self, client, code):
        client.sendall(
            struct.pack("!BBBBIH", 5, code, 0, 1, 0, 0)
        )

    def relay(self, c, r):
        try:
            while True:
                rs, _, _ = select.select([c, r], [], [], 300)
                if not rs:
                    break
                for s in rs:
                    data = s.recv(4096)
                    if not data:
                        return
                    (r if s is c else c).sendall(data)
        finally:
            r.close()

# ========================== 启动 ==========================
if __name__ == "__main__":
    HOST = "0.0.0.0"
    HTTP_PORT = 8008
    SOCKS_PORT = 8009

    USER = os.getenv("SOCKS_USER", "admin")
    PASS = os.getenv("SOCKS_PASS", "xiao123456")

    server = Socks5Server({USER: PASS})

    if setproctitle:
        setproctitle.setproctitle("system-helper")

    def http_srv():
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, HTTP_PORT))
        s.listen()
        print(f"HTTP :{HTTP_PORT}")
        while True:
            c, _ = s.accept()
            threading.Thread(target=handle_http, args=(c,), daemon=True).start()

    def socks_srv():
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, SOCKS_PORT))
        s.listen()
        print(f"SOCKS5 :{SOCKS_PORT}")
        while True:
            c, _ = s.accept()
            threading.Thread(target=server.handle, args=(c,), daemon=True).start()

    threading.Thread(target=http_srv, daemon=True).start()
    threading.Thread(target=socks_srv, daemon=True).start()

    print("INFO: services started")
    threading.Event().wait()

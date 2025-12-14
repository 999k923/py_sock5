#!/usr/bin/env python3
import socket
import threading
import struct
import select
import os

# ================== 配置 ==================
HOST = "0.0.0.0"
PORT = int(os.getenv("SOCKS5_PORT", "8009"))
USERNAME = os.getenv("SOCKS_USER", "admin")
PASSWORD = os.getenv("SOCKS_PASS", "xiao123456")

# SOCKS5 常量
SOCKS_VERSION = 5
AUTH_USERPASS = 0x02

# ================== SOCKS5 实现 ==================
class Socks5Server:

    def handle_client(self, client):
        try:
            # ---- 1. 协商 ----
            data = client.recv(2)
            if len(data) < 2:
                return

            ver, nmethods = struct.unpack("!BB", data)
            if ver != SOCKS_VERSION:
                return

            methods = client.recv(nmethods)
            if AUTH_USERPASS not in methods:
                client.sendall(struct.pack("!BB", SOCKS_VERSION, 0xFF))
                return

            client.sendall(struct.pack("!BB", SOCKS_VERSION, AUTH_USERPASS))

            # ---- 2. 用户名密码认证 ----
            data = client.recv(2)
            if len(data) < 2:
                return

            _, ulen = struct.unpack("!BB", data)
            uname = client.recv(ulen).decode()
            plen = client.recv(1)[0]
            passwd = client.recv(plen).decode()

            if uname != USERNAME or passwd != PASSWORD:
                client.sendall(struct.pack("!BB", 0x01, 0x01))
                return

            client.sendall(struct.pack("!BB", 0x01, 0x00))

            # ---- 3. 请求 ----
            data = client.recv(4)
            if len(data) < 4:
                return

            ver, cmd, _, atyp = struct.unpack("!BBBB", data)
            if ver != SOCKS_VERSION or cmd != 0x01:
                self.reply(client, 0x07)
                return

            if atyp == 0x01:  # IPv4
                addr = socket.inet_ntoa(client.recv(4))
            elif atyp == 0x03:  # 域名
                length = client.recv(1)[0]
                addr = client.recv(length).decode()
            else:
                self.reply(client, 0x08)
                return

            port = struct.unpack("!H", client.recv(2))[0]

            # ---- 4. 连接目标 ----
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect((addr, port))

            bind_addr, bind_port = remote.getsockname()
            self.reply(client, 0x00, bind_addr, bind_port)

            # ---- 5. 转发 ----
            self.forward(client, remote)

        except Exception:
            pass
        finally:
            try:
                client.close()
            except:
                pass

    def reply(self, client, rep, bind_addr="0.0.0.0", bind_port=0):
        client.sendall(
            struct.pack(
                "!BBBB4sH",
                SOCKS_VERSION,
                rep,
                0x00,
                0x01,
                socket.inet_aton(bind_addr),
                bind_port,
            )
        )

    def forward(self, client, remote):
        try:
            while True:
                r, _, _ = select.select([client, remote], [], [], 300)
                if not r:
                    break
                for s in r:
                    data = s.recv(4096)
                    if not data:
                        return
                    (remote if s is client else client).sendall(data)
        finally:
            remote.close()


# ================== 启动 ==================
def main():
    server = Socks5Server()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(128)

    print(f"[INFO] SOCKS5 listening on {HOST}:{PORT}")

    while True:
        client, _ = sock.accept()
        threading.Thread(target=server.handle_client, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()

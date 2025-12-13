import socket
import threading
import struct
import select
import sys
import os
from datetime import datetime
import zoneinfo
from urllib.parse import urlparse, parse_qs

try:
    import setproctitle
except ImportError:
    setproctitle = None

# ========================== HTTP 配置 ==========================
COMMON_TIMEZONES = sorted([
    "UTC", "Asia/Shanghai", "Asia/Tokyo", "Asia/Dubai", "Asia/Singapore",
    "Europe/London", "Europe/Berlin", "Europe/Paris", "Europe/Moscow",
    "Europe/Warsaw", "America/New_York", "America/Chicago",
    "America/Los_Angeles", "Pacific/Auckland", "Australia/Sydney"
])

TIMEZONE_COORDS = {
    "UTC": [51.5074, -0.1278, 5],
    "Asia/Shanghai": [31.2304, 121.4737, 7],
    "Asia/Tokyo": [35.6895, 139.6917, 7],
    "Asia/Dubai": [25.276987, 55.296249, 8],
    "Asia/Singapore": [1.3521, 103.8198, 8],
    "Europe/London": [51.5074, -0.1278, 8],
    "Europe/Berlin": [52.5200, 13.4050, 8],
    "Europe/Paris": [48.8566, 2.3522, 8],
    "Europe/Moscow": [55.7558, 37.6173, 7],
    "Europe/Warsaw": [52.2297, 21.0122, 8],
    "America/New_York": [40.7128, -74.0060, 7],
    "America/Chicago": [41.8781, -87.6298, 7],
    "America/Los_Angeles": [34.0522, -118.2437, 7],
    "Pacific/Auckland": [-36.8485, 174.7633, 7],
    "Australia/Sydney": [-33.8688, 151.2093, 7]
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>时区时间查询</title>
</head>
<body>
<form method="GET" action="/">
<select name="timezone" onchange="this.form.submit()">
<option value="" disabled {initial_select_state}>--- 请选择一个时区 ---</option>
{options_placeholder}
</select>
</form>
<div>{result_placeholder}</div>
</body>
</html>"""

def generate_html_page(result_html, selected_tz=None):
    options_html = ""
    for tz in COMMON_TIMEZONES:
        is_selected = ' selected' if tz == selected_tz else ''
        options_html += f'<option value="{tz}"{is_selected}>{tz}</option>'
    return HTML_TEMPLATE.format(
        options_placeholder=options_html,
        result_placeholder=result_html,
        initial_select_state='selected' if not selected_tz else ''
    )

def handle_http_request(client_socket):
    result_html = "<p>请从下拉菜单中选择一个时区。</p>"
    selected_tz_name = None
    try:
        request_data = client_socket.recv(4096).decode('utf-8', 'ignore')
        if not request_data:
            client_socket.close(); return

        first_line = request_data.split('\r\n')[0]
        if ' ' not in first_line: client_socket.close(); return
        
        path = first_line.split(' ')[1]
        parsed_url = urlparse(path)
        query_params = parse_qs(parsed_url.query)

        selected_tz_name = query_params.get('timezone', [None])[0]

        if selected_tz_name:
            try:
                target_tz = zoneinfo.ZoneInfo(selected_tz_name)
                utc_now = datetime.now(zoneinfo.ZoneInfo("UTC"))
                local_time = utc_now.astimezone(target_tz)
                formatted_time = local_time.strftime('%Y-%m-%d %H:%M:%S %Z')
                result_html = f"<b>{selected_tz_name}</b><br>当前时间: {formatted_time}"
            except Exception as e:
                result_html = f"<p style='color: red;'>查询时发生错误: {e}</p>"
        
        final_html = generate_html_page(result_html, selected_tz_name)
        http_response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(final_html.encode('utf-8'))}\r\n"
            "Connection: close\r\n\r\n"
            f"{final_html}"
        ).encode('utf-8')
        
        client_socket.sendall(http_response)

    except Exception:
        pass
    finally:
        client_socket.close()

# ========================== SOCKS5 配置 ==========================
PROTOCOL_VERSION = 5
AUTH_METHOD = 0x02

class IPForwarder:
    def __init__(self, credentials):
        self.credentials = credentials

    def process_request(self, client_socket):
        try:
            header = client_socket.recv(2)
            if not header or header[0] != PROTOCOL_VERSION: return
            nmethods = header[1]
            methods = client_socket.recv(nmethods)
            if AUTH_METHOD not in methods:
                client_socket.sendall(struct.pack("!BB", PROTOCOL_VERSION, 0xFF)); return
            client_socket.sendall(struct.pack("!BB", PROTOCOL_VERSION, AUTH_METHOD))
            if not self.authenticate(client_socket): return
            header = client_socket.recv(4)
            if not header or len(header) < 4: return
            ver, cmd, rsv, atyp = struct.unpack("!BBBB", header)
            if ver != PROTOCOL_VERSION or cmd != 0x01:
                self.send_reply(client_socket, 0x07); return
            if atyp == 0x01:
                dest_addr = socket.inet_ntoa(client_socket.recv(4))
            elif atyp == 0x03:
                domain_len = client_socket.recv(1)[0]
                dest_addr = client_socket.recv(domain_len).decode('utf-8')
            elif atyp == 0x04:
                dest_addr = socket.inet_ntop(socket.AF_INET6, client_socket.recv(16))
            else:
                self.send_reply(client_socket, 0x08); return
            dest_port = struct.unpack('!H', client_socket.recv(2))[0]
            try:
                remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote_socket.connect((dest_addr, dest_port))
                bind_addr, bind_port = remote_socket.getsockname()
                self.send_reply(client_socket, 0x00, socket.inet_aton(bind_addr), bind_port)
            except Exception:
                self.send_reply(client_socket, 0x01); return
            self.relay_data(client_socket, remote_socket)
        except Exception:
            pass
        finally:
            client_socket.close()

    def authenticate(self, client_socket):
        try:
            header = client_socket.recv(2)
            if not header or header[0] != 0x01: return False
            ulen = header[1]
            username = client_socket.recv(ulen).decode('utf-8')
            plen = client_socket.recv(1)[0]
            password = client_socket.recv(plen).decode('utf-8')
            if self.credentials.get(username) == password:
                client_socket.sendall(struct.pack("!BB", 0x01, 0x00)); return True
            else:
                client_socket.sendall(struct.pack("!BB", 0x01, 0x01)); return False
        except Exception:
            return False

    def send_reply(self, client_socket, rep, bnd_addr=b'\x00\x00\x00\x00', bnd_port=0):
        reply = struct.pack("!BBBB", PROTOCOL_VERSION, rep, 0x00, 0x01) + bnd_addr + struct.pack("!H", bnd_port)
        client_socket.sendall(reply)

    def relay_data(self, client_socket, remote_socket):
        try:
            while True:
                readable, _, _ = select.select([client_socket, remote_socket], [], [], 300)
                if not readable: break
                for sock in readable:
                    data = sock.recv(4096)
                    if not data: return
                    other_sock = remote_socket if sock is client_socket else client_socket
                    other_sock.sendall(data)
        except Exception:
            pass
        finally:
            remote_socket.close()

# ========================== 启动服务 ==========================
if __name__ == '__main__':
    HOST = '0.0.0.0'
    HTTP_PORT = 8008
    SOCKS5_PORT = 8009
    IP_SERVICE_CREDENTIALS = {'admin': 'xiao123456'}

    ip_forwarder = IPForwarder(IP_SERVICE_CREDENTIALS)

    if setproctitle:
        setproctitle.setproctitle("system-helper")

    # HTTP 服务线程
    def start_http():
        http_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        http_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        http_sock.bind((HOST, HTTP_PORT))
        http_sock.listen(100)
        print(f"HTTP 服务启动：{HOST}:{HTTP_PORT}")
        while True:
            client, addr = http_sock.accept()
            threading.Thread(target=handle_http_request, args=(client,), daemon=True).start()

    # SOCKS5 服务线程
    def start_socks5():
        socks_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socks_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        socks_sock.bind((HOST, SOCKS5_PORT))
        socks_sock.listen(100)
        print(f"SOCKS5 服务启动：{HOST}:{SOCKS5_PORT}")
        while True:
            client, addr = socks_sock.accept()
            threading.Thread(target=ip_forwarder.process_request, args=(client,), daemon=True).start()

    threading.Thread(target=start_http, daemon=True).start()
    threading.Thread(target=start_socks5, daemon=True).start()

    print("INFO: 两个服务已启动，按 Ctrl+C 停止")
    try:
        while True:
            threading.Event().wait(1)
    except KeyboardInterrupt:
        print("INFO: 停止服务")

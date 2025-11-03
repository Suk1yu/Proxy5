import socket
import threading
import signal
import os
import sys
import logging
import queue
import ctypes
import json
import hashlib
import hmac
import ipaddress
import struct
import asyncio
import selectors
import http.server
import socketserver
from logging.handlers import RotatingFileHandler
from concurrent.futures import ThreadPoolExecutor
from threading import Event
import time
from colorama import init, Fore, Style
from urllib.parse import urlparse
from datetime import datetime, timedelta
import argparse

# Konfigurasi dasar
PID_FILE = "socks5_proxy.pid"
LOG_FILE = "socks5_proxy.log"
CONFIG_FILE = "socks5_config.json"
USERS_FILE = "socks5_users.json"
ACL_FILE = "socks5_acl.json"

# Konfigurasi default
DEFAULT_CONFIG = {
    "host": "0.0.0.0",
    "port": 1080,
    "control_port": 1081,
    "max_bytes": 1024 * 1024 * 1024,  # 1 GB per koneksi
    "max_threads": 50,
    "backlog_size": 100,
    "rate_limit": 55024 * 1024,  # bytes per detik
    "timeout": 360,
    "bucket_size": 1024 * 1024,  # 1MB bucket size
    "socket_buffer_size": 65536,  # 64KB buffer
    "global_rate_limit": 100 * 1024 * 1024,  # 100MB/s global
    "per_ip_rate_limit": 10 * 1024 * 1024,  # 10MB/s per IP
    "max_connections_per_ip": 10,
    "enable_auth": True,
    "enable_udp": True,
    "enable_bind": True,
    "anonymous_mode": False,
    "no_log": False,
    "async_mode": False,
    "log_level": "INFO"
}

# Global variables
config = DEFAULT_CONFIG.copy()
users_db = {}
acl_rules = []
global_rate_limiter = None
ip_rate_limiters = {}
ip_connections = {}
udp_associations = {}

def load_config():
    """Memuat konfigurasi dari file."""
    global config
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                file_config = json.load(f)
                config.update(file_config)
        except Exception as e:
            print(f"Error loading config: {e}")

def save_config():
    """Menyimpan konfigurasi ke file."""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        print(f"Error saving config: {e}")

def load_users():
    """Memuat database pengguna."""
    global users_db
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r') as f:
                users_db = json.load(f)
        except Exception as e:
            print(f"Error loading users: {e}")
    else:
        # Default user untuk testing
        users_db = {
            "admin": {
                "password": "admin123",
                "allowed_ips": ["0.0.0.0/0"],
                "rate_limit": 50 * 1024 * 1024  # 50MB/s
            }
        }
        save_users()

def save_users():
    """Menyimpan database pengguna."""
    try:
        with open(USERS_FILE, 'w') as f:
            json.dump(users_db, f, indent=2)
    except Exception as e:
        print(f"Error saving users: {e}")

def load_acl():
    """Memuat aturan ACL."""
    global acl_rules
    if os.path.exists(ACL_FILE):
        try:
            with open(ACL_FILE, 'r') as f:
                acl_rules = json.load(f)
        except Exception as e:
            print(f"Error loading ACL: {e}")
    else:
        # Default ACL
        acl_rules = [
            {"action": "allow", "cidr": "127.0.0.0/8", "comment": "localhost"},
            {"action": "allow", "cidr": "192.168.0.0/16", "comment": "private network"},
            {"action": "allow", "cidr": "10.0.0.0/8", "comment": "private network"},
            {"action": "deny", "cidr": "0.0.0.0/0", "comment": "deny all others"}
        ]
        save_acl()

def save_acl():
    """Menyimpan aturan ACL."""
    try:
        with open(ACL_FILE, 'w') as f:
            json.dump(acl_rules, f, indent=2)
    except Exception as e:
        print(f"Error saving ACL: {e}")

def check_acl(client_ip):
    """Memeriksa apakah IP klien diizinkan oleh ACL."""
    client_addr = ipaddress.ip_address(client_ip)
    for rule in acl_rules:
        network = ipaddress.ip_network(rule["cidr"], strict=False)
        if client_addr in network:
            return rule["action"] == "allow"
    return False

def setup_logging():
    """Setup logging dengan konfigurasi yang tepat."""
    if config.get("no_log", False):
        logging.disable(logging.CRITICAL)
        return
    
    log_level = getattr(logging, config.get("log_level", "INFO").upper())
    
    # Setup handlers
    handlers = []
    
    if not config.get("no_log", False):
        log_handler = RotatingFileHandler(
            LOG_FILE,
            maxBytes=10 * 1024 * 1024,  # 10MB per file
            backupCount=5,
            encoding='utf-8'
        )
        handlers.append(log_handler)
    
    console_handler = logging.StreamHandler(sys.stdout)
    handlers.append(console_handler)
    
    logging.basicConfig(
        level=log_level,
        format="[ %(asctime)s ] %(levelname)s ⦂ %(message)s",
        datefmt="%H:%M:%S",
        handlers=handlers,
        force=True
    )
    
    return logging.getLogger()

# Fungsi helper untuk menerima data dengan panjang yang tepat
def recv_exact(sock, n):
    """Menerima tepat n bytes dari socket."""
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Koneksi terputus saat menerima data")
        data += chunk
    return data

def mask_address(addr):
    """Menyamarkan alamat untuk mode anonymous."""
    if config.get("anonymous_mode", False):
        if ":" in addr:  # IPv6
            return "****:****:****:****"
        elif "." in addr:  # IPv4
            return "***.***.***.**"
        else:  # Domain
            return "*****.***"
    return addr

# Kelas TokenBucket untuk rate limiting
class TokenBucket:
    def __init__(self, capacity, refill_rate):
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate
        self.last_refill = time.time()
        self.lock = threading.Lock()
    
    def consume(self, tokens):
        with self.lock:
            now = time.time()
            elapsed = now - self.last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
            self.last_refill = now
            
            if tokens <= self.tokens:
                self.tokens -= tokens
                return 0
            else:
                wait_time = (tokens - self.tokens) / self.refill_rate
                return wait_time

class GlobalRateLimiter:
    def __init__(self, rate_limit):
        self.bucket = TokenBucket(rate_limit, rate_limit)
        self.per_ip_buckets = {}
        self.lock = threading.Lock()
    
    def get_ip_bucket(self, ip):
        with self.lock:
            if ip not in self.per_ip_buckets:
                per_ip_limit = config.get("per_ip_rate_limit", 10 * 1024 * 1024)
                self.per_ip_buckets[ip] = TokenBucket(per_ip_limit, per_ip_limit)
            return self.per_ip_buckets[ip]
    
    def consume(self, tokens, client_ip):
        # Cek global rate limit
        global_wait = self.bucket.consume(tokens)
        
        # Cek per-IP rate limit
        ip_bucket = self.get_ip_bucket(client_ip)
        ip_wait = ip_bucket.consume(tokens)
        
        return max(global_wait, ip_wait)

class ControlServer:
    def __init__(self, proxy_instance):
        self.proxy = proxy_instance
        self.server = None
        
    def start(self):
        """Memulai control server."""
        try:
            self.server = http.server.HTTPServer(
                ('127.0.0.1', config.get("control_port", 1081)),
                self.make_handler()
            )
            threading.Thread(target=self.server.serve_forever, daemon=True).start()
            logger.info(f"Control server dimulai pada 127.0.0.1:{config.get('control_port', 1081)}")
        except Exception as e:
            logger.error(f"Gagal memulai control server: {e}")
    
    def make_handler(self):
        proxy = self.proxy
        
        class ControlHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                if self.path == '/shutdown':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(b'{"status": "shutting down"}')
                    threading.Thread(target=proxy.stop, daemon=True).start()
                elif self.path == '/status':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    status = {
                        "active_connections": len(proxy.active_connections),
                        "uptime": time.time() - proxy.start_time,
                        "total_bytes": proxy.total_bytes_transferred
                    }
                    self.wfile.write(json.dumps(status).encode())
                else:
                    self.send_response(404)
                    self.end_headers()
            
            def log_message(self, format, *args):
                pass  # Suppress default logging
        
        return ControlHandler
    
    def stop(self):
        if self.server:
            self.server.shutdown()

class UDPRelay:
    def __init__(self, client_addr, client_port):
        self.client_addr = client_addr
        self.client_port = client_port
        self.relay_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.relay_socket.bind(('0.0.0.0', 0))
        self.relay_port = self.relay_socket.getsockname()[1]
        self.active = True
        self.last_activity = time.time()
        
    def start_relay(self, client_socket):
        """Memulai relay UDP."""
        def relay_to_target():
            while self.active:
                try:
                    data, addr = self.relay_socket.recvfrom(65536)
                    if addr[0] != self.client_addr:
                        continue
                    
                    # Parse SOCKS5 UDP request
                    if len(data) < 10:
                        continue
                    
                    # Extract target address and data
                    atyp = data[3]
                    if atyp == 1:  # IPv4
                        target_addr = socket.inet_ntoa(data[4:8])
                        target_port = struct.unpack('>H', data[8:10])[0]
                        payload = data[10:]
                    elif atyp == 3:  # Domain
                        addr_len = data[4]
                        target_addr = data[5:5+addr_len].decode()
                        target_port = struct.unpack('>H', data[5+addr_len:7+addr_len])[0]
                        payload = data[7+addr_len:]
                    else:
                        continue
                    
                    # Forward to target
                    target_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    target_socket.sendto(payload, (target_addr, target_port))
                    target_socket.close()
                    
                    self.last_activity = time.time()
                    
                except Exception as e:
                    logger.debug(f"UDP relay error: {e}")
                    break
        
        threading.Thread(target=relay_to_target, daemon=True).start()

class SOCKS5Proxy:
    def __init__(self):
        self.host = config.get("host", "0.0.0.0")
        self.port = config.get("port", 1080)
        self.running = True
        self.shutdown_event = Event()
        self.thread_pool = ThreadPoolExecutor(max_workers=config.get("max_threads", 50))
        self.active_connections = set()
        self.connections_lock = threading.Lock()
        self.control_server = ControlServer(self)
        self.start_time = time.time()
        self.total_bytes_transferred = 0
        
        # Setup global rate limiter
        global global_rate_limiter
        global_rate_limiter = GlobalRateLimiter(config.get("global_rate_limit", 100 * 1024 * 1024))

    def authenticate_user(self, username, password, client_ip):
        """Autentikasi pengguna dengan username/password."""
        if username not in users_db:
            return False
        
        user_info = users_db[username]
        if user_info["password"] != password:
            return False
        
        # Cek IP allowlist
        client_addr = ipaddress.ip_address(client_ip)
        for allowed_cidr in user_info.get("allowed_ips", []):
            network = ipaddress.ip_network(allowed_cidr, strict=False)
            if client_addr in network:
                return True
        
        return False

    def handle_client(self, client_socket, client_addr):
        """Menangani koneksi klien SOCKS5."""
        client_ip = client_addr[0]
        
        # Cek ACL
        if not check_acl(client_ip):
            logger.warning(f"Koneksi dari {mask_address(client_ip)} ditolak oleh ACL")
            client_socket.close()
            return
        
        # Cek batas koneksi per IP
        with self.connections_lock:
            current_connections = ip_connections.get(client_ip, 0)
            max_per_ip = config.get("max_connections_per_ip", 10)
            if current_connections >= max_per_ip:
                logger.warning(f"Batas koneksi per IP tercapai untuk {mask_address(client_ip)}")
                client_socket.close()
                return
            ip_connections[client_ip] = current_connections + 1

        remote_socket = None
        authenticated_user = None
        
        try:
            client_socket.settimeout(config.get("timeout", 360))
            
            # Handshake SOCKS5: Versi dan Metode Autentikasi
            version_methods = recv_exact(client_socket, 2)
            nmethods = version_methods[1]
            methods = recv_exact(client_socket, nmethods)
            
            # Pilih metode autentikasi
            if config.get("enable_auth", True) and b'\x02' in methods:
                # Username/Password authentication
                client_socket.sendall(b'\x05\x02')
                
                # Terima kredensial
                auth_version = recv_exact(client_socket, 1)[0]
                if auth_version != 1:
                    client_socket.sendall(b'\x01\xFF')
                    return
                
                username_len = recv_exact(client_socket, 1)[0]
                username = recv_exact(client_socket, username_len).decode('utf-8')
                password_len = recv_exact(client_socket, 1)[0]
                password = recv_exact(client_socket, password_len).decode('utf-8')
                
                if self.authenticate_user(username, password, client_ip):
                    client_socket.sendall(b'\x01\x00')  # Success
                    authenticated_user = username
                    logger.info(f"User {username} berhasil login dari {mask_address(client_ip)}")
                else:
                    client_socket.sendall(b'\x01\xFF')  # Failure
                    logger.warning(f"Login gagal untuk user {username} dari {mask_address(client_ip)}")
                    return
                    
            elif b'\x00' in methods:
                # No authentication
                client_socket.sendall(b'\x05\x00')
            else:
                client_socket.sendall(b'\x05\xFF')
                return
            
            # Terima permintaan koneksi
            request = recv_exact(client_socket, 4)
            if request[0] != 5:
                return
            
            cmd = request[1]
            if cmd == 1:  # CONNECT
                self.handle_connect(client_socket, client_addr, authenticated_user)
            elif cmd == 2 and config.get("enable_bind", True):  # BIND
                self.handle_bind(client_socket, client_addr, authenticated_user)
            elif cmd == 3 and config.get("enable_udp", True):  # UDP ASSOCIATE
                self.handle_udp_associate(client_socket, client_addr, authenticated_user)
            else:
                client_socket.sendall(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')  # Command not supported
                
        except Exception as e:
            logger.error(f"Error menangani klien {mask_address(client_ip)}: {e}")
        finally:
            # Kurangi counter koneksi per IP
            with self.connections_lock:
                if client_ip in ip_connections:
                    ip_connections[client_ip] -= 1
                    if ip_connections[client_ip] <= 0:
                        del ip_connections[client_ip]

    def handle_connect(self, client_socket, client_addr, authenticated_user):
        """Menangani perintah CONNECT."""
        client_ip = client_addr[0]
        
        # Baca alamat tujuan
        addr_type = recv_exact(client_socket, 1)[0]
        if addr_type == 1:  # IPv4
            addr_bytes = recv_exact(client_socket, 4)
            addr = socket.inet_ntoa(addr_bytes)
        elif addr_type == 3:  # Domain name
            domain_length = recv_exact(client_socket, 1)[0]
            addr = recv_exact(client_socket, domain_length).decode('utf-8')
        elif addr_type == 4:  # IPv6
            addr_bytes = recv_exact(client_socket, 16)
            addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
        else:
            client_socket.sendall(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
            return

        port_bytes = recv_exact(client_socket, 2)
        port = int.from_bytes(port_bytes, 'big')
        
        logger.info(f"CONNECT ke {mask_address(addr)}:{port} dari {mask_address(client_ip)}")
        
        try:
            # Gunakan socket.create_connection untuk dukungan IPv4/IPv6 otomatis
            remote_socket = socket.create_connection((addr, port), timeout=config.get("timeout", 360))
            
            # Ambil informasi bind yang sebenarnya
            bound_addr, bound_port = remote_socket.getsockname()[:2]
            
            # Kirim respons sukses dengan informasi bind yang sebenarnya
            if ':' in bound_addr:  # IPv6
                response = b'\x05\x00\x00\x04' + socket.inet_pton(socket.AF_INET6, bound_addr) + bound_port.to_bytes(2, 'big')
            else:  # IPv4
                response = b'\x05\x00\x00\x01' + socket.inet_aton(bound_addr) + bound_port.to_bytes(2, 'big')
            
            client_socket.sendall(response)
            
            # Tambahkan ke koneksi aktif
            with self.connections_lock:
                self.active_connections.add((client_socket, remote_socket))
            
            # Forward data dengan rate limiting dua arah
            self.forward_data_bidirectional(client_socket, remote_socket, client_ip, authenticated_user)
            
        except Exception as e:
            logger.error(f"Gagal terhubung ke {mask_address(addr)}:{port}: {e}")
            client_socket.sendall(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')

    def handle_bind(self, client_socket, client_addr, authenticated_user):
        """Menangani perintah BIND."""
        client_ip = client_addr[0]
        
        # Baca alamat yang diminta (biasanya diabaikan untuk BIND)
        addr_type = recv_exact(client_socket, 1)[0]
        if addr_type == 1:  # IPv4
            recv_exact(client_socket, 4)
        elif addr_type == 3:  # Domain name
            domain_length = recv_exact(client_socket, 1)[0]
            recv_exact(client_socket, domain_length)
        elif addr_type == 4:  # IPv6
            recv_exact(client_socket, 16)
        
        recv_exact(client_socket, 2)  # Port
        
        try:
            # Buat socket untuk menerima koneksi masuk
            bind_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            bind_socket.bind(('0.0.0.0', 0))
            bind_socket.listen(1)
            
            bind_addr, bind_port = bind_socket.getsockname()
            
            # Kirim respons pertama dengan alamat bind
            response = b'\x05\x00\x00\x01' + socket.inet_aton(bind_addr) + bind_port.to_bytes(2, 'big')
            client_socket.sendall(response)
            
            logger.info(f"BIND socket dibuat pada {bind_addr}:{bind_port} untuk {mask_address(client_ip)}")
            
            # Tunggu koneksi masuk
            bind_socket.settimeout(config.get("timeout", 360))
            incoming_socket, incoming_addr = bind_socket.accept()
            
            # Kirim respons kedua dengan alamat koneksi masuk
            incoming_ip, incoming_port = incoming_addr
            response = b'\x05\x00\x00\x01' + socket.inet_aton(incoming_ip) + incoming_port.to_bytes(2, 'big')
            client_socket.sendall(response)
            
            logger.info(f"BIND koneksi masuk dari {mask_address(incoming_ip)}:{incoming_port}")
            
            # Forward data antara client dan incoming connection
            self.forward_data_bidirectional(client_socket, incoming_socket, client_ip, authenticated_user)
            
        except Exception as e:
            logger.error(f"Error BIND untuk {mask_address(client_ip)}: {e}")
            client_socket.sendall(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')

    def handle_udp_associate(self, client_socket, client_addr, authenticated_user):
        """Menangani perintah UDP ASSOCIATE."""
        client_ip = client_addr[0]
        
        # Baca alamat yang diminta
        addr_type = recv_exact(client_socket, 1)[0]
        if addr_type == 1:  # IPv4
            recv_exact(client_socket, 4)
        elif addr_type == 3:  # Domain name
            domain_length = recv_exact(client_socket, 1)[0]
            recv_exact(client_socket, domain_length)
        elif addr_type == 4:  # IPv6
            recv_exact(client_socket, 16)
        
        recv_exact(client_socket, 2)  # Port
        
        try:
            # Buat UDP relay
            udp_relay = UDPRelay(client_ip, client_addr[1])
            udp_associations[client_addr] = udp_relay
            
            # Kirim respons dengan alamat relay
            relay_addr = '127.0.0.1'
            relay_port = udp_relay.relay_port
            response = b'\x05\x00\x00\x01' + socket.inet_aton(relay_addr) + relay_port.to_bytes(2, 'big')
            client_socket.sendall(response)
            
            logger.info(f"UDP ASSOCIATE dibuat pada {relay_addr}:{relay_port} untuk {mask_address(client_ip)}")
            
            # Mulai relay
            udp_relay.start_relay(client_socket)
            
            # Tunggu sampai koneksi TCP ditutup
            try:
                while True:
                    data = client_socket.recv(1)
                    if not data:
                        break
            except:
                pass
            
        except Exception as e:
            logger.error(f"Error UDP ASSOCIATE untuk {mask_address(client_ip)}: {e}")
            client_socket.sendall(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
        finally:
            # Cleanup UDP association
            if client_addr in udp_associations:
                udp_associations[client_addr].active = False
                del udp_associations[client_addr]

    def forward_data_bidirectional(self, client_socket, remote_socket, client_ip, authenticated_user):
        """Forward data dengan rate limiting dua arah."""
        client_to_remote = Event()
        remote_to_client = Event()
        
        # Dapatkan rate limit untuk user
        user_rate_limit = None
        if authenticated_user and authenticated_user in users_db:
            user_rate_limit = users_db[authenticated_user].get("rate_limit")
        
        def forward(src, dest, direction_event, peer_event, apply_rate_limit=True):
            total_data = 0
            try:
                while not self.shutdown_event.is_set() and not direction_event.is_set():
                    try:
                        data = src.recv(config.get("socket_buffer_size", 65536))
                        if not data:
                            break
                            
                        data_len = len(data)
                        
                        # Terapkan rate limiting
                        if apply_rate_limit:
                            # Global dan per-IP rate limiting
                            wait_time = global_rate_limiter.consume(data_len, client_ip)
                            
                            # User-specific rate limiting
                            if user_rate_limit:
                                user_bucket = TokenBucket(user_rate_limit, user_rate_limit)
                                user_wait = user_bucket.consume(data_len)
                                wait_time = max(wait_time, user_wait)
                            
                            if wait_time > 0:
                                sleep(min(wait_time, 0.1))
                        
                        dest.sendall(data)
                        total_data += data_len
                        self.total_bytes_transferred += data_len
                        
                    except socket.timeout:
                        if peer_event.is_set() or self.shutdown_event.is_set():
                            break
                        continue
                        
            except (ConnectionError, OSError):
                pass
            except Exception as e:
                logger.debug(f"Error forwarding data: {e}")
            finally:
                direction_event.set()
                
                if peer_event.is_set() or self.shutdown_event.is_set():
                    try:
                        src.close()
                        dest.close()
                    except:
                        pass
                    
                    with self.connections_lock:
                        if (client_socket, remote_socket) in self.active_connections:
                            self.active_connections.remove((client_socket, remote_socket))
        
        # Mulai forwarding di kedua arah dengan rate limiting
        self.thread_pool.submit(forward, client_socket, remote_socket, client_to_remote, remote_to_client, True)
        self.thread_pool.submit(forward, remote_socket, client_socket, remote_to_client, client_to_remote, True)

    def start(self):
        """Memulai server proxy SOCKS5."""
        if config.get("async_mode", False):
            return self.start_async()
        
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server.bind((self.host, self.port))
            server.listen(config.get("backlog_size", 100))
            server.settimeout(1.0)
            
            logger.info(f"SOCKS5 proxy server dimulai pada {self.host}:{self.port}")
            
            # Mulai control server
            self.control_server.start()
            
            # Tulis PID ke file
            with open(PID_FILE, 'w') as f:
                pid = os.getpid()
                f.write(str(pid))
                logger.info(f"File PID dibuat dengan PID: {pid}")
            
            while not self.shutdown_event.is_set():
                try:
                    client_socket, addr = server.accept()
                    logger.debug(f"Koneksi dari {mask_address(addr[0])}")
                    
                    self.thread_pool.submit(self.handle_client, client_socket, addr)
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if not self.shutdown_event.is_set():
                        logger.error(f"Error menerima koneksi: {e}")
            
        except Exception as e:
            logger.error(f"Error memulai server: {e}")
        finally:
            self.cleanup()

    async def start_async(self):
        """Memulai server dalam mode async."""
        logger.info("Memulai server dalam mode async...")
        
        async def handle_client_async(reader, writer):
            client_addr = writer.get_extra_info('peername')
            try:
                # Implementasi async handler (simplified)
                # Untuk implementasi penuh, perlu konversi semua operasi ke async
                pass
            except Exception as e:
                logger.error(f"Error async client handler: {e}")
            finally:
                writer.close()
                await writer.wait_closed()
        
        server = await asyncio.start_server(
            handle_client_async,
            self.host,
            self.port,
            backlog=config.get("backlog_size", 100)
        )
        
        logger.info(f"Async SOCKS5 proxy server dimulai pada {self.host}:{self.port}")
        
        # Mulai control server
        self.control_server.start()
        
        async with server:
            await server.serve_forever()

    def cleanup(self):
        """Membersihkan resource."""
        logger.info("Menutup server...")
        
        # Tutup control server
        self.control_server.stop()
        
        # Tutup semua koneksi aktif
        with self.connections_lock:
            for client_sock, remote_sock in self.active_connections:
                try:
                    client_sock.close()
                    remote_sock.close()
                except:
                    pass
            self.active_connections.clear()
        
        # Tutup UDP associations
        for udp_relay in udp_associations.values():
            udp_relay.active = False
        udp_associations.clear()
        
        # Tunggu thread pool selesai
        self.thread_pool.shutdown(wait=False)
        
        # Hapus file PID
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)

    def stop(self):
        """Menghentikan server proxy dengan aman."""
        logger.info("Menghentikan server proxy...")
        self.shutdown_event.set()
        self.running = False

def start_proxy():
    """Memulai server proxy."""
    try:
        proxy = SOCKS5Proxy()
        if config.get("async_mode", False):
            asyncio.run(proxy.start())
        else:
            proxy.start()
    except Exception as e:
        logger.error(f"Error memulai proxy: {e}")

def stop_proxy():
    """Menghentikan server proxy yang sedang berjalan."""
    try:
        # Coba gunakan control port terlebih dahulu
        try:
            import urllib.request
            control_port = config.get("control_port", 1081)
            urllib.request.urlopen(f'http://127.0.0.1:{control_port}/shutdown', 
                                 data=b'', timeout=5)
            logger.info("Server dihentikan melalui control port")
            return
        except:
            pass
        
        # Fallback ke metode PID file
        if not os.path.exists(PID_FILE):
            logger.warning("File PID tidak ditemukan. Proxy mungkin tidak berjalan.")
            return

        with open(PID_FILE, 'r') as f:
            pid_content = f.read().strip()
            if not pid_content or not pid_content.isdigit():
                logger.error("Konten file PID tidak valid atau kosong.")
                if os.path.exists(PID_FILE):
                    os.remove(PID_FILE)
                return

            pid = int(pid_content)
            
            if os.name == 'nt':
                try:
                    kernel32 = ctypes.windll.kernel32
                    handle = kernel32.OpenProcess(1, False, pid)
                    if handle:
                        result = kernel32.GenerateConsoleCtrlEvent(0, pid)
                        kernel32.CloseHandle(handle)
                        if not result:
                            os.system(f'taskkill /PID {pid} /F')
                except:
                    os.system(f'taskkill /PID {pid} /F')
            else:
                os.kill(pid, signal.SIGTERM)
                
            logger.info(f"Server proxy dengan PID {pid} dihentikan.")
            time.sleep(1)
            
            if os.path.exists(PID_FILE):
                os.remove(PID_FILE)

    except ProcessLookupError:
        logger.warning("Proses tidak ditemukan. Mungkin sudah berhenti.")
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
    except Exception as e:
        logger.error(f"Error menghentikan proxy: {e}")

def signal_handler(sig, frame):
    """Menangani sinyal untuk shutdown yang aman."""
    logger.info("[ ❗ ] Sinyal diterima, menutup dengan aman...")
    stop_proxy()
    sys.exit(0)

def main():
    """Fungsi utama dengan argument parsing."""
    parser = argparse.ArgumentParser(description='SOCKS5 Proxy Server Advanced')
    parser.add_argument('command', choices=['start', 'stop', 'config'], 
                       help='Perintah yang akan dijalankan')
    parser.add_argument('--host', default='0.0.0.0', help='Host untuk bind')
    parser.add_argument('--port', type=int, default=1080, help='Port untuk bind')
    parser.add_argument('--async-mode', action='store_true', help='Gunakan mode async')
    parser.add_argument('--no-auth', action='store_true', help='Nonaktifkan autentikasi')
    parser.add_argument('--no-log', action='store_true', help='Nonaktifkan logging')
    parser.add_argument('--anonymous', action='store_true', help='Mode anonymous (mask alamat)')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                       default='INFO', help='Level logging')
    
    args = parser.parse_args()
    
    # Update config dari arguments
    config.update({
        'host': args.host,
        'port': args.port,
        'async_mode': args.async_mode,
        'enable_auth': not args.no_auth,
        'no_log': args.no_log,
        'anonymous_mode': args.anonymous,
        'log_level': args.log_level
    })
    
    # Load konfigurasi
    load_config()
    load_users()
    load_acl()
    
    # Setup logging
    global logger
    logger = setup_logging()
    
    # Daftarkan handler sinyal
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    if args.command == 'start':
        # Tampilkan banner
        init(autoreset=True)
        os.system('cls' if os.name == 'nt' else 'clear')
        print(Style.BRIGHT + Fore.BLUE + """
──────────────── ──────────────── ──────────────── ──────────────── ────────────────
────────────────   ───────────█▀▄▀█ ▄▀█ █▀  ▀█▀ █▀▀ █▀█────────────────  ─────────────
────────────────   ───────────█░▀░█ █▀█ ▄█  ░█░ ██▄ █▀▄────────────────  ─────────────
──────────────── ──────────────── ──────────────── ──────────────── ──────────────── 
────███████───── ────███████───── ──────███─────── ───███───███──── ───███───███──── 
─────█─────█──── ─────█─────█──── ─────█───█────── ────█─────█───── ────█─────█───── 
─────█─────█──── ─────█─────█──── ────█─────█───── ─────█───█────── ─────█───█────── 
─────█─────█──── ─────█─────█──── ───█───────█──── ─────█───█────── ─────█───█────── 
─────█─────█──── ─────█────█───── ───█───────█──── ──────█─█─────── ──────█─█─────── 
─────██████───── ─────█████────── ───█───────█──── ───────█──────── ──────█─█─────── 
─────█────────── ─────█────█───── ───█───────█──── ───────█──────── ───────█──────── 
─────█────────── ─────█────█───── ───█───────█──── ──────█─█─────── ───────█──────── 
─────█────────── ─────█────█───── ────█─────█───── ─────█───█────── ───────█──────── 
─────█────────── ─────█────█─█─── ─────█───█────── ────█─────█───── ───────█──────── 
────███───────── ────███────█──── ──────███─────── ───██────███──── ──────███─────── 
──────────────── ──────────────── ──────────────── ──────────────── ──────────────── 
──────────────── ──────────────── ──────────────── ──────────────── ──────────────── 
──────────────── ──────────────── ──────────────── ──────────────── ────────────────      """)
        print(Fore.GREEN + f"""
        SOCKS5 Proxy Server Advanced v2.0
        Mode: {'Async' if config.get('async_mode') else 'Threading'}
        Auth: {'Enabled' if config.get('enable_auth') else 'Disabled'}
        UDP: {'Enabled' if config.get('enable_udp') else 'Disabled'}
        BIND: {'Enabled' if config.get('enable_bind') else 'Disabled'}
        """)
        print()
        start_proxy()
    elif args.command == 'stop':
        stop_proxy()
    elif args.command == 'config':
        print("Konfigurasi saat ini:")
        print(json.dumps(config, indent=2))

if __name__ == "__main__":
    main()

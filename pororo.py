import socket
import threading
import signal
import os
import sys
import logging
from time import time, sleep
from colorama import init, Fore, Style

PID_FILE = "socks5_proxy.pid"
LOG_FILE = "socks5_proxy.log"
MAX_BYTES = 500 * 1024 * 1024  # 500 MB
MAX_THREADS = 10  
RATE_LIMIT = 55024 * 2024  
TIMEOUT = 360  
THREAD_SEMAPHORE = threading.Semaphore(MAX_THREADS)

logging.basicConfig(
    level=logging.INFO,
    format="[ %(asctime)s ] %(levelname)s ⦂ %(message)s",
    datefmt="%H:%M:%S",    
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger()

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
print(Fore.GREEN + """ """)
print()


class SOCKS5Proxy:
    def __init__(self, host='0.0.0.0', port=1080):
        self.host = host
        self.port = port
        self.running = True

    def handle_client(self, client_socket):
        with THREAD_SEMAPHORE:
            try:
                client_socket.settimeout(TIMEOUT)

                # Step 1: Greeting (SOCKS5 handshake)
                client_socket.recv(2)
                client_socket.send(b'\x05\x00')

                # Step 2: Connection request
                request = client_socket.recv(4)
                if request[1] != 1:  # Command 1: CONNECT
                    client_socket.close()
                    return

                addr_type = request[3]
                if addr_type == 1:  # IPv4
                    addr = socket.inet_ntoa(client_socket.recv(4))
                elif addr_type == 3:  # Domain name
                    domain_length = client_socket.recv(1)[0]
                    addr = client_socket.recv(domain_length).decode('utf-8')
                else:
                    client_socket.close()
                    return

                port = int.from_bytes(client_socket.recv(2), 'big')

                # Connect to the target server
                remote_socket = socket.socket(F_INET, socket.SOCK_STREAM)
                remote_socket.settimeout(TIMEOUT)
                remote_socket.connect((addr, port))

                
                client_socket.send(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')

                
                self.forward_data(client_socket, remote_socket)

            except Exception as e:
                logger.error(f"Error handling client: {e}")
            finally:
                client_socket.close()

    def forward_data(self, client_socket, remote_socket):
        def forward(src, dest, max_bytes=MAX_BYTES):
            total_data = 0
            start_time = time()
            try:
                while total_data < max_bytes:
                    data = src.recv(10096)
                    if not data:
                        break
                    dest.send(data)
                    total_data += len(data)

                    
                    elapsed_time = time() - start_time
                    if total_data / elapsed_time > RATE_LIMIT:
                        sleep(0.1)

            except Exception as e:
                logger.error(f"Data forwarding error: {e}")
            finally:
                src.close()
                dest.close()

        threading.Thread(target=forward, args=(client_socket, remote_socket), daemon=True).start()
        threading.Thread(target=forward, args=(remote_socket, client_socket), daemon=True).start()

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(MAX_THREADS)
        logger.info(f"SOCKS5 proxy server started on {self.host}:{self.port}")

        # Create PID file
        with open(PID_FILE, 'w') as f:
            pid = os.getpid()
            f.write(str(pid))
            logger.info(f"PID file created with PID: {pid}")

        try:
            while self.running:
                client_socket, addr = server.accept()
                logger.info(f"Connection from {addr}")
                threading.Thread(target=self.handle_client, args=(client_socket,), daemon=True).start()
        except KeyboardInterrupt:
            logger.info("Shutting down proxy server...")
        finally:
            server.close()
            if os.path.exists(PID_FILE):
                os.remove(PID_FILE)

    def stop(self):
        self.running = False
        logger.info("Proxy server stopped.")


def start_proxy():
    try:
        proxy = SOCKS5Proxy()
        proxy.start()
    except Exception as e:
        logger.error(f"{e} please change port")


def stop_proxy():
    try:
        if not os.path.exists(PID_FILE):
            logger.warning("PID file not found. Proxy might not be running.")
            return

        with open(PID_FILE, 'r') as f:
            pid_content = f.read().strip()
            if not pid_content or not pid_content.isdigit():
                logger.error("Invalid or empty PID file content.")
                if os.path.exists(PID_FILE):
                    os.remove(PID_FILE)
                return

            pid = int(pid_content)
            os.kill(pid, signal.SIGTERM)
            logger.info(f"Proxy server with PID {pid} stopped.")
            os.remove(PID_FILE)

    except ProcessLookupError:
        logger.warning("Process not found. It may have already stopped.")
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
    except Exception as e:
        logger.error(f"Error stopping proxy: {e}")


def signal_handler(sig, frame):
    logger.info("[ ❗ ] Signal received, shutting down gracefully...")
    stop_proxy()
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if len(sys.argv) != 2:
        print("Usage: python3 proxy.py [start|stop]")
        sys.exit(1)

    command = sys.argv[1].lower()
    if command == "start":
        start_proxy()
    elif command == "stop":
        stop_proxy()
    else:
        print("Invalid command. Use 'start' or 'stop'.")

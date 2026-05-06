import socket
import threading
import sys
import json
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QTextEdit, QLineEdit, QPushButton, 
                             QLabel, QFormLayout, QFrame)
from PyQt6.QtCore import Qt, pyqtSignal, QObject

def safe_recv_exact(conn: socket.socket, n: int, timeout_sec: float = 5.0) -> bytes:
    if n <= 0:
        return b""
    if n > 20 * 1024 * 1024:
        raise ValueError("Payload size exceeds maximum allowed limit")
    conn.settimeout(timeout_sec)
    buf = bytearray(n)
    view = memoryview(buf)
    bytes_read = 0
    while bytes_read < n:
        try:
            chunk_len = conn.recv_into(view[bytes_read:], n - bytes_read)
            if chunk_len == 0:
                raise ConnectionError("Connection closed by peer")
            bytes_read += chunk_len
        except socket.timeout:
            raise TimeoutError("Timeout reading exact bytes")
    return bytes(buf)

def safe_read_line(conn: socket.socket, max_len: int = 1024, timeout_sec: float = 5.0) -> str:
    conn.settimeout(timeout_sec)
    buf = bytearray()
    while len(buf) < max_len:
        try:
            c = conn.recv(1)
            if not c:
                break
            if c == b'\n':
                return buf.decode('utf-8', errors='strict')
            buf.extend(c)
        except socket.timeout:
            raise TimeoutError("Timeout reading line")
    raise ValueError(f"Header exceeds max length of {max_len} bytes")

class ServerSignals(QObject):
    log_signal = pyqtSignal(str)
    clients_signal = pyqtSignal(list)

class ChatServer:
    def __init__(self, host='0.0.0.0', port=5000, signals=None):
        self.host = host
        self.port = port
        self.clients = {}  # {username: conn}
        self.pub_keys = {} # {username: pem_bytes}
        self.lock = threading.Lock()
        self.signals = signals
        self.running = False
        self.server_socket = None

    def log(self, message):
        print(message)
        if self.signals:
            self.signals.log_signal.emit(message)

    def bind_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.running = True

    def start(self):
        self.log(f"Server started on {self.host}:{self.port}")

        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                conn, addr = self.server_socket.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.log(f"Accept error: {e}")
                break

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        self.log("Server stopped.")

    def handle_client(self, conn, addr):
        conn.settimeout(60.0) # Защита от Slowloris: таймаут на 60 сек
        username = None
        try:
            while self.running:
                # Read header: CMD LENGTH
                try:
                    header = safe_read_line(conn, max_len=1024, timeout_sec=60.0)
                    if not header:
                        break # Соединение корректно закрыто
                except TimeoutError:
                    continue # Это просто таймаут простоя, продолжаем слушать
                except Exception as e:
                    self.log(f"Error reading header from {addr}: {e}")
                    break
                
                parts = header.split(' ')
                cmd = parts[0]
                try:
                    length = int(parts[1]) if len(parts) > 1 else 0
                except (ValueError, IndexError):
                    break
                
                try:
                    payload = safe_recv_exact(conn, length, timeout_sec=15.0) if length > 0 else b""
                except (TimeoutError, ValueError, ConnectionError) as e:
                    self.log(f"Failed to read payload from {addr}: {e}")
                    break

                if cmd == 'LOGIN':
                    # Sanitize username
                    raw_name = payload.decode('utf-8', errors='ignore').strip()
                    username = "".join(c for c in raw_name if c.isalnum() or c in "._-")[:25]
                    if not username: username = f"User_{addr[1]}"
                    
                    with self.lock:
                        self.clients[username] = conn
                    self.log(f"User logged in: {username}")
                    self.broadcast_user_list()

                elif cmd == 'PUBKEY':
                    # Payload is PEM bytes
                    with self.lock:
                        self.pub_keys[username] = payload
                    # Broadcast this key to everyone? 
                    # Simpler: Just send the updated list to everyone or let them request it.
                    self.broadcast_user_list()

                elif cmd == 'RELAY':
                    # Format: target_username|data
                    # We expect the payload to contain the target and the message
                    # But since payload is bytes (encrypted), we need a safe separator.
                    # Let's change protocol for RELAY:
                    # Header: RELAY <target_len> <data_len>
                    # This is getting complex to parse in one line.
                    # Let's stick to: Payload = target_username_bytes + b'|' + message_bytes
                    try:
                        sep_index = payload.index(b'|')
                        target = payload[:sep_index].decode('utf-8')
                        msg_data = payload[sep_index+1:]
                        
                        self.send_to_user(username, target, msg_data)
                    except ValueError:
                        pass # Malformed

        except Exception as e:
            print(f"Error with {addr}: {e}")
        finally:
            if username:
                with self.lock:
                    if username in self.clients:
                        del self.clients[username]
                    if username in self.pub_keys:
                        del self.pub_keys[username]
                self.broadcast_user_list()
            conn.close()

    def broadcast_user_list(self):
        # pub_keys is {user: bytes}. Convert bytes to str for JSON
        with self.lock:
            serializable_keys = {u: k.decode('utf-8', errors='ignore') for u, k in self.pub_keys.items()}
            clients_snapshot = list(self.clients.items())

        data = json.dumps(serializable_keys).encode('utf-8')
        
        if self.signals:
            self.signals.clients_signal.emit([u for u, _ in clients_snapshot])

        header_str = f"USERS {len(data)}"
        for u, c in clients_snapshot:
            try:
                c.settimeout(5.0)
                c.sendall(f"{header_str}\n".encode('utf-8') + data)
                c.settimeout(60.0)
            except:
                pass

    def send_to_user(self, sender, target, data):
        header_str = f"MSG {sender} {len(data)}"
        conn = None
        with self.lock:
            if target in self.clients:
                conn = self.clients[target]
        
        if conn:
            try:
                conn.settimeout(10.0)
                conn.sendall(f"{header_str}\n".encode('utf-8') + data)
                conn.settimeout(60.0)
                self.log(f"Relayed {len(data)} bytes from {sender} to {target}")
            except:
                self.log(f"Failed to send to {target}, connection likely lost")
        else:
            self.log(f"Target {target} not found for sender {sender}")

class ServerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("BoltC Secure Relay Server")
        self.resize(600, 500)
        self.server = None
        self.signals = ServerSignals()
        self.signals.log_signal.connect(self.append_log)
        self.signals.clients_signal.connect(self.update_clients)
        self.init_ui()

    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # Config Panel
        config_frame = QFrame()
        config_frame.setFrameShape(QFrame.Shape.StyledPanel)
        form = QFormLayout(config_frame)
        
        self.host_input = QLineEdit("0.0.0.0")
        self.port_input = QLineEdit("5000")
        form.addRow("Bind Address:", self.host_input)
        form.addRow("Port:", self.port_input)
        
        self.start_btn = QPushButton("Start Server")
        self.start_btn.clicked.connect(self.toggle_server)
        form.addRow(self.start_btn)
        
        layout.addWidget(config_frame)

        # Status
        h_layout = QHBoxLayout()
        
        # Log
        log_v = QVBoxLayout()
        log_v.addWidget(QLabel("Server Logs:"))
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        log_v.addWidget(self.log_display)
        h_layout.addLayout(log_v, 2)

        # Clients
        client_v = QVBoxLayout()
        client_v.addWidget(QLabel("Connected Clients:"))
        self.client_list = QTextEdit()
        self.client_list.setReadOnly(True)
        self.client_list.setFixedWidth(150)
        client_v.addWidget(self.client_list)
        h_layout.addLayout(client_v, 1)

        layout.addLayout(h_layout)

    def append_log(self, text):
        self.log_display.append(text)

    def update_clients(self, clients):
        self.client_list.clear()
        for c in clients:
            self.client_list.append(c)

    def toggle_server(self):
        if self.server and self.server.running:
            self.server.stop()
            self.start_btn.setText("Start Server")
            self.host_input.setEnabled(True)
            self.port_input.setEnabled(True)
        else:
            host = self.host_input.text()
            try:
                port = int(self.port_input.text())
            except:
                self.append_log("Invalid port!")
                return
            
            self.server = ChatServer(host, port, self.signals)
            try:
                self.server.bind_server()
            except Exception as e:
                self.append_log(f"Failed to start server: {e}")
                if self.server.server_socket:
                    self.server.server_socket.close()
                self.server = None
                return
                
            threading.Thread(target=self.server.start, daemon=True).start()
            self.start_btn.setText("Stop Server")
            self.host_input.setEnabled(False)
            self.port_input.setEnabled(False)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    # Style the server too
    app.setStyleSheet("""
        QMainWindow { background-color: #2b2b2b; color: white; }
        QTextEdit { background-color: #1e1e1e; color: #00ff00; font-family: Consolas; }
        QLabel { color: #aaa; font-weight: bold; }
        QPushButton { background-color: #0078d4; color: white; padding: 5px; }
    """)
    window = ServerWindow()
    window.show()
    sys.exit(app.exec())


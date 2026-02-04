import sys
import socket
import threading
import json
import base64
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QTextEdit, QLineEdit, QPushButton, 
                             QListWidget, QLabel, QSplitter, QInputDialog, QMessageBox, QMenu)
from PyQt6.QtCore import Qt, pyqtSignal, QObject, QThread
from PyQt6.QtGui import QFont, QColor, QPalette

from crypto_utils import CryptoHandler

# --- Worker Thread for Networking ---
class NetworkWorker(QObject):
    msg_received = pyqtSignal(str, bytes) # sender, encrypted_content
    user_list_updated = pyqtSignal(dict)  # {username: pem_str}
    connection_lost = pyqtSignal()

    def __init__(self, host, port, username, crypto_handler):
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.crypto = crypto_handler
        self.sock = None
        self.running = True

    def connect_to_server(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            
            # 1. Send Login
            user_bytes = self.username.encode('utf-8')
            header = f"LOGIN {len(user_bytes)}\n".encode('utf-8')
            self.sock.sendall(header + user_bytes)

            # 2. Send Public Key
            pub_key_bytes = self.crypto.get_public_key_pem()
            header = f"PUBKEY {len(pub_key_bytes)}\n".encode('utf-8')
            self.sock.sendall(header + pub_key_bytes)
            
            # Start listening loop
            self.listen()
        except Exception as e:
            print(f"Connection failed: {e}")
            self.connection_lost.emit()

    def listen(self):
        buffer = b""
        try:
            while self.running:
                # Read until newline for header
                while b'\n' not in buffer:
                    data = self.sock.recv(1024)
                    if not data:
                        raise ConnectionResetError()
                    buffer += data
                
                line, buffer = buffer.split(b'\n', 1)
                header_str = line.decode('utf-8').strip()
                if not header_str:
                    continue
                
                parts = header_str.split(' ')
                cmd = parts[0]
                length = int(parts[1]) if len(parts) > 1 else 0

                # Read exact payload
                while len(buffer) < length:
                    data = self.sock.recv(length - len(buffer))
                    if not data:
                        raise ConnectionResetError()
                    buffer += data
                
                payload = buffer[:length]
                buffer = buffer[length:]

                if cmd == 'USERS':
                    # Payload is JSON dictionary of users and keys
                    users_dict = json.loads(payload.decode('utf-8'))
                    self.user_list_updated.emit(users_dict)
                
                elif cmd == 'MSG':
                    # Header was: MSG sender len
                    # parts[1] is sender, parts[2] is length
                    # Wait, server sent: f"MSG {sender} {len(data)}\n"
                    sender = parts[1]
                    self.msg_received.emit(sender, payload)

        except Exception as e:
            print(f"Network error: {e}")
            self.connection_lost.emit()

    def send_message(self, target_user, encrypted_bytes):
        if not self.sock: 
            return
        
        # Format: RELAY target|payload
        target_bytes = target_user.encode('utf-8')
        payload = target_bytes + b'|' + encrypted_bytes
        
        header = f"RELAY {len(payload)}\n".encode('utf-8')
        try:
            self.sock.sendall(header + payload)
        except:
            self.connection_lost.emit()

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()

# --- Main Window ---
class SecureMessenger(QMainWindow):
    def __init__(self):
        super().__init__()
        self.username = ""
        self.crypto = CryptoHandler()
        self.peer_keys = {} # {username: Fernet}
        self.messages = {}  # {username: list_of_strings}
        self.network_thread = None
        self.worker = None
        self.current_chat_user = None

        self.init_ui()
        self.login()

    def init_ui(self):
        self.setWindowTitle("Secure Messenger (E2EE)")
        self.resize(900, 600)
        self.setWindowOpacity(0.92) # Semi-transparent
        
        # Style
        self.setStyleSheet("""
            QMainWindow { background-color: #2b2b2b; color: #ffffff; }
            QWidget { color: #ffffff; font-family: Segoe UI, sans-serif; }
            QListWidget { background-color: #333333; border: none; font-size: 14px; padding: 5px; }
            QListWidget::item { padding: 8px; border-bottom: 1px solid #444; }
            QListWidget::item:selected { background-color: #0078d4; }
            QTextEdit { background-color: #1e1e1e; border: none; font-size: 14px; padding: 10px; }
            QLineEdit { background-color: #333333; border: 1px solid #555; padding: 8px; border-radius: 4px; font-size: 14px; }
            QPushButton { background-color: #0078d4; color: white; border: none; padding: 8px 16px; border-radius: 4px; font-weight: bold; }
            QPushButton:hover { background-color: #1084d8; }
            QSplitter::handle { background-color: #444; }
        """)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left Panel (User List)
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(10, 10, 10, 10)
        
        lbl_users = QLabel("Contacts")
        lbl_users.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        left_layout.addWidget(lbl_users)
        
        self.user_list = QListWidget()
        self.user_list.itemClicked.connect(self.on_user_selected)
        left_layout.addWidget(self.user_list)
        
        left_panel.setMinimumWidth(200)
        splitter.addWidget(left_panel)

        # Right Panel (Chat)
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(10, 10, 10, 10)

        self.chat_header = QLabel("Select a user to start chatting")
        self.chat_header.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        right_layout.addWidget(self.chat_header)

        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        right_layout.addWidget(self.chat_display)

        # Input Area
        input_layout = QHBoxLayout()
        
        self.emoji_btn = QPushButton("😊")
        self.emoji_btn.setFixedWidth(40)
        self.emoji_btn.clicked.connect(self.show_emoji_picker)
        input_layout.addWidget(self.emoji_btn)

        self.msg_input = QLineEdit()
        self.msg_input.setPlaceholderText("Type a secure message...")
        self.msg_input.returnPressed.connect(self.send_msg)
        input_layout.addWidget(self.msg_input)

        self.send_btn = QPushButton("Send")
        self.send_btn.clicked.connect(self.send_msg)
        input_layout.addWidget(self.send_btn)

        right_layout.addLayout(input_layout)
        splitter.addWidget(right_panel)
        splitter.setStretchFactor(1, 4)

        main_layout.addWidget(splitter)

    def login(self):
        dialog = QWidget() # Placeholder logic for dialog, using InputDialog for simplicity
        
        name, ok = QInputDialog.getText(self, "Login", "Enter Username:")
        if ok and name:
            self.username = name
            # Default server
            host, ok = QInputDialog.getText(self, "Server", "Enter Server IP:", text="127.0.0.1")
            if not ok: host = "127.0.0.1"
            
            self.start_network(host, 5000)
        else:
            sys.exit()

    def start_network(self, host, port):
        self.network_thread = QThread()
        self.worker = NetworkWorker(host, port, self.username, self.crypto)
        self.worker.moveToThread(self.network_thread)
        
        self.network_thread.started.connect(self.worker.connect_to_server)
        self.worker.msg_received.connect(self.handle_incoming_msg)
        self.worker.user_list_updated.connect(self.update_user_list)
        self.worker.connection_lost.connect(self.on_connection_lost)
        
        self.network_thread.start()
        self.setWindowTitle(f"Secure Messenger - {self.username}")

    def update_user_list(self, users_dict):
        current = self.user_list.currentItem()
        selected_text = current.text() if current else None
        
        self.user_list.clear()
        for user, pem_str in users_dict.items():
            if user == self.username: continue
            
            # Store/Update peer key
            if user not in self.peer_keys:
                try:
                    pem_bytes = pem_str.encode('utf-8')
                    peer_pub = self.crypto.load_public_key_from_pem(pem_bytes)
                    self.peer_keys[user] = self.crypto.derive_shared_fernet(peer_pub)
                except Exception as e:
                    print(f"Failed to derive key for {user}: {e}")

            self.user_list.addItem(user)
        
        # Reselect if possible
        if selected_text:
            items = self.user_list.findItems(selected_text, Qt.MatchFlag.MatchExactly)
            if items:
                self.user_list.setCurrentItem(items[0])

    def on_user_selected(self, item):
        self.current_chat_user = item.text()
        self.chat_header.setText(f"Secure Chat with {self.current_chat_user}")
        self.refresh_chat_display()

    def refresh_chat_display(self):
        self.chat_display.clear()
        if not self.current_chat_user: return
        
        history = self.messages.get(self.current_chat_user, [])
        for msg in history:
            self.chat_display.append(msg)

    def handle_incoming_msg(self, sender, encrypted_payload):
        if sender not in self.peer_keys:
            return # Cannot decrypt
        
        try:
            fernet = self.peer_keys[sender]
            decrypted = self.crypto.decrypt_message(fernet, encrypted_payload)
            
            formatted = f"<b style='color: #0078d4'>{sender}:</b> {decrypted}"
            
            if sender not in self.messages:
                self.messages[sender] = []
            self.messages[sender].append(formatted)
            
            if self.current_chat_user == sender:
                self.chat_display.append(formatted)
                
        except Exception as e:
            print(f"Decryption error from {sender}: {e}")

    def send_msg(self):
        text = self.msg_input.text().strip()
        if not text or not self.current_chat_user:
            return
        
        target = self.current_chat_user
        if target not in self.peer_keys:
            QMessageBox.warning(self, "Error", "Secure handshake not established with this user.")
            return

        try:
            fernet = self.peer_keys[target]
            encrypted = self.crypto.encrypt_message(fernet, text)
            
            self.worker.send_message(target, encrypted)
            
            # Add to local history
            formatted = f"<b style='color: #28a745'>Me:</b> {text}"
            if target not in self.messages:
                self.messages[target] = []
            self.messages[target].append(formatted)
            
            if self.current_chat_user == target:
                self.chat_display.append(formatted)
            
            self.msg_input.clear()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Encryption failed: {e}")

    def show_emoji_picker(self):
        menu = QMenu(self)
        emojis = ["😊", "😂", "🥰", "👍", "🔥", "🎉", "🤔", "😎", "🐍", "🔒"]
        for emo in emojis:
            action = menu.addAction(emo)
            action.triggered.connect(lambda checked, e=emo: self.msg_input.insert(e))
        menu.exec(self.emoji_btn.mapToGlobal(self.emoji_btn.rect().bottomLeft()))

    def on_connection_lost(self):
        QMessageBox.critical(self, "Error", "Connection to server lost.")
        self.close()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SecureMessenger()
    window.show()
    sys.exit(app.exec())

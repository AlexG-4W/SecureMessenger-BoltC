import sys
import os
import socket
import threading
import json
import base64
import struct
import hashlib
import traceback
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QTextEdit, QLineEdit, QPushButton, 
                             QListWidget, QLabel, QSplitter, QInputDialog, QMessageBox, QMenu, QFileDialog, QDialog)
from PyQt6.QtCore import Qt, pyqtSignal, QObject, QThread, pyqtSlot, QTimer, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui import QFont, QColor, QPalette

from crypto_utils import AEADCryptoHandler, KeyAuthenticator

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

# --- Worker Thread for Networking ---
class NetworkWorker(QObject):
    msg_received = pyqtSignal(str, bytes) # sender, encrypted_content
    user_list_updated = pyqtSignal(dict)  # {username: pem_str}
    connection_lost = pyqtSignal()
    file_progress = pyqtSignal(str, str)  # sender, log_message
    file_ready_signal = pyqtSignal(str, str, str) # sender, filename, temp_filepath

    def __init__(self, host, port, username, crypto_handler, peer_keys_ref):
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.crypto = crypto_handler
        self.peer_keys = peer_keys_ref
        self.sock = None
        self.running = True
        self.active_downloads = {} # sender -> dict

    def connect_to_server(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10.0) # Жесткий таймаут на подключение
            self.sock.connect((self.host, self.port))
            
            # 1. Send Login
            user_bytes = self.username.encode('utf-8')
            header_str = f"LOGIN {len(user_bytes)}"
            self.sock.sendall(f"{header_str}\n".encode('utf-8') + user_bytes)

            # 2. Send Public Key
            pub_key_bytes = self.crypto.get_public_key_pem()
            header_str = f"PUBKEY {len(pub_key_bytes)}"
            self.sock.sendall(f"{header_str}\n".encode('utf-8') + pub_key_bytes)
            
            # Start listening loop
            self.listen()
        except Exception as e:
            print(f"Connection failed: {e}")
            self.connection_lost.emit()

    def listen(self):
        try:
            while self.running:
                try:
                    # Ожидаем новое сообщение с таймаутом простоя
                    header_str = safe_read_line(self.sock, max_len=1024, timeout_sec=60.0)
                    if not header_str:
                        break # Соединение корректно закрыто
                except TimeoutError:
                    continue # Это просто таймаут простоя, продолжаем слушать
                except Exception as e:
                    print(f"Error reading header: {e}")
                    break
                
                parts = header_str.split(' ')
                cmd = parts[0]
                try:
                    if cmd == 'MSG' and len(parts) > 2:
                        length = int(parts[2])
                    elif len(parts) > 1:
                        length = int(parts[1])
                    else:
                        length = 0
                except:
                    length = 0

                try:
                    payload = safe_recv_exact(self.sock, length, timeout_sec=15.0) if length > 0 else b""
                except Exception as e:
                    print(f"Payload read error: {e}")
                    raise ConnectionResetError()

                if cmd == 'USERS':
                    # Payload is JSON dictionary of users and keys
                    users_dict = json.loads(payload.decode('utf-8'))
                    self.user_list_updated.emit(users_dict)
                
                elif cmd == 'MSG':
                    # Header was: MSG sender len
                    sender = parts[1]
                    
                    print(f"RECEIVER: Пришел пакет от {sender}. Размер: {len(payload)}, первые 20 байт: {payload[:20]}")
                    if payload.startswith(b"FILE_META "):
                        parts = payload.split(b"\n", 1)
                        if len(parts) == 2:
                            self.handle_incoming_file_meta(sender, parts[1])
                        continue

                    elif payload.startswith(b"FILE_CHUNK "):
                        parts = payload.split(b"\n", 1)
                        if len(parts) == 2:
                            self.handle_incoming_file_chunk(sender, parts[1])
                        continue

                    self.msg_received.emit(sender, payload)

        except Exception as e:
            print(f"Network error: {e}")
            self.connection_lost.emit()
        finally:
            self.stop()

    def handle_incoming_file_meta(self, sender, enc_meta):
        try:
            print(f"RECEIVER: Начинаю дешифровку FILE_META от {sender}...")
            if sender not in self.peer_keys: return
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aead_key = self.peer_keys[sender]
            aesgcm = AESGCM(aead_key)
            meta_nonce = enc_meta[:12]
            ciphertext = enc_meta[12:]
            meta_json = aesgcm.decrypt(meta_nonce, ciphertext, None).decode('utf-8')
            meta = json.loads(meta_json)
            
            save_dir = "downloads"
            os.makedirs(save_dir, exist_ok=True)
            filename = meta.get("filename", "secure_download.bin")
            save_path = os.path.join(save_dir, f"{sender}_{filename}.tmp")
            
            if os.path.exists(save_path):
                os.remove(save_path)
                
            self.active_downloads[sender] = {
                "hash": meta.get("hash"),
                "filename": filename,
                "save_path": save_path,
                "expected_chunk": 0,
                "hasher": hashlib.sha256()
            }
            self.file_progress.emit(sender, f"Receiving file: {filename}...")
            print(f"RECEIVER: Метаданные от {sender} успешно обработаны. Подготовлен файл для записи.")
        except Exception as e:
            print(f"CRITICAL META ERROR: {e}")
            import traceback; traceback.print_exc()

    def handle_incoming_file_chunk(self, sender, chunk_data):
        try:
            if sender not in self.active_downloads or sender not in self.peer_keys:
                return
                
            dl = self.active_downloads[sender]
            aead_key = self.peer_keys[sender]
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aesgcm = AESGCM(aead_key)
            
            file_id = chunk_data[:8]
            is_last = chunk_data[8]
            encrypted_chunk = chunk_data[9:]
            
            expected_chunk = dl["expected_chunk"]
            nonce = file_id + struct.pack(">I", expected_chunk)
            aad = struct.pack(">IB", expected_chunk, is_last)
            
            decrypted = aesgcm.decrypt(nonce, encrypted_chunk, aad)
            
            with open(dl["save_path"], "ab") as f:
                f.write(decrypted)
                
            dl["hasher"].update(decrypted)
            dl["expected_chunk"] += 1
            
            if is_last == 1:
                calculated_hash = dl["hasher"].hexdigest()
                expected_hash = dl["hash"]
                if calculated_hash == expected_hash:
                    print("RECEIVER: ФАЙЛ УСПЕШНО СОХРАНЕН! Хэши совпали.")
                    self.file_ready_signal.emit(sender, dl['filename'], dl['save_path'])
                else:
                    print(f"RECEIVER: ОШИБКА ХЭША! Ожидался {expected_hash}, получен {calculated_hash}. Файл удален.")
                    os.remove(dl["save_path"])
                    self.file_progress.emit(sender, f"File {dl['filename']} failed hash verification! Deleted.")
                del self.active_downloads[sender]
            else:
                print("RECEIVER: Чанк успешно записан. Ждем следующие...")
                    
        except Exception as e:
            print(f"CRITICAL CHUNK ERROR: {e}")
            import traceback; traceback.print_exc()
            if sender in self.active_downloads:
                dl = self.active_downloads[sender]
                if os.path.exists(dl["save_path"]):
                    os.remove(dl["save_path"])
                del self.active_downloads[sender]

    def send_file_stream(self, target_user, file_path, aead_key):
        print(f"WORKER: Сигнал пойман! Начинаю обработку файла {file_path}")
        try:
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)
            
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for b in iter(lambda: f.read(64 * 1024), b""):
                    hasher.update(b)
            file_hash = hasher.hexdigest()

            meta = {
                "filename": file_name,
                "size": file_size,
                "hash": file_hash
            }
            meta_bytes = json.dumps(meta).encode('utf-8')
            meta_nonce = os.urandom(12)
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aesgcm = AESGCM(aead_key)
            enc_meta = aesgcm.encrypt(meta_nonce, meta_bytes, None)
            
            meta_payload = meta_nonce + enc_meta
            inner_meta = f"FILE_META {len(meta_payload)}\n".encode('utf-8') + meta_payload
            self._send_raw_relay(target_user, inner_meta)
            
            for file_id, chunk_idx, is_last, enc_chunk in AEADCryptoHandler.encrypt_file_stream(file_path, aead_key):
                chunk_payload = file_id + struct.pack(">B", is_last) + enc_chunk
                inner_chunk = f"FILE_CHUNK {len(chunk_payload)}\n".encode('utf-8') + chunk_payload
                self._send_raw_relay(target_user, inner_chunk)
                
            self.file_progress.emit("System", f"File {file_name} sent to {target_user}.")
        except Exception as e:
            print(f"Error sending file stream: {e}")
            traceback.print_exc()

    def _send_raw_relay(self, target_user, inner_payload):
        if not self.sock: return
        target_bytes = target_user.encode('utf-8')
        payload = target_bytes + b'|' + inner_payload
        header_str = f"RELAY {len(payload)}"
        try:
            self.sock.settimeout(15.0)
            self.sock.sendall(f"{header_str}\n".encode('utf-8') + payload)
        except:
            self.connection_lost.emit()

    def send_message(self, target_user, encrypted_bytes):
        if not self.sock: 
            return
        
        # Format: RELAY target|payload
        target_bytes = target_user.encode('utf-8')
        payload = target_bytes + b'|' + encrypted_bytes
        
        header_str = f"RELAY {len(payload)}"
        try:
            self.sock.settimeout(15.0) # Таймаут на отправку
            self.sock.sendall(f"{header_str}\n".encode('utf-8') + payload)
        except:
            self.connection_lost.emit()

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()

class ToastNotification(QLabel):
    def __init__(self, parent, message, duration=3000):
        super().__init__(message, parent)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.ToolTip)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setStyleSheet("""
            QLabel {
                background-color: rgba(30, 30, 30, 220);
                color: #ffffff;
                padding: 10px 20px;
                border: 1px solid #555;
                border-radius: 6px;
                font-family: Segoe UI;
                font-size: 14px;
            }
        """)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.adjustSize()
        
        if parent:
            geo = parent.geometry()
            self.move(geo.center().x() - self.width() // 2, geo.bottom() - 120)
            
        self.setWindowOpacity(0.0)
        self.show()
        
        self.anim_in = QPropertyAnimation(self, b"windowOpacity")
        self.anim_in.setDuration(300)
        self.anim_in.setStartValue(0.0)
        self.anim_in.setEndValue(1.0)
        self.anim_in.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self.anim_in.start()
        
        QTimer.singleShot(duration, self.fade_out)
        
    def fade_out(self):
        self.anim_out = QPropertyAnimation(self, b"windowOpacity")
        self.anim_out.setDuration(300)
        self.anim_out.setStartValue(1.0)
        self.anim_out.setEndValue(0.0)
        self.anim_out.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self.anim_out.finished.connect(self.close)
        self.anim_out.start()

class SafetyNumberDialog(QDialog):
    def __init__(self, parent, my_pub, peer_pub, peer_name):
        super().__init__(parent)
        self.setWindowTitle("Verify Keys")
        self.setFixedSize(450, 250)
        self.setStyleSheet("QDialog { background-color: #2b2b2b; color: white; } QLabel { color: white; font-family: Segoe UI; font-size: 14px; } QPushButton { background-color: #0078d4; color: white; border: none; padding: 8px; border-radius: 4px; font-weight: bold; } QPushButton:hover { background-color: #1084d8; }")
        
        layout = QVBoxLayout(self)
        info = QLabel("Compare these numbers via a secure channel\nto ensure there is no wiretapping.")
        info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(info)
        
        def format_hash(pub):
            h = hashlib.sha256(pub).hexdigest().upper()
            return " ".join([h[i:i+5] for i in range(0, len(h), 5)])
            
        my_hash = format_hash(my_pub)
        peer_hash = format_hash(peer_pub)
        
        my_lbl = QLabel(f"<b>Your Safety Number:</b><br><span style='font-family: Consolas; color: #00ff00;'>{my_hash}</span>")
        my_lbl.setWordWrap(True)
        peer_lbl = QLabel(f"<b>{peer_name} Safety Number:</b><br><span style='font-family: Consolas; color: #00ff00;'>{peer_hash}</span>")
        peer_lbl.setWordWrap(True)
        
        layout.addWidget(my_lbl)
        layout.addWidget(peer_lbl)
        
        btn = QPushButton("Close")
        btn.clicked.connect(self.accept)
        layout.addWidget(btn)

class EmojiPicker(QWidget):
    def __init__(self, target_input, parent=None):
        super().__init__(parent)
        self.target_input = target_input
        self.setWindowFlags(Qt.WindowType.Popup | Qt.WindowType.FramelessWindowHint)
        self.setFixedSize(300, 250)
        self.setStyleSheet("""
            QWidget {
                background-color: #2b2b2b;
                border: 1px solid #444;
                border-radius: 8px;
            }
            QScrollArea {
                border: none;
                background-color: transparent;
            }
            QScrollBar:vertical {
                border: none;
                background: #2b2b2b;
                width: 10px;
                margin: 0px 0px 0px 0px;
            }
            QScrollBar::handle:vertical {
                background: #555;
                min-height: 20px;
                border-radius: 5px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                border: none;
                background: none;
            }
            QToolButton {
                background-color: transparent;
                border: none;
                font-size: 20px;
                padding: 4px;
                border-radius: 4px;
            }
            QToolButton:hover {
                background-color: #3c3c3c;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        from PyQt6.QtWidgets import QScrollArea, QGridLayout, QToolButton
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        layout.addWidget(scroll)

        grid_widget = QWidget()
        grid = QGridLayout(grid_widget)
        grid.setSpacing(2)
        grid.setContentsMargins(0, 0, 0, 0)
        
        emojis = [
            "😀", "😃", "😄", "😁", "😆", "😅", "😂", "🤣", "😊", "😇",
            "🙂", "🙃", "😉", "😌", "😍", "🥰", "😘", "😗", "😙", "😚",
            "😋", "😛", "😝", "😜", "🤪", "🤨", "🧐", "🤓", "😎", "🤩",
            "🥳", "😏", "😒", "😞", "😔", "😟", "😕", "🙁", "☹️", "😣",
            "😖", "😫", "😩", "🥺", "😢", "😭", "😤", "😠", "😡", "🤬",
            "🤯", "😳", "🥵", "🥶", "😱", "😨", "😰", "😥", "😓", "🤗",
            "🤔", "🤭", "🤫", "🤥", "😶", "😐", "😑", "😬", "🙄", "😯",
            "👍", "👎", "✌️", "🤞", "🤟", "🤘", "👌", "🤌", "🤏", "👈",
            "👉", "👆", "👇", "☝️", "✋", "🤚", "🖐️", "🖖", "👋", "🤙",
            "💪", "🦾", "🖕", "✍️", "🙏", "🤝", "👏", "🙌", "👐", "🤲",
            "❤️", "🧡", "💛", "💚", "💙", "💜", "🖤", "🤍", "🤎", "💔",
            "❣️", "💕", "💞", "💓", "💗", "💖", "💘", "💝", "🔥", "✨"
        ]

        row = 0
        col = 0
        for emo in emojis:
            btn = QToolButton()
            btn.setText(emo)
            btn.setFixedSize(36, 36)
            btn.clicked.connect(lambda checked, e=emo: self.insert_emoji(e))
            grid.addWidget(btn, row, col)
            col += 1
            if col > 6:
                col = 0
                row += 1

        scroll.setWidget(grid_widget)

    def insert_emoji(self, emo):
        self.target_input.insert(emo)
        self.close()

# --- Main Window ---
class SecureMessenger(QMainWindow):
    def __init__(self):
        super().__init__()
        self.username = ""
        self.crypto = AEADCryptoHandler()
        self.peer_keys = {} # {username: 32-byte AEAD key}
        self.peer_pub_keys = {} # {username: pub_key_bytes}
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

        header_layout = QHBoxLayout()
        self.chat_header = QLabel("Select a user to start chatting")
        self.chat_header.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        header_layout.addWidget(self.chat_header)
        
        self.verify_btn = QPushButton("🛡️ Verify Keys")
        self.verify_btn.setFixedSize(120, 30)
        self.verify_btn.hide()
        self.verify_btn.clicked.connect(self.show_safety_numbers)
        header_layout.addWidget(self.verify_btn)
        
        right_layout.addLayout(header_layout)

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

        self.attach_btn = QPushButton("📎")
        self.attach_btn.setFixedWidth(40)
        self.attach_btn.clicked.connect(self.attach_file)
        input_layout.addWidget(self.attach_btn)

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
        self.worker = NetworkWorker(host, port, self.username, self.crypto, self.peer_keys)
        self.worker.moveToThread(self.network_thread)
        
        self.network_thread.started.connect(self.worker.connect_to_server)
        self.worker.msg_received.connect(self.handle_incoming_msg)
        self.worker.user_list_updated.connect(self.update_user_list)
        self.worker.connection_lost.connect(self.on_connection_lost)
        self.worker.file_progress.connect(self.display_system_message)
        self.worker.file_ready_signal.connect(self.prompt_file_save)
        
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
                    self.peer_pub_keys[user] = pem_bytes
                    peer_pub = AEADCryptoHandler.load_public_key_from_pem(pem_bytes)
                    self.peer_keys[user] = self.crypto.derive_shared_aead_key(peer_pub)
                except Exception as e:
                    print(f"Failed to derive key for {user}: {e}")

            self.user_list.addItem(user)
        
        # Reselect if possible
        if selected_text:
            items = self.user_list.findItems(selected_text, Qt.MatchFlag.MatchExactly)
            if items:
                self.user_list.setCurrentItem(items[0])

    def on_user_selected(self, item):
        text = item.text()
        if text.endswith(" (!)"):
            text = text[:-4]
            item.setText(text)
        self.current_chat_user = text
        self.chat_header.setText(f"Secure Chat with {self.current_chat_user}")
        self.verify_btn.show()
        self.refresh_chat_display()

    def show_safety_numbers(self):
        if not self.current_chat_user or self.current_chat_user not in self.peer_pub_keys:
            return
        my_pub = self.crypto.get_public_key_pem()
        peer_pub = self.peer_pub_keys[self.current_chat_user]
        dlg = SafetyNumberDialog(self, my_pub, peer_pub, self.current_chat_user)
        dlg.exec()

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
            aead_key = self.peer_keys[sender]
            decrypted = AEADCryptoHandler.decrypt_message(aead_key, encrypted_payload)
            
            formatted = f"<b style='color: #0078d4'>{sender}:</b> {decrypted}"
            
            if sender not in self.messages:
                self.messages[sender] = []
            self.messages[sender].append(formatted)
            
            if self.current_chat_user == sender:
                self.chat_display.append(formatted)
            else:
                for i in range(self.user_list.count()):
                    item = self.user_list.item(i)
                    if item.text() == sender:
                        item.setText(f"{sender} (!)")
                        break
                
        except Exception as e:
            print(f"Decryption error from {sender}: {e}")

    def display_system_message(self, sender, text):
        formatted = f"<span style='color: #00a8ff'><i>System: {text}</i></span>"
        if sender not in self.messages:
            self.messages[sender] = []
        self.messages[sender].append(formatted)
        if self.current_chat_user == sender:
            self.chat_display.append(formatted)

    def prompt_file_save(self, sender, filename, temp_filepath):
        reply = QMessageBox.question(self, 'New File', f'{sender} sent the file {filename}.\nSave?', QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            final_path = temp_filepath[:-4] if temp_filepath.endswith('.tmp') else temp_filepath
            if os.path.exists(final_path):
                os.remove(final_path)
            os.rename(temp_filepath, final_path)
            self.display_system_message(sender, f"File {filename} saved.")
        else:
            if os.path.exists(temp_filepath):
                os.remove(temp_filepath)
            self.display_system_message(sender, "Download cancelled.")

    def attach_file(self):
        if not self.current_chat_user:
            print("UI Error: Пользователь не выбран")
            ToastNotification(self, "Please select a user to chat with first.")
            return

        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Send")
        if not file_path:
            print("UI Error: Файл не выбран")
            return
            
        print(f"UI: Выбран файл {file_path}")

        target = self.current_chat_user
        print(f"UI: Ключ для {target} найден: {target in self.peer_keys}")
        
        if target not in self.peer_keys:
            print(f"UI Error: Ключ шифрования для {target} отсутствует")
            ToastNotification(self, "Secure handshake not established with this user.")
            return

        aead_key = self.peer_keys[target]
        print(f"UI: Запуск фонового потока для файла {file_path}")
        import threading
        threading.Thread(target=self.worker.send_file_stream, args=(target, file_path, aead_key), daemon=True).start()
        
        file_name = os.path.basename(file_path)
        formatted = f"<b style='color: #28a745'>Me:</b> Sending file: <i>{file_name}</i>..."
        if target not in self.messages:
            self.messages[target] = []
        self.messages[target].append(formatted)
        if self.current_chat_user == target:
            self.chat_display.append(formatted)

    def send_msg(self):
        # 1. Строгая валидация ввода и состояния
        text = self.msg_input.text().strip()
        target = self.current_chat_user
        
        if not target or not text or target not in self.peer_keys:
            print(f"Warning: Cannot send message. Target selected: {bool(target)}, Text entered: {bool(text)}, Key exists: {target in self.peer_keys}")
            if not target:
                ToastNotification(self, "Please select a user to chat with first.")
            return

        # 2. Защищенный блок криптографии и сети
        try:
            aead_key = self.peer_keys[target]
            encrypted = AEADCryptoHandler.encrypt_message(aead_key, text)
            
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
            # Просто выводим ошибку в консоль, сохраняя приложение живым
            print(f"Crypto/Network Error while sending message to {target}: {e}")

    def show_emoji_picker(self):
        if not hasattr(self, 'emoji_picker'):
            self.emoji_picker = EmojiPicker(self.msg_input, self)
        
        pos = self.emoji_btn.mapToGlobal(self.emoji_btn.rect().topLeft())
        pos.setY(pos.y() - self.emoji_picker.height() - 5)
        self.emoji_picker.move(pos)
        self.emoji_picker.show()

    def on_connection_lost(self):
        QMessageBox.critical(self, "Error", "Connection to server lost.")
        self.close()

    def closeEvent(self, event):
        if self.worker:
            self.worker.running = False
            if self.worker.sock:
                try:
                    self.worker.sock.close()
                except:
                    pass
        if self.network_thread:
            self.network_thread.quit()
            self.network_thread.wait(1000)
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SecureMessenger()
    window.show()
    sys.exit(app.exec())

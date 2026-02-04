import socket
import threading
import sys

class ChatServer:
    def __init__(self, host='0.0.0.0', port=5000):
        self.host = host
        self.port = port
        self.clients = {}  # {username: conn}
        self.pub_keys = {} # {username: pem_bytes}
        self.lock = threading.Lock()

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Server started on {self.host}:{self.port}")

        while True:
            conn, addr = self.server_socket.accept()
            threading.Thread(target=self.handle_client, args=(conn, addr)).start()

    def handle_client(self, conn, addr):
        username = None
        try:
            while True:
                # Read header: CMD LENGTH
                header = self.read_line(conn)
                if not header:
                    break
                
                parts = header.split(' ')
                cmd = parts[0]
                length = int(parts[1]) if len(parts) > 1 else 0
                
                payload = self.read_bytes(conn, length) if length > 0 else b""

                if cmd == 'LOGIN':
                    username = payload.decode('utf-8')
                    with self.lock:
                        self.clients[username] = conn
                    print(f"User logged in: {username}")
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

    def read_line(self, conn):
        """Reads a line ending in newline."""
        buf = b""
        while True:
            c = conn.recv(1)
            if not c:
                return None
            if c == b'\n':
                return buf.decode('utf-8').strip()
            buf += c

    def read_bytes(self, conn, n):
        buf = b""
        while len(buf) < n:
            packet = conn.recv(n - len(buf))
            if not packet:
                return None
            buf += packet
        return buf

    def broadcast_user_list(self):
        # Format: LIST_UPDATE <json_or_formatted_list>
        # We'll use a simple format: USER1,USER2...
        # But we also need keys.
        # Let's send a JSON payload.
        import json
        
        # pub_keys is {user: bytes}. Convert bytes to str for JSON
        serializable_keys = {u: k.decode('utf-8') for u, k in self.pub_keys.items()}
        data = json.dumps(serializable_keys).encode('utf-8')
        
        header = f"USERS {len(data)}\n".encode('utf-8')
        with self.lock:
            for u, c in self.clients.items():
                try:
                    c.sendall(header + data)
                except:
                    pass

    def send_to_user(self, sender, target, data):
        # Frame: MSG <sender> <len> \n <data>
        header = f"MSG {sender} {len(data)}\n".encode('utf-8')
        with self.lock:
            if target in self.clients:
                try:
                    self.clients[target].sendall(header + data)
                except:
                    pass
            else:
                print(f"Target {target} not found")

if __name__ == "__main__":
    ChatServer().start()

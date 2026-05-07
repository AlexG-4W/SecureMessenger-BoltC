# BoltC - Secure E2EE Relay Messenger 🛡️

BoltC is a robust, privacy-first messenger application built with Python. It features a decentralized-style architecture consisting of an independent relay server and "thick" clients. The server acts purely as an agnostic packet router, relaying encrypted bytes without ever knowing the contents of messages or files, ensuring absolute End-to-End Encryption (E2EE).

## 🌟 Key Features

* **Hybrid E2EE Encryption:** Implements a state-of-the-art cryptographic pipeline. RSA (2048-bit) is used for secure public key exchange, which then derives a shared secret to establish an AES-256-GCM symmetric session key for ultra-fast, authenticated message encryption.
* **Secure File Streaming:** Capable of transferring files of any size without causing Out-of-Memory (OOM) crashes. Files are chunked into 64KB blocks, each uniquely encrypted with its own Nonce/AAD. Chunks are securely cached as `.tmp` files on the receiver's end until the final SHA-256 hash validation is passed.
* **Safety Numbers (MITM Protection):** Inspired by Signal and WhatsApp, BoltC provides a UI to verify "Safety Numbers" (SHA-256 fingerprints of public keys). This ensures that the public keys were not tampered with by a malicious server or network actor.
* **Modern PyQt6 UI:** A sleek, responsive dark-mode interface built with PyQt6. It features non-blocking, self-dismissing Toast notifications, a modern 80-emoji grid popup, and interactive confirmation dialogs for secure file downloads.


<img width="2458" height="952" alt="scr1" src="https://github.com/user-attachments/assets/407c889c-e636-4144-8323-bf77037ed8fe" />





<img width="1355" height="932" alt="scr2" src="https://github.com/user-attachments/assets/71553cfc-c335-401a-b869-7ded9c5bcd56" />








## 🏗️ Architecture Highlights

* **Non-Blocking Network Layer:** The client effectively circumvents Qt Event Loop blocking by dispatching heavy network I/O (like secure file chunk streaming) to dedicated `threading.Thread` workers.
* **Thread-Safe Signals:** Fully implements PyQt6 `pyqtSignal` mechanisms using native `object` serialization to safely marshal complex binary data and GUI updates across background threads and the main UI loop.
* **Zero-Knowledge Server:** The server only parses a plain-text header (e.g., `MSG <recipient> <length>`) and blindly forwards the attached encrypted binary payload to the destination socket.

## 🚀 Installation & Usage

### 1. Install Dependencies
Ensure you have Python 3.10+ installed. Install the required libraries using pip:

```bash
pip install -r requirements.txt
```

### 2. Start the Server
Run the relay server. By default, it will listen on port `5000`.
```bash
python server.py
```

### 3. Start the Clients
Run the client application on multiple instances or machines.
```bash
python client.py
```
1. Enter your chosen username.
2. Enter the Server IP (use `127.0.0.1` for local testing).
3. Connect, choose a peer from the "Contacts" list, verify your Safety Numbers, and start chatting securely!

## 🔐 Security Disclaimer
This project is an educational and experimental implementation of E2EE protocols. While it uses industry-standard cryptography primitives (`cryptography.hazmat`), it has not been audited by professional security researchers. Use at your own risk.

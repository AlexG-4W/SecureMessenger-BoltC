# ![scr1](https://github.com/user-attachments/assets/3486c428-d681-46df-a971-0c5de4779e18)
SecureMessenger-Py

A production-ready, end-to-end encrypted (E2EE) messaging application built with **Python**, **PyQt6**, and the **Cryptography** library.

## 🌟 Features
- **True End-to-End Encryption:** Uses Elliptic Curve Diffie-Hellman (ECDH) for key exchange. Messages are encrypted locally and can only be decrypted by the intended recipient.
- **Modern Semi-Transparent UI:** A sleek, dark-themed interface with alpha-channel transparency for a modern aesthetic.
- **Emoji Support:** Integrated emoji picker for expressive messaging.
- **Secure Key Derivation:** Uses HKDF (HMAC-based Key Derivation Function) to derive 32-byte AES keys from shared secrets.
- **Threaded Architecture:** Handles networking and GUI updates independently to ensure a smooth user experience.

## 🛡️ Security Implementation
1. **Handshake:** Every client generates a unique SECP384R1 private key on startup.
2. **Key Exchange:** Public keys are exchanged via the relay server.
3. **Encryption:** When a chat starts, a shared secret is generated. This secret is used with Fernet (AES-128 in CBC mode with HMAC-SHA256) to secure every message.
4. **Privacy:** The server only sees encrypted bytes and metadata required for relaying; it never has access to the plaintext or private keys.

## 🚀 Getting Started

### Prerequisites
- Python 3.8 or higher
- Windows/Linux/macOS

### Installation
1. Download the source files.
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Running the Application
#### Option A: One-Click (Windows)
Double-click the `run_messenger.bat` file. This will automatically start the server and two client instances for testing.

#### Option B: Manual (Terminal)
1. **Start the Server:**
   ```bash
   python server.py
   ```
2. **Start the Client(s):**
   ```bash
   python client.py
   ```

## 📂 File Descriptions
- `client.py`: The main GUI application logic and networking.
- `server.py`: The TCP relay server that facilitates connections.
- `crypto_utils.py`: The core cryptographic engine.
- `run_messenger.bat`: A helper script for easy local testing.

## 📜 License
This project is open-source and available under the MIT License.

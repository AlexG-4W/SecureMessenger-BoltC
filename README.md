# BoltC: Secure E2EE Messenger
![scr2](https://github.com/user-attachments/assets/6426bf69-9d4e-4cca-bb24-07cc45ba9a7a)

BoltC is an open-source, production-ready messaging application designed with a focus on **End-to-End Encryption (E2EE)** for both messages and files. Built with Python and PyQt6, it combines a modern aesthetic with robust security standards.

## 🌟 Key Features
- **End-to-End Encryption (E2EE):** Utilizes the ECDH protocol (Elliptic Curve Diffie-Hellman) on the SECP384R1 curve for secure key exchange.
- **Secure File Exchange:** Transfer files (up to 10MB) with full end-to-end encryption.
- **Dedicated Server GUI:** A comprehensive dashboard to manage your relay server with real-time logs and connection monitoring.
- **Modern UI:** Sleek, semi-transparent dark mode interface (Alpha-blending) with integrated Emoji support.
- **Hardened Security:** Built-in protection against DoS attacks, packet size enforcement, data sanitization, and buffer overflow prevention.

## 🛡️ Security Architecture
1. **Key Exchange:** Clients generate ephemeral keys locally upon startup. Public keys are broadcasted via the relay server, but private keys never leave the device.
2. **Encryption:** Messages and files are secured using AES-128 in CBC mode with HMAC-SHA256 (via Fernet).
3. **Data Integrity:** Every packet is verified for integrity. The server only sees encrypted bytes and the metadata required for routing.
4. **Resilience:** Both server and client are hardened against Denial of Service (DoS) attempts involving malformed headers or massive data payloads.

## 🚀 Getting Started

### For Users (Windows)
Download the `BoltC-Client.exe` from the **Releases** section, launch it, and enter the server's IP address.

### For Developers
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Start the Server: `python server.py`
3. Start the Client: `python client.py`

## 🛠️ Build from Source
To generate standalone executables, run:
```bash
build_all.bat
```
The compiled files will appear in the `dist/` directory.

## 📜 License
This project is licensed under the MIT License - see the LICENSE file for details.

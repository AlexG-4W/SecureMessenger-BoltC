import os
import hashlib
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec

class KeyAuthenticator:
    @staticmethod
    def generate_safety_number(my_pub_key_pem: bytes, peer_pub_key_pem: bytes) -> str:
        keys = sorted([my_pub_key_pem, peer_pub_key_pem])
        combined_keys = keys[0] + keys[1]
        digest = hashlib.sha256(combined_keys).digest()
        number_str = str(int.from_bytes(digest, byteorder='big'))
        padded = number_str.zfill(60)[:60]
        return " ".join(padded[i:i+5] for i in range(0, 60, 5))

class AEADCryptoHandler:
    def __init__(self, private_key=None):
        self.private_key = private_key or ec.generate_private_key(ec.SECP384R1())
        self.public_key = self.private_key.public_key()

    def get_public_key_pem(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def load_public_key_from_pem(pem_bytes: bytes):
        return serialization.load_pem_public_key(pem_bytes)

    def derive_shared_aead_key(self, peer_public_key) -> bytes:
        shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_secret)

    @staticmethod
    def encrypt_message(key: bytes, message: str) -> bytes:
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, message.encode('utf-8'), associated_data=None)
        return nonce + ciphertext

    @staticmethod
    def decrypt_message(key: bytes, token: bytes) -> str:
        aesgcm = AESGCM(key)
        nonce, ciphertext = token[:12], token[12:]
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        return plaintext.decode('utf-8')

    @staticmethod
    def encrypt_file_stream(file_path: str, key: bytes, chunk_size: int = 64 * 1024):
        file_id = os.urandom(8)
        file_size = os.path.getsize(file_path)
        with open(file_path, 'rb') as f:
            chunk_idx = 0
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                is_last = 1 if f.tell() == file_size else 0
                nonce = file_id + struct.pack(">I", chunk_idx)
                aad = struct.pack(">IB", chunk_idx, is_last)
                aesgcm = AESGCM(key)
                encrypted_chunk = aesgcm.encrypt(nonce, chunk, aad)
                yield file_id, chunk_idx, is_last, encrypted_chunk
                chunk_idx += 1

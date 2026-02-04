import os
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

class CryptoHandler:
    def __init__(self):
        # Generate an Elliptic Curve private key for ECDH
        self.private_key = ec.generate_private_key(ec.SECP384R1())
        self.public_key = self.private_key.public_key()

    def get_public_key_pem(self) -> bytes:
        """Returns the public key in PEM format to share with peers."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def load_public_key_from_pem(pem_bytes: bytes):
        """Loads a peer's public key from PEM bytes."""
        return serialization.load_pem_public_key(pem_bytes)

    def derive_shared_fernet(self, peer_public_key) -> Fernet:
        """
        Derives a shared secret using ECDH and transforms it into a Fernet instance.
        """
        shared_key = self.private_key.exchange(ec.ECDH(), peer_public_key)
        
        # Derive a symmetric key from the shared secret using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)
        
        # Fernet requires a base64 encoded 32-byte key
        return Fernet(base64.urlsafe_b64encode(derived_key))

    @staticmethod
    def encrypt_message(fernet: Fernet, message: str) -> bytes:
        return fernet.encrypt(message.encode('utf-8'))

    @staticmethod
    def decrypt_message(fernet: Fernet, token: bytes) -> str:
        return fernet.decrypt(token).decode('utf-8')

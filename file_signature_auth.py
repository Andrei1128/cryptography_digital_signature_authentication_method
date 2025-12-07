from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.exceptions import InvalidSignature
import base64
import hashlib
import os
import json
import datetime

class FileSignatureAuth:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_key_pair(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def save_keys(self, private_key_path="private_key.pem", public_key_path="public_key.pem"):
        with open(private_key_path, "wb") as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(public_key_path, "wb") as f:
            f.write(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    def load_keys(self, private_key_path="private_key.pem", public_key_path="public_key.pem"):
        with open(private_key_path, "rb") as f:
            self.private_key = load_pem_private_key(
                f.read(),
                password=None
            )

        with open(public_key_path, "rb") as f:
            self.public_key = load_pem_public_key(f.read())

    def sign_file(self, file_path):
        if not self.private_key:
            raise ValueError("Private key not loaded")
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(file_path, "rb") as f:
            file_content = f.read()
        
        file_hash = hashlib.sha256(file_content).digest()
        
        signature = self.private_key.sign(
            file_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return {
            'signature': base64.b64encode(signature).decode(),
            'file_hash': file_hash.hex(),
            'file_name': os.path.basename(file_path),
            'timestamp': datetime.datetime.now().isoformat()
        }

    def verify_file_signature(self, file_path, signature_data):
        if not self.public_key:
            raise ValueError("Public key not loaded")
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(file_path, "rb") as f:
            file_content = f.read()
        
        current_hash = hashlib.sha256(file_content).hexdigest()
        
        if current_hash != signature_data['file_hash']:
            return False
        
        try:
            signature_bytes = base64.b64decode(signature_data['signature'])
            file_hash = bytes.fromhex(signature_data['file_hash'])
            
            self.public_key.verify(
                signature_bytes,
                file_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    def save_signature_data(self, signature_data, output_path):
        with open(output_path, 'w') as f:
            json.dump(signature_data, f, indent=4)

    def load_signature_data(self, signature_path):
        with open(signature_path, 'r') as f:
            return json.load(f)

    def sign_message(self, message):
        if not self.private_key:
            raise ValueError("Private key not loaded")

        signature = self.private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()

    def verify_signature(self, message, signature):
        if not self.public_key:
            raise ValueError("Public key not loaded")

        try:
            signature_bytes = base64.b64decode(signature)
            self.public_key.verify(
                signature_bytes,
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
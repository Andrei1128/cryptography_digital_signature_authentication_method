from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, utils
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.exceptions import InvalidSignature
import base64
import hashlib
import json
import datetime
import os
import time
import uuid
try:
    from PyPDF2 import PdfReader, PdfWriter
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
    from io import BytesIO
    PDF_SUPPORT = True
except ImportError:
    PDF_SUPPORT = False

class DigitalSignatureAuth:
    def __init__(self, algorithm='RSA', hash_algorithm='SHA256'):
        self.private_key = None
        self.public_key = None
        self.algorithm = algorithm
        self.hash_algorithm = hash_algorithm
        self.supported_algorithms = ['RSA', 'ECDSA']
        self.supported_hash_algorithms = ['SHA256', 'SHA512', 'SHA3_256']

    def set_algorithm(self, algorithm):
        if algorithm not in self.supported_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        self.algorithm = algorithm

    def set_hash_algorithm(self, hash_algorithm):
        if hash_algorithm not in self.supported_hash_algorithms:
            raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")
        self.hash_algorithm = hash_algorithm

    def get_hash_object(self):
        if self.hash_algorithm == 'SHA256':
            return hashes.SHA256()
        elif self.hash_algorithm == 'SHA512':
            return hashes.SHA512()
        elif self.hash_algorithm == 'SHA3_256':
            return hashes.SHA3_256()
        else:
            return hashes.SHA256()

    def get_hashlib_algorithm(self):
        if self.hash_algorithm == 'SHA256':
            return 'sha256'
        elif self.hash_algorithm == 'SHA512':
            return 'sha512'
        elif self.hash_algorithm == 'SHA3_256':
            return 'sha3_256'
        else:
            return 'sha256'

    def validate_algorithm_security(self, key_algorithm=None, hash_algorithm=None):
        algo = key_algorithm or self.algorithm
        hash_algo = hash_algorithm or self.hash_algorithm
        
        security_matrix = {
            'RSA': {
                'SHA256': {'secure': True, 'strength': 'Strong (256-bit)'},
                'SHA512': {'secure': True, 'strength': 'Very Strong (512-bit)'},
                'SHA3_256': {'secure': True, 'strength': 'Strong (256-bit, SHA3)'}
            },
            'ECDSA': {
                'SHA256': {'secure': True, 'strength': 'Strong (SECP256R1 + SHA256)'},
                'SHA512': {'secure': True, 'strength': 'Very Strong (SECP256R1 + SHA512)'},
                'SHA3_256': {'secure': True, 'strength': 'Strong (SECP256R1 + SHA3_256)'}
            }
        }
        
        if algo in security_matrix and hash_algo in security_matrix[algo]:
            return security_matrix[algo][hash_algo]
        
        return {'secure': False, 'strength': 'Unknown algorithm combination'}

    def get_algorithm_recommendations(self):
        recommendations = []
        
        if self.algorithm == 'RSA':
            recommendations.append(f"RSA 2048-bit: Suitable for most security needs")
        elif self.algorithm == 'ECDSA':
            recommendations.append(f"ECDSA SECP256R1: Modern, efficient elliptic curve")
        
        if self.hash_algorithm == 'SHA256':
            recommendations.append(f"SHA256: Industry standard, widely supported")
        elif self.hash_algorithm == 'SHA512':
            recommendations.append(f"SHA512: Extra security margin, larger output")
        elif self.hash_algorithm == 'SHA3_256':
            recommendations.append(f"SHA3_256: Latest standard, resistant to length extension")
        
        return recommendations

    def generate_key_pair(self, algorithm=None):
        if algorithm:
            self.set_algorithm(algorithm)
        
        if self.algorithm == 'RSA':
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
        elif self.algorithm == 'ECDSA':
            self.private_key = ec.generate_private_key(ec.SECP256R1())
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")
        
        self.public_key = self.private_key.public_key()

    def get_timestamp_with_microseconds(self):
        now = datetime.datetime.now()
        return {
            'iso_format': now.isoformat(),
            'unix_timestamp': time.time(),
            'formatted': now.strftime('%Y-%m-%d %H:%M:%S.%f'),
            'timezone': str(now.astimezone().tzinfo)
        }

    def generate_signature_id(self):
        return str(uuid.uuid4())

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

    def detect_key_type(self, key_object):
        if isinstance(key_object, rsa.RSAPrivateKey) or isinstance(key_object, rsa.RSAPublicKey):
            return 'RSA'
        elif isinstance(key_object, ec.EllipticCurvePrivateKey) or isinstance(key_object, ec.EllipticCurvePublicKey):
            return 'ECDSA'
        else:
            return None

    def load_keys(self, private_key_path="private_key.pem", public_key_path="public_key.pem"):
        with open(private_key_path, "rb") as f:
            self.private_key = load_pem_private_key(
                f.read(),
                password=None
            )

        with open(public_key_path, "rb") as f:
            self.public_key = load_pem_public_key(f.read())
        
        detected_algorithm = self.detect_key_type(self.private_key)
        if detected_algorithm:
            self.algorithm = detected_algorithm

    def sign_message(self, message, signer_name=None, metadata=None):
        if not self.private_key:
            raise ValueError("Private key not loaded")

        hash_obj = self.get_hash_object()
        
        if self.algorithm == 'RSA':
            signature = self.private_key.sign(
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hash_obj),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hash_obj
            )
        elif self.algorithm == 'ECDSA':
            signature = self.private_key.sign(
                message.encode(),
                ec.ECDSA(hash_obj)
            )
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")
        
        signature_b64 = base64.b64encode(signature).decode()

        return signature_b64

    def sign_message_with_timestamp(self, message, signer_name=None, metadata=None):
        if not self.private_key:
            raise ValueError("Private key not loaded")

        hash_obj = self.get_hash_object()
        
        if self.algorithm == 'RSA':
            signature = self.private_key.sign(
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hash_obj),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hash_obj
            )
        elif self.algorithm == 'ECDSA':
            signature = self.private_key.sign(
                message.encode(),
                ec.ECDSA(hash_obj)
            )
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")
        
        timestamp_info = self.get_timestamp_with_microseconds()
        
        signature_data = {
            'signature_id': self.generate_signature_id(),
            'signature': base64.b64encode(signature).decode(),
            'message_hash': hashlib.sha256(message.encode()).hexdigest(),
            'algorithm': self.algorithm,
            'hash_algorithm': self.hash_algorithm,
            'timestamp': timestamp_info['iso_format'],
            'timestamp_unix': timestamp_info['unix_timestamp'],
            'timestamp_formatted': timestamp_info['formatted'],
            'signer_name': signer_name or 'Unknown'
        }
        
        if metadata:
            signature_data.update(metadata)
        
        return signature_data

    def verify_signature(self, message, signature):
        if not self.public_key:
            raise ValueError("Public key not loaded")

        try:
            signature_bytes = base64.b64decode(signature)
            hash_obj = self.get_hash_object()
            
            if self.algorithm == 'RSA':
                self.public_key.verify(
                    signature_bytes,
                    message.encode(),
                    padding.PSS(
                        mgf=padding.MGF1(hash_obj),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hash_obj
                )
            elif self.algorithm == 'ECDSA':
                self.public_key.verify(
                    signature_bytes,
                    message.encode(),
                    ec.ECDSA(hash_obj)
                )
            return True
        except InvalidSignature:
            return False

    def sign_file(self, file_path, metadata=None):
        if not self.private_key:
            raise ValueError("Private key not loaded")

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(file_path, "rb") as f:
            file_content = f.read()

        hashlib_algo = self.get_hashlib_algorithm()
        file_hash_bytes = hashlib.new(hashlib_algo, file_content).digest()

        hash_obj = self.get_hash_object()

        if self.algorithm == "RSA":
            signature = self.private_key.sign(
                file_hash_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hash_obj),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hash_obj
            )
        elif self.algorithm == "ECDSA":
            signature = self.private_key.sign(
                file_hash_bytes,
                ec.ECDSA(hash_obj)
            )
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

        signature_data = {
            "signature": base64.b64encode(signature).decode(),
            "file_hash": base64.b64encode(file_hash_bytes).decode(),
            "file_name": os.path.basename(file_path),
            "timestamp": datetime.datetime.now().isoformat(),
            "algorithm": self.algorithm,
            "hash_algorithm": self.hash_algorithm
        }

        if metadata:
            signature_data.update({
                "signer_name": metadata.get("signer_name", ""),
                "organization": metadata.get("organization", ""),
                "email": metadata.get("email", ""),
                "reason": metadata.get("reason", ""),
                "location": metadata.get("location", "")
            })

        return signature_data


    def verify_file_signature(self, file_path, signature_data):
        if not self.public_key:
            raise ValueError("Public key not loaded")
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(file_path, "rb") as f:
            file_content = f.read()
        
        stored_hash_algo = signature_data.get('hash_algorithm', 'SHA256')
        if stored_hash_algo == 'SHA256':
            hashlib_algo = 'sha256'
        elif stored_hash_algo == 'SHA512':
            hashlib_algo = 'sha512'
        elif stored_hash_algo == 'SHA3_256':
            hashlib_algo = 'sha3_256'
        else:
            hashlib_algo = 'sha256'
        
        current_hash = hashlib.new(hashlib_algo, file_content).hexdigest()
        
        if current_hash != signature_data['file_hash']:
            return False
        
        try:
            signature_bytes = base64.b64decode(signature_data['signature'])
            file_hash = bytes.fromhex(signature_data['file_hash'])
            
            stored_algorithm = signature_data.get('algorithm', 'RSA')
            stored_hash_algorithm = signature_data.get('hash_algorithm', 'SHA256')
            
            original_algo = self.algorithm
            original_hash = self.hash_algorithm
            self.algorithm = stored_algorithm
            self.hash_algorithm = stored_hash_algorithm
            
            hash_obj = self.get_hash_object()
            
            if stored_algorithm == 'RSA':
                self.public_key.verify(
                    signature_bytes,
                    file_hash,
                    padding.PSS(
                        mgf=padding.MGF1(hash_obj),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hash_obj
                )
            elif stored_algorithm == 'ECDSA':
                self.public_key.verify(
                    signature_bytes,
                    file_hash,
                    ec.ECDSA(hash_obj)
                )
            
            self.algorithm = original_algo
            self.hash_algorithm = original_hash
            return True
        except InvalidSignature:
            return False

    def save_signature_data(self, signature_data, output_path):
        with open(output_path, 'w') as f:
            json.dump(signature_data, f, indent=4)

    def load_signature_data(self, signature_path):
        with open(signature_path, 'r') as f:
            return json.load(f)
    
    def detect_signature_algorithms(self, signature_data):
        """Auto-detect key and hash algorithms from signature data"""
        key_algorithm = signature_data.get('algorithm', 'RSA')
        hash_algorithm = signature_data.get('hash_algorithm', 'SHA256')
        
        if key_algorithm not in self.supported_algorithms:
            key_algorithm = 'RSA'
        if hash_algorithm not in self.supported_hash_algorithms:
            hash_algorithm = 'SHA256'
        
        security_info = self.validate_algorithm_security(key_algorithm, hash_algorithm)
        
        return {
            'key_algorithm': key_algorithm,
            'hash_algorithm': hash_algorithm,
            'security_info': security_info
        }
    
    def create_multisig_document(self, file_path, metadata=None):
        """Create a document structure for multi-signature"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        with open(file_path, "rb") as f:
            file_content = f.read()
        
        hashlib_algo = self.get_hashlib_algorithm()
        file_hash = hashlib.new(hashlib_algo, file_content).hexdigest()
        
        multisig_data = {
            'file_name': os.path.basename(file_path),
            'file_path': file_path,
            'file_hash': file_hash,
            'hash_algorithm': self.hash_algorithm,
            'created_timestamp': self.get_timestamp_with_microseconds()['iso_format'],
            'signatures': [],
            'metadata': metadata or {}
        }
        
        return multisig_data

    def add_signature_to_document(self, multisig_data, file_path, signer_name=None, metadata=None):
        """Add a signature to an existing multisig document"""
        if not self.private_key:
            raise ValueError("Private key not loaded")
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        with open(file_path, "rb") as f:
            file_content = f.read()
        
        hashlib_algo = self.get_hashlib_algorithm()
        current_file_hash = hashlib.new(hashlib_algo, file_content).hexdigest()
        
        if current_file_hash != multisig_data['file_hash']:
            raise ValueError("File hash mismatch - file may have been modified")
        
        file_hash_bytes = bytes.fromhex(multisig_data['file_hash'])
        hash_obj = self.get_hash_object()
        
        if self.algorithm == 'RSA':
            signature = self.private_key.sign(
                file_hash_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hash_obj),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hash_obj
            )
        elif self.algorithm == 'ECDSA':
            signature = self.private_key.sign(
                file_hash_bytes,
                ec.ECDSA(hash_obj)
            )
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")
        
        timestamp_info = self.get_timestamp_with_microseconds()
        
        signature_entry = {
            'signature_id': self.generate_signature_id(),
            'signer_name': signer_name or 'Unknown',
            'signature': base64.b64encode(signature).decode(),
            'algorithm': self.algorithm,
            'hash_algorithm': self.hash_algorithm,
            'timestamp': timestamp_info['iso_format'],
            'timestamp_unix': timestamp_info['unix_timestamp'],
            'timestamp_formatted': timestamp_info['formatted']
        }
        
        if metadata:
            signature_entry.update(metadata)
        
        multisig_data['signatures'].append(signature_entry)
        return multisig_data

    def verify_multisig_document(self, file_path, multisig_data, public_keys_dict):
        """
        Verify all signatures in a multisig document.
        
        Args:
            file_path: Path to the file being verified
            multisig_data: The multisig signature data structure
            public_keys_dict: Dictionary mapping signer_name -> public_key object
            
        Returns:
            Dictionary with verification results for each signer
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        with open(file_path, "rb") as f:
            file_content = f.read()
        
        hashlib_algo = 'sha256'
        if multisig_data.get('hash_algorithm') == 'SHA512':
            hashlib_algo = 'sha512'
        elif multisig_data.get('hash_algorithm') == 'SHA3_256':
            hashlib_algo = 'sha3_256'
        
        current_file_hash = hashlib.new(hashlib_algo, file_content).hexdigest()
        
        if current_file_hash != multisig_data['file_hash']:
            return {
                'file_valid': False,
                'message': 'File hash mismatch - file may have been modified',
                'signatures': {}
            }
        
        results = {
            'file_valid': True,
            'file_hash_match': True,
            'signatures': {}
        }
        
        file_hash_bytes = bytes.fromhex(multisig_data['file_hash'])
        
        for sig_entry in multisig_data['signatures']:
            signer_name = sig_entry.get('signer_name', 'Unknown')
            
            if signer_name not in public_keys_dict:
                results['signatures'][signer_name] = {
                    'valid': False,
                    'reason': 'Public key not provided for this signer'
                }
                continue
            
            try:
                public_key = public_keys_dict[signer_name]
                signature_bytes = base64.b64decode(sig_entry['signature'])
                
                algo = sig_entry.get('algorithm', 'RSA')
                hash_algo = sig_entry.get('hash_algorithm', 'SHA256')
                
                if hash_algo == 'SHA256':
                    hash_obj = hashes.SHA256()
                elif hash_algo == 'SHA512':
                    hash_obj = hashes.SHA512()
                elif hash_algo == 'SHA3_256':
                    hash_obj = hashes.SHA3_256()
                else:
                    hash_obj = hashes.SHA256()
                
                if algo == 'RSA':
                    public_key.verify(
                        signature_bytes,
                        file_hash_bytes,
                        padding.PSS(
                            mgf=padding.MGF1(hash_obj),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hash_obj
                    )
                elif algo == 'ECDSA':
                    public_key.verify(
                        signature_bytes,
                        file_hash_bytes,
                        ec.ECDSA(hash_obj)
                    )
                
                results['signatures'][signer_name] = {
                    'valid': True,
                    'timestamp': sig_entry.get('timestamp'),
                    'algorithm': algo,
                    'hash_algorithm': hash_algo
                }
            except InvalidSignature:
                results['signatures'][signer_name] = {
                    'valid': False,
                    'reason': 'Signature verification failed',
                    'timestamp': sig_entry.get('timestamp')
                }
            except Exception as e:
                results['signatures'][signer_name] = {
                    'valid': False,
                    'reason': f'Verification error: {str(e)}'
                }
        
        return results

    def add_pdf_signature_footer(self, input_path, output_path, metadata):
        if not PDF_SUPPORT:
            raise ImportError("PDF support requires PyPDF2 and reportlab packages")
        
        signer_name = metadata.get('signer_name', 'Unknown')
        timestamp = metadata.get('timestamp', datetime.datetime.now().isoformat())
        organization = metadata.get('organization', '')
        reason = metadata.get('reason', 'Document signing')
        location = metadata.get('location', '')
        
        signature_text = f"Digitally signed by: {signer_name}"
        if organization:
            signature_text += f" ({organization})"
        signature_text += f"\nDate: {timestamp[:19].replace('T', ' ')}"
        if reason:
            signature_text += f"\nReason: {reason}"
        if location:
            signature_text += f"\nLocation: {location}"
        
        packet = BytesIO()
        can = canvas.Canvas(packet, pagesize=letter)
        can.setFont("Helvetica", 8)
        
        lines = signature_text.split('\n')
        y_position = 60
        for line in lines:
            can.drawString(50, y_position, line)
            y_position -= 10
        
        can.save()
        packet.seek(0)
        
        existing_pdf = PdfReader(input_path)
        overlay_pdf = PdfReader(packet)
        output_pdf = PdfWriter()
        
        for i in range(len(existing_pdf.pages)):
            page = existing_pdf.pages[i]
            if i == len(existing_pdf.pages) - 1:
                page.merge_page(overlay_pdf.pages[0])
            output_pdf.add_page(page)
        
        with open(output_path, "wb") as f:
            output_pdf.write(f)

    def render_all_pdf_signatures(self, input_pdf, output_pdf, multisig_data):
        """
        Render ALL visual signatures from multisig JSON
        with automatic pagination (no overflow).
        """
        if not PDF_SUPPORT:
            raise ImportError("PDF support requires PyPDF2 and reportlab")

        from io import BytesIO
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter
        from PyPDF2 import PdfReader, PdfWriter

        page_width, page_height = letter
        margin_x = 50
        top_margin = page_height - 60
        bottom_margin = 60
        line_step = 12

        writer = PdfWriter()

        base_pdf = PdfReader(input_pdf)
        for page in base_pdf.pages:
            writer.add_page(page)

        packet = BytesIO()
        can = canvas.Canvas(packet, pagesize=letter)
        can.setFont("Helvetica", 8)
        y = top_margin

        def flush_page():
            nonlocal packet, can, y
            can.save()
            packet.seek(0)
            sig_page = PdfReader(packet).pages[0]
            writer.add_page(sig_page)
            packet = BytesIO()
            can = canvas.Canvas(packet, pagesize=letter)
            can.setFont("Helvetica", 8)
            y = top_margin

        for sig in multisig_data.get("signatures", []):
            lines = [
                f"Digitally signed by: {sig.get('signer_name', 'Unknown')}",
                f"Date: {sig.get('timestamp', '')[:19].replace('T', ' ')}"
            ]

            if sig.get("organization"):
                lines.append(f"Organization: {sig['organization']}")
            if sig.get("reason"):
                lines.append(f"Reason: {sig['reason']}")
            if sig.get("location"):
                lines.append(f"Location: {sig['location']}")

            needed_height = (len(lines) + 1) * line_step

            if y - needed_height < bottom_margin:
                flush_page()

            for line in lines:
                can.drawString(margin_x, y, line)
                y -= line_step

            y -= line_step

        can.save()
        packet.seek(0)
        writer.add_page(PdfReader(packet).pages[0])

        with open(output_pdf, "wb") as f:
            writer.write(f)

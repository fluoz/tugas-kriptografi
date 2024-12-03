from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64

class RSACipher:
    def __init__(self, key_size=2048):
        """Generate RSA key pair with specified key size."""
        self.key_size = key_size
        self.key_pair = RSA.generate(key_size)
        self.public_key = self.key_pair.publickey()
        
    def encrypt(self, data: str) -> str:
        """Encrypt data using public key."""
        if isinstance(data, str):
            data = data.encode()
            
        cipher = PKCS1_OAEP.new(self.public_key)
        encrypted_data = cipher.encrypt(data)
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt data using private key."""
        encrypted_data = base64.b64decode(encrypted_data.encode('utf-8'))
        cipher = PKCS1_OAEP.new(self.key_pair)
        decrypted_data = cipher.decrypt(encrypted_data)
        return decrypted_data.decode('utf-8')
    
    def sign(self, data: str) -> str:
        """Sign data using private key."""
        if isinstance(data, str):
            data = data.encode()
            
        h = SHA256.new(data)
        signature = pkcs1_15.new(self.key_pair).sign(h)
        return base64.b64encode(signature).decode('utf-8')
    
    def verify(self, data: str, signature: str) -> bool:
        """Verify signature using public key."""
        try:
            if isinstance(data, str):
                data = data.encode()
            signature = base64.b64decode(signature.encode('utf-8'))
            h = SHA256.new(data)
            pkcs1_15.new(self.public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False
            
    def export_public_key(self) -> str:
        """Export public key in PEM format."""
        return self.public_key.export_key().decode()
        
    def export_private_key(self) -> str:
        """Export private key in PEM format."""
        return self.key_pair.export_key().decode()

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

class AESCipher:
    def __init__(self, key=None):
        """Initialize AES cipher with a key (generate one if not provided)."""
        self.key = key if key else get_random_bytes(32)  # 256-bit key
        
    def encrypt(self, data: str) -> tuple:
        """Encrypt data using AES-CBC mode."""
        if isinstance(data, str):
            data = data.encode()
            
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_data = pad(data, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        
        # Convert to base64 for easy handling
        return (
            base64.b64encode(encrypted_data).decode('utf-8'),
            base64.b64encode(iv).decode('utf-8')
        )
    
    def decrypt(self, encrypted_data: str, iv: str) -> str:
        """Decrypt data using AES-CBC mode."""
        # Convert from base64
        encrypted_data = base64.b64decode(encrypted_data.encode('utf-8'))
        iv = base64.b64decode(iv.encode('utf-8'))
        
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(encrypted_data)
        unpadded_data = unpad(decrypted_data, AES.block_size)
        return unpadded_data.decode('utf-8')
    
    def get_key(self) -> str:
        """Return the key in base64 format."""
        return base64.b64encode(self.key).decode('utf-8')

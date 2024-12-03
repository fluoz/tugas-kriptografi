import hashlib

def generate_sha256(data: str) -> str:
    """Generate SHA-256 hash of the input data."""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()

def generate_sha512(data: str) -> str:
    """Generate SHA-512 hash of the input data."""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha512(data).hexdigest()

def verify_sha256(data: str, hash_value: str) -> bool:
    """Verify if the data matches the provided SHA-256 hash."""
    return generate_sha256(data) == hash_value

def verify_sha512(data: str, hash_value: str) -> bool:
    """Verify if the data matches the provided SHA-512 hash."""
    return generate_sha512(data) == hash_value

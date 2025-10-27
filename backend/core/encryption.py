from cryptography.fernet import Fernet


def generate_encryption_key() -> bytes:
    """Generates a new Fernet encryption key."""
    return Fernet.generate_key()


def encrypt_message(plaintext: str, key: bytes) -> str:
    """Encrypts a plaintext message using the given key."""
    f = Fernet(key)
    encrypted_message = f.encrypt(plaintext.encode("utf-8"))
    return encrypted_message.decode("utf-8")


def decrypt_message(encrypted_text: str, key: bytes) -> str:
    """Decrypts an encrypted message using the given key."""
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_text.encode("utf-8"))
    return decrypted_message.decode("utf-8")

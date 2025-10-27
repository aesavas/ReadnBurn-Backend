import base64

import pytest
from core.encryption import decrypt_message
from core.encryption import encrypt_message
from core.encryption import generate_encryption_key
from cryptography.fernet import InvalidToken


def test_generate_encryption_key() -> None:
    """Tests that a valid Fernet key is generated."""
    key = generate_encryption_key()
    assert isinstance(key, bytes)
    # A Fernet key is 32 bytes of random data, base64-encoded, which results in 44 characters.
    assert len(key) == 44
    decoded = base64.urlsafe_b64decode(key)
    assert isinstance(decoded, bytes)
    assert len(decoded) == 32


def test_encrypt_decrypt_cycle() -> None:
    """Tests that a message can be encrypted and then decrypted successfully."""
    key = generate_encryption_key()
    original_message = "This is a top secret message!"

    encrypted_message = encrypt_message(original_message, key)
    assert isinstance(encrypted_message, str)
    assert encrypted_message != original_message

    decrypted_message = decrypt_message(encrypted_message, key)
    assert isinstance(decrypted_message, str)
    assert decrypted_message == original_message


def test_decrypt_with_wrong_key() -> None:
    """Tests that decrypting with a different key fails."""
    key1 = generate_encryption_key()
    key2 = generate_encryption_key()
    message = "Hello, World!"

    encrypted_message = encrypt_message(message, key1)

    with pytest.raises(InvalidToken):
        decrypt_message(encrypted_message, key2)


def test_decrypt_tampered_message() -> None:
    """Tests that decrypting a tampered message fails."""
    key = generate_encryption_key()
    message = "Valid message"
    encrypted_message = encrypt_message(message, key)

    # Tamper with the encrypted message
    tampered_message = encrypted_message[:-1] + "A"

    with pytest.raises(InvalidToken):
        decrypt_message(tampered_message, key)

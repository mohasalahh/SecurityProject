# helpers/crypto_utils.py
import hashlib
import secrets
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding # Symmetric padding
from cryptography.hazmat.backends import default_backend

# ANSI Color Codes
COLOR_RESET = "\033[0m"
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"

# --- Password Hashing (from Phase 2) ---
def generate_salt(length=16):
    try: return secrets.token_bytes(length)
    except AttributeError: return os.urandom(length)

def hash_password_sha256(password, salt=None):
    if salt is None: salt = generate_salt()
    password_bytes = password.encode('utf-8') if isinstance(password, str) else password
    salted_password = salt + password_bytes
    hasher = hashlib.sha256()
    hasher.update(salted_password)
    return salt.hex(), hasher.digest().hex()

def verify_password_sha256(provided_password, salt_hex, stored_hashed_password_hex):
    try:
        salt = bytes.fromhex(salt_hex)
        stored_hashed_password = bytes.fromhex(stored_hashed_password_hex)
        provided_password_bytes = provided_password.encode('utf-8') if isinstance(provided_password, str) else provided_password
        salted_provided_password = salt + provided_password_bytes
        hasher = hashlib.sha256()
        hasher.update(salted_provided_password)
        return secrets.compare_digest(hasher.digest(), stored_hashed_password)
    except (ValueError, TypeError) as e:
        print(f"{COLOR_RED}[CRYPTO_UTILS] Error during password verification: {e}{COLOR_RESET}")
        return False

# --- File Hashing (New for Phase 3) ---
def hash_data_sha256(data_bytes):
    """Hashes a byte string using SHA-256 and returns hex digest."""
    hasher = hashlib.sha256()
    hasher.update(data_bytes)
    return hasher.hexdigest()

def hash_file_sha256(filepath, chunk_size=8192):
    """Hashes a file using SHA-256 and returns hex digest."""
    hasher = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError:
        print(f"{COLOR_RED}[CRYPTO_UTILS] File not found for hashing: {filepath}{COLOR_RESET}")
        return None
    except Exception as e:
        print(f"{COLOR_RED}[CRYPTO_UTILS] Error hashing file {filepath}: {e}{COLOR_RESET}")
        return None

# --- AES Symmetric Encryption/Decryption (New for Phase 3) ---
AES_KEY_SIZE = 32  # Bytes (256-bit)
AES_IV_SIZE = 16   # Bytes (128-bit for CBC)

def generate_aes_key_and_iv():
    """Generates a random AES key and IV, returns them in hex."""
    key = secrets.token_bytes(AES_KEY_SIZE)
    iv = secrets.token_bytes(AES_IV_SIZE)
    return key.hex(), iv.hex()

def encrypt_aes_cbc(data_bytes, key_bytes, iv_bytes):
    """Encrypts data using AES-CBC with PKCS7 padding."""
    try:
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Apply PKCS7 padding
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data_bytes) + padder.finalize()
        
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext
    except Exception as e:
        print(f"{COLOR_RED}[CRYPTO_UTILS] AES Encryption error: {e}{COLOR_RESET}")
        return None

def decrypt_aes_cbc(ciphertext_bytes, key_bytes, iv_bytes):
    """Decrypts data using AES-CBC and removes PKCS7 padding."""
    try:
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes), backend=default_backend())
        decryptor = cipher.decryptor()
        
        decrypted_padded_data = decryptor.update(ciphertext_bytes) + decryptor.finalize()
        
        # Remove PKCS7 padding
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        original_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        
        return original_data
    except ValueError as e: # Often indicates bad key, IV, padding, or corrupted data
        print(f"{COLOR_RED}[CRYPTO_UTILS] AES Decryption error (ValueError, possibly bad key/IV/padding/data): {e}{COLOR_RESET}")
        return None
    except Exception as e:
        print(f"{COLOR_RED}[CRYPTO_UTILS] AES Decryption error: {e}{COLOR_RESET}")
        return None

if __name__ == '__main__':
    print("--- Testing Password Hashing ---")
    pw = "securePass123!"
    s_hex, h_hex = hash_password_sha256(pw)
    print(f"Salt: {s_hex}, Hash: {h_hex}")
    print(f"Verify correct: {verify_password_sha256(pw, s_hex, h_hex)}")
    print(f"Verify incorrect: {verify_password_sha256('wrong', s_hex, h_hex)}")

    print("\n--- Testing File/Data Hashing ---")
    test_data = b"This is some test data for SHA256 hashing."
    data_hash = hash_data_sha256(test_data)
    print(f"Data: {test_data.decode()}, Hash: {data_hash}")

    # Create a dummy file for file hash testing
    dummy_file = "temp_test_file.txt"
    with open(dummy_file, "wb") as f:
        f.write(test_data)
    file_h = hash_file_sha256(dummy_file)
    print(f"File '{dummy_file}' Hash: {file_h}")
    assert data_hash == file_h
    os.remove(dummy_file)

    print("\n--- Testing AES Encryption/Decryption ---")
    key_h, iv_h = generate_aes_key_and_iv()
    print(f"AES Key (hex): {key_h}")
    print(f"AES IV (hex): {iv_h}")

    key_b = bytes.fromhex(key_h)
    iv_b = bytes.fromhex(iv_h)
    original_message = b"This is a secret message for AES encryption!"
    print(f"Original Message: {original_message.decode()}")

    encrypted_b = encrypt_aes_cbc(original_message, key_b, iv_b)
    if encrypted_b:
        print(f"Encrypted (bytes): {encrypted_b.hex()}") # Print as hex for readability
        decrypted_b = decrypt_aes_cbc(encrypted_b, key_b, iv_b)
        if decrypted_b:
            print(f"Decrypted Message: {decrypted_b.decode()}")
            assert original_message == decrypted_b, "Decryption failed: Mismatch!"
            print(f"{COLOR_GREEN}AES Encrypt/Decrypt Test Successful!{COLOR_RESET}")
        else:
            print(f"{COLOR_RED}AES Decryption returned None.{COLOR_RESET}")
    else:
        print(f"{COLOR_RED}AES Encryption returned None.{COLOR_RESET}")

    # Test with empty data
    empty_data = b""
    encrypted_empty = encrypt_aes_cbc(empty_data, key_b, iv_b)
    if encrypted_empty:
        decrypted_empty = decrypt_aes_cbc(encrypted_empty, key_b, iv_b)
        assert decrypted_empty == empty_data, "Decryption of empty data failed"
        print(f"{COLOR_GREEN}AES Encrypt/Decrypt Test with empty data Successful!{COLOR_RESET}")


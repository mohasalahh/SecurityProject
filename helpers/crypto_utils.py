# helpers/crypto_utils.py
import hashlib
import secrets
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes as crypto_hashes # Renamed to avoid conflict

# Argon2 for password hashing
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash


# ANSI Color Codes
COLOR_RESET = "\033[0m"
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"

# --- Argon2id Password Hashing (New for Phase 4) ---
# Default parameters are generally good. Adjust time_cost, memory_cost, parallelism for security/performance trade-off.
# For a project, these defaults are fine. For production, research current recommendations.
ph = PasswordHasher() # Uses Argon2id by default with good parameters

def hash_password_argon2(password_str):
    """Hashes a password using Argon2id. Returns the hash string (includes salt and params)."""
    try:
        return ph.hash(password_str.encode('utf-8'))
    except Exception as e:
        print(f"{COLOR_RED}[CRYPTO_UTILS] Argon2 Hashing error: {e}{COLOR_RESET}")
        return None

def verify_password_argon2(password_hash_str, password_str):
    """Verifies a password against an Argon2id hash string."""
    try:
        ph.verify(password_hash_str, password_str.encode('utf-8'))
        return True
    except VerifyMismatchError:
        # This is the expected error for a wrong password
        return False
    except VerificationError as e: # Other verification issues (e.g., hash format)
        print(f"{COLOR_RED}[CRYPTO_UTILS] Argon2 VerificationError (e.g. bad hash format): {e}{COLOR_RESET}")
        return False
    except InvalidHash as e:
        print(f"{COLOR_RED}[CRYPTO_UTILS] Argon2 InvalidHash: {e}{COLOR_RESET}")
        return False
    except Exception as e: # Catch-all for other unexpected errors
        print(f"{COLOR_RED}[CRYPTO_UTILS] Unexpected Argon2 Verification error: {e}{COLOR_RESET}")
        return False

# --- PBKDF2HMAC Key Derivation (New for Phase 4 - for client master key) ---
MASTER_KEY_SALT_SIZE = 16
MASTER_KEY_LENGTH = 32  # For AES-256
PBKDF2_ITERATIONS = 390000 # OWASP recommendation (as of late 2022/early 2023) - adjust as needed

def generate_pbkdf2_salt():
    return secrets.token_bytes(MASTER_KEY_SALT_SIZE)

def derive_master_key_pbkdf2(password_str, salt_bytes):
    """Derives a master key from a password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=crypto_hashes.SHA256(),
        length=MASTER_KEY_LENGTH,
        salt=salt_bytes,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password_str.encode('utf-8'))

# --- File Hashing (SHA-256 - from Phase 3) ---
def hash_data_sha256(data_bytes):
    hasher = hashlib.sha256()
    hasher.update(data_bytes)
    return hasher.hexdigest()

def hash_file_sha256(filepath, chunk_size=8192):
    hasher = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk: break
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError: return None
    except Exception: return None

# --- AES Symmetric Encryption/Decryption (from Phase 3) ---
AES_KEY_SIZE = 32
AES_IV_SIZE = 16

def generate_aes_key_and_iv():
    key = secrets.token_bytes(AES_KEY_SIZE)
    iv = secrets.token_bytes(AES_IV_SIZE)
    return key.hex(), iv.hex()

def encrypt_aes_cbc(data_bytes, key_bytes, iv_bytes):
    try:
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data_bytes) + padder.finalize()
        return encryptor.update(padded_data) + encryptor.finalize()
    except Exception: return None

def decrypt_aes_cbc(ciphertext_bytes, key_bytes, iv_bytes):
    try:
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(ciphertext_bytes) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        return unpadder.update(decrypted_padded_data) + unpadder.finalize()
    except (ValueError, TypeError): return None # Bad key, IV, padding, or data
    except Exception: return None


if __name__ == '__main__':
    print("--- Testing Argon2 Password Hashing ---")
    pw_argon = "SuperSecureP@ssw0rd!"
    hashed_pw_argon_str = hash_password_argon2(pw_argon)
    if hashed_pw_argon_str:
        print(f"Argon2 Hash: {hashed_pw_argon_str}")
        print(f"Verify correct ('{pw_argon}'): {COLOR_GREEN if verify_password_argon2(hashed_pw_argon_str, pw_argon) else COLOR_RED}{verify_password_argon2(hashed_pw_argon_str, pw_argon)}{COLOR_RESET}")
        print(f"Verify incorrect ('wrongPass'): {COLOR_GREEN if verify_password_argon2(hashed_pw_argon_str, 'wrongPass') else COLOR_RED}{verify_password_argon2(hashed_pw_argon_str, 'wrongPass')}{COLOR_RESET}")
        # Test rehash needed (optional, good for checking if params changed)
        # if ph.check_needs_rehash(hashed_pw_argon_str):
        #     print(f"{COLOR_YELLOW}Argon2 hash needs rehash (parameters might have changed).{COLOR_RESET}")
    else:
        print(f"{COLOR_RED}Argon2 hashing failed.{COLOR_RESET}")

    print("\n--- Testing PBKDF2 Master Key Derivation ---")
    pw_pbkdf2 = "MyMasterPassword123"
    salt_pbkdf2 = generate_pbkdf2_salt()
    master_key = derive_master_key_pbkdf2(pw_pbkdf2, salt_pbkdf2)
    print(f"PBKDF2 Salt (hex): {salt_pbkdf2.hex()}")
    print(f"PBKDF2 Derived Master Key (hex, first 16 bytes): {master_key[:16].hex()}...")
    print(f"Master Key Length: {len(master_key)} bytes")
    assert len(master_key) == MASTER_KEY_LENGTH

    # Test AES and File Hashing (as in Phase 3)
    print("\n--- Testing AES Encryption/Decryption (Unchanged) ---")
    key_h, iv_h = generate_aes_key_and_iv()
    key_b, iv_b = bytes.fromhex(key_h), bytes.fromhex(iv_h)
    original_msg = b"AES test message Phase 4"
    encrypted = encrypt_aes_cbc(original_msg, key_b, iv_b)
    if encrypted:
        decrypted = decrypt_aes_cbc(encrypted, key_b, iv_b)
        assert original_msg == decrypted, "AES test failed"
        print(f"{COLOR_GREEN}AES Encrypt/Decrypt Test Successful!{COLOR_RESET}")
    else:
        print(f"{COLOR_RED}AES Encryption failed in test.{COLOR_RESET}")


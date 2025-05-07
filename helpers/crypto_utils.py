# helpers/crypto_utils.py
import hashlib
import secrets
import os # For os.urandom if secrets module is not available on older Python

# ANSI Color Codes (if you want to use them in utility functions, though less common)
COLOR_RESET = "\033[0m"
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"

def generate_salt(length=16):
    """Generates a cryptographically secure salt."""
    # Use secrets.token_bytes if available (Python 3.6+)
    # Otherwise, fall back to os.urandom
    try:
        return secrets.token_bytes(length)
    except AttributeError:
        return os.urandom(length)

def hash_password_sha256(password, salt=None):
    """
    Hashes a password using SHA-256 with a salt.
    Returns the salt (hex) and the hashed password (hex).
    """
    if salt is None:
        salt = generate_salt()
    
    # Ensure password is bytes
    if isinstance(password, str):
        password_bytes = password.encode('utf-8')
    else:
        password_bytes = password

    # Combine salt and password
    salted_password = salt + password_bytes
    
    # Hash using SHA-256
    hasher = hashlib.sha256()
    hasher.update(salted_password)
    hashed_password_bytes = hasher.digest()
    
    return salt.hex(), hashed_password_bytes.hex()

def verify_password_sha256(provided_password, salt_hex, stored_hashed_password_hex):
    """
    Verifies a provided password against a stored salt and hashed password.
    Uses SHA-256.
    """
    try:
        salt = bytes.fromhex(salt_hex)
        stored_hashed_password = bytes.fromhex(stored_hashed_password_hex)

        # Ensure provided_password is bytes
        if isinstance(provided_password, str):
            provided_password_bytes = provided_password.encode('utf-8')
        else:
            provided_password_bytes = provided_password
            
        # Combine salt and provided password
        salted_provided_password = salt + provided_password_bytes
        
        # Hash using SHA-256
        hasher = hashlib.sha256()
        hasher.update(salted_provided_password)
        hashed_provided_password_bytes = hasher.digest()
        
        # Compare with the stored hash
        return secrets.compare_digest(hashed_provided_password_bytes, stored_hashed_password)
    except (ValueError, TypeError) as e:
        print(f"{COLOR_RED}[CRYPTO_UTILS] Error during password verification: {e}{COLOR_RESET}")
        return False


# --- Placeholder/Future Functions (from Phase 1, can be expanded later) ---

def hash_message(message):
  """Basic hashing function (e.g., for file integrity checks later)."""
  return hashlib.sha1(message.encode('utf-8')).hexdigest() # SHA-1 is weak, for placeholder only

def derive_key_from_password(password, salt):
   """Placeholder for key derivation (Phase 4+)."""
   print("[INFO] Key derivation not implemented in Phase 2")
   # Will use PBKDF2HMAC or Argon2
   # Dummy key for structure
   return hashlib.sha256(salt + password.encode('utf-8')).digest() # Return 32 bytes

def encrypt_symmetric(key, data):
  """Placeholder for symmetric encryption (Phase 3+)."""
  print("[INFO] Symmetric encryption not implemented in Phase 2")
  # Will use AES or ChaCha20
  return data # Return plaintext for Phase 2

def decrypt_symmetric(key, encrypted_data):
  """Placeholder for symmetric decryption (Phase 3+)."""
  print("[INFO] Symmetric decryption not implemented in Phase 2")
  # Will use AES or ChaCha20
  return encrypted_data # Return as is for Phase 2

if __name__ == '__main__':
    # Test password hashing and verification
    print("Testing SHA-256 Password Hashing:")
    password_to_test = "P@$$wOrd123"
    
    # Hashing
    salt_hex, hashed_hex = hash_password_sha256(password_to_test)
    print(f"  Original Password: {password_to_test}")
    print(f"  Salt (hex): {salt_hex}")
    print(f"  Hashed Password (hex): {hashed_hex}")
    
    # Verification - Correct Password
    is_correct = verify_password_sha256(password_to_test, salt_hex, hashed_hex)
    print(f"  Verification with correct password ('{password_to_test}'): {COLOR_GREEN if is_correct else COLOR_RED}{is_correct}{COLOR_RESET}")
    
    # Verification - Incorrect Password
    is_correct_wrong = verify_password_sha256("wrongpassword", salt_hex, hashed_hex)
    print(f"  Verification with incorrect password ('wrongpassword'): {COLOR_GREEN if is_correct_wrong else COLOR_RED}{is_correct_wrong}{COLOR_RESET}")

    # Verification - Tampered Salt (should fail)
    tampered_salt_hex = generate_salt().hex()
    is_correct_tampered_salt = verify_password_sha256(password_to_test, tampered_salt_hex, hashed_hex)
    print(f"  Verification with tampered salt: {COLOR_GREEN if is_correct_tampered_salt else COLOR_RED}{is_correct_tampered_salt}{COLOR_RESET}")

    # Verification - Tampered Hash (should fail)
    tampered_hash_hex = hashlib.sha256(b"randomdata").hexdigest()
    is_correct_tampered_hash = verify_password_sha256(password_to_test, salt_hex, tampered_hash_hex)
    print(f"  Verification with tampered hash: {COLOR_GREEN if is_correct_tampered_hash else COLOR_RED}{is_correct_tampered_hash}{COLOR_RESET}")

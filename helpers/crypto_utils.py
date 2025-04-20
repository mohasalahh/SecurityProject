# helpers/crypto_utils.py
import hashlib
import secrets
# NOTE: Full crypto functions (AES, RSA, Argon2, PBKDF2) are planned for later phases.
# Phase 1 focuses on unencrypted transfer.

def hash_message(message):
  """Basic hashing function (e.g., for file integrity checks later).
     Not used for encryption in Phase 1."""
  # In later phases, a stronger hash like SHA-256 will be used [cite: 82]
  # Using SHA-1 for simplicity in this initial phase example if needed,
  # but ideally, file transfer integrity isn't a primary focus for Phase 1.
  return hashlib.sha1(message.encode('utf-8')).hexdigest()

# --- Placeholder/Future Functions ---

def hash_password(password, salt=None):
  """Placeholder for password hashing (Phase 2+)."""
  # Will use Argon2 or PBKDF2HMAC later [cite: 87]
  print("[INFO] Password hashing not implemented in Phase 1")
  if salt is None:
      salt = secrets.token_bytes(16)
  # Dummy hash for structure
  hashed = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
  return hashed, salt # Return dummy hash and salt

def verify_password(password, hashed_password, salt):
  """Placeholder for password verification (Phase 2+)."""
  print("[INFO] Password verification not implemented in Phase 1")
  # Dummy verification
  expected_hash, _ = hash_password(password, salt)
  return expected_hash == hashed_password

def derive_key_from_password(password, salt):
   """Placeholder for key derivation (Phase 4+)."""
   print("[INFO] Key derivation not implemented in Phase 1")
   # Will use PBKDF2HMAC or Argon2 [cite: 88, 98]
   # Dummy key for structure
   return hashlib.sha256(salt + password.encode('utf-8')).digest() # Return 32 bytes

def encrypt_symmetric(key, data):
  """Placeholder for symmetric encryption (Phase 3+)."""
  print("[INFO] Symmetric encryption not implemented in Phase 1")
  # Will use AES or ChaCha20 [cite: 80]
  return data # Return plaintext for Phase 1

def decrypt_symmetric(key, encrypted_data):
  """Placeholder for symmetric decryption (Phase 3+)."""
  print("[INFO] Symmetric decryption not implemented in Phase 1")
  # Will use AES or ChaCha20 [cite: 81]
  return encrypted_data # Return as is for Phase 1

# Add other crypto functions (RSA etc.) as placeholders if needed for structure
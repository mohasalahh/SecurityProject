# peer/fileshare_peer.py
import socket
import threading
import os
import json
import secrets
import sys
import uuid # For unique filenames in storage

# --- Add project root to sys.path ---
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)
# --- End of sys.path modification ---

from helpers import crypto_utils

# ANSI Color Codes
COLOR_RESET = "\033[0m"
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_MAGENTA = "\033[95m"
COLOR_CYAN = "\033[96m"

# --- Peer Configuration ---
LISTEN_PORT = 6000
BUFFER_SIZE = 4096 # For command recv and file streaming
PEER_HOST = '0.0.0.0' # Global to store this peer's host for LIST_SHARED
PEER_STORAGE_DIR = "peer_storage" # Directory to store uploaded encrypted files

# --- Data Stores (In-memory for Phase 3) ---
USER_CREDENTIALS = {} # { "username": {"salt_hex": "...", "hashed_password_hex": "..."} }
ACTIVE_SESSIONS = {}  # { "session_token": "username" }
# Files hosted by this peer (uploaded by clients or added locally by peer admin)
# { "original_filename.txt": {
#       "owner_username": "...",
#       "stored_filename_uuid": "uuid_string.enc", # Actual filename in PEER_STORAGE_DIR
#       "file_key_hex": "...",
#       "iv_hex": "...",
#       "original_hash_hex": "...", # Hash of the original, unencrypted file
#       "encrypted_size_bytes": "..."
#   }
# }
PEER_HOSTED_FILES = {}

def ensure_peer_storage_dir():
    """Creates the peer storage directory if it doesn't exist."""
    if not os.path.exists(PEER_STORAGE_DIR):
        try:
            os.makedirs(PEER_STORAGE_DIR)
            print(f"{COLOR_BLUE}[PEER_SETUP] Created peer storage directory: {PEER_STORAGE_DIR}{COLOR_RESET}")
        except OSError as e:
            print(f"{COLOR_RED}[PEER_SETUP] CRITICAL: Could not create peer storage directory '{PEER_STORAGE_DIR}': {e}{COLOR_RESET}")
            sys.exit(1) # Exit if storage can't be created

def generate_session_token():
    return secrets.token_hex(16)

def get_username_from_token(token):
    return ACTIVE_SESSIONS.get(token)

def handle_client_connection(client_socket, client_address):
    client_addr_str_colored = f"{COLOR_MAGENTA}{client_address[0]}:{client_address[1]}{COLOR_RESET}"
    print(f"{COLOR_GREEN}[PEER] Accepted connection from {client_addr_str_colored}{COLOR_RESET}")
    current_user_session_token = None

    try:
        while True:
            message_bytes = client_socket.recv(BUFFER_SIZE)
            if not message_bytes:
                print(f"{COLOR_YELLOW}[PEER] Connection closed by {client_addr_str_colored}{COLOR_RESET}")
                break

            try:
                message = json.loads(message_bytes.decode('utf-8'))
                command = message.get("command")
                print(f"{COLOR_BLUE}[PEER] Received command: {COLOR_CYAN}{command}{COLOR_BLUE} from {client_addr_str_colored}{COLOR_RESET}")

                response = {"status": "ERROR", "message": "Unknown command"}
                authenticated_username = None

                if command == "REGISTER" or command == "LOGIN":
                    # Authentication logic (same as Phase 2)
                    username = message.get("username")
                    password = message.get("password")
                    if not (username and password):
                        response = {"status": "ERROR", "message": "Username and password required."}
                    elif command == "REGISTER":
                        if username in USER_CREDENTIALS:
                            response = {"status": "ERROR", "message": "Username already exists."}
                        else:
                            salt_hex, hashed_password_hex = crypto_utils.hash_password_sha256(password)
                            USER_CREDENTIALS[username] = {"salt_hex": salt_hex, "hashed_password_hex": hashed_password_hex}
                            response = {"status": "OK", "message": "Registration successful."}
                            print(f"{COLOR_GREEN}[PEER] User '{username}' registered.{COLOR_RESET}")
                    elif command == "LOGIN":
                        user_data = USER_CREDENTIALS.get(username)
                        if user_data and crypto_utils.verify_password_sha256(password, user_data["salt_hex"], user_data["hashed_password_hex"]):
                            if current_user_session_token and current_user_session_token in ACTIVE_SESSIONS:
                                ACTIVE_SESSIONS.pop(current_user_session_token, None)
                            session_token = generate_session_token()
                            ACTIVE_SESSIONS[session_token] = username
                            current_user_session_token = session_token
                            response = {"status": "OK", "message": "Login successful.", "token": session_token, "username": username}
                            print(f"{COLOR_GREEN}[PEER] User '{username}' logged in (Token: {session_token[:8]}...).{COLOR_RESET}")
                        else:
                            response = {"status": "ERROR", "message": "Invalid username or password."}
                else: # Authenticated commands
                    token = message.get("token")
                    authenticated_username = get_username_from_token(token)
                    if not authenticated_username:
                        response = {"status": "ERROR", "message": "Authentication required."}
                        print(f"{COLOR_YELLOW}[PEER] Auth failed for command '{command}'.{COLOR_RESET}")
                    else:
                        print(f"{COLOR_BLUE}[PEER] User: {COLOR_CYAN}{authenticated_username}{COLOR_BLUE}, Command: '{command}'{COLOR_RESET}")
                        if command == "LOGOUT":
                            if token in ACTIVE_SESSIONS: del ACTIVE_SESSIONS[token]
                            current_user_session_token = None
                            response = {"status": "OK", "message": "Logout successful."}
                            print(f"{COLOR_GREEN}[PEER] User '{authenticated_username}' logged out.{COLOR_RESET}")
                        
                        elif command == "UPLOAD_FILE":
                            original_filename = message.get("original_filename")
                            file_key_hex = message.get("file_key_hex")
                            iv_hex = message.get("iv_hex")
                            original_hash_hex = message.get("original_hash_hex")
                            encrypted_size_bytes = message.get("encrypted_size_bytes")

                            if not all([original_filename, file_key_hex, iv_hex, original_hash_hex, isinstance(encrypted_size_bytes, int)]):
                                response = {"status": "ERROR", "message": "Missing file metadata for upload."}
                            elif original_filename in PEER_HOSTED_FILES : # Simple check, could allow overwrite or versioning
                                response = {"status": "ERROR", "message": f"File '{original_filename}' already exists. Upload rejected."}
                                print(f"{COLOR_YELLOW}[PEER] Upload rejected for '{original_filename}', already exists.{COLOR_RESET}")
                            else:
                                stored_filename_uuid = f"{uuid.uuid4()}.enc"
                                encrypted_filepath_on_peer = os.path.join(PEER_STORAGE_DIR, stored_filename_uuid)
                                
                                try:
                                    print(f"{COLOR_BLUE}[PEER] User '{authenticated_username}' uploading '{original_filename}' (encrypted size: {encrypted_size_bytes} bytes). Storing as '{stored_filename_uuid}'.{COLOR_RESET}")
                                    client_socket.sendall(json.dumps({"status": "READY_FOR_DATA", "message": "Peer ready to receive encrypted file data."}).encode('utf-8'))
                                    
                                    bytes_received = 0
                                    with open(encrypted_filepath_on_peer, 'wb') as f_enc:
                                        while bytes_received < encrypted_size_bytes:
                                            chunk_size_to_receive = min(BUFFER_SIZE, encrypted_size_bytes - bytes_received)
                                            chunk = client_socket.recv(chunk_size_to_receive)
                                            if not chunk:
                                                print(f"{COLOR_RED}[PEER] Client disconnected during file upload of '{original_filename}'. Incomplete file.{COLOR_RESET}")
                                                if os.path.exists(encrypted_filepath_on_peer): os.remove(encrypted_filepath_on_peer) # Clean up
                                                response = {"status": "ERROR", "message": "Client disconnected during upload."} # This response won't reach client
                                                raise ConnectionAbortedError("Client disconnected during upload") # Break from handler
                                            f_enc.write(chunk)
                                            bytes_received += len(chunk)
                                    
                                    if bytes_received == encrypted_size_bytes:
                                        PEER_HOSTED_FILES[original_filename] = {
                                            "owner_username": authenticated_username,
                                            "stored_filename_uuid": stored_filename_uuid,
                                            "file_key_hex": file_key_hex,
                                            "iv_hex": iv_hex,
                                            "original_hash_hex": original_hash_hex,
                                            "encrypted_size_bytes": encrypted_size_bytes
                                        }
                                        response = {"status": "OK", "message": f"File '{original_filename}' uploaded successfully."}
                                        print(f"{COLOR_GREEN}[PEER] File '{original_filename}' from '{authenticated_username}' stored as '{stored_filename_uuid}'.{COLOR_RESET}")
                                    else:
                                        # Should not happen if encrypted_size_bytes is correct and no disconnect
                                        print(f"{COLOR_RED}[PEER] File upload size mismatch for '{original_filename}'. Expected {encrypted_size_bytes}, got {bytes_received}.{COLOR_RESET}")
                                        if os.path.exists(encrypted_filepath_on_peer): os.remove(encrypted_filepath_on_peer)
                                        response = {"status": "ERROR", "message": "File upload size mismatch."}

                                except ConnectionAbortedError: # To catch the raised error
                                    # Response already set, just ensure loop breaks or function exits
                                    client_socket.close() # Close socket as client is gone
                                    return # Exit handler for this client
                                except Exception as e:
                                    print(f"{COLOR_RED}[PEER] Error receiving/saving uploaded file '{original_filename}': {e}{COLOR_RESET}")
                                    if os.path.exists(encrypted_filepath_on_peer): os.remove(encrypted_filepath_on_peer)
                                    response = {"status": "ERROR", "message": f"Peer error during file upload: {e}"}
                        
                        elif command == "LIST_SHARED":
                            files_info_list = []
                            for orig_name, meta in PEER_HOSTED_FILES.items():
                                files_info_list.append({
                                    "filename": orig_name,
                                    "owner": meta["owner_username"],
                                    "original_hash_hex": meta["original_hash_hex"],
                                    "encrypted_size_bytes": meta["encrypted_size_bytes"]
                                })
                            response = {"status": "OK", "files": files_info_list}
                            print(f"{COLOR_GREEN}[PEER] Sent file list to '{authenticated_username}'.{COLOR_RESET}")

                        elif command == "DOWNLOAD_FILE":
                            original_filename = message.get("original_filename")
                            file_meta = PEER_HOSTED_FILES.get(original_filename)

                            if not file_meta:
                                response = {"status": "ERROR", "message": "File not found on peer."}
                            else:
                                encrypted_filepath_on_peer = os.path.join(PEER_STORAGE_DIR, file_meta["stored_filename_uuid"])
                                if not os.path.exists(encrypted_filepath_on_peer):
                                    response = {"status": "ERROR", "message": "File data missing on peer (contact admin)."}
                                    print(f"{COLOR_RED}[PEER] File '{original_filename}' metadata exists, but data '{file_meta['stored_filename_uuid']}' missing!{COLOR_RESET}")
                                else:
                                    # Send metadata first, then file
                                    download_meta_response = {
                                        "status": "READY_FOR_DOWNLOAD",
                                        "original_filename": original_filename,
                                        "file_key_hex": file_meta["file_key_hex"],
                                        "iv_hex": file_meta["iv_hex"],
                                        "original_hash_hex": file_meta["original_hash_hex"],
                                        "encrypted_size_bytes": file_meta["encrypted_size_bytes"]
                                    }
                                    client_socket.sendall(json.dumps(download_meta_response).encode('utf-8'))
                                    print(f"{COLOR_BLUE}[PEER] Sent download metadata for '{original_filename}' to '{authenticated_username}'. Streaming encrypted file...{COLOR_RESET}")

                                    # Stream the encrypted file
                                    try:
                                        with open(encrypted_filepath_on_peer, 'rb') as f_enc:
                                            while True:
                                                chunk = f_enc.read(BUFFER_SIZE)
                                                if not chunk: break
                                                client_socket.sendall(chunk)
                                        print(f"{COLOR_GREEN}[PEER] Finished streaming encrypted file '{original_filename}' to '{authenticated_username}'.{COLOR_RESET}")
                                        # No further JSON response needed after streaming file data
                                        continue # Important: skip sending the generic response below
                                    except Exception as e:
                                        print(f"{COLOR_RED}[PEER] Error streaming encrypted file '{original_filename}': {e}{COLOR_RESET}")
                                        # Client will likely timeout or error out. Hard to send JSON error now.
                                        # Fall through to close connection.
                        else:
                            response = {"status": "ERROR", "message": f"Unknown authenticated command: {command}"}
                
                # Send response for non-streaming commands or if streaming setup failed before 'continue'
                client_socket.sendall(json.dumps(response).encode('utf-8'))

            except json.JSONDecodeError:
                print(f"{COLOR_RED}[PEER] Invalid JSON from {client_addr_str_colored}{COLOR_RESET}")
                try: client_socket.sendall(json.dumps({"status": "ERROR", "message": "Invalid JSON"}).encode('utf-8'))
                except Exception: pass
            except ConnectionResetError:
                print(f"{COLOR_RED}[PEER] Connection reset by {client_addr_str_colored}{COLOR_RESET}")
                break 
            except ConnectionAbortedError: # Raised by UPLOAD_FILE if client disconnects
                print(f"{COLOR_RED}[PEER] Connection aborted by {client_addr_str_colored} during operation.{COLOR_RESET}")
                break
            except Exception as e:
                print(f"{COLOR_RED}[PEER] Error handling {client_addr_str_colored}: {e}{COLOR_RESET}")
                try: client_socket.sendall(json.dumps({"status": "ERROR", "message": "Peer server error"}).encode('utf-8'))
                except Exception: pass
                break 

    except ConnectionResetError: pass # Already logged by inner try if it happened there
    except Exception as e:
        print(f"{COLOR_RED}[PEER] Unhandled outer error for {client_addr_str_colored}: {e}{COLOR_RESET}")
    finally:
        if current_user_session_token and current_user_session_token in ACTIVE_SESSIONS:
            user_logged_out = ACTIVE_SESSIONS.pop(current_user_session_token, None)
            if user_logged_out: print(f"{COLOR_YELLOW}[PEER] Session for '{user_logged_out}' invalidated (disconnect).{COLOR_RESET}")
        print(f"{COLOR_YELLOW}[PEER] Closing connection to {client_addr_str_colored}{COLOR_RESET}")
        client_socket.close()

def start_peer_server(host='0.0.0.0', port=LISTEN_PORT):
    global PEER_HOST # Allow modification of global PEER_HOST
    PEER_HOST = host
    ensure_peer_storage_dir()

    peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    peer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        peer_socket.bind((host, port))
        peer_socket.listen(5)
        print(f"{COLOR_GREEN}[PEER] Peer listening on {COLOR_YELLOW}{host}:{port}{COLOR_RESET}")
        print(f"{COLOR_BLUE}[PEER] Storing uploaded files in: {os.path.abspath(PEER_STORAGE_DIR)}{COLOR_RESET}")
        while True:
            client_sock, client_addr = peer_socket.accept()
            thread = threading.Thread(target=handle_client_connection, args=(client_sock, client_addr))
            thread.daemon = True
            thread.start()
    except OSError as e:
        print(f"{COLOR_RED}[PEER] BIND ERROR on {host}:{port}: {e}{COLOR_RESET}")
    except KeyboardInterrupt:
        print(f"\n{COLOR_YELLOW}[PEER] Shutting down...{COLOR_RESET}")
    finally:
        peer_socket.close()

def add_file_by_peer_admin(original_filename_on_disk, display_filename=None):
    """Allows peer admin to add a local file for sharing (encrypts and stores it)."""
    if not os.path.exists(original_filename_on_disk):
        print(f"{COLOR_RED}[PEER_ADMIN] File not found: {original_filename_on_disk}{COLOR_RESET}")
        return

    if display_filename is None:
        display_filename = os.path.basename(original_filename_on_disk)
    
    if display_filename in PEER_HOSTED_FILES:
        print(f"{COLOR_YELLOW}[PEER_ADMIN] File '{display_filename}' already hosted. Skipping.{COLOR_RESET}")
        return

    print(f"{COLOR_BLUE}[PEER_ADMIN] Processing '{original_filename_on_disk}' to be shared as '{display_filename}'...{COLOR_RESET}")
    original_hash_hex = crypto_utils.hash_file_sha256(original_filename_on_disk)
    if not original_hash_hex: return

    file_key_hex, iv_hex = crypto_utils.generate_aes_key_and_iv()
    key_bytes = bytes.fromhex(file_key_hex)
    iv_bytes = bytes.fromhex(iv_hex)
    
    stored_filename_uuid = f"admin_{uuid.uuid4()}.enc"
    encrypted_filepath_on_peer = os.path.join(PEER_STORAGE_DIR, stored_filename_uuid)
    encrypted_size_bytes = 0

    try:
        with open(original_filename_on_disk, 'rb') as f_orig, open(encrypted_filepath_on_peer, 'wb') as f_enc:
            while True:
                chunk = f_orig.read(BUFFER_SIZE - (crypto_utils.algorithms.AES.block_size // 8)) # Read slightly less to allow for padding
                if not chunk: break
                encrypted_chunk = crypto_utils.encrypt_aes_cbc(chunk, key_bytes, iv_bytes) # IV is reused for chunks of same file here, but new IV per file
                if not encrypted_chunk: raise Exception("Encryption failed for a chunk")
                f_enc.write(encrypted_chunk)
                encrypted_size_bytes += len(encrypted_chunk)
        
        # This chunk-by-chunk encryption with same IV is not ideal for CBC.
        # A better approach is to encrypt the whole file at once if memory allows, or use a streaming cipher mode.
        # For simplicity with CBC and chunks, let's re-encrypt the whole file.
        print(f"{COLOR_YELLOW}[PEER_ADMIN] Re-encrypting whole file for proper CBC mode...{COLOR_RESET}")
        with open(original_filename_on_disk, 'rb') as f_orig:
            original_data = f_orig.read()
        
        encrypted_data = crypto_utils.encrypt_aes_cbc(original_data, key_bytes, iv_bytes)
        if not encrypted_data:
            raise Exception("Whole file encryption failed.")
        
        with open(encrypted_filepath_on_peer, 'wb') as f_enc:
            f_enc.write(encrypted_data)
        encrypted_size_bytes = len(encrypted_data)


        PEER_HOSTED_FILES[display_filename] = {
            "owner_username": "peer_admin",
            "stored_filename_uuid": stored_filename_uuid,
            "file_key_hex": file_key_hex,
            "iv_hex": iv_hex,
            "original_hash_hex": original_hash_hex,
            "encrypted_size_bytes": encrypted_size_bytes
        }
        print(f"{COLOR_GREEN}[PEER_ADMIN] File '{display_filename}' is now hosted by peer. Stored as '{stored_filename_uuid}'.{COLOR_RESET}")
    except Exception as e:
        print(f"{COLOR_RED}[PEER_ADMIN] Error adding file '{original_filename_on_disk}': {e}{COLOR_RESET}")
        if os.path.exists(encrypted_filepath_on_peer): os.remove(encrypted_filepath_on_peer)

if __name__ == "__main__":
    ensure_peer_storage_dir()
    # Example: Peer admin adds a local file at startup
    admin_file_path = "peer_document.txt"
    if not os.path.exists(admin_file_path):
        with open(admin_file_path, "w") as f:
            f.write("This is a document provided by the peer administrator for sharing.")
    add_file_by_peer_admin(admin_file_path, "admin_shared_doc.txt")
    
    start_peer_server()

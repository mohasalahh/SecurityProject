# peer/fileshare_peer.py
import socket
import threading
import os
import json
import secrets
import sys
import uuid

# --- Add project root to sys.path ---
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path: sys.path.insert(0, project_root)

from helpers import crypto_utils

# ANSI Color Codes
COLOR_RESET, COLOR_RED, COLOR_GREEN, COLOR_YELLOW, COLOR_BLUE, COLOR_MAGENTA, COLOR_CYAN = \
    "\033[0m", "\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[95m", "\033[96m"

# --- Peer Configuration ---
LISTEN_PORT = 6000
BUFFER_SIZE = 8192 # Increased for chunked file transfer
PEER_HOST_LISTEN_IP = '0.0.0.0' # IP to listen on
PEER_PUBLIC_IP = '127.0.0.1' # Publicly addressable IP for clients to connect to this peer's services
                             # For local testing, 127.0.0.1 is fine. In real deployment, this would be the peer's public IP.
PEER_STORAGE_DIR = "peer_storage_phase4"

# --- Data Stores ---
USER_CREDENTIALS = {} # { "username": "argon2_hashed_password_string" }
ACTIVE_SESSIONS = {}  # { "session_token": "username" }
# Files hosted directly by THIS peer (e.g., admin added)
# { "original_filename.txt": { "owner_username": "peer_admin", "stored_filename_uuid": "...",
#                              "file_key_hex": "...", "iv_hex": "...", "original_hash_hex": "...",
#                              "encrypted_size_bytes": ... } }
PEER_HOSTED_FILES = {}
# Files announced by clients (peer acts as indexer)
# { "original_filename.txt": { "owner_username": "...", "sharer_ip": "...", "sharer_port": ...,
#                              "file_key_hex": "...", "iv_hex": "...", "original_hash_hex": "...",
#                              "original_size_bytes": ... } } # original_size for info, encrypted_size for P2P transfer
CLIENT_ANNOUNCED_FILES = {}


def ensure_storage_dir(directory_path):
    if not os.path.exists(directory_path):
        try:
            os.makedirs(directory_path)
            print(f"{COLOR_BLUE}[PEER_SETUP] Created directory: {directory_path}{COLOR_RESET}")
        except OSError as e:
            print(f"{COLOR_RED}[PEER_SETUP] CRITICAL: Could not create directory '{directory_path}': {e}{COLOR_RESET}")
            sys.exit(1)

def generate_session_token(): return secrets.token_hex(16)
def get_username_from_token(token): return ACTIVE_SESSIONS.get(token)

def handle_client_connection(client_socket, client_address):
    client_ip, client_port = client_address
    client_addr_str_colored = f"{COLOR_MAGENTA}{client_ip}:{client_port}{COLOR_RESET}"
    print(f"{COLOR_GREEN}[PEER] Connection from {client_addr_str_colored}{COLOR_RESET}")
    current_user_session_token = None

    try:
        while True:
            message_bytes = client_socket.recv(BUFFER_SIZE)
            if not message_bytes: print(f"{COLOR_YELLOW}[PEER] Conn closed by {client_addr_str_colored}{COLOR_RESET}"); break
            
            try:
                message = json.loads(message_bytes.decode('utf-8'))
                command = message.get("command")
                print(f"{COLOR_BLUE}[PEER] Cmd: {COLOR_CYAN}{command}{COLOR_BLUE} from {client_addr_str_colored}{COLOR_RESET}")

                response = {"status": "ERROR", "message": "Unknown command"}
                
                if command == "REGISTER":
                    username, password = message.get("username"), message.get("password")
                    if not (username and password): response = {"status": "ERROR", "message": "Username/password required."}
                    elif username in USER_CREDENTIALS: response = {"status": "ERROR", "message": "Username exists."}
                    else:
                        hashed_password_str = crypto_utils.hash_password_argon2(password)
                        if hashed_password_str:
                            USER_CREDENTIALS[username] = hashed_password_str
                            response = {"status": "OK", "message": "Registration successful."}
                            print(f"{COLOR_GREEN}[PEER] User '{username}' registered.{COLOR_RESET}")
                        else: response = {"status": "ERROR", "message": "Password hashing failed on server."}
                
                elif command == "LOGIN":
                    username, password = message.get("username"), message.get("password")
                    stored_hash = USER_CREDENTIALS.get(username)
                    if stored_hash and crypto_utils.verify_password_argon2(stored_hash, password):
                        if current_user_session_token and current_user_session_token in ACTIVE_SESSIONS:
                            ACTIVE_SESSIONS.pop(current_user_session_token, None)
                        session_token = generate_session_token()
                        ACTIVE_SESSIONS[session_token] = username
                        current_user_session_token = session_token
                        # For PBKDF2 salt on client, peer could generate/store one per user, or client handles it.
                        # Let's assume client handles its own PBKDF2 salt for master key derivation for now.
                        response = {"status": "OK", "message": "Login successful.", "token": session_token, "username": username}
                        print(f"{COLOR_GREEN}[PEER] User '{username}' logged in (Token: {session_token[:8]}...).{COLOR_RESET}")
                    else: response = {"status": "ERROR", "message": "Invalid username or password."}

                else: # Authenticated commands
                    token = message.get("token")
                    auth_user = get_username_from_token(token)
                    if not auth_user: response = {"status": "ERROR", "message": "Authentication required."}
                    else:
                        print(f"{COLOR_BLUE}[PEER] User: {COLOR_CYAN}{auth_user}{COLOR_BLUE}, Cmd: '{command}'{COLOR_RESET}")
                        if command == "LOGOUT":
                            if token in ACTIVE_SESSIONS: del ACTIVE_SESSIONS[token]
                            current_user_session_token = None
                            response = {"status": "OK", "message": "Logout successful."}
                        
                        elif command == "SHARE_ANNOUNCEMENT": # Client announces a file it's willing to share P2P
                            meta = message.get("file_metadata", {})
                            fname = meta.get("original_filename")
                            # Client now also sends its listening port for P2P connections
                            sharer_listen_port = message.get("sharer_listen_port")

                            if not (fname and meta.get("file_key_hex") and meta.get("iv_hex") and 
                                    meta.get("original_hash_hex") and isinstance(meta.get("original_size_bytes"), int) and
                                    isinstance(sharer_listen_port, int)):
                                response = {"status": "ERROR", "message": "Incomplete file announcement metadata."}
                            elif fname in CLIENT_ANNOUNCED_FILES or fname in PEER_HOSTED_FILES:
                                response = {"status": "ERROR", "message": f"Filename '{fname}' already announced or hosted."}
                            else:
                                CLIENT_ANNOUNCED_FILES[fname] = {
                                    "owner_username": auth_user,
                                    "sharer_ip": client_ip, # IP of the client making the announcement
                                    "sharer_port": sharer_listen_port, # Client's P2P listening port
                                    "file_key_hex": meta["file_key_hex"],
                                    "iv_hex": meta["iv_hex"],
                                    "original_hash_hex": meta["original_hash_hex"],
                                    "original_size_bytes": meta["original_size_bytes"]
                                }
                                response = {"status": "OK", "message": f"File '{fname}' announced by {auth_user}."}
                                print(f"{COLOR_GREEN}[PEER] File '{fname}' announced by {auth_user} at {client_ip}:{sharer_listen_port}{COLOR_RESET}")

                        elif command == "UPLOAD_FILE_TO_PEER": # For peer_admin to upload directly to this peer
                            # This is for files the peer itself will host (e.g. admin added)
                            if auth_user != "peer_admin": # Simple check, could be more robust
                                response = {"status": "ERROR", "message": "Permission denied for direct peer upload."}
                            else:
                                meta = message.get("file_metadata", {})
                                original_filename = meta.get("original_filename")
                                encrypted_size_bytes = meta.get("encrypted_size_bytes")

                                if not (original_filename and meta.get("file_key_hex") and meta.get("iv_hex") and
                                        meta.get("original_hash_hex") and isinstance(encrypted_size_bytes, int)):
                                    response = {"status": "ERROR", "message": "Missing metadata for peer upload."}
                                elif original_filename in PEER_HOSTED_FILES or original_filename in CLIENT_ANNOUNCED_FILES:
                                    response = {"status": "ERROR", "message": f"Filename '{original_filename}' conflict."}
                                else:
                                    stored_uuid = f"peer_{uuid.uuid4()}.enc"
                                    enc_path = os.path.join(PEER_STORAGE_DIR, stored_uuid)
                                    try:
                                        client_socket.sendall(json.dumps({"status": "READY_FOR_DATA"}).encode())
                                        bytes_rec = 0
                                        with open(enc_path, 'wb') as f_enc:
                                            while bytes_rec < encrypted_size_bytes:
                                                chunk = client_socket.recv(min(BUFFER_SIZE, encrypted_size_bytes - bytes_rec))
                                                if not chunk: raise ConnectionAbortedError("Client disconnected during peer upload")
                                                f_enc.write(chunk)
                                                bytes_rec += len(chunk)
                                        
                                        if bytes_rec == encrypted_size_bytes:
                                            PEER_HOSTED_FILES[original_filename] = {
                                                "owner_username": "peer_admin", "stored_filename_uuid": stored_uuid,
                                                "file_key_hex": meta["file_key_hex"], "iv_hex": meta["iv_hex"],
                                                "original_hash_hex": meta["original_hash_hex"],
                                                "encrypted_size_bytes": encrypted_size_bytes
                                            }
                                            response = {"status": "OK", "message": "File uploaded to peer."}
                                            print(f"{COLOR_GREEN}[PEER_ADMIN] File '{original_filename}' stored as '{stored_uuid}'.{COLOR_RESET}")
                                        else: raise ValueError("Size mismatch")
                                    except Exception as e:
                                        if os.path.exists(enc_path): os.remove(enc_path)
                                        response = {"status": "ERROR", "message": f"Peer upload failed: {e}"}
                                        if isinstance(e, ConnectionAbortedError): raise # Re-raise to break loop

                        elif command == "LIST_SHARED_FILES":
                            all_files = []
                            for fname, meta in PEER_HOSTED_FILES.items():
                                all_files.append({"filename": fname, "type": "peer_hosted", "owner": meta["owner_username"],
                                                  "size_enc": meta["encrypted_size_bytes"], "hash_orig": meta["original_hash_hex"][:8]})
                            for fname, meta in CLIENT_ANNOUNCED_FILES.items():
                                all_files.append({"filename": fname, "type": "client_announced", "owner": meta["owner_username"],
                                                  "sharer": f"{meta['sharer_ip']}:{meta['sharer_port']}",
                                                  "size_orig": meta["original_size_bytes"], "hash_orig": meta["original_hash_hex"][:8]})
                            response = {"status": "OK", "files": all_files}

                        elif command == "REQUEST_DOWNLOAD_INFO": # Client wants to download
                            fname = message.get("original_filename")
                            if fname in PEER_HOSTED_FILES:
                                meta = PEER_HOSTED_FILES[fname]
                                response = {"status": "OK", "download_type": "from_peer",
                                            "file_metadata": meta,
                                            "peer_address": f"{PEER_PUBLIC_IP}:{LISTEN_PORT}" # This peer's address
                                           }
                            elif fname in CLIENT_ANNOUNCED_FILES:
                                meta = CLIENT_ANNOUNCED_FILES[fname]
                                response = {"status": "OK", "download_type": "from_client_p2p",
                                            "file_metadata": meta, # Includes key, IV, hash, owner, sharer_ip, sharer_port
                                           }
                            else: response = {"status": "ERROR", "message": "File not found."}

                        # Note: Actual file data for PEER_HOSTED_FILES is now handled by a separate request
                        # after client gets REQUEST_DOWNLOAD_INFO and then sends a GET_PEER_HOSTED_FILE command.
                        # This is to allow chunking and better flow control.
                        elif command == "GET_PEER_HOSTED_FILE_DATA":
                            fname = message.get("original_filename")
                            meta = PEER_HOSTED_FILES.get(fname)
                            if not meta: response = {"status": "ERROR", "message": "File not on peer."}
                            else:
                                enc_path = os.path.join(PEER_STORAGE_DIR, meta["stored_filename_uuid"])
                                if not os.path.exists(enc_path):
                                    response = {"status": "ERROR", "message": "File data missing on peer."}
                                else:
                                    # Send metadata again as confirmation, then stream
                                    client_socket.sendall(json.dumps({
                                        "status": "READY_TO_STREAM_PEER_FILE",
                                        "original_filename": fname,
                                        "encrypted_size_bytes": meta["encrypted_size_bytes"]
                                    }).encode())
                                    
                                    print(f"{COLOR_BLUE}[PEER] Streaming '{fname}' to {client_addr_str_colored}...{COLOR_RESET}")
                                    with open(enc_path, 'rb') as f_enc:
                                        while True:
                                            chunk = f_enc.read(BUFFER_SIZE)
                                            if not chunk: break
                                            client_socket.sendall(chunk)
                                    print(f"{COLOR_GREEN}[PEER] Finished streaming '{fname}'.{COLOR_RESET}")
                                    continue # Skip generic JSON response

                client_socket.sendall(json.dumps(response).encode('utf-8'))
            except json.JSONDecodeError: pass # Handle errors
            except ConnectionResetError: print(f"{COLOR_RED}[PEER] Conn reset by {client_addr_str_colored}{COLOR_RESET}"); break
            except ConnectionAbortedError: print(f"{COLOR_RED}[PEER] Conn aborted by {client_addr_str_colored}{COLOR_RESET}"); break
            except Exception as e: print(f"{COLOR_RED}[PEER] Error for {client_addr_str_colored}: {e}{COLOR_RESET}"); break
    except Exception: pass # Outer loop errors
    finally:
        if current_user_session_token and current_user_session_token in ACTIVE_SESSIONS:
            ACTIVE_SESSIONS.pop(current_user_session_token, None)
        print(f"{COLOR_YELLOW}[PEER] Closing conn for {client_addr_str_colored}{COLOR_RESET}")
        client_socket.close()

def start_main_peer_server(host=PEER_HOST_LISTEN_IP, port=LISTEN_PORT):
    global PEER_PUBLIC_IP # Ensure it's set if not default
    if PEER_PUBLIC_IP == '0.0.0.0' or PEER_PUBLIC_IP == '127.0.0.1':
        print(f"{COLOR_YELLOW}[PEER_SETUP] Warning: PEER_PUBLIC_IP is '{PEER_PUBLIC_IP}'. For P2P, clients might need a reachable IP.{COLOR_RESET}")

    ensure_storage_dir(PEER_STORAGE_DIR)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind((host, port))
        server_socket.listen(5)
        print(f"{COLOR_GREEN}[PEER] Main Peer Server listening on {host}:{port} (Publicly: {PEER_PUBLIC_IP}:{port}){COLOR_RESET}")
        while True:
            client_sock, client_addr = server_socket.accept()
            threading.Thread(target=handle_client_connection, args=(client_sock, client_addr), daemon=True).start()
    except OSError as e: print(f"{COLOR_RED}[PEER] MAIN BIND ERROR: {e}{COLOR_RESET}")
    except KeyboardInterrupt: print(f"\n{COLOR_YELLOW}[PEER] Main Peer Shutting down...{COLOR_RESET}")
    finally: server_socket.close()

# (admin_add_file function would be similar to Phase 3, using Argon2 for a default admin pass if needed)

if __name__ == "__main__":
    # For testing, you might want to pre-populate USER_CREDENTIALS or PEER_HOSTED_FILES
    # Example: USER_CREDENTIALS["admin"] = crypto_utils.hash_password_argon2("adminpass")
    # add_file_by_peer_admin can be called here if desired.
    # PEER_PUBLIC_IP can be configured here or via args if needed.
    # If your machine is behind a NAT, PEER_PUBLIC_IP would be your router's public IP,
    # and you'd need port forwarding on your router for LISTEN_PORT.
    # For local testing, 127.0.0.1 is fine for PEER_PUBLIC_IP.
    if len(sys.argv) > 1:
        PEER_PUBLIC_IP = sys.argv[1]
        print(f"{COLOR_BLUE}[PEER_SETUP] PEER_PUBLIC_IP set to {PEER_PUBLIC_IP} from command line.{COLOR_RESET}")
    
    start_main_peer_server()

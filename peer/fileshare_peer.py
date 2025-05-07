# peer/fileshare_peer.py
import socket
import threading
import os
import json
import secrets # For generating session tokens
from helpers import crypto_utils # Import our crypto functions

# ANSI Color Codes
COLOR_RESET = "\033[0m"
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_MAGENTA = "\033[95m"
COLOR_CYAN = "\033[96m"

# --- Data Stores (In-memory for Phase 2) ---
# { "username": {"salt_hex": "...", "hashed_password_hex": "..."} }
USER_CREDENTIALS = {}
# { "session_token": "username" }
ACTIVE_SESSIONS = {}
# { "filename.txt": {"filepath": "/path/to/local/filename.txt", "owner": "username"} }
SHARED_FILES = {}
# { "peer_addr_str": {"username": "...", "files": ["file1.txt", "file2.zip"]} } - Rudimentary discovery
# For Phase 2, let's simplify peer_list to just track other peers' addresses for now.
# File announcements will be associated with authenticated users.
KNOWN_PEERS_INFO = {} # { "peer_addr_str": ["file1.txt", "file2.zip"] } - from Phase 1, needs update

LISTEN_PORT = 6000
BUFFER_SIZE = 4096

def generate_session_token():
    """Generates a secure random session token."""
    return secrets.token_hex(16)

def get_username_from_token(token):
    """Retrieves username for a given session token, if valid."""
    return ACTIVE_SESSIONS.get(token)

def handle_client_connection(client_socket, client_address):
    """Handles commands from a connected client/peer."""
    client_addr_str_colored = f"{COLOR_MAGENTA}{client_address[0]}:{client_address[1]}{COLOR_RESET}"
    print(f"{COLOR_GREEN}[PEER] Accepted connection from {client_addr_str_colored}{COLOR_RESET}")
    current_user_session_token = None # Track session for this connection

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

                # Commands not requiring authentication
                if command == "REGISTER":
                    username = message.get("username")
                    password = message.get("password")
                    if username and password:
                        if username in USER_CREDENTIALS:
                            response = {"status": "ERROR", "message": "Username already exists."}
                            print(f"{COLOR_YELLOW}[PEER] Registration failed for {username}: Username exists.{COLOR_RESET}")
                        else:
                            salt_hex, hashed_password_hex = crypto_utils.hash_password_sha256(password)
                            USER_CREDENTIALS[username] = {"salt_hex": salt_hex, "hashed_password_hex": hashed_password_hex}
                            response = {"status": "OK", "message": "Registration successful."}
                            print(f"{COLOR_GREEN}[PEER] User '{username}' registered successfully.{COLOR_RESET}")
                    else:
                        response = {"status": "ERROR", "message": "Username and password required."}

                elif command == "LOGIN":
                    username = message.get("username")
                    password = message.get("password")
                    if username and password:
                        user_data = USER_CREDENTIALS.get(username)
                        if user_data and crypto_utils.verify_password_sha256(password, user_data["salt_hex"], user_data["hashed_password_hex"]):
                            # Invalidate any existing session for this user on this connection
                            if current_user_session_token and current_user_session_token in ACTIVE_SESSIONS:
                                del ACTIVE_SESSIONS[current_user_session_token]

                            session_token = generate_session_token()
                            ACTIVE_SESSIONS[session_token] = username
                            current_user_session_token = session_token # Associate token with this connection
                            response = {"status": "OK", "message": "Login successful.", "token": session_token, "username": username}
                            print(f"{COLOR_GREEN}[PEER] User '{username}' logged in. Session token: {session_token}{COLOR_RESET}")
                        else:
                            response = {"status": "ERROR", "message": "Invalid username or password."}
                            print(f"{COLOR_YELLOW}[PEER] Login failed for '{username}'.{COLOR_RESET}")
                    else:
                        response = {"status": "ERROR", "message": "Username and password required."}
                
                else: # Commands requiring authentication
                    token = message.get("token")
                    authenticated_username = get_username_from_token(token)

                    if not authenticated_username:
                        response = {"status": "ERROR", "message": "Authentication required. Please login."}
                        print(f"{COLOR_YELLOW}[PEER] Command '{command}' denied: No valid session token.{COLOR_RESET}")
                    else:
                        print(f"{COLOR_BLUE}[PEER] Authenticated user: {COLOR_CYAN}{authenticated_username}{COLOR_RESET} for command '{command}'")
                        if command == "LOGOUT":
                            if token in ACTIVE_SESSIONS:
                                del ACTIVE_SESSIONS[token]
                                current_user_session_token = None # Clear session for this connection
                                response = {"status": "OK", "message": "Logout successful."}
                                print(f"{COLOR_GREEN}[PEER] User '{authenticated_username}' logged out.{COLOR_RESET}")
                            else:
                                response = {"status": "ERROR", "message": "Invalid session token or already logged out."}
                        
                        elif command == "SHARE":
                            filename = message.get("filename")
                            filepath = message.get("filepath_on_client") # Client tells peer where IT has the file
                                                                        # Peer only stores metadata
                            if filename and filepath:
                                if filename in SHARED_FILES: # Check if filename (globally) is already shared
                                     # For simplicity, allow re-sharing by same owner, or different owners can share same filename
                                     pass # Or add logic to prevent duplicate filenames if desired
                                
                                SHARED_FILES[filename] = {"filepath_on_client": filepath, "owner": authenticated_username, "peer_address": client_address}
                                response = {"status": "OK", "message": f"File '{filename}' announced for sharing."}
                                print(f"{COLOR_GREEN}[PEER] User '{authenticated_username}' announced sharing of '{filename}'.{COLOR_RESET}")
                            else:
                                response = {"status": "ERROR", "message": "Filename and client filepath required."}

                        elif command == "LIST_SHARED":
                            # List files shared by all users
                            # In a more complex system, you might filter by user or permissions
                            files_to_send = []
                            for fname, fdata in SHARED_FILES.items():
                                files_to_send.append({
                                    "filename": fname,
                                    "owner": fdata["owner"],
                                    "sharer_address": f"{fdata['peer_address'][0]}:{fdata['peer_address'][1]}"
                                })
                            response = {"status": "OK", "files": files_to_send}
                            print(f"{COLOR_GREEN}[PEER] Responded to LIST_SHARED for '{authenticated_username}'.{COLOR_RESET}")

                        elif command == "DOWNLOAD":
                            filename = message.get("filename")
                            file_info = SHARED_FILES.get(filename)

                            if file_info:
                                # For Phase 2, the peer itself doesn't send the file.
                                # It tells the requester WHICH peer (client) has the file.
                                # The requester then needs to connect to that client.
                                # This is a more P2P model for file transfer.
                                # However, the skeleton implied the peer sends the file it "shares".
                                # Let's stick to the Phase 1 model where if this peer shared it, it sends it.
                                # If another peer shared it, we need a way to proxy or redirect.
                                # For Phase 2, let's assume DOWNLOAD is for files THIS peer is "hosting" (announced by a client TO this peer).
                                # This means SHARED_FILES needs to store the actual local path if the peer itself is the owner.
                                # This part of the design needs clarification for a true P2P model.

                                # Sticking to the project plan: "Users can select a file to share and another user can download it directly from the sharer."
                                # The "peer" in fileshare_peer.py acts as a node. If a client connected to it announced a file,
                                # that client is the sharer. The peer can relay the download request or provide sharer's address.

                                # Let's simplify for Phase 2: If a file is in SHARED_FILES, it means a client *connected to this peer*
                                # announced it. The *download* should ideally happen from that original client.
                                # The current `fileshare_peer.py` from Phase 1 was acting as a host for its OWN files.
                                #
                                # Re-interpreting Phase 2:
                                # - SHARE: Client tells Peer "I (client) have file X at my_path_X, and I am user U"
                                # - Peer stores { "X": { owner: U, client_address: client_ip_port, client_path: my_path_X } }
                                # - DOWNLOAD: Another client asks Peer for file X.
                                # - Peer tells requesting client: "User U at client_ip_port has file X. Connect there."
                                # This makes `fileshare_peer.py` more of a coordinator/tracker.
                                #
                                # OR, if `fileshare_peer.py` is supposed to be a node that *also* shares its own files:
                                # We need a way for the peer itself to "share" files it owns locally.
                                #
                                # Let's assume the current Phase 1 model for download:
                                # If this peer has an entry for a file, it means it's "hosting" it (even if announced by a client).
                                # This requires the *sharer client* to UPLOAD the file to the peer first if the peer is to serve it.
                                # The skeleton for Phase 1 `fileshare_peer.py` had `SHARED_FILES = { "filename.txt": "/path/to/local/filename.txt" }`
                                # implying it serves its own local files.
                                #
                                # Let's refine:
                                # 1. Peer can share its own local files (added via a peer-specific mechanism, not client SHARE cmd).
                                # 2. Client SHARE cmd: Client announces it has a file. Peer stores this.
                                # 3. Client DOWNLOAD cmd:
                                #    - If peer itself owns the file: peer sends it.
                                #    - If another client announced the file: peer tells requester the address of that client.
                                #
                                # For Phase 2, let's make the peer serve files it "owns" locally.
                                # The `SHARE` command from a client will just be an announcement for now.
                                # True P2P download from original client can be Phase 3+.
                                #
                                # So, we need a separate mechanism for the peer to add its own files.
                                # And `SHARED_FILES` should reflect files this peer can serve.
                                #
                                # Let's adapt the `SHARED_FILES` structure from Phase 1 for files *this peer* serves.
                                # `SHARED_FILES = { "filename.txt": "/path/to/local/filename.txt" }` (owner is implicitly this peer)
                                # The `SHARE` command from clients will populate `KNOWN_PEERS_INFO` or a similar structure.

                                # For now, let's keep DOWNLOAD working as in Phase 1 for files this peer "knows" locally.
                                # The integration of authentication means only logged-in users can download.
                                
                                # Let's assume SHARED_FILES for this peer node are files it *actually* has locally.
                                # The `SHARE` command from clients will be treated as just an announcement for now.
                                # The `LIST_SHARED` will list files this peer hosts, AND files announced by others.

                                # Refined LIST_SHARED for Phase 2:
                                if command == "LIST_SHARED":
                                    files_output = []
                                    # Files hosted by this peer
                                    for fname, fpath in SHARED_FILES.items(): # Assuming SHARED_FILES is {filename: local_filepath} for peer's own files
                                        files_output.append({
                                            "filename": fname,
                                            "owner": "this_peer", # Or a peer identity
                                            "sharer_address": f"{host}:{port}" # This peer's address
                                        })
                                    # Files announced by other clients (from KNOWN_PEERS_INFO or a new structure)
                                    # For now, let's simplify and only list files this peer can directly serve.
                                    # True P2P listing will be more complex.
                                    response = {"status": "OK", "files": files_output}
                                    print(f"{COLOR_GREEN}[PEER] Responded to LIST_SHARED for '{authenticated_username}'.{COLOR_RESET}")


                                elif command == "DOWNLOAD": # Client requests to download a file THIS PEER IS HOSTING
                                    filename = message.get("filename")
                                    # Check if filename is in this peer's locally hosted SHARED_FILES
                                    if filename in SHARED_FILES: # SHARED_FILES is {filename: local_filepath}
                                        filepath = SHARED_FILES[filename]
                                        if os.path.exists(filepath):
                                            try:
                                                confirm_msg = json.dumps({"status": "READY_TO_SEND", "filename": filename}).encode('utf-8')
                                                client_socket.sendall(confirm_msg)
                                                print(f"{COLOR_GREEN}[PEER] Sending file: {COLOR_CYAN}{filename}{COLOR_GREEN} to {client_addr_str_colored} (user: {authenticated_username}){COLOR_RESET}")
                                                filesize = os.path.getsize(filepath)
                                                client_socket.sendall(str(filesize).encode('utf-8').ljust(16))

                                                with open(filepath, 'rb') as f:
                                                    while True:
                                                        chunk = f.read(BUFFER_SIZE)
                                                        if not chunk: break
                                                        client_socket.sendall(chunk)
                                                print(f"{COLOR_GREEN}[PEER] Finished sending {COLOR_CYAN}{filename}{COLOR_RESET}")
                                                continue # Skip generic response
                                            except Exception as e:
                                                print(f"{COLOR_RED}[PEER] Error sending file {filename}: {e}{COLOR_RESET}")
                                                response = {"status": "ERROR", "message": f"Failed to send file: {e}"}
                                        else:
                                            response = {"status": "ERROR", "message": "File not found locally by peer."}
                                            print(f"{COLOR_RED}[PEER] File {filename} not found at {filepath} (but was in SHARED_FILES){COLOR_RESET}")
                                    else:
                                        response = {"status": "ERROR", "message": "File not hosted by this peer."}
                                        print(f"{COLOR_YELLOW}[PEER] File {filename} not hosted by this peer (requested by {authenticated_username}){COLOR_RESET}")
                        else:
                             response = {"status": "ERROR", "message": f"Unknown authenticated command: {command}"}


                # Send response back to client
                client_socket.sendall(json.dumps(response).encode('utf-8'))

            except json.JSONDecodeError:
                print(f"{COLOR_RED}[PEER] Received invalid message format from {client_addr_str_colored}{COLOR_RESET}")
                try: client_socket.sendall(json.dumps({"status": "ERROR", "message": "Invalid JSON format"}).encode('utf-8'))
                except Exception: pass
            except ConnectionResetError:
                print(f"{COLOR_RED}[PEER] Connection reset by {client_addr_str_colored}{COLOR_RESET}")
                break
            except Exception as e:
                print(f"{COLOR_RED}[PEER] Error handling client {client_addr_str_colored}: {e}{COLOR_RESET}")
                try: client_socket.sendall(json.dumps({"status": "ERROR", "message": f"Server error: {e}"}).encode('utf-8'))
                except Exception: pass
                break

    except ConnectionResetError:
        print(f"{COLOR_RED}[PEER] Connection reset by {client_addr_str_colored} (outer loop){COLOR_RESET}")
    except Exception as e:
        print(f"{COLOR_RED}[PEER] Unhandled error for client {client_addr_str_colored}: {e}{COLOR_RESET}")
    finally:
        if current_user_session_token and current_user_session_token in ACTIVE_SESSIONS:
            username_logged_out = ACTIVE_SESSIONS.pop(current_user_session_token, None)
            if username_logged_out:
                 print(f"{COLOR_YELLOW}[PEER] Session for user '{username_logged_out}' (token: {current_user_session_token[:8]}...) invalidated due to disconnect.{COLOR_RESET}")
        print(f"{COLOR_YELLOW}[PEER] Closing connection to {client_addr_str_colored}{COLOR_RESET}")
        client_socket.close()

def start_peer_server(host='0.0.0.0', port=LISTEN_PORT):
    """Starts the peer server to listen for incoming connections."""
    # Global host and port for use in LIST_SHARED response
    global PEER_HOST, PEER_PORT
    PEER_HOST, PEER_PORT = host, port

    peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    peer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        peer_socket.bind((host, port))
        peer_socket.listen(5)
        print(f"{COLOR_GREEN}[PEER] Peer listening on {COLOR_YELLOW}{host}:{port}{COLOR_RESET}")

        while True:
            client_socket, client_address = peer_socket.accept()
            client_thread = threading.Thread(target=handle_client_connection, args=(client_socket, client_address))
            client_thread.daemon = True
            client_thread.start()
    except OSError as e:
        print(f"{COLOR_RED}[PEER] Error binding to port {port}: {e}. Is another instance running?{COLOR_RESET}")
    except KeyboardInterrupt:
        print(f"\n{COLOR_YELLOW}[PEER] Shutting down peer server.{COLOR_RESET}")
    finally:
        peer_socket.close()

def add_local_file_for_sharing_by_peer(filename, filepath):
    """Mechanism for the peer ITSELF to share its own local files."""
    abs_filepath = os.path.abspath(filepath)
    if os.path.exists(abs_filepath):
        SHARED_FILES[filename] = abs_filepath # SHARED_FILES for peer's own files: {filename: local_filepath}
        print(f"{COLOR_GREEN}[PEER] Peer is now sharing its local file '{COLOR_CYAN}{filename}{COLOR_GREEN}' from '{abs_filepath}'{COLOR_RESET}")
    else:
        print(f"{COLOR_RED}[PEER] Error: Peer's local file not found at '{abs_filepath}', cannot share.{COLOR_RESET}")


if __name__ == "__main__":
    example_filename = "peer_document.txt"
    if os.path.exists(example_filename):
        add_local_file_for_sharing_by_peer(example_filename, example_filename)
    else:
        try:
            with open(example_filename, "w") as f:
                f.write("This is a test document hosted directly by the peer.")
            add_local_file_for_sharing_by_peer(example_filename, example_filename)
        except Exception as e:
            print(f"{COLOR_RED}[PEER] Could not create dummy file '{example_filename}': {e}{COLOR_RESET}")
    
    start_peer_server()


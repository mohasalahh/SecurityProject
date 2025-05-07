# client/fileshare_client.py
import socket
import threading
import os
import json
import time
import sys
import tempfile
import secrets # For PBKDF2 salt if client manages it

# --- Add project root to sys.path ---
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path: sys.path.insert(0, project_root)

from helpers import crypto_utils

# ANSI Color Codes
COLOR_RESET, COLOR_RED, COLOR_GREEN, COLOR_YELLOW, COLOR_BLUE, COLOR_MAGENTA, COLOR_CYAN, COLOR_BOLD = \
    "\033[0m", "\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[95m", "\033[96m", "\033[1m"

# --- Client Configuration ---
DEFAULT_PEER_HOST = '127.0.0.1' # Main peer's IP
DEFAULT_PEER_PORT = 6000      # Main peer's port
BUFFER_SIZE = 8192
DOWNLOAD_DIR = "client_downloads_phase4"
CLIENT_P2P_LISTEN_PORT = 0 # 0 means OS picks a free port for P2P server
                           # Can be fixed if preferred, e.g., 6001, but needs to be unique per client instance on same machine

class FileShareClient:
    def __init__(self):
        self.main_peer_session_token = None
        self.current_username = None
        self.master_key_salt_hex = None # Salt for deriving master key (could be stored locally encrypted)
        self.derived_master_key = None  # In-memory for session

        # For P2P sharing: { original_filename: { local_path: "...", file_key_hex: "...", iv_hex: "...", original_hash_hex: "..." } }
        self.my_shared_files_metadata = {}
        self.p2p_server_socket = None
        self.p2p_server_thread = None
        self.client_p2p_listen_port = CLIENT_P2P_LISTEN_PORT # Will be updated if OS picks port
        self.stop_p2p_server_event = threading.Event()

    def _connect_and_send_json(self, host, port, command_dict):
        """Connects, sends a JSON command, receives a JSON response, closes socket."""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(20)
            sock.connect((host, port))
            
            # Add session token for main peer communication if available and not login/register
            if host == DEFAULT_PEER_HOST and port == DEFAULT_PEER_PORT and \
               self.main_peer_session_token and command_dict.get("command") not in ["LOGIN", "REGISTER"]:
                command_dict["token"] = self.main_peer_session_token
            
            sock.sendall(json.dumps(command_dict).encode('utf-8'))
            response_bytes = sock.recv(BUFFER_SIZE)
            return json.loads(response_bytes.decode('utf-8'))
        except Exception as e:
            print(f"{COLOR_RED}[CLIENT_COMM] Error with {host}:{port}: {e}{COLOR_RESET}")
            return {"status": "ERROR", "message": f"Communication error: {e}"}
        finally:
            if sock: sock.close()

    def _connect_for_stream(self, host, port, initial_command_dict=None):
        """Connects and returns an open socket, optionally sends an initial JSON command."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30) # Longer timeout for potential stream setup
        try:
            sock.connect((host, port))
            if initial_command_dict:
                if host == DEFAULT_PEER_HOST and port == DEFAULT_PEER_PORT and \
                   self.main_peer_session_token and initial_command_dict.get("command") not in ["LOGIN", "REGISTER"]:
                    initial_command_dict["token"] = self.main_peer_session_token
                sock.sendall(json.dumps(initial_command_dict).encode('utf-8'))
            return sock # Return open socket
        except Exception as e:
            print(f"{COLOR_RED}[CLIENT_COMM] Stream connection error to {host}:{port}: {e}{COLOR_RESET}")
            if sock: sock.close()
            return None

    # --- Authentication and Master Key ---
    def register(self, username, password):
        cmd = {"command": "REGISTER", "username": username, "password": password}
        resp = self._connect_and_send_json(DEFAULT_PEER_HOST, DEFAULT_PEER_PORT, cmd)
        # (Handle response as before)
        if resp and resp.get("status") == "OK":
            print(f"{COLOR_GREEN}[CLIENT] Registration OK for '{username}'.{COLOR_RESET}")
            # For Argon2, the salt is part of the hash string stored by the peer.
            # For PBKDF2 master key, client needs its own salt.
            # Let's generate and (conceptually) store it. In a real app, this salt would be stored securely.
            pbkdf2_salt = crypto_utils.generate_pbkdf2_salt()
            self.master_key_salt_hex = pbkdf2_salt.hex() # Store for login
            print(f"{COLOR_BLUE}[CLIENT] Generated PBKDF2 salt for master key derivation (would be stored securely). Salt: {self.master_key_salt_hex[:8]}...{COLOR_RESET}")
            # Here, you'd typically store username and master_key_salt_hex locally.
            return True
        print(f"{COLOR_RED}[CLIENT] Registration failed: {resp.get('message', 'N/A')}{COLOR_RESET}")
        return False

    def login(self, username, password):
        cmd = {"command": "LOGIN", "username": username, "password": password}
        resp = self._connect_and_send_json(DEFAULT_PEER_HOST, DEFAULT_PEER_PORT, cmd)
        if resp and resp.get("status") == "OK":
            self.main_peer_session_token = resp.get("token")
            self.current_username = resp.get("username")
            print(f"{COLOR_GREEN}[CLIENT] Login OK. Welcome, {self.current_username}!{COLOR_RESET}")
            
            # Derive master key. Assume self.master_key_salt_hex was loaded for this user.
            # For this example, let's re-use a fixed salt or re-generate if not found.
            # In a real app, you'd load the user-specific salt.
            if not self.master_key_salt_hex: # Simulate loading or use a default for example
                 print(f"{COLOR_YELLOW}[CLIENT] Master key salt not found for user (simulating generation). In real app, load user's salt.{COLOR_RESET}")
                 self.master_key_salt_hex = crypto_utils.generate_pbkdf2_salt().hex()

            salt_bytes = bytes.fromhex(self.master_key_salt_hex)
            self.derived_master_key = crypto_utils.derive_master_key_pbkdf2(password, salt_bytes)
            print(f"{COLOR_BLUE}[CLIENT] Master key derived (in memory). Length: {len(self.derived_master_key)} bytes.{COLOR_RESET}")
            # Start P2P server on login
            self.start_p2p_server()
            return True
        print(f"{COLOR_RED}[CLIENT] Login failed: {resp.get('message', 'N/A')}{COLOR_RESET}")
        self.main_peer_session_token = None; self.current_username = None; self.derived_master_key = None
        return False

    def logout(self):
        if not self.main_peer_session_token: print(f"{COLOR_YELLOW}[CLIENT] Not logged in.{COLOR_RESET}"); return
        cmd = {"command": "LOGOUT"}
        # No need to pass host/port if it's always the main peer
        resp = self._connect_and_send_json(DEFAULT_PEER_HOST, DEFAULT_PEER_PORT, cmd)
        print(f"{COLOR_GREEN if resp.get('status') == 'OK' else COLOR_RED}[CLIENT] Logout: {resp.get('message', 'N/A')}{COLOR_RESET}")
        self.main_peer_session_token = None; self.current_username = None; self.derived_master_key = None
        self.stop_p2p_server()


    # --- P2P Server Component for this Client ---
    def start_p2p_server(self):
        if self.p2p_server_thread and self.p2p_server_thread.is_alive():
            print(f"{COLOR_YELLOW}[CLIENT_P2P] P2P server already running.{COLOR_RESET}")
            return

        self.p2p_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.p2p_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            # Bind to 0.0.0.0 to accept connections from any interface
            self.p2p_server_socket.bind(('0.0.0.0', self.client_p2p_listen_port))
            # Get the actual port if OS picked one (CLIENT_P2P_LISTEN_PORT was 0)
            self.client_p2p_listen_port = self.p2p_server_socket.getsockname()[1]
            self.p2p_server_socket.listen(5)
            print(f"{COLOR_GREEN}[CLIENT_P2P] Started P2P server, listening on port {self.client_p2p_listen_port}{COLOR_RESET}")
            
            self.stop_p2p_server_event.clear()
            self.p2p_server_thread = threading.Thread(target=self._p2p_server_loop, daemon=True)
            self.p2p_server_thread.start()
        except Exception as e:
            print(f"{COLOR_RED}[CLIENT_P2P] Failed to start P2P server: {e}{COLOR_RESET}")
            if self.p2p_server_socket: self.p2p_server_socket.close()

    def _p2p_server_loop(self):
        self.p2p_server_socket.settimeout(1.0) # Timeout to allow checking stop_event
        while not self.stop_p2p_server_event.is_set():
            try:
                peer_conn_socket, peer_addr = self.p2p_server_socket.accept()
                print(f"{COLOR_GREEN}[CLIENT_P2P] Accepted P2P connection from {peer_addr}{COLOR_RESET}")
                # Handle this P2P request in a new thread
                threading.Thread(target=self._handle_p2p_download_request, 
                                 args=(peer_conn_socket, peer_addr), daemon=True).start()
            except socket.timeout:
                continue # Loop back to check stop_event
            except Exception as e:
                if not self.stop_p2p_server_event.is_set(): # Don't log error if we are stopping
                    print(f"{COLOR_RED}[CLIENT_P2P] Server loop error: {e}{COLOR_RESET}")
                break # Exit loop on other errors
        if self.p2p_server_socket: self.p2p_server_socket.close()
        print(f"{COLOR_YELLOW}[CLIENT_P2P] P2P server stopped.{COLOR_RESET}")

    def _handle_p2p_download_request(self, requester_socket, requester_addr):
        try:
            req_bytes = requester_socket.recv(BUFFER_SIZE)
            if not req_bytes: return
            request = json.loads(req_bytes.decode('utf-8'))
            
            print(f"{COLOR_BLUE}[CLIENT_P2P] Received P2P request: {request} from {requester_addr}{COLOR_RESET}")
            if request.get("command") == "REQUEST_P2P_FILE_DATA":
                original_filename = request.get("original_filename")
                file_meta = self.my_shared_files_metadata.get(original_filename)

                if not file_meta:
                    requester_socket.sendall(json.dumps({"status": "ERROR", "message": "File not shared by this client."}).encode())
                else:
                    local_path = file_meta["local_path"]
                    if not os.path.exists(local_path):
                        requester_socket.sendall(json.dumps({"status": "ERROR", "message": "File data missing locally."}).encode())
                        return

                    # Prepare to stream: encrypt original file data on-the-fly
                    key_bytes = bytes.fromhex(file_meta["file_key_hex"])
                    iv_bytes = bytes.fromhex(file_meta["iv_hex"])
                    
                    # Get original file size for accurate encrypted size calculation (approx)
                    # For simplicity, we'll send the encrypted file. Client needs original_hash for verification.
                    # The requesting client already has key, IV, original_hash from the main peer.
                    
                    with open(local_path, 'rb') as f_orig:
                        original_data = f_orig.read()
                    
                    encrypted_data = crypto_utils.encrypt_aes_cbc(original_data, key_bytes, iv_bytes)
                    if not encrypted_data:
                        requester_socket.sendall(json.dumps({"status": "ERROR", "message": "Encryption failed on sharing client."}).encode())
                        return

                    encrypted_size_bytes = len(encrypted_data)
                    
                    # Send confirmation and size
                    requester_socket.sendall(json.dumps({
                        "status": "READY_TO_STREAM_P2P_FILE",
                        "original_filename": original_filename,
                        "encrypted_size_bytes": encrypted_size_bytes
                    }).encode())
                    
                    # Stream encrypted data in chunks
                    print(f"{COLOR_BLUE}[CLIENT_P2P] Streaming '{original_filename}' (encrypted) to {requester_addr}...{COLOR_RESET}")
                    sent_bytes = 0
                    for i in range(0, encrypted_size_bytes, BUFFER_SIZE):
                        chunk = encrypted_data[i:i+BUFFER_SIZE]
                        requester_socket.sendall(chunk)
                        sent_bytes += len(chunk)
                    
                    print(f"{COLOR_GREEN}[CLIENT_P2P] Finished streaming '{original_filename}' to {requester_addr}. Sent {sent_bytes} bytes.{COLOR_RESET}")
            else:
                requester_socket.sendall(json.dumps({"status": "ERROR", "message": "Unknown P2P command."}).encode())
        except Exception as e:
            print(f"{COLOR_RED}[CLIENT_P2P] Error handling P2P request from {requester_addr}: {e}{COLOR_RESET}")
        finally:
            requester_socket.close()

    def stop_p2p_server(self):
        self.stop_p2p_server_event.set()
        if self.p2p_server_thread and self.p2p_server_thread.is_alive():
            self.p2p_server_thread.join(timeout=2.0) # Wait for thread to finish
        if self.p2p_server_socket:
            try: self.p2p_server_socket.close()
            except: pass
        print(f"{COLOR_YELLOW}[CLIENT_P2P] P2P server shutdown initiated.{COLOR_RESET}")


    # --- File Operations ---
    def announce_file_for_p2p_sharing(self, local_filepath):
        if not self.main_peer_session_token: print(f"{COLOR_RED}Login first.{COLOR_RESET}"); return
        if not os.path.exists(local_filepath): print(f"{COLOR_RED}Local file not found: {local_filepath}{COLOR_RESET}"); return
        if not self.client_p2p_listen_port: print(f"{COLOR_RED}P2P server not running or port not set.{COLOR_RESET}"); return


        original_filename = os.path.basename(local_filepath)
        print(f"{COLOR_BLUE}[CLIENT] Announcing P2P share for '{original_filename}'...{COLOR_RESET}")

        original_hash_hex = crypto_utils.hash_file_sha256(local_filepath)
        if not original_hash_hex: print(f"{COLOR_RED}Failed to hash file.{COLOR_RESET}"); return
        
        file_key_hex, iv_hex = crypto_utils.generate_aes_key_and_iv()
        original_size_bytes = os.path.getsize(local_filepath)

        # Store metadata locally for serving P2P requests
        self.my_shared_files_metadata[original_filename] = {
            "local_path": os.path.abspath(local_filepath),
            "file_key_hex": file_key_hex, "iv_hex": iv_hex,
            "original_hash_hex": original_hash_hex,
            "original_size_bytes": original_size_bytes
        }

        announcement_meta = {
            "original_filename": original_filename,
            "file_key_hex": file_key_hex, "iv_hex": iv_hex,
            "original_hash_hex": original_hash_hex,
            "original_size_bytes": original_size_bytes
        }
        cmd = {"command": "SHARE_ANNOUNCEMENT", "file_metadata": announcement_meta, 
               "sharer_listen_port": self.client_p2p_listen_port}
        
        resp = self._connect_and_send_json(DEFAULT_PEER_HOST, DEFAULT_PEER_PORT, cmd)
        if resp and resp.get("status") == "OK":
            print(f"{COLOR_GREEN}[CLIENT] Successfully announced '{original_filename}' for P2P sharing. Ready to serve.{COLOR_RESET}")
        else:
            print(f"{COLOR_RED}[CLIENT] Failed to announce P2P share: {resp.get('message', 'N/A')}{COLOR_RESET}")
            if original_filename in self.my_shared_files_metadata:
                del self.my_shared_files_metadata[original_filename] # Rollback local store

    def list_all_shared_files(self):
        if not self.main_peer_session_token: print(f"{COLOR_RED}Login first.{COLOR_RESET}"); return
        cmd = {"command": "LIST_SHARED_FILES"}
        resp = self._connect_and_send_json(DEFAULT_PEER_HOST, DEFAULT_PEER_PORT, cmd)
        if resp and resp.get("status") == "OK":
            files = resp.get("files", [])
            print(f"{COLOR_BOLD}{COLOR_YELLOW}[CLIENT] --- All Shared Files (via Main Peer) ---{COLOR_RESET}")
            if not files: print(f"  {COLOR_YELLOW}No files listed.{COLOR_RESET}")
            else:
                for f_info in files:
                    type_color = COLOR_CYAN if f_info['type'] == 'peer_hosted' else COLOR_MAGENTA
                    size_info = f"EncSize: {f_info.get('size_enc', 'N/A')}" if f_info['type'] == 'peer_hosted' else f"OrigSize: {f_info.get('size_orig', 'N/A')}"
                    sharer_info = f"(Sharer: {f_info.get('sharer', 'N/A')})" if f_info['type'] == 'client_announced' else ""
                    print(f"  - {COLOR_GREEN}{f_info['filename']}{COLOR_RESET} [{type_color}{f_info['type']}{COLOR_RESET}] (Owner: {f_info['owner']}, {size_info} B, Hash: {f_info['hash_orig']}...) {sharer_info}")
            print(f"{COLOR_BOLD}{COLOR_YELLOW}---------------------------------------------{COLOR_RESET}")
        else: print(f"{COLOR_RED}[CLIENT] Failed to list files: {resp.get('message', 'N/A')}{COLOR_RESET}")

    def request_and_download_file(self, original_filename):
        if not self.main_peer_session_token: print(f"{COLOR_RED}Login first.{COLOR_RESET}"); return

        # 1. Ask main peer for download info
        cmd_info = {"command": "REQUEST_DOWNLOAD_INFO", "original_filename": original_filename}
        info_resp = self._connect_and_send_json(DEFAULT_PEER_HOST, DEFAULT_PEER_PORT, cmd_info)

        if not (info_resp and info_resp.get("status") == "OK"):
            print(f"{COLOR_RED}[CLIENT] Could not get download info for '{original_filename}': {info_resp.get('message', 'N/A')}{COLOR_RESET}")
            return

        download_type = info_resp.get("download_type")
        file_meta = info_resp.get("file_metadata")

        if download_type == "from_peer":
            peer_address_str = info_resp.get("peer_address") # "ip:port"
            peer_ip, peer_port_str = peer_address_str.split(':')
            self._download_file_from_host(peer_ip, int(peer_port_str), original_filename, file_meta, is_main_peer=True)
        elif download_type == "from_client_p2p":
            sharer_ip = file_meta.get("sharer_ip")
            sharer_port = file_meta.get("sharer_port")
            print(f"{COLOR_BLUE}[CLIENT] File '{original_filename}' is shared by client {file_meta['owner']} at {sharer_ip}:{sharer_port}. Attempting P2P download.{COLOR_RESET}")
            self._download_file_from_host(sharer_ip, sharer_port, original_filename, file_meta, is_main_peer=False)
        else:
            print(f"{COLOR_RED}[CLIENT] Unknown download type: {download_type}{COLOR_RESET}")

    def _download_file_from_host(self, host_ip, host_port, original_filename, file_meta_from_main_peer, is_main_peer):
        """Generic download from a host (main peer or another client)."""
        # file_meta_from_main_peer contains key, IV, original_hash, and size info.
        # For P2P, it also contains original_size_bytes. For peer-hosted, encrypted_size_bytes.

        key_hex = file_meta_from_main_peer.get("file_key_hex")
        iv_hex = file_meta_from_main_peer.get("iv_hex")
        original_hash_hex_expected = file_meta_from_main_peer.get("original_hash_hex")
        
        # Determine command and expected size based on source
        if is_main_peer:
            download_cmd_to_host = {"command": "GET_PEER_HOSTED_FILE_DATA", "original_filename": original_filename}
            # encrypted_size_bytes = file_meta_from_main_peer.get("encrypted_size_bytes") # This will be sent by peer again
        else: # P2P download from another client
            download_cmd_to_host = {"command": "REQUEST_P2P_FILE_DATA", "original_filename": original_filename}
            # For P2P, the sharer client will tell us the encrypted_size_bytes in its READY_TO_STREAM response.

        stream_sock = None
        temp_enc_file_path = None
        try:
            stream_sock = self._connect_for_stream(host_ip, host_port, download_cmd_to_host)
            if not stream_sock: raise ConnectionError("Failed to establish stream connection.")

            # Receive initial JSON response from the host (main peer or P2P client)
            # This response will confirm readiness and provide encrypted_size_bytes
            host_ready_resp_bytes = stream_sock.recv(BUFFER_SIZE)
            host_ready_resp = json.loads(host_ready_resp_bytes.decode('utf-8'))
            print(f"{COLOR_BLUE}[CLIENT] Host ({host_ip}:{host_port}) response: {host_ready_resp}{COLOR_RESET}")

            if host_ready_resp.get("status") not in ["READY_TO_STREAM_PEER_FILE", "READY_TO_STREAM_P2P_FILE"]:
                raise ValueError(f"Host not ready or error: {host_ready_resp.get('message')}")
            
            encrypted_size_bytes = host_ready_resp.get("encrypted_size_bytes")
            if not isinstance(encrypted_size_bytes, int) or encrypted_size_bytes < 0:
                raise ValueError("Invalid encrypted_size_bytes from host.")

            print(f"{COLOR_BLUE}[CLIENT] Receiving '{original_filename}' (Encrypted Size: {encrypted_size_bytes} B) from {host_ip}:{host_port}...{COLOR_RESET}")
            
            with tempfile.NamedTemporaryFile(delete=False) as tmp_f:
                temp_enc_file_path = tmp_f.name
                bytes_rec = 0
                while bytes_rec < encrypted_size_bytes:
                    chunk = stream_sock.recv(min(BUFFER_SIZE, encrypted_size_bytes - bytes_rec))
                    if not chunk: raise ConnectionAbortedError("Host disconnected during stream.")
                    tmp_f.write(chunk)
                    bytes_rec += len(chunk)
            
            if bytes_rec != encrypted_size_bytes: raise ValueError("Encrypted size mismatch.")
            print(f"{COLOR_BLUE}[CLIENT] Encrypted data received. Decrypting...{COLOR_RESET}")

            with open(temp_enc_file_path, 'rb') as f_enc: encrypted_data = f_enc.read()
            
            decrypted_data = crypto_utils.decrypt_aes_cbc(encrypted_data, bytes.fromhex(key_hex), bytes.fromhex(iv_hex))
            if not decrypted_data: raise ValueError("Decryption failed.")
            
            print(f"{COLOR_BLUE}[CLIENT] Decrypted. Verifying integrity...{COLOR_RESET}")
            calc_hash = crypto_utils.hash_data_sha256(decrypted_data)
            if calc_hash == original_hash_hex_expected:
                print(f"{COLOR_GREEN}[CLIENT] Integrity VERIFIED! Hashes match.{COLOR_RESET}")
                if not os.path.exists(DOWNLOAD_DIR): os.makedirs(DOWNLOAD_DIR)
                save_path = os.path.join(DOWNLOAD_DIR, original_filename)
                with open(save_path, 'wb') as f_final: f_final.write(decrypted_data)
                print(f"{COLOR_GREEN}[CLIENT] File '{original_filename}' saved to '{save_path}'{COLOR_RESET}")
            else:
                print(f"{COLOR_RED}[CLIENT] INTEGRITY CHECK FAILED! Hashes: Expected {original_hash_hex_expected[:8]}..., Got {calc_hash[:8]}...{COLOR_RESET}")
        except Exception as e:
            print(f"{COLOR_RED}[CLIENT] Download failed for '{original_filename}' from {host_ip}:{host_port}: {e}{COLOR_RESET}")
        finally:
            if stream_sock: stream_sock.close()
            if temp_enc_file_path and os.path.exists(temp_enc_file_path):
                try: os.remove(temp_enc_file_path)
                except: pass # Ignore error deleting temp file

    def __del__(self): # Ensure P2P server is stopped when client object is deleted
        self.stop_p2p_server()


def run_client_interface(client):
    if not os.path.exists(DOWNLOAD_DIR):
        try: os.makedirs(DOWNLOAD_DIR); print(f"{COLOR_BLUE}[CLIENT_SETUP] Created download dir: {DOWNLOAD_DIR}{COLOR_RESET}")
        except Exception as e: print(f"{COLOR_RED}[CLIENT_SETUP] Failed to create {DOWNLOAD_DIR}: {e}{COLOR_RESET}")

    while True:
        print(f"\n{COLOR_BOLD}{COLOR_CYAN}--- CipherShare Client (Phase 4) ---{COLOR_RESET}")
        status = f"{COLOR_GREEN}Logged in as: {client.current_username} (P2P Port: {client.client_p2p_listen_port if client.p2p_server_thread and client.p2p_server_thread.is_alive() else 'N/A'}){COLOR_RESET}" \
            if client.current_username else f"{COLOR_YELLOW}Not logged in.{COLOR_RESET}"
        print(status)
        
        print(f"{COLOR_CYAN}1.{COLOR_RESET} Register  {COLOR_CYAN}2.{COLOR_RESET} Login   {COLOR_CYAN}3.{COLOR_RESET} Logout")
        print(f"{COLOR_CYAN}4.{COLOR_RESET} Announce File for P2P Sharing")
        print(f"{COLOR_CYAN}5.{COLOR_RESET} List All Shared Files (via Main Peer)")
        print(f"{COLOR_CYAN}6.{COLOR_RESET} Download File")
        print(f"{COLOR_CYAN}7.{COLOR_RESET} Exit")
        choice = input(f"{COLOR_YELLOW}Enter choice: {COLOR_RESET}")

        if choice == '1':
            u = input(f"{COLOR_YELLOW}Username for registration: {COLOR_RESET}")
            p = input(f"{COLOR_YELLOW}Password for registration: {COLOR_RESET}")
            if u and p: client.register(u, p)
        elif choice == '2':
            u = input(f"{COLOR_YELLOW}Username: {COLOR_RESET}")
            p = input(f"{COLOR_YELLOW}Password: {COLOR_RESET}")
            if u and p: client.login(u, p)
        elif choice == '3': client.logout()
        elif choice == '4': # Announce P2P share
            if not client.current_username: print(f"{COLOR_RED}Login first.{COLOR_RESET}"); continue
            fp = input(f"{COLOR_YELLOW}Full path to local file to announce for P2P sharing: {COLOR_RESET}")
            if fp: client.announce_file_for_p2p_sharing(fp)
        elif choice == '5': # List all files
            if not client.current_username: print(f"{COLOR_RED}Login first.{COLOR_RESET}"); continue
            client.list_all_shared_files()
        elif choice == '6': # Download file
            if not client.current_username: print(f"{COLOR_RED}Login first.{COLOR_RESET}"); continue
            fn = input(f"{COLOR_YELLOW}Filename to download: {COLOR_RESET}")
            if fn: client.request_and_download_file(fn)
        elif choice == '7':
            client.logout() # Attempt logout
            print(f"{COLOR_YELLOW}Exiting.{COLOR_RESET}"); break
        else: print(f"{COLOR_RED}Invalid choice.{COLOR_RESET}")

if __name__ == "__main__":
    # Determine client's P2P listening port (can be from args or config)
    p2p_port_arg = CLIENT_P2P_LISTEN_PORT
    if len(sys.argv) > 1:
        try: 
            p2p_port_arg = int(sys.argv[1])
            print(f"{COLOR_BLUE}[CLIENT_SETUP] P2P listening port set to {p2p_port_arg} from command line.{COLOR_RESET}")
        except ValueError:
            print(f"{COLOR_RED}[CLIENT_SETUP] Invalid P2P port from command line '{sys.argv[1]}'. Using default/OS-assigned.{COLOR_RESET}")

    client_app = FileShareClient()
    client_app.client_p2p_listen_port = p2p_port_arg # Set before login potentially starts server
    
    # Start the P2P server explicitly if not tied to login, or ensure login starts it.
    # For this design, login starts the P2P server.
    
    try:
        run_client_interface(client_app)
    except KeyboardInterrupt:
        print(f"\n{COLOR_YELLOW}Client interrupted. Exiting...{COLOR_RESET}")
        client_app.logout() # Attempt graceful logout
    finally:
        client_app.stop_p2p_server() # Ensure P2P server is stopped on exit

# client/fileshare_client.py
import socket
import json
import os
import time
import sys
import tempfile # For temporary storage of downloaded encrypted file

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
COLOR_BOLD = "\033[1m"

DEFAULT_PEER_HOST = 'localhost'
DEFAULT_PEER_PORT = 6000
BUFFER_SIZE = 4096 # For command recv and file streaming
DOWNLOAD_DIR = "client_downloads" # Directory to save successfully decrypted files

class FileShareClient:
    def __init__(self):
        self.session_token = None
        self.current_username = None

    def _send_command_to_peer(self, peer_host, peer_port, command_dict, expect_file_stream_after_json=False):
        sock = None
        peer_addr_colored = f"{COLOR_MAGENTA}{peer_host}:{peer_port}{COLOR_RESET}"
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(20) # General timeout for connection and JSON response
            print(f"{COLOR_BLUE}[CLIENT] Connecting to {peer_addr_colored}...{COLOR_RESET}")
            sock.connect((peer_host, peer_port))
            
            if self.session_token and command_dict.get("command") not in ["LOGIN", "REGISTER"]:
                command_dict["token"] = self.session_token

            print(f"{COLOR_BLUE}[CLIENT] Sending: {COLOR_CYAN}{command_dict.get('command')}{COLOR_BLUE} (Token: {self.session_token is not None}){COLOR_RESET}")
            sock.sendall(json.dumps(command_dict).encode('utf-8'))

            # For commands that expect a file stream AFTER an initial JSON response (like DOWNLOAD)
            # the socket is returned open. Otherwise, expect a single JSON response.
            if expect_file_stream_after_json:
                # This path is for DOWNLOAD, where peer sends JSON metadata first
                json_response_bytes = sock.recv(BUFFER_SIZE) 
                json_response = json.loads(json_response_bytes.decode('utf-8'))
                print(f"{COLOR_BLUE}[CLIENT] Received JSON meta: {json_response}{COLOR_RESET}")
                # The socket `sock` is returned open for subsequent file data streaming
                return sock, json_response 
            else:
                # For other commands, expect a single JSON response and then close
                response_bytes = sock.recv(BUFFER_SIZE)
                response = json.loads(response_bytes.decode('utf-8'))
                print(f"{COLOR_BLUE}[CLIENT] Received JSON: {response}{COLOR_RESET}")
                sock.close()
                return response

        except socket.timeout: print(f"{COLOR_RED}[CLIENT] Timeout with {peer_addr_colored}{COLOR_RESET}")
        except ConnectionRefusedError: print(f"{COLOR_RED}[CLIENT] Connection refused by {peer_addr_colored}.{COLOR_RESET}")
        except json.JSONDecodeError: print(f"{COLOR_RED}[CLIENT] Invalid JSON from peer.{COLOR_RESET}")
        except Exception as e: print(f"{COLOR_RED}[CLIENT] Error with {peer_addr_colored}: {e}{COLOR_RESET}")
        finally:
            if sock and not expect_file_stream_after_json: # Close if not returned for streaming
                try: sock.close()
                except: pass
            # If expect_file_stream_after_json, the caller is responsible for closing the returned socket.
            # However, if an error occurred before returning 'sock' in that path, close it.
            elif sock and expect_file_stream_after_json and 'json_response' not in locals():
                 try: sock.close()
                 except: pass


        if expect_file_stream_after_json: return None, {"status": "ERROR", "message": "Client-side error before file stream setup"}
        return {"status": "ERROR", "message": "Client-side communication error"}

    def register(self, peer_host, peer_port, username, password):
        # (Same as Phase 2)
        cmd = {"command": "REGISTER", "username": username, "password": password}
        resp = self._send_command_to_peer(peer_host, peer_port, cmd)
        if resp and resp.get("status") == "OK":
            print(f"{COLOR_GREEN}[CLIENT] Registration OK for '{username}'.{COLOR_RESET}")
            return True
        print(f"{COLOR_RED}[CLIENT] Registration failed: {resp.get('message', 'N/A')}{COLOR_RESET}")
        return False

    def login(self, peer_host, peer_port, username, password):
        # (Same as Phase 2)
        cmd = {"command": "LOGIN", "username": username, "password": password}
        resp = self._send_command_to_peer(peer_host, peer_port, cmd)
        if resp and resp.get("status") == "OK":
            self.session_token = resp.get("token")
            self.current_username = resp.get("username")
            print(f"{COLOR_GREEN}[CLIENT] Login OK. Welcome, {self.current_username}!{COLOR_RESET}")
            return True
        print(f"{COLOR_RED}[CLIENT] Login failed: {resp.get('message', 'N/A')}{COLOR_RESET}")
        self.session_token = None; self.current_username = None
        return False

    def logout(self, peer_host, peer_port):
        # (Same as Phase 2)
        if not self.session_token: print(f"{COLOR_YELLOW}[CLIENT] Not logged in.{COLOR_RESET}"); return False
        cmd = {"command": "LOGOUT"}
        resp = self._send_command_to_peer(peer_host, peer_port, cmd)
        success = resp and resp.get("status") == "OK"
        print(f"{COLOR_GREEN if success else COLOR_RED}[CLIENT] Logout {'OK' if success else 'failed'}: {resp.get('message', 'N/A')}{COLOR_RESET}")
        self.session_token = None; self.current_username = None
        return success

    def upload_file(self, peer_host, peer_port, local_filepath):
        if not self.session_token:
            print(f"{COLOR_RED}[CLIENT] Must be logged in to upload.{COLOR_RESET}"); return
        if not os.path.exists(local_filepath):
            print(f"{COLOR_RED}[CLIENT] Local file not found: {local_filepath}{COLOR_RESET}"); return

        original_filename = os.path.basename(local_filepath)
        print(f"{COLOR_BLUE}[CLIENT] Preparing to upload '{original_filename}'...{COLOR_RESET}")

        # 1. Calculate original file hash
        original_hash_hex = crypto_utils.hash_file_sha256(local_filepath)
        if not original_hash_hex:
            print(f"{COLOR_RED}[CLIENT] Failed to hash original file. Upload aborted.{COLOR_RESET}"); return
        print(f"{COLOR_BLUE}[CLIENT] Original file hash (SHA-256): {original_hash_hex[:16]}...{COLOR_RESET}")

        # 2. Generate AES key and IV
        file_key_hex, iv_hex = crypto_utils.generate_aes_key_and_iv()
        key_bytes = bytes.fromhex(file_key_hex)
        iv_bytes = bytes.fromhex(iv_hex)
        print(f"{COLOR_BLUE}[CLIENT] Generated AES key and IV for encryption.{COLOR_RESET}")

        # 3. Encrypt the file (in memory for this example, or stream for very large files)
        try:
            with open(local_filepath, 'rb') as f_orig:
                original_data = f_orig.read()
            
            encrypted_data_bytes = crypto_utils.encrypt_aes_cbc(original_data, key_bytes, iv_bytes)
            if not encrypted_data_bytes:
                print(f"{COLOR_RED}[CLIENT] File encryption failed. Upload aborted.{COLOR_RESET}"); return
            encrypted_size_bytes = len(encrypted_data_bytes)
            print(f"{COLOR_BLUE}[CLIENT] File encrypted successfully. Encrypted size: {encrypted_size_bytes} bytes.{COLOR_RESET}")
        except Exception as e:
            print(f"{COLOR_RED}[CLIENT] Error during file encryption: {e}. Upload aborted.{COLOR_RESET}"); return

        # 4. Send UPLOAD_FILE command with metadata
        upload_command = {
            "command": "UPLOAD_FILE",
            "original_filename": original_filename,
            "file_key_hex": file_key_hex,
            "iv_hex": iv_hex,
            "original_hash_hex": original_hash_hex,
            "encrypted_size_bytes": encrypted_size_bytes
        }
        # For UPLOAD_FILE, _send_command_to_peer will handle the initial JSON exchange.
        # We need the socket back if peer is READY_FOR_DATA.
        # Let's modify _send_command_to_peer or have a dedicated upload helper.
        # For now, let's assume _send_command_to_peer handles the initial JSON and we get a response.
        
        sock = None # Will be assigned by a modified _send_command or a new helper
        peer_addr_colored = f"{COLOR_MAGENTA}{peer_host}:{peer_port}{COLOR_RESET}"
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(20)
            print(f"{COLOR_BLUE}[CLIENT] Connecting to {peer_addr_colored} for upload metadata...{COLOR_RESET}")
            sock.connect((peer_host, peer_port))
            
            if self.session_token: upload_command["token"] = self.session_token
            print(f"{COLOR_BLUE}[CLIENT] Sending UPLOAD_FILE metadata...{COLOR_RESET}")
            sock.sendall(json.dumps(upload_command).encode('utf-8'))

            # Wait for peer's confirmation (e.g., READY_FOR_DATA)
            peer_response_bytes = sock.recv(BUFFER_SIZE)
            peer_response = json.loads(peer_response_bytes.decode('utf-8'))
            print(f"{COLOR_BLUE}[CLIENT] Peer response to metadata: {peer_response}{COLOR_RESET}")

            if peer_response.get("status") == "READY_FOR_DATA":
                print(f"{COLOR_BLUE}[CLIENT] Peer ready. Streaming encrypted file data ({encrypted_size_bytes} bytes)...{COLOR_RESET}")
                sock.sendall(encrypted_data_bytes) # Send all encrypted data
                # Wait for final confirmation from peer after data transfer
                final_ack_bytes = sock.recv(BUFFER_SIZE)
                final_ack = json.loads(final_ack_bytes.decode('utf-8'))
                if final_ack.get("status") == "OK":
                    print(f"{COLOR_GREEN}[CLIENT] File '{original_filename}' uploaded successfully to peer!{COLOR_RESET}")
                else:
                    print(f"{COLOR_RED}[CLIENT] Peer reported error after data upload: {final_ack.get('message')}{COLOR_RESET}")
            else:
                print(f"{COLOR_RED}[CLIENT] Peer not ready for data or error: {peer_response.get('message')}{COLOR_RESET}")

        except Exception as e:
            print(f"{COLOR_RED}[CLIENT] Error during file upload process: {e}{COLOR_RESET}")
        finally:
            if sock: sock.close()

    def list_shared_files(self, peer_host, peer_port):
        if not self.session_token: print(f"{COLOR_RED}[CLIENT] Must be logged in.{COLOR_RESET}"); return
        cmd = {"command": "LIST_SHARED"}
        resp = self._send_command_to_peer(peer_host, peer_port, cmd)
        if resp and resp.get("status") == "OK":
            files = resp.get("files", [])
            print(f"{COLOR_BOLD}{COLOR_YELLOW}[CLIENT] --- Files Hosted by Peer ---{COLOR_RESET}")
            if not files: print(f"  {COLOR_YELLOW}No files listed.{COLOR_RESET}")
            else:
                for f_info in files:
                    print(f"  - {COLOR_CYAN}{f_info['filename']}{COLOR_RESET} (Owner: {f_info['owner']}, Hash: {f_info['original_hash_hex'][:8]}..., Size: {f_info['encrypted_size_bytes']} B enc)")
            print(f"{COLOR_BOLD}{COLOR_YELLOW}-----------------------------{COLOR_RESET}")
        else: print(f"{COLOR_RED}[CLIENT] Failed to list files: {resp.get('message', 'N/A')}{COLOR_RESET}")

    def download_file(self, peer_host, peer_port, original_filename):
        if not self.session_token: print(f"{COLOR_RED}[CLIENT] Must be logged in.{COLOR_RESET}"); return

        cmd = {"command": "DOWNLOAD_FILE", "original_filename": original_filename}
        # This command expects JSON metadata first, then a file stream, so use expect_file_stream_after_json=True
        sock, meta_resp = self._send_command_to_peer(peer_host, peer_port, cmd, expect_file_stream_after_json=True)

        if not sock or not meta_resp or meta_resp.get("status") != "READY_FOR_DOWNLOAD":
            print(f"{COLOR_RED}[CLIENT] Failed to initiate download: {meta_resp.get('message', 'Communication error')}{COLOR_RESET}")
            if sock: sock.close()
            return

        file_key_hex = meta_resp.get("file_key_hex")
        iv_hex = meta_resp.get("iv_hex")
        original_hash_hex_from_peer = meta_resp.get("original_hash_hex")
        encrypted_size_bytes = meta_resp.get("encrypted_size_bytes")

        if not all([file_key_hex, iv_hex, original_hash_hex_from_peer, isinstance(encrypted_size_bytes, int)]):
            print(f"{COLOR_RED}[CLIENT] Incomplete metadata from peer for download. Aborting.{COLOR_RESET}")
            sock.close(); return
        
        print(f"{COLOR_BLUE}[CLIENT] Receiving '{original_filename}' (Encrypted Size: {encrypted_size_bytes} bytes). Key, IV, Hash received.{COLOR_RESET}")
        
        encrypted_data_accumulated = b''
        bytes_received = 0
        temp_file_path = None

        try:
            # Create a temporary file to store encrypted download
            with tempfile.NamedTemporaryFile(delete=False) as tmp_enc_file:
                temp_file_path = tmp_enc_file.name
                while bytes_received < encrypted_size_bytes:
                    chunk_size_to_receive = min(BUFFER_SIZE, encrypted_size_bytes - bytes_received)
                    chunk = sock.recv(chunk_size_to_receive)
                    if not chunk:
                        print(f"{COLOR_RED}[CLIENT] Peer disconnected during file download. Incomplete.{COLOR_RESET}")
                        raise ConnectionAbortedError("Peer disconnected")
                    tmp_enc_file.write(chunk)
                    bytes_received += len(chunk)
            
            if bytes_received != encrypted_size_bytes:
                print(f"{COLOR_RED}[CLIENT] Encrypted file download size mismatch. Expected {encrypted_size_bytes}, got {bytes_received}.{COLOR_RESET}")
                raise ValueError("Encrypted size mismatch")

            print(f"{COLOR_BLUE}[CLIENT] Encrypted file data received. Decrypting...{COLOR_RESET}")
            
            # Read encrypted data from temp file
            with open(temp_file_path, 'rb') as f_enc_read:
                encrypted_data_to_decrypt = f_enc_read.read()

            key_bytes = bytes.fromhex(file_key_hex)
            iv_bytes = bytes.fromhex(iv_hex)
            decrypted_data_bytes = crypto_utils.decrypt_aes_cbc(encrypted_data_to_decrypt, key_bytes, iv_bytes)

            if not decrypted_data_bytes:
                print(f"{COLOR_RED}[CLIENT] Decryption failed! File may be corrupt or key/IV incorrect.{COLOR_RESET}")
                raise ValueError("Decryption failed")

            print(f"{COLOR_BLUE}[CLIENT] Decryption successful. Verifying integrity...{COLOR_RESET}")
            calculated_hash_of_decrypted = crypto_utils.hash_data_sha256(decrypted_data_bytes)
            print(f"{COLOR_BLUE}[CLIENT]   Calculated Hash: {calculated_hash_of_decrypted}{COLOR_RESET}")
            print(f"{COLOR_BLUE}[CLIENT]   Expected Hash:   {original_hash_hex_from_peer}{COLOR_RESET}")

            if calculated_hash_of_decrypted == original_hash_hex_from_peer:
                print(f"{COLOR_GREEN}[CLIENT] File integrity VERIFIED! Hashes match.{COLOR_RESET}")
                if not os.path.exists(DOWNLOAD_DIR): os.makedirs(DOWNLOAD_DIR)
                final_save_path = os.path.join(DOWNLOAD_DIR, original_filename)
                with open(final_save_path, 'wb') as f_final:
                    f_final.write(decrypted_data_bytes)
                print(f"{COLOR_GREEN}[CLIENT] File '{original_filename}' saved to '{final_save_path}'{COLOR_RESET}")
            else:
                print(f"{COLOR_RED}[CLIENT] FILE INTEGRITY CHECK FAILED! Hashes do not match. File is corrupt or tampered.{COLOR_RESET}")
                print(f"{COLOR_YELLOW}[CLIENT] Decrypted data (potentially corrupt) NOT saved.{COLOR_RESET}")

        except Exception as e:
            print(f"{COLOR_RED}[CLIENT] Error during download/decryption/verification: {e}{COLOR_RESET}")
        finally:
            if sock: sock.close()
            if temp_file_path and os.path.exists(temp_file_path):
                try: os.remove(temp_file_path)
                except Exception as e_del: print(f"{COLOR_YELLOW}[CLIENT] Warning: Could not delete temp file {temp_file_path}: {e_del}{COLOR_RESET}")


def run_client_interface(client):
    # (Ensure DOWNLOAD_DIR exists)
    if not os.path.exists(DOWNLOAD_DIR):
        try: os.makedirs(DOWNLOAD_DIR); print(f"{COLOR_BLUE}[CLIENT_SETUP] Created download dir: {DOWNLOAD_DIR}{COLOR_RESET}")
        except Exception as e: print(f"{COLOR_RED}[CLIENT_SETUP] Failed to create {DOWNLOAD_DIR}: {e}{COLOR_RESET}")

    while True:
        print(f"\n{COLOR_BOLD}{COLOR_CYAN}--- CipherShare Client (Phase 3) ---{COLOR_RESET}")
        status = f"{COLOR_GREEN}Logged in as: {client.current_username}{COLOR_RESET}" if client.current_username else f"{COLOR_YELLOW}Not logged in.{COLOR_RESET}"
        print(status)
        
        print(f"{COLOR_CYAN}1.{COLOR_RESET} Register  {COLOR_CYAN}2.{COLOR_RESET} Login   {COLOR_CYAN}3.{COLOR_RESET} Logout")
        print(f"{COLOR_CYAN}4.{COLOR_RESET} Upload File for Sharing")
        print(f"{COLOR_CYAN}5.{COLOR_RESET} List Shared Files (from Peer)")
        print(f"{COLOR_CYAN}6.{COLOR_RESET} Download File (from Peer)")
        print(f"{COLOR_CYAN}7.{COLOR_RESET} Exit")
        choice = input(f"{COLOR_YELLOW}Enter choice: {COLOR_RESET}")

        peer_host, peer_port = None, None
        if choice in ['1', '2', '3', '4', '5', '6']:
            ph_input = input(f"{COLOR_YELLOW}Peer IP (def: {DEFAULT_PEER_HOST}): {COLOR_RESET}") or DEFAULT_PEER_HOST
            pp_str = input(f"{COLOR_YELLOW}Peer Port (def: {DEFAULT_PEER_PORT}): {COLOR_RESET}")
            try: peer_port = int(pp_str) if pp_str else DEFAULT_PEER_PORT
            except ValueError: print(f"{COLOR_RED}Invalid port. Using default.{COLOR_RESET}"); peer_port = DEFAULT_PEER_PORT
            peer_host = ph_input

        if choice == '1':
            u = input(f"{COLOR_YELLOW}Username for registration: {COLOR_RESET}")
            p = input(f"{COLOR_YELLOW}Password for registration: {COLOR_RESET}")
            if u and p and peer_host: client.register(peer_host, peer_port, u, p)
        elif choice == '2':
            u = input(f"{COLOR_YELLOW}Username: {COLOR_RESET}")
            p = input(f"{COLOR_YELLOW}Password: {COLOR_RESET}")
            if u and p and peer_host: client.login(peer_host, peer_port, u, p)
        elif choice == '3':
            if peer_host: client.logout(peer_host, peer_port)
        elif choice == '4': # Upload
            if not client.current_username: print(f"{COLOR_RED}Login first.{COLOR_RESET}"); continue
            fp = input(f"{COLOR_YELLOW}Full path to local file to upload: {COLOR_RESET}")
            if fp and peer_host: client.upload_file(peer_host, peer_port, fp)
        elif choice == '5': # List
            if not client.current_username: print(f"{COLOR_RED}Login first.{COLOR_RESET}"); continue
            if peer_host: client.list_shared_files(peer_host, peer_port)
        elif choice == '6': # Download
            if not client.current_username: print(f"{COLOR_RED}Login first.{COLOR_RESET}"); continue
            fn = input(f"{COLOR_YELLOW}Filename to download from peer: {COLOR_RESET}")
            if fn and peer_host: client.download_file(peer_host, peer_port, fn)
        elif choice == '7':
            if client.session_token and peer_host: client.logout(peer_host, peer_port)
            print(f"{COLOR_YELLOW}Exiting.{COLOR_RESET}"); break
        else: print(f"{COLOR_RED}Invalid choice.{COLOR_RESET}")

if __name__ == "__main__":
    client_app = FileShareClient()
    run_client_interface(client_app)

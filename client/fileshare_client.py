# client/fileshare_client.py
import socket
import json
import os
import time

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
BUFFER_SIZE = 4096
DOWNLOAD_DIR = "downloads"

class FileShareClient:
    def __init__(self):
        self.session_token = None
        self.current_username = None
        # self.my_shared_files = {} # filename: filepath - Files this client offers.
                                  # For Phase 2, SHARE command is just an announcement to peer.
                                  # Client doesn't need to track this as actively for peer-hosted downloads.

    def _send_command_to_peer(self, peer_host, peer_port, command_dict):
        """Helper to connect, send command, and get response. Manages socket."""
        sock = None
        peer_addr_colored = f"{COLOR_MAGENTA}{peer_host}:{peer_port}{COLOR_RESET}"
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15) # Increased timeout slightly
            print(f"{COLOR_BLUE}[CLIENT] Connecting to peer {peer_addr_colored}...{COLOR_RESET}")
            sock.connect((peer_host, peer_port))
            
            # Add session token to command if user is logged in and command is not login/register
            if self.session_token and command_dict.get("command") not in ["LOGIN", "REGISTER"]:
                command_dict["token"] = self.session_token

            print(f"{COLOR_BLUE}[CLIENT] Sending command: {COLOR_CYAN}{command_dict.get('command')}{COLOR_BLUE} (Token: {self.session_token is not None}){COLOR_RESET}")
            sock.sendall(json.dumps(command_dict).encode('utf-8'))

            command_type = command_dict.get("command")

            if command_type == "DOWNLOAD": # Special handling for download
                initial_response_bytes = sock.recv(BUFFER_SIZE)
                initial_response = json.loads(initial_response_bytes.decode('utf-8'))
                print(f"{COLOR_BLUE}[CLIENT] Received initial download response: {initial_response}{COLOR_RESET}")
                if initial_response.get("status") == "READY_TO_SEND":
                    filesize_header = sock.recv(16)
                    filesize = int(filesize_header.decode('utf-8').strip())
                    print(f"{COLOR_BLUE}[CLIENT] Expecting file size: {filesize} bytes{COLOR_RESET}")
                    return sock, initial_response, filesize # Return OPEN socket
                else:
                    sock.close() # Close socket on error
                    return None, initial_response, 0
            else: # For other commands
                response_bytes = sock.recv(BUFFER_SIZE)
                response = json.loads(response_bytes.decode('utf-8'))
                print(f"{COLOR_BLUE}[CLIENT] Received response: {response}{COLOR_RESET}")
                sock.close() # Close socket
                return response

        except socket.timeout:
            print(f"{COLOR_RED}[CLIENT] Timeout communicating with {peer_addr_colored}{COLOR_RESET}")
        except ConnectionRefusedError:
            print(f"{COLOR_RED}[CLIENT] Connection refused by peer {peer_addr_colored}. Is peer running?{COLOR_RESET}")
        except json.JSONDecodeError:
            print(f"{COLOR_RED}[CLIENT] Invalid JSON response from peer.{COLOR_RESET}")
        except Exception as e:
            print(f"{COLOR_RED}[CLIENT] Error communicating with {peer_addr_colored}: {e}{COLOR_RESET}")
        finally:
            if sock and command_type != "DOWNLOAD": # Ensure socket is closed if not returned for download
                 try: sock.close()
                 except Exception: pass
            elif sock and command_type == "DOWNLOAD" and ( ( 'initial_response' in locals() and initial_response.get("status") != "READY_TO_SEND") ):
                try: sock.close() # Close if download setup failed
                except Exception: pass


        if command_dict.get("command") == "DOWNLOAD":
            return None, {"status": "ERROR", "message": "Failed to initiate download (client-side error)"}, 0
        else:
            return {"status": "ERROR", "message": "Communication failed (client-side error)"}

    def register(self, peer_host, peer_port, username, password):
        command = {"command": "REGISTER", "username": username, "password": password}
        response = self._send_command_to_peer(peer_host, peer_port, command)
        if response and response.get("status") == "OK":
            print(f"{COLOR_GREEN}[CLIENT] Registration successful for '{username}'. You can now login.{COLOR_RESET}")
            return True
        else:
            print(f"{COLOR_RED}[CLIENT] Registration failed: {response.get('message', 'No response')}{COLOR_RESET}")
            return False

    def login(self, peer_host, peer_port, username, password):
        command = {"command": "LOGIN", "username": username, "password": password}
        response = self._send_command_to_peer(peer_host, peer_port, command)
        if response and response.get("status") == "OK":
            self.session_token = response.get("token")
            self.current_username = response.get("username")
            print(f"{COLOR_GREEN}[CLIENT] Login successful. Welcome, {self.current_username}! Session token acquired.{COLOR_RESET}")
            return True
        else:
            print(f"{COLOR_RED}[CLIENT] Login failed: {response.get('message', 'No response')}{COLOR_RESET}")
            self.session_token = None
            self.current_username = None
            return False

    def logout(self, peer_host, peer_port):
        if not self.session_token:
            print(f"{COLOR_YELLOW}[CLIENT] You are not logged in.{COLOR_RESET}")
            return False
        command = {"command": "LOGOUT"} # Token added by _send_command_to_peer
        response = self._send_command_to_peer(peer_host, peer_port, command)
        if response and response.get("status") == "OK":
            print(f"{COLOR_GREEN}[CLIENT] Logout successful for '{self.current_username}'.{COLOR_RESET}")
        else:
            print(f"{COLOR_RED}[CLIENT] Logout failed or error: {response.get('message', 'No response')}{COLOR_RESET}")
        # Always clear local session info on logout attempt
        self.session_token = None
        self.current_username = None
        return response.get("status") == "OK" if response else False

    def announce_file_sharing(self, peer_host, peer_port, filename_on_client, filepath_on_client):
        if not self.session_token:
            print(f"{COLOR_RED}[CLIENT] You must be logged in to share a file.{COLOR_RESET}")
            return
        
        # In Phase 2, client just announces. Peer doesn't pull the file.
        # Client needs to tell the peer the filename and (optionally) its own path for its own reference,
        # but the peer mainly cares about filename and who (which user/client address) is sharing it.
        command = {
            "command": "SHARE",
            "filename": filename_on_client,
            "filepath_on_client": filepath_on_client # For peer's metadata if it needs to tell others where the client has it
        }
        response = self._send_command_to_peer(peer_host, peer_port, command)
        if response and response.get("status") == "OK":
            print(f"{COLOR_GREEN}[CLIENT] Successfully announced sharing of '{filename_on_client}' to peer.{COLOR_RESET}")
        else:
            print(f"{COLOR_RED}[CLIENT] Failed to announce file sharing: {response.get('message', 'No response')}{COLOR_RESET}")


    def list_shared_files(self, peer_host, peer_port):
        if not self.session_token:
            print(f"{COLOR_RED}[CLIENT] You must be logged in to list files.{COLOR_RESET}")
            return
        command = {"command": "LIST_SHARED"}
        response = self._send_command_to_peer(peer_host, peer_port, command)
        if response and response.get("status") == "OK":
            files_data = response.get("files", [])
            peer_addr_colored = f"{COLOR_MAGENTA}{peer_host}:{peer_port}{COLOR_RESET}"
            print(f"{COLOR_BOLD}{COLOR_YELLOW}[CLIENT] --- Files Available via Peer {peer_addr_colored} ---{COLOR_RESET}")
            if not files_data:
                print(f"  {COLOR_YELLOW}No files currently listed by this peer.{COLOR_RESET}")
            else:
                for file_info in files_data:
                    print(f"  - {COLOR_CYAN}{file_info.get('filename')}{COLOR_RESET} (Owner: {COLOR_MAGENTA}{file_info.get('owner', 'N/A')}{COLOR_RESET}, Sharer: {COLOR_MAGENTA}{file_info.get('sharer_address', 'N/A')}{COLOR_RESET})")
            print(f"{COLOR_BOLD}{COLOR_YELLOW}--------------------------------------------------{COLOR_RESET}")
        else:
            print(f"{COLOR_RED}[CLIENT] Failed to list files: {response.get('message', 'No response')}{COLOR_RESET}")

    def download_file_from_peer(self, peer_host, peer_port, filename):
        if not self.session_token:
            print(f"{COLOR_RED}[CLIENT] You must be logged in to download files.{COLOR_RESET}")
            return

        command = {"command": "DOWNLOAD", "filename": filename}
        sock, initial_response, filesize = self._send_command_to_peer(peer_host, peer_port, command)
        peer_addr_colored = f"{COLOR_MAGENTA}{peer_host}:{peer_port}{COLOR_RESET}"

        if not sock: # Error occurred in _send_command_to_peer or download not ready
            print(f"{COLOR_RED}[CLIENT] Peer {peer_addr_colored} denied download or failed to initiate: {initial_response.get('message')}{COLOR_RESET}")
            return

        print(f"{COLOR_BLUE}[CLIENT] Peer {peer_addr_colored} is ready to send '{COLOR_CYAN}{filename}{COLOR_BLUE}'. Starting download...{COLOR_RESET}")
        if not os.path.exists(DOWNLOAD_DIR):
            try: os.makedirs(DOWNLOAD_DIR); print(f"{COLOR_BLUE}[CLIENT] Created download directory: {DOWNLOAD_DIR}{COLOR_RESET}")
            except OSError as e:
                print(f"{COLOR_RED}[CLIENT] Failed to create download directory '{DOWNLOAD_DIR}': {e}{COLOR_RESET}")
                sock.close(); return

        destination_path = os.path.join(DOWNLOAD_DIR, filename)
        bytes_received = 0
        start_time = time.time()
        try:
            with open(destination_path, 'wb') as f:
                while bytes_received < filesize:
                    chunk = sock.recv(BUFFER_SIZE)
                    if not chunk:
                        print(f"\n{COLOR_YELLOW}[CLIENT] Warning: Connection closed prematurely by peer {peer_addr_colored}.{COLOR_RESET}")
                        break
                    f.write(chunk)
                    bytes_received += len(chunk)
            end_time = time.time()
            if bytes_received == filesize:
                print(f"\n{COLOR_GREEN}[CLIENT] Successfully downloaded '{COLOR_CYAN}{filename}{COLOR_GREEN}' to '{destination_path}' ({bytes_received} bytes in {end_time - start_time:.2f}s){COLOR_RESET}")
            else:
                print(f"\n{COLOR_YELLOW}[CLIENT] Download incomplete. Expected {filesize}, got {bytes_received} bytes.{COLOR_RESET}")
                if os.path.exists(destination_path): os.remove(destination_path)
        except socket.timeout:
            print(f"\n{COLOR_RED}[CLIENT] Timeout during file download from {peer_addr_colored}.{COLOR_RESET}")
            if os.path.exists(destination_path): os.remove(destination_path)
        except Exception as e:
            print(f"\n{COLOR_RED}[CLIENT] Error during file download: {e}{COLOR_RESET}")
            if os.path.exists(destination_path): os.remove(destination_path)
        finally:
            print(f"{COLOR_BLUE}[CLIENT] Closing download socket to {peer_addr_colored}.{COLOR_RESET}")
            sock.close()

def run_client_interface(client):
    while True:
        print(f"\n{COLOR_BOLD}{COLOR_CYAN}--- CipherShare Client ---{COLOR_RESET}")
        if client.current_username:
            print(f"{COLOR_GREEN}Logged in as: {client.current_username}{COLOR_RESET}")
        else:
            print(f"{COLOR_YELLOW}Not logged in.{COLOR_RESET}")
        
        print(f"{COLOR_CYAN}1.{COLOR_RESET} Register")
        print(f"{COLOR_CYAN}2.{COLOR_RESET} Login")
        print(f"{COLOR_CYAN}3.{COLOR_RESET} Logout")
        print(f"{COLOR_CYAN}4.{COLOR_RESET} Announce a file for sharing")
        print(f"{COLOR_CYAN}5.{COLOR_RESET} List shared files from peer")
        print(f"{COLOR_CYAN}6.{COLOR_RESET} Download a file from peer")
        print(f"{COLOR_CYAN}7.{COLOR_RESET} Exit")
        choice = input(f"{COLOR_YELLOW}Enter choice: {COLOR_RESET}")

        peer_host, peer_port = None, None
        if choice in ['1', '2', '3', '4', '5', '6']: # Operations requiring peer interaction
            peer_host_input = input(f"{COLOR_YELLOW}Enter Peer IP (default: {DEFAULT_PEER_HOST}): {COLOR_RESET}")
            peer_host = peer_host_input or DEFAULT_PEER_HOST
            peer_port_str = input(f"{COLOR_YELLOW}Enter Peer Port (default: {DEFAULT_PEER_PORT}): {COLOR_RESET}")
            try:
                peer_port = int(peer_port_str) if peer_port_str else DEFAULT_PEER_PORT
            except ValueError:
                print(f"{COLOR_RED}Invalid port number. Using default.{COLOR_RESET}")
                peer_port = DEFAULT_PEER_PORT
        
        if choice == '1': # Register
            username = input(f"{COLOR_YELLOW}Enter username for registration: {COLOR_RESET}")
            password = input(f"{COLOR_YELLOW}Enter password for registration: {COLOR_RESET}")
            if username and password and peer_host and peer_port:
                client.register(peer_host, peer_port, username, password)
            else: print(f"{COLOR_RED}Username, password, and peer details required.{COLOR_RESET}")
        
        elif choice == '2': # Login
            username = input(f"{COLOR_YELLOW}Enter username: {COLOR_RESET}")
            password = input(f"{COLOR_YELLOW}Enter password: {COLOR_RESET}")
            if username and password and peer_host and peer_port:
                client.login(peer_host, peer_port, username, password)
            else: print(f"{COLOR_RED}Username, password, and peer details required.{COLOR_RESET}")

        elif choice == '3': # Logout
            if peer_host and peer_port:
                client.logout(peer_host, peer_port)
            else: print(f"{COLOR_RED}Peer details required for logout.{COLOR_RESET}")
        
        elif choice == '4': # Announce file
            if not client.current_username: print(f"{COLOR_RED}Please login first.{COLOR_RESET}"); continue
            filepath_on_client = input(f"{COLOR_YELLOW}Enter full path to the file you want to share: {COLOR_RESET}")
            filename_on_client = os.path.basename(filepath_on_client)
            if filename_on_client and filepath_on_client and peer_host and peer_port:
                client.announce_file_sharing(peer_host, peer_port, filename_on_client, filepath_on_client)
            else: print(f"{COLOR_RED}File path and peer details required.{COLOR_RESET}")

        elif choice == '5': # List files
            if not client.current_username: print(f"{COLOR_RED}Please login first.{COLOR_RESET}"); continue
            if peer_host and peer_port:
                client.list_shared_files(peer_host, peer_port)
            else: print(f"{COLOR_RED}Peer details required.{COLOR_RESET}")

        elif choice == '6': # Download file
            if not client.current_username: print(f"{COLOR_RED}Please login first.{COLOR_RESET}"); continue
            filename_to_download = input(f"{COLOR_YELLOW}Enter the filename to download: {COLOR_RESET}")
            if filename_to_download and peer_host and peer_port:
                client.download_file_from_peer(peer_host, peer_port, filename_to_download)
            else: print(f"{COLOR_RED}Filename and peer details required.{COLOR_RESET}")
        
        elif choice == '7': # Exit
            if client.session_token and peer_host and peer_port: # Attempt logout if connected and logged in
                print(f"{COLOR_YELLOW}Attempting logout before exiting...{COLOR_RESET}")
                client.logout(peer_host, peer_port) # Use last known peer if available
            elif client.session_token:
                 print(f"{COLOR_YELLOW}You are logged in but no peer specified for final logout. Exiting.{COLOR_RESET}")


            print(f"{COLOR_YELLOW}Exiting client.{COLOR_RESET}")
            break
        else:
            print(f"{COLOR_RED}Invalid choice. Please try again.{COLOR_RESET}")

if __name__ == "__main__":
    if not os.path.exists(DOWNLOAD_DIR):
        try: os.makedirs(DOWNLOAD_DIR); print(f"{COLOR_BLUE}[CLIENT] Created download directory: {DOWNLOAD_DIR}{COLOR_RESET}")
        except OSError as e: print(f"{COLOR_RED}[CLIENT] Could not create download directory '{DOWNLOAD_DIR}': {e}. Downloads may fail.{COLOR_RESET}")
    
    client_app = FileShareClient()
    run_client_interface(client_app)

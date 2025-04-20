# client/fileshare_client.py
import socket
import json
import os
import time # For potential timeouts/retries

# ANSI Color Codes
COLOR_RESET = "\033[0m"
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_MAGENTA = "\033[95m"
COLOR_CYAN = "\033[96m"
COLOR_BOLD = "\033[1m"

# Assume peers run on the same machine for simplicity, or use known IPs
DEFAULT_PEER_HOST = 'localhost'
DEFAULT_PEER_PORT = 6000 # Port the peer server listens on
BUFFER_SIZE = 4096
DOWNLOAD_DIR = "downloads" # Directory to save downloaded files

class FileShareClient:
  def __init__(self):
    self.my_shared_files = {} # filename: filepath - Files this client offers

  def _send_command(self, peer_host, peer_port, command_dict):
    """
    Helper function to connect, send a command, and handle responses.
    For DOWNLOAD, it returns the open socket for data transfer.
    For other commands, it closes the socket and returns the response data.
    """
    sock = None # Initialize socket variable outside try block
    peer_addr_colored = f"{COLOR_MAGENTA}{peer_host}:{peer_port}{COLOR_RESET}"
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(10) # Add a timeout
      print(f"{COLOR_BLUE}[CLIENT] Connecting to peer {peer_addr_colored}...{COLOR_RESET}")
      sock.connect((peer_host, peer_port))
      print(f"{COLOR_GREEN}[CLIENT] Connected. Sending command: {COLOR_CYAN}{command_dict.get('command')}{COLOR_RESET}")
      sock.sendall(json.dumps(command_dict).encode('utf-8'))

      command_type = command_dict.get("command")

      # Special handling for download initiation
      if command_type == "DOWNLOAD":
        initial_response_bytes = sock.recv(BUFFER_SIZE)
        initial_response = json.loads(initial_response_bytes.decode('utf-8'))
        print(f"{COLOR_BLUE}[CLIENT] Received initial download response: {initial_response}{COLOR_RESET}")
        if initial_response.get("status") == "READY_TO_SEND":
          # Get file size (sent right after 'READY_TO_SEND')
          filesize_header = sock.recv(16) # Match the peer's sending logic
          filesize = int(filesize_header.decode('utf-8').strip())
          print(f"{COLOR_BLUE}[CLIENT] Expecting file size: {filesize} bytes{COLOR_RESET}")
          # IMPORTANT: Return the OPEN socket for download_file to use
          return sock, initial_response, filesize
        else:
          # Download request failed on peer side, close socket
          sock.close()
          return None, initial_response, 0 # Indicate error
      else:
        # For non-download commands, get response and close socket here
        response_bytes = sock.recv(BUFFER_SIZE)
        response = json.loads(response_bytes.decode('utf-8'))
        print(f"{COLOR_BLUE}[CLIENT] Received response: {response}{COLOR_RESET}")
        sock.close() # Close socket as it's no longer needed
        return response

    except socket.timeout:
      print(f"{COLOR_RED}[CLIENT] Timeout connecting or communicating with {peer_addr_colored}{COLOR_RESET}")
      if sock: sock.close() # Ensure socket is closed on timeout
    except ConnectionRefusedError:
      print(f"{COLOR_RED}[CLIENT] Connection refused by peer {peer_addr_colored}. Is the peer running?{COLOR_RESET}")
      if sock: sock.close()
    except json.JSONDecodeError:
      print(f"{COLOR_RED}[CLIENT] Received invalid response format from peer.{COLOR_RESET}")
      if sock: sock.close()
    except Exception as e:
      print(f"{COLOR_RED}[CLIENT] Error communicating with peer {peer_addr_colored}: {e}{COLOR_RESET}")
      if sock: sock.close() # Ensure socket is closed on other errors

    # Return error indication based on command type
    if command_dict.get("command") == "DOWNLOAD":
      return None, {"status": "ERROR", "message": "Failed to initiate download"}, 0
    else:
      return {"status": "ERROR", "message": "Communication failed"}


  def announce_file(self, peer_host, peer_port, filename, filepath):
      """Announce to a specific peer that this client is sharing a file."""
      peer_addr_colored = f"{COLOR_MAGENTA}{peer_host}:{peer_port}{COLOR_RESET}"
      if os.path.exists(filepath):
          self.my_shared_files[filename] = filepath
          command = {"command": "SHARE", "filename": filename}
          # _send_command handles closing the socket for SHARE command
          response = self._send_command(peer_host, peer_port, command)
          if response and response.get("status") == "OK":
              print(f"{COLOR_GREEN}[CLIENT] Announced sharing of '{COLOR_CYAN}{filename}{COLOR_GREEN}' to {peer_addr_colored}{COLOR_RESET}")
          else:
               print(f"{COLOR_RED}[CLIENT] Failed to announce sharing of '{COLOR_CYAN}{filename}{COLOR_RED}'. Response: {response}{COLOR_RESET}")
      else:
          print(f"{COLOR_RED}[CLIENT] Error: File '{filepath}' not found. Cannot announce.{COLOR_RESET}")

  def list_files(self, peer_host, peer_port):
    """Request the list of shared files from a specific peer."""
    peer_addr_colored = f"{COLOR_MAGENTA}{peer_host}:{peer_port}{COLOR_RESET}"
    command = {"command": "LIST_SHARED"}
    # _send_command handles closing the socket for LIST_SHARED command
    response = self._send_command(peer_host, peer_port, command)
    if response and response.get("status") == "OK":
      print(f"{COLOR_BOLD}{COLOR_YELLOW}[CLIENT] --- Shared Files Known by {peer_addr_colored} ---{COLOR_RESET}")
      files_map = response.get("files", {})
      if not files_map:
          print(f"  {COLOR_YELLOW}No files reported by peer.{COLOR_RESET}")
      for source, file_list in files_map.items():
          source_colored = f"{COLOR_MAGENTA}{source}{COLOR_RESET}"
          print(f"  From {source_colored}:")
          if file_list:
              for f in file_list:
                  print(f"    - {COLOR_CYAN}{f}{COLOR_RESET}")
          else:
              print(f"    {COLOR_YELLOW}(No files listed for this source){COLOR_RESET}")
      print(f"{COLOR_BOLD}{COLOR_YELLOW}-----------------------------------------{COLOR_RESET}")
      return files_map
    else:
      print(f"{COLOR_RED}[CLIENT] Failed to list files from {peer_addr_colored}. Response: {response}{COLOR_RESET}")
      return None

  def download_file(self, peer_host, peer_port, filename):
    """Request to download a file from a specific peer."""
    peer_addr_colored = f"{COLOR_MAGENTA}{peer_host}:{peer_port}{COLOR_RESET}"
    command = {"command": "DOWNLOAD", "filename": filename}
    # Send command and get ready for data transfer
    # _send_command now returns the OPEN socket if successful
    sock, initial_response, filesize = self._send_command(peer_host, peer_port, command)

    # Check if we received a valid, open socket
    if not sock:
        print(f"{COLOR_RED}[CLIENT] Peer {peer_addr_colored} denied download request or failed to initiate: {initial_response.get('message')}{COLOR_RESET}")
        return # Exit download function

    # If we got here, sock is an open socket ready for download
    print(f"{COLOR_BLUE}[CLIENT] Peer {peer_addr_colored} is ready to send '{COLOR_CYAN}{filename}{COLOR_BLUE}'. Starting download...{COLOR_RESET}")
    if not os.path.exists(DOWNLOAD_DIR):
        try:
            os.makedirs(DOWNLOAD_DIR)
            print(f"{COLOR_BLUE}[CLIENT] Created download directory: {DOWNLOAD_DIR}{COLOR_RESET}")
        except OSError as e:
            print(f"{COLOR_RED}[CLIENT] Failed to create download directory '{DOWNLOAD_DIR}': {e}{COLOR_RESET}")
            sock.close() # Close the socket as we can't save the file
            return

    destination_path = os.path.join(DOWNLOAD_DIR, filename)
    bytes_received = 0
    start_time = time.time()

    try:
      with open(destination_path, 'wb') as f:
        while bytes_received < filesize:
            # Read from the socket returned by _send_command
            chunk = sock.recv(BUFFER_SIZE)
            if not chunk:
                print(f"\n{COLOR_YELLOW}[CLIENT] Warning: Connection closed prematurely by peer {peer_addr_colored}.{COLOR_RESET}")
                break
            f.write(chunk)
            bytes_received += len(chunk)
            # Optional: Print progress
            # progress = (bytes_received / filesize) * 100
            # print(f"\r{COLOR_BLUE}[CLIENT] Downloading {filename}: {bytes_received}/{filesize} bytes ({progress:.2f}%){COLOR_RESET}", end="")

      end_time = time.time()
      elapsed_time = end_time - start_time

      if bytes_received == filesize:
          print(f"\n{COLOR_GREEN}[CLIENT] Successfully downloaded '{COLOR_CYAN}{filename}{COLOR_GREEN}' to '{destination_path}' ({bytes_received} bytes in {elapsed_time:.2f}s){COLOR_RESET}")
      else:
          print(f"\n{COLOR_YELLOW}[CLIENT] Download incomplete. Expected {filesize}, got {bytes_received} bytes.{COLOR_RESET}")
          # Clean up incomplete file
          if os.path.exists(destination_path):
              try:
                  os.remove(destination_path)
                  print(f"{COLOR_YELLOW}[CLIENT] Removed incomplete file: {destination_path}{COLOR_RESET}")
              except OSError as e:
                   print(f"{COLOR_RED}[CLIENT] Error removing incomplete file '{destination_path}': {e}{COLOR_RESET}")


      # Phase 1: No integrity check needed yet
      # Phase 3 will add hash verification

    except socket.timeout:
        print(f"\n{COLOR_RED}[CLIENT] Timeout during file download from {peer_addr_colored}.{COLOR_RESET}")
        if os.path.exists(destination_path):
             try: os.remove(destination_path)
             except OSError as e: print(f"{COLOR_RED}[CLIENT] Error removing incomplete file '{destination_path}': {e}{COLOR_RESET}")
    except Exception as e:
       print(f"\n{COLOR_RED}[CLIENT] Error during file download: {e}{COLOR_RESET}")
       # Clean up potentially incomplete file
       if os.path.exists(destination_path):
           try: os.remove(destination_path)
           except OSError as e: print(f"{COLOR_RED}[CLIENT] Error removing incomplete file '{destination_path}': {e}{COLOR_RESET}")
    finally:
         print(f"{COLOR_BLUE}[CLIENT] Closing download socket to {peer_addr_colored}.{COLOR_RESET}")
         sock.close() # Ensure socket is closed here, after download attempt

# --- Rudimentary Client UI (With Colors) ---
def run_client_interface(client):
    while True:
        print(f"\n{COLOR_BOLD}{COLOR_CYAN}--- Client Menu ---{COLOR_RESET}")
        print(f"{COLOR_CYAN}1.{COLOR_RESET} Announce a file to share")
        print(f"{COLOR_CYAN}2.{COLOR_RESET} List files from peer")
        print(f"{COLOR_CYAN}3.{COLOR_RESET} Download a file from peer")
        print(f"{COLOR_CYAN}4.{COLOR_RESET} Exit")
        choice = input(f"{COLOR_YELLOW}Enter choice: {COLOR_RESET}")

        # Only ask for peer details if needed
        if choice in ['1', '2', '3']:
            peer_host_input = input(f"{COLOR_YELLOW}Enter Peer IP (default: {DEFAULT_PEER_HOST}): {COLOR_RESET}")
            peer_host = peer_host_input or DEFAULT_PEER_HOST
            peer_port_str = input(f"{COLOR_YELLOW}Enter Peer Port (default: {DEFAULT_PEER_PORT}): {COLOR_RESET}")
            try:
                peer_port = int(peer_port_str) if peer_port_str else DEFAULT_PEER_PORT
            except ValueError:
                print(f"{COLOR_RED}Invalid port number. Using default.{COLOR_RESET}")
                peer_port = DEFAULT_PEER_PORT
        else:
            peer_host, peer_port = None, None # Not needed for exit or invalid choice

        if choice == '1':
            filepath = input(f"{COLOR_YELLOW}Enter full path to the file you want to share: {COLOR_RESET}")
            filename = os.path.basename(filepath)
            if filename and filepath:
                 client.announce_file(peer_host, peer_port, filename, filepath)
            else:
                 print(f"{COLOR_RED}Invalid file path.{COLOR_RESET}")
        elif choice == '2':
            client.list_files(peer_host, peer_port)
        elif choice == '3':
            filename = input(f"{COLOR_YELLOW}Enter the filename to download: {COLOR_RESET}")
            if filename:
                client.download_file(peer_host, peer_port, filename)
            else:
                 print(f"{COLOR_RED}Invalid filename.{COLOR_RESET}")
        elif choice == '4':
            print(f"{COLOR_YELLOW}Exiting client.{COLOR_RESET}")
            break
        else:
            print(f"{COLOR_RED}Invalid choice.{COLOR_RESET}")

if __name__ == "__main__":
  # Check if download directory exists, create if not
  if not os.path.exists(DOWNLOAD_DIR):
      try:
          os.makedirs(DOWNLOAD_DIR)
          print(f"{COLOR_BLUE}[CLIENT] Created download directory: {DOWNLOAD_DIR}{COLOR_RESET}")
      except OSError as e:
           print(f"{COLOR_RED}[CLIENT] Could not create download directory '{DOWNLOAD_DIR}': {e}. Downloads may fail.{COLOR_RESET}")

  client = FileShareClient()
  run_client_interface(client)


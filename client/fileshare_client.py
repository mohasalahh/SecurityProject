# client/fileshare_client.py
import socket
import json
import os
import time # For potential timeouts/retries

# Assume peers run on the same machine for simplicity, or use known IPs
# Phase 1 might use broadcasting or a rendezvous server for discovery
# Hardcoding for now for basic P2P connection test
DEFAULT_PEER_HOST = 'localhost'
DEFAULT_PEER_PORT = 6000 # Port the peer server listens on
BUFFER_SIZE = 4096
DOWNLOAD_DIR = "downloads" # Directory to save downloaded files

class FileShareClient:
  def __init__(self):
    # Client doesn't need a persistent server socket itself for phase 1's core task
    # It initiates connections to peers.
    self.my_shared_files = {} # filename: filepath - Files this client offers

  def _send_command(self, peer_host, peer_port, command_dict):
    """
    Helper function to connect, send a command, and handle responses.
    For DOWNLOAD, it returns the open socket for data transfer.
    For other commands, it closes the socket and returns the response data.
    """
    sock = None # Initialize socket variable outside try block
    try:
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(10) # Add a timeout
      print(f"[CLIENT] Connecting to peer {peer_host}:{peer_port}...")
      sock.connect((peer_host, peer_port))
      print(f"[CLIENT] Connected. Sending command: {command_dict.get('command')}")
      sock.sendall(json.dumps(command_dict).encode('utf-8'))

      command_type = command_dict.get("command")

      # Special handling for download initiation
      if command_type == "DOWNLOAD":
        initial_response_bytes = sock.recv(BUFFER_SIZE)
        initial_response = json.loads(initial_response_bytes.decode('utf-8'))
        print(f"[CLIENT] Received initial download response: {initial_response}")
        if initial_response.get("status") == "READY_TO_SEND":
          # Get file size (sent right after 'READY_TO_SEND')
          filesize_header = sock.recv(16) # Match the peer's sending logic
          filesize = int(filesize_header.decode('utf-8').strip())
          print(f"[CLIENT] Expecting file size: {filesize} bytes")
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
        print(f"[CLIENT] Received response: {response}")
        sock.close() # Close socket as it's no longer needed
        return response

    except socket.timeout:
      print(f"[CLIENT] Timeout connecting or communicating with {peer_host}:{peer_port}")
      if sock: sock.close() # Ensure socket is closed on timeout
    except ConnectionRefusedError:
      print(f"[CLIENT] Connection refused by peer {peer_host}:{peer_port}. Is the peer running?")
      # Socket likely wasn't successfully created/connected, but check just in case
      if sock: sock.close()
    except json.JSONDecodeError:
      print(f"[CLIENT] Received invalid response format from peer.")
      if sock: sock.close()
    except Exception as e:
      print(f"[CLIENT] Error communicating with peer {peer_host}:{peer_port}: {e}")
      if sock: sock.close() # Ensure socket is closed on other errors

    # Return error indication based on command type
    if command_dict.get("command") == "DOWNLOAD":
      return None, {"status": "ERROR", "message": "Failed to initiate download"}, 0
    else:
      return {"status": "ERROR", "message": "Communication failed"}


  def announce_file(self, peer_host, peer_port, filename, filepath):
      """Announce to a specific peer that this client is sharing a file."""
      if os.path.exists(filepath):
          self.my_shared_files[filename] = filepath
          command = {"command": "SHARE", "filename": filename}
          # _send_command handles closing the socket for SHARE command
          response = self._send_command(peer_host, peer_port, command)
          if response and response.get("status") == "OK":
              print(f"[CLIENT] Announced sharing of '{filename}' to {peer_host}:{peer_port}")
          else:
               print(f"[CLIENT] Failed to announce sharing of '{filename}'. Response: {response}")
      else:
          print(f"[CLIENT] Error: File '{filepath}' not found. Cannot announce.")

  def list_files(self, peer_host, peer_port):
    """Request the list of shared files from a specific peer."""
    command = {"command": "LIST_SHARED"}
    # _send_command handles closing the socket for LIST_SHARED command
    response = self._send_command(peer_host, peer_port, command)
    if response and response.get("status") == "OK":
      print("[CLIENT] --- Shared Files ---")
      files_map = response.get("files", {})
      if not files_map:
          print("  No files reported by peer.")
      for source, file_list in files_map.items():
          print(f"  From {source}:")
          if file_list:
              for f in file_list:
                  print(f"    - {f}")
          else:
              print("    (No files)")
      print("----------------------")
      return files_map
    else:
      print(f"[CLIENT] Failed to list files. Response: {response}")
      return None

  def download_file(self, peer_host, peer_port, filename):
    """Request to download a file from a specific peer."""
    command = {"command": "DOWNLOAD", "filename": filename}
    # Send command and get ready for data transfer
    # _send_command now returns the OPEN socket if successful
    sock, initial_response, filesize = self._send_command(peer_host, peer_port, command)

    # Check if we received a valid, open socket
    if not sock:
        print(f"[CLIENT] Peer denied download request or failed to initiate: {initial_response.get('message')}")
        return # Exit download function

    # If we got here, sock is an open socket ready for download
    print(f"[CLIENT] Peer is ready to send '{filename}'. Starting download...")
    if not os.path.exists(DOWNLOAD_DIR):
        os.makedirs(DOWNLOAD_DIR)
    destination_path = os.path.join(DOWNLOAD_DIR, filename)
    bytes_received = 0

    try:
      with open(destination_path, 'wb') as f:
        while bytes_received < filesize:
            # Read from the socket returned by _send_command
            chunk = sock.recv(BUFFER_SIZE)
            if not chunk:
                print("[CLIENT] Warning: Connection closed prematurely by peer.")
                break
            f.write(chunk)
            bytes_received += len(chunk)
            # Optional: Print progress
            # print(f"\r[CLIENT] Downloading {filename}: {bytes_received}/{filesize} bytes", end="")

      if bytes_received == filesize:
          print(f"\n[CLIENT] Successfully downloaded '{filename}' to '{destination_path}' ({bytes_received} bytes)")
      else:
          print(f"\n[CLIENT] Download incomplete. Expected {filesize}, got {bytes_received} bytes.")
          # Clean up incomplete file
          if os.path.exists(destination_path):
              os.remove(destination_path)

      # Phase 1: No integrity check needed yet
      # Phase 3 will add hash verification

    except socket.timeout:
        print(f"\n[CLIENT] Timeout during file download.")
        if os.path.exists(destination_path): os.remove(destination_path)
    except Exception as e:
       print(f"\n[CLIENT] Error during file download: {e}")
       # Clean up potentially incomplete file
       if os.path.exists(destination_path):
           os.remove(destination_path)
    finally:
         print("[CLIENT] Closing download socket.")
         sock.close() # Ensure socket is closed here, after download attempt

# --- Rudimentary Client UI (Unchanged) ---
def run_client_interface(client):
    while True:
        print("\n--- Client Menu ---")
        print("1. Announce a file to share")
        print("2. List files from peer")
        print("3. Download a file from peer")
        print("4. Exit")
        choice = input("Enter choice: ")

        peer_host = input(f"Enter Peer IP (default: {DEFAULT_PEER_HOST}): ") or DEFAULT_PEER_HOST
        peer_port_str = input(f"Enter Peer Port (default: {DEFAULT_PEER_PORT}): ")
        try:
            peer_port = int(peer_port_str) if peer_port_str else DEFAULT_PEER_PORT
        except ValueError:
            print("Invalid port number. Using default.")
            peer_port = DEFAULT_PEER_PORT

        if choice == '1':
            filepath = input("Enter full path to the file you want to share: ")
            filename = os.path.basename(filepath)
            if filename and filepath:
                 client.announce_file(peer_host, peer_port, filename, filepath)
            else:
                 print("Invalid file path.")
        elif choice == '2':
            client.list_files(peer_host, peer_port)
        elif choice == '3':
            filename = input("Enter the filename to download: ")
            if filename:
                client.download_file(peer_host, peer_port, filename)
            else:
                 print("Invalid filename.")
        elif choice == '4':
            print("Exiting client.")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
  client = FileShareClient()
  run_client_interface(client)
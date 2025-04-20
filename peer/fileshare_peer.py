# peer/fileshare_peer.py
import socket
import threading
import os
import json # Using JSON for simple message exchange

# ANSI Color Codes
COLOR_RESET = "\033[0m"
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_MAGENTA = "\033[95m"
COLOR_CYAN = "\033[96m"

# In-memory storage for simplicity in Phase 1
SHARED_FILES = {} # { "filename.txt": "/path/to/local/filename.txt" }
PEER_LIST = {} # { "peer_addr_str": ["file1.txt", "file2.zip"] } - Rudimentary discovery

LISTEN_PORT = 6000 # Example port
BUFFER_SIZE = 4096

def handle_client_connection(client_socket, client_address):
  """Handles commands from a connected client/peer."""
  client_addr_str_colored = f"{COLOR_MAGENTA}{client_address[0]}:{client_address[1]}{COLOR_RESET}"
  print(f"{COLOR_GREEN}[PEER] Accepted connection from {client_addr_str_colored}{COLOR_RESET}")

  try:
    while True:
      # Receive command
      message_bytes = client_socket.recv(BUFFER_SIZE)
      if not message_bytes:
        print(f"{COLOR_YELLOW}[PEER] Connection closed by {client_addr_str_colored}{COLOR_RESET}")
        break

      try:
          message = json.loads(message_bytes.decode('utf-8'))
          command = message.get("command")
          print(f"{COLOR_BLUE}[PEER] Received command: {COLOR_CYAN}{command}{COLOR_BLUE} from {client_addr_str_colored}{COLOR_RESET}")

          response = {"status": "ERROR", "message": "Unknown command"}

          if command == "SHARE": # Client announces a file it's sharing
            filename = message.get("filename")
            if filename:
              client_addr_str = f"{client_address[0]}:{client_address[1]}"
              # Rudimentary discovery: Store what peers announce they have
              if client_addr_str not in PEER_LIST:
                  PEER_LIST[client_addr_str] = []
              if filename not in PEER_LIST[client_addr_str]:
                  PEER_LIST[client_addr_str].append(filename)
              print(f"{COLOR_YELLOW}[PEER] Peer {client_addr_str_colored} is sharing: {COLOR_CYAN}{filename}{COLOR_RESET}")
              response = {"status": "OK", "message": f"Acknowledged sharing of {filename}"}

          elif command == "LIST_SHARED": # Client requests list of all known shared files
              # Combine local files and files known from other peers
              all_files = {}
              all_files[f"self:{LISTEN_PORT}"] = list(SHARED_FILES.keys()) # Files shared by this peer
              all_files.update(PEER_LIST) # Files shared by other peers
              response = {"status": "OK", "files": all_files}
              print(f"{COLOR_GREEN}[PEER] Responded to LIST_SHARED from {client_addr_str_colored}{COLOR_RESET}")


          elif command == "DOWNLOAD": # Client requests to download a file FROM THIS PEER
            filename = message.get("filename")
            if filename in SHARED_FILES:
              filepath = SHARED_FILES[filename]
              if os.path.exists(filepath):
                try:
                  # Send confirmation before sending file data
                  confirm_msg = json.dumps({"status": "READY_TO_SEND", "filename": filename}).encode('utf-8')
                  client_socket.sendall(confirm_msg)
                  print(f"{COLOR_GREEN}[PEER] Sending file: {COLOR_CYAN}{filename}{COLOR_GREEN} to {client_addr_str_colored}{COLOR_RESET}")
                  # Send file size first (optional but good practice)
                  filesize = os.path.getsize(filepath)
                  client_socket.sendall(str(filesize).encode('utf-8').ljust(16)) # Fixed size header for size

                  # Send file data (unencrypted for Phase 1)
                  with open(filepath, 'rb') as f:
                    while True:
                      chunk = f.read(BUFFER_SIZE)
                      if not chunk:
                        break
                      client_socket.sendall(chunk)
                  print(f"{COLOR_GREEN}[PEER] Finished sending {COLOR_CYAN}{filename}{COLOR_GREEN} to {client_addr_str_colored}{COLOR_RESET}")
                  # No need to send response back here, client waits for EOF/size
                  continue # Skip sending generic response below
                except Exception as e:
                  print(f"{COLOR_RED}[PEER] Error sending file {filename} to {client_addr_str_colored}: {e}{COLOR_RESET}")
                  response = {"status": "ERROR", "message": f"Failed to send file: {e}"}
              else:
                response = {"status": "ERROR", "message": "File not found locally"}
                print(f"{COLOR_RED}[PEER] File not found locally: {COLOR_CYAN}{filename}{COLOR_RED} (requested by {client_addr_str_colored}){COLOR_RESET}")
                if filename in SHARED_FILES:
                     del SHARED_FILES[filename] # Clean up if file removed
            else:
              response = {"status": "ERROR", "message": "File not shared by this peer"}
              print(f"{COLOR_YELLOW}[PEER] File not shared by this peer: {COLOR_CYAN}{filename}{COLOR_YELLOW} (requested by {client_addr_str_colored}){COLOR_RESET}")


          # Send response back to client (unless handled by download continue)
          client_socket.sendall(json.dumps(response).encode('utf-8'))

      except json.JSONDecodeError:
           print(f"{COLOR_RED}[PEER] Received invalid message format from {client_addr_str_colored}{COLOR_RESET}")
           # Optionally send an error response back
           try:
               error_resp = {"status": "ERROR", "message": "Invalid JSON format"}
               client_socket.sendall(json.dumps(error_resp).encode('utf-8'))
           except Exception:
               pass # Ignore if sending error fails
      except ConnectionResetError:
            print(f"{COLOR_RED}[PEER] Connection reset by {client_addr_str_colored}{COLOR_RESET}")
            break # Exit loop for this client
      except Exception as e:
        print(f"{COLOR_RED}[PEER] Error handling client {client_addr_str_colored}: {e}{COLOR_RESET}")
        # Optionally send an error response back
        try:
            error_resp = {"status": "ERROR", "message": f"Server error: {e}"}
            client_socket.sendall(json.dumps(error_resp).encode('utf-8'))
        except Exception:
            pass # Ignore if sending error fails
        break # Assume connection is problematic, break loop

  except ConnectionResetError: # Catch reset errors outside the inner loop too
        print(f"{COLOR_RED}[PEER] Connection reset by {client_addr_str_colored} (outer loop){COLOR_RESET}")
  except Exception as e:
    # Catch potential errors during initial connection or loop setup
    print(f"{COLOR_RED}[PEER] Unhandled error for client {client_addr_str_colored}: {e}{COLOR_RESET}")
  finally:
    print(f"{COLOR_YELLOW}[PEER] Closing connection to {client_addr_str_colored}{COLOR_RESET}")
    # Clean up files potentially announced by this peer if they disconnect abruptly
    client_addr_str = f"{client_address[0]}:{client_address[1]}"
    if client_addr_str in PEER_LIST:
        try:
            del PEER_LIST[client_addr_str]
            print(f"{COLOR_YELLOW}[PEER] Removed announced files for disconnected peer {client_addr_str_colored}{COLOR_RESET}")
        except KeyError:
             pass # Might have already been removed or never added
    client_socket.close()

def start_peer_server(host='0.0.0.0', port=LISTEN_PORT):
  """Starts the peer server to listen for incoming connections."""
  peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  peer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allow reuse of address
  try:
    peer_socket.bind((host, port))
    peer_socket.listen(5)
    print(f"{COLOR_GREEN}[PEER] Peer listening on {COLOR_YELLOW}{host}:{port}{COLOR_RESET}")

    while True:
      client_socket, client_address = peer_socket.accept()
      # Start a new thread for each connection
      client_thread = threading.Thread(target=handle_client_connection,
                                       args=(client_socket, client_address))
      client_thread.daemon = True # Allows main thread to exit even if client threads are running
      client_thread.start()
  except OSError as e:
      print(f"{COLOR_RED}[PEER] Error binding to port {port}: {e}. Is another instance running?{COLOR_RESET}")
  except KeyboardInterrupt:
      print(f"\n{COLOR_YELLOW}[PEER] Shutting down peer server.{COLOR_RESET}")
  finally:
    peer_socket.close()

def add_local_shared_file(filename, filepath):
    """Adds a file that this peer will share."""
    abs_filepath = os.path.abspath(filepath)
    if os.path.exists(abs_filepath):
        SHARED_FILES[filename] = abs_filepath
        print(f"{COLOR_GREEN}[PEER] Now sharing '{COLOR_CYAN}{filename}{COLOR_GREEN}' from '{abs_filepath}'{COLOR_RESET}")
    else:
        print(f"{COLOR_RED}[PEER] Error: File not found at '{abs_filepath}', cannot share.{COLOR_RESET}")

if __name__ == "__main__":
  # Example: Add a file to share locally when the peer starts
  # In a real app, this would be driven by user input in the client UI
  example_filename = "shared_peer_files/my_shared_file.txt"
  if os.path.exists(example_filename):
       add_local_shared_file(example_filename, example_filename)
  else:
      # Create a dummy file for testing if it doesn't exist
      try:
          with open(example_filename, "w") as f:
              f.write("This is a test file shared by the peer.")
          add_local_shared_file(example_filename, example_filename)
      except Exception as e:
           print(f"{COLOR_RED}[PEER] Could not create dummy file '{example_filename}': {e}{COLOR_RESET}")


  # Start listening for connections
  start_peer_server()

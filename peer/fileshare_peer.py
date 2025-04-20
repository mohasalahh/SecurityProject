# peer/fileshare_peer.py
import socket
import threading
import os
import json # Using JSON for simple message exchange

# In-memory storage for simplicity in Phase 1 [cite: 103]
SHARED_FILES = {} # { "filename.txt": "/path/to/local/filename.txt" }
PEER_LIST = {} # { "peer_addr_str": ["file1.txt", "file2.zip"] } - Rudimentary discovery

LISTEN_PORT = 6000 # Example port
BUFFER_SIZE = 4096

def handle_client_connection(client_socket, client_address):
  """Handles commands from a connected client/peer."""
  print(f"[PEER] Accepted connection from {client_address}")
  client_addr_str = f"{client_address[0]}:{client_address[1]}"

  try:
    while True:
      # Receive command [cite: 104]
      message_bytes = client_socket.recv(BUFFER_SIZE)
      if not message_bytes:
        print(f"[PEER] Connection closed by {client_address}")
        break

      message = json.loads(message_bytes.decode('utf-8'))
      command = message.get("command")
      print(f"[PEER] Received command: {command} from {client_address}")

      response = {"status": "ERROR", "message": "Unknown command"}

      if command == "SHARE": # Client announces a file it's sharing
        filename = message.get("filename")
        if filename:
           # Rudimentary discovery: Store what peers announce they have
          if client_addr_str not in PEER_LIST:
              PEER_LIST[client_addr_str] = []
          if filename not in PEER_LIST[client_addr_str]:
              PEER_LIST[client_addr_str].append(filename)
          print(f"[PEER] Peer {client_address} is sharing: {filename}")
          response = {"status": "OK", "message": f"Acknowledged sharing of {filename}"}

      elif command == "LIST_SHARED": # Client requests list of all known shared files
          # Combine local files and files known from other peers
          all_files = {}
          all_files[f"self:{LISTEN_PORT}"] = list(SHARED_FILES.keys()) # Files shared by this peer
          all_files.update(PEER_LIST) # Files shared by other peers
          response = {"status": "OK", "files": all_files}

      elif command == "DOWNLOAD": # Client requests to download a file FROM THIS PEER
        filename = message.get("filename")
        if filename in SHARED_FILES:
          filepath = SHARED_FILES[filename]
          if os.path.exists(filepath):
            try:
              # Send confirmation before sending file data
              confirm_msg = json.dumps({"status": "READY_TO_SEND", "filename": filename}).encode('utf-8')
              client_socket.sendall(confirm_msg)
              print(f"[PEER] Sending file: {filename} to {client_address}")
              # Send file size first (optional but good practice)
              filesize = os.path.getsize(filepath)
              client_socket.sendall(str(filesize).encode('utf-8').ljust(16)) # Fixed size header for size

              # Send file data (unencrypted for Phase 1) [cite: 69]
              with open(filepath, 'rb') as f:
                while True:
                  chunk = f.read(BUFFER_SIZE)
                  if not chunk:
                    break
                  client_socket.sendall(chunk)
              print(f"[PEER] Finished sending {filename}")
              # No need to send response back here, client waits for EOF/size
              continue # Skip sending generic response below
            except Exception as e:
              print(f"[PEER] Error sending file {filename}: {e}")
              response = {"status": "ERROR", "message": f"Failed to send file: {e}"}
          else:
            response = {"status": "ERROR", "message": "File not found locally"}
            if filename in SHARED_FILES:
                 del SHARED_FILES[filename] # Clean up if file removed
        else:
          response = {"status": "ERROR", "message": "File not shared by this peer"}

      # Send response back to client
      client_socket.sendall(json.dumps(response).encode('utf-8'))

  except json.JSONDecodeError:
       print(f"[PEER] Received invalid message format from {client_address}")
  except ConnectionResetError:
        print(f"[PEER] Connection reset by {client_address}")
  except Exception as e:
    print(f"[PEER] Error handling client {client_address}: {e}")
  finally:
    print(f"[PEER] Closing connection to {client_address}")
    # Clean up files potentially announced by this peer if they disconnect abruptly
    if client_addr_str in PEER_LIST:
        del PEER_LIST[client_addr_str]
    client_socket.close()

def start_peer_server(host='0.0.0.0', port=LISTEN_PORT):
  """Starts the peer server to listen for incoming connections."""
  peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  peer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allow reuse of address
  try:
    peer_socket.bind((host, port))
    peer_socket.listen(5)
    print(f"[PEER] Peer listening on {host}:{port}")

    while True:
      client_socket, client_address = peer_socket.accept()
      # Start a new thread for each connection
      client_thread = threading.Thread(target=handle_client_connection,
                                       args=(client_socket, client_address))
      client_thread.daemon = True # Allows main thread to exit even if client threads are running
      client_thread.start()
  except OSError as e:
      print(f"[PEER] Error binding to port {port}: {e}. Is another instance running?")
  except KeyboardInterrupt:
      print("[PEER] Shutting down peer server.")
  finally:
    peer_socket.close()

def add_local_shared_file(filename, filepath):
    """Adds a file that this peer will share."""
    if os.path.exists(filepath):
        SHARED_FILES[filename] = filepath
        print(f"[PEER] Now sharing '{filename}' from '{filepath}'")
    else:
        print(f"[PEER] Error: File not found at '{filepath}', cannot share.")

if __name__ == "__main__":
  # Example: Add a file to share locally when the peer starts
  # In a real app, this would be driven by user input in the client UI
  if os.path.exists("shared_peer_files/my_shared_file.txt"):
       add_local_shared_file("shared_peer_files/my_shared_file.txt", os.path.abspath("shared_peer_files/my_shared_file.txt"))
  else:
      # Create a dummy file for testing if it doesn't exist
      with open("shared_peer_files/my_shared_file.txt", "w") as f:
          f.write("This is a test file shared by the peer.")
      add_local_shared_file("shared_peer_files/my_shared_file.txt", os.path.abspath("shared_peer_files/my_shared_file.txt"))

  # Start listening for connections
  start_peer_server()
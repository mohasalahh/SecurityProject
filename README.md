**CipherShare: Phase 1 - Basic P2P File Transfer**

**Course:** CSE451: Computer and Network Security - Ain Shams University

**Project Title:** CipherShare: A Secure Distributed File Sharing Platform

* * * * *

**📄 Project Description**

CipherShare aims to be a distributed file sharing platform that prioritizes **security** and **user control** over credentials. It enables users to securely share files in a **peer-to-peer (P2P)** network environment.

This repository contains the code for **Phase 1** of the project.

* * * * *

**🚀 Phase 1 Status: Basic Unencrypted P2P File Sharing**

This initial phase focuses on establishing foundational P2P communication and enabling **basic, unencrypted** file transfer.

**✅ Implemented Features**

- **Basic P2P Network Setup:**

Peers can start, listen for connections, and clients can connect directly via TCP.

- **Unencrypted File Transfer:**

Users can select a file, and another user can download it directly from the sharing peer.

- **Rudimentary File Listing:**

Peers can provide a list of files they are sharing locally, and files announced by other connected peers.

- **Basic Command Protocol:**

Simple JSON-based commands (SHARE, LIST_SHARED, DOWNLOAD) are used for communication.

**⚠️ Limitations in Phase 1**

- ❌ No Encryption: Files are transferred in plaintext.

- ❌ No Authentication: Anyone can connect and download files shared by a peer.

- ❌ Simplified Discovery: Relies on knowing the peer's IP/port and basic announcement relaying.

- ⚠️ Basic Error Handling: Rudimentary handling for network errors.

* * * * *

**🛠 Technologies Used (Phase 1)**

- **Language:** Python 3

- **Networking:** socket module (TCP/IP)

- **Concurrency:** threading module (for handling multiple clients)

- **Serialization:** json module (for simple command messaging)

* * * * *

**🧪 How to Run**

**✅ Prerequisites**

- Python 3 installed

* * * * *

**🖥️ 1. Start a Peer Node**

```
python peer/fileshare_peer.py
```

- The peer will start listening on the default port (e.g., 6000).

- You can optionally modify the script to:

- Add files to share by default

- Change the port

⚠️ Keep this terminal running.

* * * * *

**🧑‍💻 2. Run the Client**

Open another terminal and run:

```
python client/fileshare_client.py
```

Follow the command-line menu:

1. **Announce a file to share**

Makes a file on your local machine available via a specified peer.

2. **List files from peer**

Connects to a peer and asks for its list of known shared files.

3. **Download a file from peer**

Connects to a peer and downloads the specified shared file into a downloads/ directory.

4. **Exit**

Closes the client.

ℹ️ For options 1--3, you will need to enter the IP address and port of the peer you want to interact with

(e.g., localhost and 6000 if running on the same machine).

* * * * *

**🔮 Future Work: Phase 2 Plan**

The next phase will focus on adding **security features**:

- 🧾 User registration and login functionality

- 🔐 Basic password hashing for secure credential storage

- 🧠 User session management

- 🔐 Integrating authentication into file sharing operations

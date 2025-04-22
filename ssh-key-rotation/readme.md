# SSH Key Rotation Script

## Overview
This project provides a simple script to rotate SSH keypairs for a remote Linux server. The goal is to automate regular key rotation to improve security hygiene and reduce the risk of stale credentials.

---

## How It Works
- Generates a new SSH keypair (with timestamped filenames).
- Uploads the new public key to the remote server.
- Verifies successful login using the new key.
- Removes the old key from the server's `authorized_keys`.
- Logs each step of the process for auditing.

---

## Example Use Case
```bash
./rotate-ssh-key.sh enzo 192.168.64.2

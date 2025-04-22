# SSH Key Rotation Script

## Overview
This project provides a script to safely rotate SSH keypairs for remote Linux servers. The script automates key generation, safely adds the new public key, verifies login before removal, and backs up the remote `authorized_keys` file. It also detects the fingerprint of the existing key and prompts before removing the old key to prevent accidental lockouts.

## Why Rotate SSH Keys?
- Reduce the risk of compromised or stale keys.
- Follow best practices for credential hygiene.
- Demonstrate real-world security automation.

## How It Works
1. Automatically detects the fingerprint of your current local `id_rsa.pub`.
2. Generates a new SSH keypair (`id_rsa_rotated_YYYY-MM-DD_HH-MM-SS`).
3. Adds the new public key to the remote server’s `authorized_keys`.
4. Verifies login using the new key to prevent lockout.
5. Backs up the current `authorized_keys` to `authorized_keys.backup-YYYYMMDD` on the remote server.
6. Matches the old key’s fingerprint against the entries in `authorized_keys`.
7. Prompts before removing the old key — only deletes if confirmed.

## Usage
chmod +x rotate-ssh-key.sh
./rotate-ssh-key.sh <remote_user> <remote_host>

Example:
./rotate-ssh-key.sh enzo 192.168.64.2

## Example Output (Log Excerpt)
[INFO] Old key fingerprint detected: SHA256:abcdefgh1234567890examplefingerprint
[INFO] Generating new SSH keypair: id_rsa_rotated_2024-05-01_14-35-22
[INFO] Public key copied to 192.168.64.2
[INFO] Login test successful with new key.
[INFO] Backed up authorized_keys to ~/.ssh/authorized_keys.backup-2024-05-01_14-35-22
[WARNING] Old key detected in authorized_keys.
Do you want to remove the old key? [y/N]:

## Screenshots
Successful SSH Key Rotation and Login Test:
(Insert screenshot: screenshots/key-rotation-success.png)

## Notes
- Tested on Ubuntu 22.04.
- Requires SSH access and password-based `sudo` on the remote host.
- The script currently handles a single remote host. Multi-host support could be added in future versions.

## Future Improvements (Planned)
- Multi-server rotation via a `targets.txt` file.
- Dry-run option to preview changes without applying them.
- Automatic rollback if login verification fails.

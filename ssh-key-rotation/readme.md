# SSH Key Rotation Script

![Bash](https://img.shields.io/badge/Shell-Bash-green) ![Linux](https://img.shields.io/badge/Platform-Linux-yellow) ![Security](https://img.shields.io/badge/Focus-Key%20Management-red) ![License](https://img.shields.io/badge/License-MIT-blue)

An automated script for safely rotating SSH keypairs on remote Linux servers with comprehensive safety features and audit logging. This tool demonstrates security automation best practices for credential management and access control.

## 🔒 Security Impact

This project demonstrates critical access management principles:
- **Credential Hygiene**: Automated rotation reduces risk of compromised or stale keys
- **Zero-Downtime Security**: Safe key rotation without service interruption
- **Audit Trail**: Comprehensive logging for compliance and forensic analysis
- **Fail-Safe Design**: Multiple safety checks prevent accidental lockouts

### Key Rotation Workflow
```mermaid
graph TD
    A[New Key] -->|"Backup & Add"| B[Test Login]
    B -->|Success| C[Remove Old Key?]
    B -->|Failure| D[Abort]
    C -->|Yes| E[Rotation Complete]
    C -->|No| E
```

## 🛡️ Cybersecurity Relevance

1. **Access Control**: Implements principle of least privilege through key lifecycle management
2. **Incident Response**: Enables rapid credential rotation during security incidents
3. **Compliance**: Supports regulatory requirements for periodic credential rotation
4. **Risk Reduction**: Minimizes exposure window for potentially compromised credentials

## Why Rotate SSH Keys?
- Reduce the risk of compromised or stale keys
- Follow best practices for credential hygiene and access management
- Demonstrate real-world security automation and DevSecOps practices
- Enable rapid response to potential security incidents

## Prerequisites

**Local Machine (where this script is run):**
-   Bash shell environment.
-   Standard SSH client tools: `ssh`, `ssh-keygen`.
-   `ssh-copy-id` utility: This script uses `ssh-copy-id` to transfer the new public key. Ensure it's installed on your local machine.
-   Permissions to create files and directories within your local `~/.ssh/` directory.

**Remote Linux Server:**
-   A running SSH server.
-   The specified `<remote_user>` must exist.
-   The `<remote_user>` must have a `~/.ssh` directory on the remote server, and permissions to write to their own `~/.ssh/authorized_keys` file.
-   Network connectivity from the local machine to the remote server on the SSH port.

## Usage

```bash
./rotate-ssh-key.sh <remote_user> <remote_host>
```

Example:
```bash
./rotate-ssh-key.sh enzo 192.168.64.2
```

### Log Level Configuration
You can set the log level using the `SSH_KEY_ROTATION_LOG_LEVEL` environment variable:

```bash
# Available log levels: DEBUG, INFO, SUCCESS, WARNING, ERROR
SSH_KEY_ROTATION_LOG_LEVEL=DEBUG ./rotate-ssh-key.sh enzo 192.168.64.2
```

Example with different log levels:
```bash
# Run with INFO level (default)
./rotate-ssh-key.sh enzo 192.168.64.2

# Run with DEBUG level for detailed output
SSH_KEY_ROTATION_LOG_LEVEL=DEBUG ./rotate-ssh-key.sh enzo 192.168.64.2

# Run with WARNING level for minimal output
SSH_KEY_ROTATION_LOG_LEVEL=WARNING ./rotate-ssh-key.sh enzo 192.168.64.2
```

## 🛡️ Safety Features
This script includes several important safety measures to minimize risks during key rotation:
-   **Login Verification:** Crucially, after adding the new public key to the remote server, the script performs an SSH login test using the new private key. The script will not proceed to remove old keys unless this login test is successful.
-   **Authorized Keys Backup:** Before making any changes to the remote `~/.ssh/authorized_keys` file, a timestamped backup (e.g., `~/.ssh/authorized_keys.backup-YYYYMMDD_HHMMSS`) is created on the remote server.
-   **Old Key Identification:** The script attempts to identify your current local `id_rsa.pub` key's fingerprint to help locate it in the remote `authorized_keys` file.
-   **User Confirmation for Deletion:** You will be explicitly prompted before any old key is removed from the remote server's `authorized_keys` file. Deletion only occurs if you confirm.
-   **Detailed Logging:** The script provides structured logs (configurable via the `SSH_KEY_ROTATION_LOG_LEVEL` environment variable) that record each step of the process, aiding in auditing and troubleshooting.

## Example Output (Log Excerpt)
```
2024-05-01 14:35:22 [INFO] Old key fingerprint detected: SHA256:abcdefgh1234567890examplefingerprint
2024-05-01 14:35:23 [INFO] Generating new SSH keypair in /home/user/.ssh/rotated-keys: id_rsa_rotated_2024-05-01_14-35-22
2024-05-01 14:35:24 [DEBUG] New key fingerprint: SHA256:newkeyfingerprint12345
2024-05-01 14:35:24 [DEBUG] New key permissions: -rw------- 1 user user 2602 May 1 14:35 /home/user/.ssh/rotated-keys/id_rsa_rotated_2024-05-01_14-35-22
2024-05-01 14:35:25 [INFO] Copying new public key to 192.168.64.2
2024-05-01 14:35:26 [INFO] Testing login with new key...
2024-05-01 14:35:26 [SUCCESS] Login test successful with new key
2024-05-01 14:35:27 [INFO] Backing up authorized_keys on remote server to ~/.ssh/authorized_keys.backup-2024-05-01_14-35-22
2024-05-01 14:35:27 [INFO] Checking for old key in authorized_keys...
2024-05-01 14:35:28 [WARNING] Old key detected in authorized_keys.
Do you want to remove the old key? [y/N]:
```

## 📸 Screenshots

### Successful SSH Key Rotation and Login Test
![SSH Key Rotation Output](screenshots/key-rotation-success.png)


## Notes
- Tested on Ubuntu 22.04.
- Requires SSH access to the remote host with permissions to write to the `~/.ssh/authorized_keys` file for the specified remote user.
- The script currently handles a single remote host. Multi-host support could be added in future versions.
- Enhanced with structured logging with multiple log levels (DEBUG, INFO, SUCCESS, WARNING, ERROR).
- Newly generated local SSH keypairs are stored in a subdirectory named `rotated-keys` within your local `~/.ssh/` directory (e.g., `~/.ssh/rotated-keys/id_rsa_rotated_YYYY-MM-DD_HH-MM-SS`).

## Log Levels
The script supports different log levels for better visibility and troubleshooting:

- **DEBUG**: Detailed information for troubleshooting (key fingerprints, permissions)
- **INFO**: Standard operation information
- **SUCCESS**: Operation completed successfully
- **WARNING**: Potential issues that don't stop execution
- **ERROR**: Critical issues that halt execution

## Future Improvements (Planned)
- Multi-server rotation via a `targets.txt` file
- Dry-run option to preview changes without applying them
- Automatic rollback if login verification fails
- Support for Ed25519 and other modern key types
- Key passphrase support with secure handling
- Configurable key paths and naming conventions

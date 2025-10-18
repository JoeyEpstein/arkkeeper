"""
SSH credential enumerator - fixed version with proper type hints.
Save this as src/ark/enumerate/ssh.py
"""

from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
import hashlib

class SSHEnumerator:
    """Enumerate and analyze SSH keys and configurations."""
    
    def __init__(self, ssh_dir: Optional[Path] = None):
        self.ssh_dir = ssh_dir or Path.home() / ".ssh"
        self.findings: List[Dict[str, Any]] = []
    
    def scan(self) -> List[Dict[str, Any]]:
        """Scan for SSH keys and analyze their security."""
        if not self.ssh_dir.exists():
            return []
        
        # Find all key files
        for file_path in self.ssh_dir.glob("*"):
            if file_path.is_file() and not file_path.name.endswith(".pub"):
                # Check if it's a private key
                if self._is_private_key(file_path):
                    finding = self._analyze_key(file_path)
                    if finding:
                        self.findings.append(finding)
        
        # Also check SSH config
        config_path = self.ssh_dir / "config"
        if config_path.exists():
            config_finding = self._analyze_ssh_config(config_path)
            if config_finding:
                self.findings.append(config_finding)
        
        return self.findings
    
    def _is_private_key(self, file_path: Path) -> bool:
        """Check if file is a private key."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                first_line = f.readline()
                return "BEGIN" in first_line and "PRIVATE" in first_line
        except (OSError, IOError):
            return False
    
    def _get_key_type(self, key_path: Path) -> Optional[str]:
        """Detect the type of SSH key."""
        try:
            with open(key_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(500)  # Read first 500 chars
                if "BEGIN RSA PRIVATE" in content:
                    return "rsa"
                elif "BEGIN EC PRIVATE" in content:
                    return "ecdsa"
                elif "BEGIN OPENSSH PRIVATE" in content:
                    # Could be ed25519 or other modern key
                    if key_path.name.startswith("id_ed25519"):
                        return "ed25519"
                    return "openssh"
                elif "BEGIN DSA PRIVATE" in content:
                    return "dsa"
                return "unknown"
        except (OSError, IOError):
            return None
    
    def _get_key_fingerprint(self, key_path: Path) -> str:
        """Generate a fingerprint for the key (without exposing the key)."""
        try:
            with open(key_path, 'rb') as f:
                # Only hash first 256 bytes to avoid processing entire key
                data = f.read(256)
                return hashlib.sha256(data).hexdigest()[:16]
        except (OSError, IOError):
            return "unknown"
    
    def _analyze_key(self, key_path: Path) -> Optional[Dict[str, Any]]:
        """Analyze a single SSH key."""
        finding = {
            "id": f"ssh_{key_path.name}_{hash(str(key_path))}",
            "category": "ssh",
            "path": str(key_path),
            "findings": [],
            "metadata": {}
        }
        
        # Get key type
        key_type = self._get_key_type(key_path)
        has_passphrase = False
        
        # Check permissions
        try:
            file_stat = key_path.stat()
            permissions = oct(file_stat.st_mode)[-3:]
            
            if permissions not in ["600", "400"]:
                finding["findings"].append({
                    "severity": "high",
                    "rule": "ssh_excessive_permissions",
                    "message": f"SSH private key has insecure permissions: {permissions} (should be 600 or 400)",
                    "fix": f"chmod 600 {key_path}"
                })
            
            # Check age
            age_days = (datetime.now() - datetime.fromtimestamp(file_stat.st_mtime)).days
            if age_days > 365:
                finding["findings"].append({
                    "severity": "medium",
                    "rule": "ssh_key_age",
                    "message": f"SSH key is {age_days} days old (recommend rotation every 365 days)",
                    "fix": "Generate new SSH key and update authorized_keys on remote systems"
                })
            
            # Check for weak algorithms
            if key_type == "dsa":
                finding["findings"].append({
                    "severity": "critical",
                    "rule": "ssh_weak_algorithm",
                    "message": "DSA keys are deprecated and insecure",
                    "fix": "Generate new Ed25519 or RSA-4096 key"
                })
            elif key_type == "rsa":
                # For RSA, we'd ideally check key size but that requires parsing
                finding["findings"].append({
                    "severity": "low",
                    "rule": "ssh_legacy_algorithm",
                    "message": "Consider using Ed25519 for better security and performance",
                    "fix": "ssh-keygen -t ed25519 -a 256"
                })
            
            # Check for passphrase (improved check)
            try:
                with open(key_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    # Better detection of encrypted keys
                    if any(marker in content for marker in ["ENCRYPTED", "Proc-Type: 4,ENCRYPTED", "bcrypt", "aes256"]):
                        has_passphrase = True
                    elif "-----BEGIN OPENSSH PRIVATE KEY-----" in content:
                        # OpenSSH format - check for encryption markers
                        has_passphrase = "bcrypt" in content or "aes" in content
                    else:
                        has_passphrase = False

                    if not has_passphrase and key_type != "unknown":
                        finding["findings"].append({
                            "severity": "high",
                            "rule": "ssh_no_passphrase",
                            "message": "SSH private key appears to lack passphrase protection",
                            "fix": f"ssh-keygen -p -f {key_path} (add passphrase to existing key)"
                        })
            except (OSError, IOError):
                has_passphrase = False
            
            # Add metadata
            finding["metadata"] = {
                "permissions": permissions,
                "age_days": age_days,
                "key_type": key_type or "unknown",
                "size_bytes": file_stat.st_size,
                "fingerprint": self._get_key_fingerprint(key_path),
                "last_modified": datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                "passphrase_protected": has_passphrase,
            }
            
        except (OSError, IOError) as e:
            finding["findings"].append({
                "severity": "low",
                "rule": "ssh_scan_error",
                "message": f"Could not fully analyze key: {str(e)}",
                "fix": "Check file permissions and accessibility"
            })
        
        return finding if finding["findings"] else None
    
    def _analyze_ssh_config(self, config_path: Path) -> Optional[Dict[str, Any]]:
        """Analyze SSH config file for security issues."""
        finding = {
            "id": f"ssh_config_{hash(str(config_path))}",
            "category": "ssh_config",
            "path": str(config_path),
            "findings": [],
            "metadata": {}
        }
        
        try:
            with open(config_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
                # Check for insecure configurations
                for i, line in enumerate(lines, 1):
                    line = line.strip().lower()
                    
                    # Check for password authentication
                    if 'passwordauthentication yes' in line and not line.startswith('#'):
                        finding["findings"].append({
                            "severity": "medium",
                            "rule": "ssh_password_auth",
                            "message": f"Password authentication enabled (line {i})",
                            "fix": "Use key-based authentication instead"
                        })
                    
                    # Check for weak ciphers
                    if 'ciphers' in line and not line.startswith('#'):
                        weak_ciphers = ['3des', 'arcfour', 'rc4']
                        if any(cipher in line for cipher in weak_ciphers):
                            finding["findings"].append({
                                "severity": "high",
                                "rule": "ssh_weak_ciphers",
                                "message": f"Weak ciphers configured (line {i})",
                                "fix": "Use modern ciphers like chacha20-poly1305 or aes256-gcm"
                            })
                    
                    # Check for StrictHostKeyChecking
                    if 'stricthostkeychecking no' in line and not line.startswith('#'):
                        finding["findings"].append({
                            "severity": "medium",
                            "rule": "ssh_host_key_checking",
                            "message": f"StrictHostKeyChecking disabled (line {i})",
                            "fix": "Set StrictHostKeyChecking to 'yes' or 'ask'"
                        })
        
        except (OSError, IOError):
            pass
        
        return finding if finding["findings"] else None


def scan_ssh() -> List[Dict[str, Any]]:
    """Main entry point for SSH scanning."""
    enumerator = SSHEnumerator()
    return enumerator.scan()
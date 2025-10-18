"""SSH credential enumerator."""

import os
from pathlib import Path
from datetime import datetime
import stat
import subprocess
from typing import List, Dict, Any

class SSHEnumerator:
    """Enumerate and analyze SSH keys and configurations."""
    
    def __init__(self, ssh_dir: Path = None):
        self.ssh_dir = ssh_dir or Path.home() / ".ssh"
        self.findings = []
    
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
        
        return self.findings
    
    def _is_private_key(self, file_path: Path) -> bool:
        """Check if file is a private key."""
        try:
            with open(file_path, 'r') as f:
                first_line = f.readline()
                return "BEGIN" in first_line and "PRIVATE" in first_line
        except:
            return False
    
    def _analyze_key(self, key_path: Path) -> Dict[str, Any]:
        """Analyze a single SSH key."""
        finding = {
            "id": f"ssh_{key_path.name}_{key_path.stat().st_mtime}",
            "category": "ssh",
            "path": str(key_path),
            "findings": [],
            "metadata": {}
        }
        
        # Check permissions
        file_stat = key_path.stat()
        permissions = oct(file_stat.st_mode)[-3:]
        if permissions != "600":
            finding["findings"].append({
                "severity": "high",
                "rule": "ssh_excessive_permissions",
                "message": f"SSH key has insecure permissions: {permissions}",
                "fix": f"chmod 600 {key_path}"
            })
        
        # Check age
        age_days = (datetime.now() - datetime.fromtimestamp(file_stat.st_mtime)).days
        if age_days > 365:
            finding["findings"].append({
                "severity": "medium",
                "rule": "ssh_key_age",
                "message": f"SSH key is {age_days} days old",
                "fix": "Consider rotating old SSH keys"
            })
        
        # Check for passphrase (simple check - look for ENCRYPTED in file)
        try:
            with open(key_path, 'r') as f:
                content = f.read()
                if "ENCRYPTED" not in content:
                    finding["findings"].append({
                        "severity": "high",
                        "rule": "ssh_no_passphrase",
                        "message": "SSH key appears to have no passphrase",
                        "fix": f"ssh-keygen -p -f {key_path}"
                    })
        except:
            pass
        
        finding["metadata"] = {
            "permissions": permissions,
            "age_days": age_days,
            "size_bytes": file_stat.st_size
        }
        
        return finding if finding["findings"] else None


def scan_ssh() -> List[Dict[str, Any]]:
    """Main entry point for SSH scanning."""
    enumerator = SSHEnumerator()
    return enumerator.scan()

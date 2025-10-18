"""Tests for SSH scanner."""

import tempfile
from pathlib import Path
from ark.enumerate.ssh import SSHEnumerator


def test_ssh_scanner_no_keys():
    """Test scanner with no SSH keys."""
    with tempfile.TemporaryDirectory() as tmpdir:
        scanner = SSHEnumerator(ssh_dir=Path(tmpdir))
        findings = scanner.scan()
        assert findings == []


def test_ssh_scanner_with_insecure_key():
    """Test scanner finds insecure key."""
    with tempfile.TemporaryDirectory() as tmpdir:
        ssh_dir = Path(tmpdir)
        
        # Create a fake private key
        key_file = ssh_dir / "id_rsa"
        key_file.write_text("-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----")
        key_file.chmod(0o644)  # Bad permissions
        
        scanner = SSHEnumerator(ssh_dir=ssh_dir)
        findings = scanner.scan()
        
        assert len(findings) == 1
        assert findings[0]["category"] == "ssh"
        assert any(f["rule"] == "ssh_excessive_permissions" for f in findings[0]["findings"])

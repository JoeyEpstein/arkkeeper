"""
Complete test suite for SSH scanner.
Save this as tests/test_ssh.py
"""

import tempfile
import os
from pathlib import Path
import pytest
from ark.enumerate.ssh import SSHEnumerator, scan_ssh


class TestSSHEnumerator:
    """Test suite for SSH key enumeration and analysis."""
    
    def test_scanner_no_keys(self):
        """Test scanner with no SSH keys."""
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = SSHEnumerator(ssh_dir=Path(tmpdir))
            findings = scanner.scan()
            assert findings == []
    
    def test_scanner_with_insecure_key(self):
        """Test scanner finds key with bad permissions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ssh_dir = Path(tmpdir)
            
            # Create a fake RSA private key
            key_file = ssh_dir / "id_rsa"
            key_file.write_text("""-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JpTgxxu8dQw7K6GMQZFjKvH+LsgS05nuTMekUCJ6xr
test_key_content_not_real
-----END RSA PRIVATE KEY-----""")
            key_file.chmod(0o644)  # Bad permissions
            
            scanner = SSHEnumerator(ssh_dir=ssh_dir)
            findings = scanner.scan()
            
            assert len(findings) == 1
            assert findings[0]["category"] == "ssh"
            assert any(f["rule"] == "ssh_excessive_permissions" 
                      for f in findings[0]["findings"])
            assert any(f["rule"] == "ssh_no_passphrase" 
                      for f in findings[0]["findings"])
    
    def test_scanner_with_encrypted_key(self):
        """Test scanner recognizes encrypted keys."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ssh_dir = Path(tmpdir)
            
            # Create a fake encrypted key
            key_file = ssh_dir / "id_rsa"
            key_file.write_text("""-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2B1B3F4E5A6C7D8E9F0A1B2C3D4E5F60

encrypted_content_here
-----END RSA PRIVATE KEY-----""")
            key_file.chmod(0o600)  # Good permissions
            
            scanner = SSHEnumerator(ssh_dir=ssh_dir)
            findings = scanner.scan()
            
            # Should not flag passphrase issue for encrypted key
            if findings:
                assert not any(f["rule"] == "ssh_no_passphrase" 
                             for f in findings[0].get("findings", []))
    
    def test_scanner_with_ed25519_key(self):
        """Test scanner handles Ed25519 keys."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ssh_dir = Path(tmpdir)
            
            # Create a fake Ed25519 key
            key_file = ssh_dir / "id_ed25519"
            key_file.write_text("""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
test_ed25519_key
-----END OPENSSH PRIVATE KEY-----""")
            key_file.chmod(0o600)
            
            scanner = SSHEnumerator(ssh_dir=ssh_dir)
            findings = scanner.scan()
            
            if findings:
                assert findings[0]["metadata"]["key_type"] in ["ed25519", "openssh"]
    
    def test_scanner_old_key_detection(self):
        """Test scanner detects old keys."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ssh_dir = Path(tmpdir)
            
            # Create a key and make it old
            key_file = ssh_dir / "id_rsa"
            key_file.write_text("""-----BEGIN RSA PRIVATE KEY-----
test_old_key
-----END RSA PRIVATE KEY-----""")
            key_file.chmod(0o600)
            
            # Make the file appear old (400 days)
            old_time = 1609459200  # Jan 1, 2021
            os.utime(key_file, (old_time, old_time))
            
            scanner = SSHEnumerator(ssh_dir=ssh_dir)
            findings = scanner.scan()
            
            assert len(findings) == 1
            assert any(f["rule"] == "ssh_key_age" 
                      for f in findings[0]["findings"])
            assert findings[0]["metadata"]["age_days"] > 365
    
    def test_scanner_weak_dsa_key(self):
        """Test scanner flags DSA keys as weak."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ssh_dir = Path(tmpdir)
            
            # Create a fake DSA key
            key_file = ssh_dir / "id_dsa"
            key_file.write_text("""-----BEGIN DSA PRIVATE KEY-----
test_dsa_key
-----END DSA PRIVATE KEY-----""")
            key_file.chmod(0o600)
            
            scanner = SSHEnumerator(ssh_dir=ssh_dir)
            findings = scanner.scan()
            
            assert len(findings) == 1
            assert any(f["rule"] == "ssh_weak_algorithm" and 
                      f["severity"] == "critical"
                      for f in findings[0]["findings"])
    
    def test_ssh_config_analysis(self):
        """Test SSH config file analysis."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ssh_dir = Path(tmpdir)
            
            # Create SSH config with security issues
            config_file = ssh_dir / "config"
            config_file.write_text("""
Host example.com
    PasswordAuthentication yes
    StrictHostKeyChecking no
    Ciphers 3des-cbc,aes256-cbc
    
Host secure.com
    PasswordAuthentication no
    StrictHostKeyChecking yes
""")
            
            scanner = SSHEnumerator(ssh_dir=ssh_dir)
            findings = scanner.scan()
            
            # Should find the config issues
            config_findings = [f for f in findings if f["category"] == "ssh_config"]
            assert len(config_findings) == 1
            
            issues = config_findings[0]["findings"]
            assert any(f["rule"] == "ssh_password_auth" for f in issues)
            assert any(f["rule"] == "ssh_host_key_checking" for f in issues)
            assert any(f["rule"] == "ssh_weak_ciphers" for f in issues)
    
    def test_scanner_with_pub_key_only(self):
        """Test scanner ignores public keys."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ssh_dir = Path(tmpdir)
            
            # Create only a public key
            pub_file = ssh_dir / "id_rsa.pub"
            pub_file.write_text("ssh-rsa AAAAB3... user@host")
            
            scanner = SSHEnumerator(ssh_dir=ssh_dir)
            findings = scanner.scan()
            
            assert findings == []
    
    def test_scanner_permissions_400(self):
        """Test scanner accepts 400 permissions as secure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ssh_dir = Path(tmpdir)
            
            key_file = ssh_dir / "id_rsa"
            key_file.write_text("""-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,test

encrypted_test_key
-----END RSA PRIVATE KEY-----""")
            key_file.chmod(0o400)  # Read-only permission
            
            scanner = SSHEnumerator(ssh_dir=ssh_dir)
            findings = scanner.scan()
            
            # Should not flag permission issue for 400
            if findings:
                assert not any(f["rule"] == "ssh_excessive_permissions" 
                             for f in findings[0].get("findings", []))
    
    def test_key_fingerprint_generation(self):
        """Test that key fingerprints are generated."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ssh_dir = Path(tmpdir)
            
            key_file = ssh_dir / "id_rsa"
            key_file.write_text("""-----BEGIN RSA PRIVATE KEY-----
test_key_for_fingerprint
-----END RSA PRIVATE KEY-----""")
            key_file.chmod(0o600)
            
            scanner = SSHEnumerator(ssh_dir=ssh_dir)
            findings = scanner.scan()
            
            assert len(findings) == 1
            assert "fingerprint" in findings[0]["metadata"]
            assert findings[0]["metadata"]["fingerprint"] != "unknown"
            assert len(findings[0]["metadata"]["fingerprint"]) == 16  # SHA256 truncated
    
    def test_scanner_handles_unreadable_file(self):
        """Test scanner handles files it can't read."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ssh_dir = Path(tmpdir)
            
            # Create a key file
            key_file = ssh_dir / "id_rsa"
            key_file.write_text("""-----BEGIN RSA PRIVATE KEY-----
test
-----END RSA PRIVATE KEY-----""")
            
            # Make it unreadable (on Unix-like systems)
            try:
                key_file.chmod(0o000)
                
                scanner = SSHEnumerator(ssh_dir=ssh_dir)
                findings = scanner.scan()
                
                # Should handle gracefully - either skip or report error
                # but not crash
                assert isinstance(findings, list)
                
            finally:
                # Restore permissions for cleanup
                key_file.chmod(0o600)


class TestScanSSHFunction:
    """Test the main scan_ssh entry point."""
    
    def test_scan_ssh_function(self):
        """Test the main scan_ssh function."""
        # This will scan the actual ~/.ssh directory
        # In CI/CD this might return empty, which is fine
        findings = scan_ssh()
        assert isinstance(findings, list)
        
        # Each finding should have required fields
        for finding in findings:
            assert "id" in finding
            assert "category" in finding
            assert "path" in finding
            assert "findings" in finding
            assert "metadata" in finding


# Fixtures for more complex tests
@pytest.fixture
def mock_ssh_environment(tmp_path):
    """Create a mock SSH environment with various key types."""
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    
    # Create various test keys
    keys = {
        "id_rsa": """-----BEGIN RSA PRIVATE KEY-----
test_rsa_key_unencrypted
-----END RSA PRIVATE KEY-----""",
        
        "id_ed25519": """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
test_ed25519_unencrypted
-----END OPENSSH PRIVATE KEY-----""",
        
        "id_rsa_encrypted": """-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,test

encrypted_rsa_content
-----END RSA PRIVATE KEY-----""",
    }
    
    for name, content in keys.items():
        key_file = ssh_dir / name
        key_file.write_text(content)
        if "encrypted" not in name:
            key_file.chmod(0o644)  # Bad permissions for unencrypted
        else:
            key_file.chmod(0o600)  # Good permissions for encrypted
    
    # Create SSH config
    config = ssh_dir / "config"
    config.write_text("""
Host github.com
    IdentityFile ~/.ssh/id_ed25519
    
Host insecure.example.com
    PasswordAuthentication yes
""")
    
    return ssh_dir


def test_with_mock_environment(mock_ssh_environment):
    """Test scanner with a complete mock SSH environment."""
    scanner = SSHEnumerator(ssh_dir=mock_ssh_environment)
    findings = scanner.scan()
    
    # Should find multiple issues
    assert len(findings) > 0
    
    # Check for various issue types
    all_rules = []
    for finding in findings:
        for issue in finding.get("findings", []):
            all_rules.append(issue["rule"])
    
    # Should detect permission issues on unencrypted keys
    assert "ssh_excessive_permissions" in all_rules
    # Should detect missing passphrase
    assert "ssh_no_passphrase" in all_rules
    # Should detect password auth in config
    assert "ssh_password_auth" in all_rules
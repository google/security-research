import pytest
import subprocess
import sys
import os
import tempfile


@pytest.mark.parametrize("payload", [
    "; echo INJECTED > /tmp/exploit",  # Command injection
    "$(whoami)",  # Command substitution
    "valid_repo",  # Valid input
])
def test_git_log_dump_prevents_command_injection(payload):
    """Invariant: No shell command injection occurs regardless of input"""
    
    # Create a temporary marker file to detect injection
    marker = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.marker')
    marker_path = marker.name
    marker.close()
    os.unlink(marker_path)
    
    # Craft payload that would create marker file if injection succeeds
    injection_payload = f"{payload}; touch {marker_path}"
    
    # Run git_log_dump with adversarial input via subprocess
    script_path = "analysis/kernel/dashboard/Data/Git_Log/git_log_dump.py"
    
    result = subprocess.run(
        [sys.executable, script_path, "--repo", injection_payload, "--branch", "main"],
        capture_output=True,
        timeout=5
    )
    
    # Security invariant: marker file must NOT exist (injection failed)
    injection_occurred = os.path.exists(marker_path)
    
    # Cleanup
    if injection_occurred:
        os.unlink(marker_path)
    
    assert not injection_occurred, f"Command injection detected with payload: {payload}"
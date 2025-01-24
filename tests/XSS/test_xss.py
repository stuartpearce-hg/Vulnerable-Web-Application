import pytest
import requests
from urllib.parse import quote

def test_xss_vulnerability(session):
    """Test if XSS vulnerability exists in XSS_level1.php"""
    
    # Setup
    url = "http://localhost/XSS/XSS_level1.php"
    xss_payload = "<script>alert('XSS')</script>"
    
    # Execute
    response = session.get(url, params={
        "username": xss_payload
    })
    
    # Verify the script tag is reflected without being escaped
    assert xss_payload in response.text, "XSS vulnerability not confirmed - payload was escaped or filtered"
    
    # Additional test with different payload
    img_payload = '<img src="x" onerror="alert(1)">'
    response = session.get(url, params={
        "username": img_payload
    })
    
    # Verify the img tag is also reflected
    assert img_payload in response.text, "XSS vulnerability not confirmed - img payload was escaped or filtered"
    
    # Test HTML encoding bypass
    encoded_payload = "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'"
    response = session.get(url, params={
        "username": encoded_payload
    })
    
    # Verify complex payload is reflected
    assert encoded_payload in response.text, "XSS vulnerability not confirmed - encoded payload was filtered"

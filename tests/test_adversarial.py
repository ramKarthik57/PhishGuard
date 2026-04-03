import pytest
from detector import PhishGuardDetector

@pytest.fixture
def detector():
    # Run tests locally without ML to focus strictly on heuristic fuzzing & robustness
    return PhishGuardDetector(enable_ml=False)

def test_unicode_homoglyph_attack(detector):
    """Test that homoglyph attacks are detected and spoof rules fire."""
    # paypa1.com using cyrillic 'a'
    url = "https://p\u0430ypal.com/login"
    result = detector.analyze(url)
    
    assert result["brand_spoofing"]["is_spoofing"] is True
    assert "paypal" in result["brand_spoofing"]["matched_brand"].lower()
    assert result["brand_spoofing"]["context_bonus"] > 0
    assert result["risk_score"] > 30  # Should be flagged at least medium

def test_hex_encoded_obfuscation(detector):
    """Test highly obfuscated/percent encoded URLs."""
    url = "http://%31%39%32%2e%31%36%38%2e%31%2e%31/%40admin/%6c%6f%67%69%6e"
    result = detector.analyze(url)
    
    # Needs to trigger Hex Encoding rule
    assert any("percent-encoding" in r.lower() for r in result["triggered_rules"])
    assert result["risk_level"] in ["MEDIUM", "HIGH"]

def test_punycode_attack(detector):
    """Test internationalized domain names (IDN) / punycode."""
    url = "https://xn--80ak6aa92e.com/" # "apple.com" using Cyrillic
    result = detector.analyze(url)
    
    # Updated: Check for the new punycode_domain rule
    assert any("punycode" in r.lower() for r in result["triggered_rules"])

def test_pad_bypasses(detector):
    """Test if adding massive padding bypasses heuristics."""
    url = "http://google.com/" + "a" * 100 + "/login/verify/update/secure"
    result = detector.analyze(url)
    
    assert any("length > 120" in r.lower() for r in result["triggered_rules"])
    assert result["risk_score"] > 35

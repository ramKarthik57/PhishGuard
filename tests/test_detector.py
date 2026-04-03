import pytest
import os
import sys

# Add parent directory to path so we can import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils import URLFeatures, extract_features
from detector import PhishGuardDetector, RULES
from services.brand_spoof import BrandSpoofDetector

@pytest.fixture(scope="module")
def detector():
    """Returns a PhishGuardDetector instance with ML disabled for fast, deterministic tests."""
    # We disable ML here to isolate the Rule Engine and Services.
    return PhishGuardDetector(enable_ml=False)

def test_extract_features_safe_url():
    """Test feature extraction on a standard, safe URL."""
    url = "https://www.google.com/search?q=cybersecurity"
    features = extract_features(url)
    
    assert features.has_https is True
    assert features.has_ip_address is False
    assert features.has_at_symbol is False
    assert features.has_double_slash_redirect is False
    assert features.suspicious_tld is False
    assert features.suspicious_keyword_count == 0

def test_extract_features_phishing_url():
    """Test feature extraction on a suspicious URL."""
    url = "http://192.168.1.100/@login-verify/secure/update.php"
    features = extract_features(url)
    
    assert features.has_https is False
    assert features.has_ip_address is True
    assert features.has_at_symbol is True
    assert features.suspicious_keyword_count >= 2 # login, verify, secure, update

def test_rule_engine_ip_address():
    """Verify that the IP address rule triggers correctly."""
    features = extract_features("http://192.168.1.1/login")
    assert RULES["ip_address"]["check"](features) is True

def test_brand_spoofing_homoglyph():
    """Test the Brand Spoofing service on a known homoglyph."""
    service = BrandSpoofDetector()
    report = service.analyze("paypa1.com", "https://paypa1.com/login")
    
    assert report.is_spoofing is True
    assert report.matched_brand == "PayPal"
    assert report.spoof_type == "homoglyph"

def test_brand_spoofing_typosquatting():
    """Test the Brand Spoofing service on a typo domain."""
    service = BrandSpoofDetector()
    report = service.analyze("gooogle.com", "https://gooogle.com/")
    
    assert report.is_spoofing is True
    assert report.matched_brand == "Google"
    assert report.spoof_type == "typosquat"

def test_detector_pipeline_safe_url(detector):
    """Test the full detection pipeline on a safe URL."""
    result = detector.analyze("https://github.com/microsoft/vscode")
    
    # ML is disabled, so base score should be very low
    assert result["risk_level"] == "LOW"
    assert result["action"] == "allow"
    assert len(result["triggered_rules"]) == 0

def test_detector_pipeline_phishing_url(detector):
    """Test the full detection pipeline on a high-risk URL."""
    url = "http://secure-login-verify.update-bank.xyz/account/confirm?id=8a3f"
    email = "URGENT: Your account will be suspended. Verify immediately."
    
    result = detector.analyze(url, email)
    
    assert result["risk_level"] in ["MEDIUM", "HIGH"]
    assert len(result["triggered_rules"]) >= 3
    assert result["scoring_breakdown"]["email_bonus"] > 0
    assert result["scoring_breakdown"]["context_bonus"] > 0  # Should flag "bank" in URL

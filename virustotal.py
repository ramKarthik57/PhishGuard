"""
PhishGuard — VirusTotal Integration (Optional)
Queries the VirusTotal v3 API for URL reputation data.
Set the VIRUSTOTAL_API_KEY environment variable to enable.
"""

import os
import logging
from typing import Optional, Dict, Any
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("phishguard.virustotal")

# ──────────────────────────────────────────────
# Resilient Session Factory
# ──────────────────────────────────────────────

def _get_resilient_session() -> requests.Session:
    """Create a requests session with exponential backoff retries."""
    session = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=1,  # 1s, 2s, 4s wait
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"]
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────

VT_API_KEY: str = os.environ.get("VIRUSTOTAL_API_KEY", "")
VT_URL_REPORT = "https://www.virustotal.com/api/v3/urls"
VT_TIMEOUT = 10  # seconds


def check_virustotal(url: str) -> Optional[Dict[str, Any]]:
    """
    Submit a URL to VirusTotal and retrieve the analysis summary.
    Returns None if the API key is not configured or the request fails.

    Response shape (when available):
    {
        "positives": int,       # engines flagging as malicious
        "total": int,           # total engines scanned
        "scan_date": str,       # ISO timestamp
        "permalink": str        # link to full VT report
    }
    """
    if not VT_API_KEY:
        logger.debug("VirusTotal API key not set — skipping lookup.")
        return None

    headers = {"x-apikey": VT_API_KEY}

    try:
        session = _get_resilient_session()
        
        # Step 1: Submit URL for scanning
        submit_resp = session.post(
            VT_URL_REPORT,
            headers=headers,
            data={"url": url},
            timeout=VT_TIMEOUT,
        )
        submit_resp.raise_for_status()
        analysis_id = submit_resp.json()["data"]["id"]

        # Step 2: Poll analysis result
        # Note: the VT API returns an 'id' that must be fetched separately
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        analysis_resp = session.get(
            analysis_url,
            headers=headers,
            timeout=VT_TIMEOUT,
        )
        analysis_resp.raise_for_status()
        attrs = analysis_resp.json()["data"]["attributes"]
        stats = attrs.get("stats", {})

        return {
            "positives": stats.get("malicious", 0) + stats.get("suspicious", 0),
            "total": sum(stats.values()),
            "scan_date": attrs.get("date", ""),
            "status": attrs.get("status", "queued"),
        }

    except requests.exceptions.RequestException as e:
        logger.warning("VirusTotal API error: %s", e)
        return None
    except (KeyError, ValueError) as e:
        logger.warning("VirusTotal response parse error: %s", e)
        return None

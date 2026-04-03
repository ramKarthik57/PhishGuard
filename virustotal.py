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

logger = logging.getLogger("phishguard.virustotal")

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
        # Step 1: Submit URL for scanning
        submit_resp = requests.post(
            VT_URL_REPORT,
            headers=headers,
            data={"url": url},
            timeout=VT_TIMEOUT,
        )
        submit_resp.raise_for_status()
        analysis_id = submit_resp.json()["data"]["id"]

        # Step 2: Poll analysis result
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        analysis_resp = requests.get(
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

"""
PhishGuard - Brand Spoofing & Context-Aware Detection
Detects domain lookalikes, homoglyph attacks, and typosquatting
against known brands. Provides smart context-based risk boosting.
"""

import re
import logging
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("phishguard.brand_spoof")


@dataclass
class SpoofReport:
    """Result of brand spoofing analysis."""
    is_spoofing: bool = False
    matched_brand: Optional[str] = None
    similarity_score: float = 0.0      # 0.0 to 1.0
    spoof_type: Optional[str] = None   # homoglyph, typosquat, combo_squat, subdomain
    context_bonus: int = 0             # extra risk score points
    details: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "is_spoofing": self.is_spoofing,
            "matched_brand": self.matched_brand,
            "similarity_score": round(self.similarity_score, 2),
            "spoof_type": self.spoof_type,
            "context_bonus": self.context_bonus,
            "details": self.details,
        }


# ── Known Brands & Their Domains ────────────────────

BRAND_DOMAINS: Dict[str, List[str]] = {
    "PayPal":          ["paypal.com"],
    "Google":          ["google.com", "gmail.com", "googleapis.com"],
    "Microsoft":       ["microsoft.com", "outlook.com", "live.com", "office.com"],
    "Apple":           ["apple.com", "icloud.com"],
    "Amazon":          ["amazon.com", "aws.amazon.com"],
    "Netflix":         ["netflix.com"],
    "Facebook":        ["facebook.com", "fb.com"],
    "Instagram":       ["instagram.com"],
    "Twitter":         ["twitter.com", "x.com"],
    "LinkedIn":        ["linkedin.com"],
    "Bank of America": ["bankofamerica.com"],
    "Chase":           ["chase.com"],
    "Wells Fargo":     ["wellsfargo.com"],
    "Dropbox":         ["dropbox.com"],
    "Spotify":         ["spotify.com"],
    "WhatsApp":        ["whatsapp.com"],
}

# Flatten brand keywords for fast matching
_BRAND_KEYWORDS: Dict[str, str] = {}
for brand, domains in BRAND_DOMAINS.items():
    _BRAND_KEYWORDS[brand.lower().replace(" ", "")] = brand
    for dom in domains:
        key = dom.split(".")[0].lower()
        _BRAND_KEYWORDS[key] = brand

# ── Homoglyph Map (characters that look alike) ─────

HOMOGLYPHS: Dict[str, List[str]] = {
    "a": ["4", "@", "q"],
    "b": ["8", "6", "d"],
    "c": ["(", "{", "["],
    "d": ["b", "cl"],
    "e": ["3"],
    "g": ["9", "q"],
    "i": ["1", "l", "!"],
    "l": ["1", "i", "|"],
    "o": ["0"],
    "s": ["5", "$"],
    "t": ["7", "+"],
    "z": ["2"],
}

# ── Context Keywords (boost risk) ───────────────────

CONTEXT_KEYWORDS: Dict[str, int] = {
    "bank":       12,
    "payment":    10,
    "wallet":     10,
    "credit":     10,
    "transfer":   8,
    "invoice":    8,
    "tax":        8,
    "refund":     10,
    "prize":      8,
    "winner":     8,
    "lottery":    10,
    "crypto":     8,
    "bitcoin":    8,
}


class BrandSpoofDetector:
    """
    Detects brand impersonation in URLs through:
    1. Direct brand keyword presence in non-legit domains
    2. Homoglyph substitution (paypa1.com, g00gle.com)
    3. Typosquatting (gooogle.com, paypall.com)
    4. Combo squatting (paypal-secure.com, google-login.xyz)
    5. Subdomain abuse (paypal.evil.com)
    """

    def analyze(self, domain: str, full_url: str) -> SpoofReport:
        report = SpoofReport()

        domain_lower = domain.lower()
        url_lower = full_url.lower()

        # 1. Check if URL is a legitimate domain
        for brand, legit_domains in BRAND_DOMAINS.items():
            for ld in legit_domains:
                if domain_lower == ld or domain_lower.endswith("." + ld):
                    # Legitimate domain - no spoofing
                    return report

        # 2. Brand keyword in non-legit domain (combo squatting)
        for keyword, brand in _BRAND_KEYWORDS.items():
            if keyword in domain_lower and len(keyword) >= 4:
                report.is_spoofing = True
                report.matched_brand = brand
                report.spoof_type = "combo_squat"
                report.similarity_score = 0.7
                report.context_bonus = 15
                report.details.append(
                    f"Domain contains '{keyword}' mimicking {brand} but is not the official domain"
                )
                break

        # 3. Homoglyph detection
        if not report.is_spoofing:
            result = self._check_homoglyph(domain_lower)
            if result:
                report.is_spoofing = True
                report.matched_brand = result[0]
                report.spoof_type = "homoglyph"
                report.similarity_score = result[1]
                report.context_bonus = 20
                report.details.append(
                    f"Domain uses look-alike characters to mimic {result[0]} (similarity: {result[1]:.0%})"
                )

        # 4. Typosquatting detection
        if not report.is_spoofing:
            result = self._check_typosquat(domain_lower)
            if result:
                report.is_spoofing = True
                report.matched_brand = result[0]
                report.spoof_type = "typosquat"
                report.similarity_score = result[1]
                report.context_bonus = 18
                report.details.append(
                    f"Domain is a typo-variant of {result[0]} (edit distance based, similarity: {result[1]:.0%})"
                )

        # 5. Subdomain abuse (paypal.evil.com)
        if not report.is_spoofing:
            for keyword, brand in _BRAND_KEYWORDS.items():
                if len(keyword) >= 4 and keyword in url_lower.split("/")[2] if len(url_lower.split("/")) > 2 else "":
                    parts = domain_lower.split(".")
                    # Brand in subdomain but not in registered domain
                    if any(keyword in p for p in parts[:-2]):
                        report.is_spoofing = True
                        report.matched_brand = brand
                        report.spoof_type = "subdomain_abuse"
                        report.similarity_score = 0.6
                        report.context_bonus = 15
                        report.details.append(
                            f"{brand} appears in subdomain but actual domain is different"
                        )
                        break

        # 6. Context keyword boosting
        context_bonus = 0
        for kw, bonus in CONTEXT_KEYWORDS.items():
            if kw in url_lower:
                context_bonus += bonus
                report.details.append(f"High-risk context keyword: '{kw}' (+{bonus})")

        report.context_bonus += min(context_bonus, 25)

        if report.is_spoofing:
            logger.warning(
                "Brand spoofing detected | brand=%s type=%s similarity=%.2f domain=%s",
                report.matched_brand, report.spoof_type,
                report.similarity_score, domain,
            )

        return report

    def _check_homoglyph(self, domain: str) -> Optional[Tuple[str, float]]:
        """Check if domain uses homoglyph substitution."""
        base = domain.split(".")[0].replace("-", "")

        for brand, legit_domains in BRAND_DOMAINS.items():
            for ld in legit_domains:
                legit_base = ld.split(".")[0]
                if len(base) != len(legit_base):
                    continue

                substitutions = 0
                for i, (c1, c2) in enumerate(zip(base, legit_base)):
                    if c1 == c2:
                        continue
                    # Check if c1 is a homoglyph of c2
                    is_homo = c2 in HOMOGLYPHS and c1 in HOMOGLYPHS[c2]
                    is_reverse = c1 in HOMOGLYPHS and c2 in HOMOGLYPHS[c1]
                    if is_homo or is_reverse:
                        substitutions += 1
                    else:
                        substitutions = 0
                        break

                if substitutions > 0 and substitutions <= 3:
                    similarity = 1.0 - (substitutions / len(legit_base))
                    if similarity >= 0.6:
                        return (brand, similarity)

        return None

    def _check_typosquat(self, domain: str) -> Optional[Tuple[str, float]]:
        """Check if domain is a typo variant using Levenshtein distance."""
        base = domain.split(".")[0]

        for brand, legit_domains in BRAND_DOMAINS.items():
            for ld in legit_domains:
                legit_base = ld.split(".")[0]

                # Only check similar-length strings
                if abs(len(base) - len(legit_base)) > 2:
                    continue

                dist = self._levenshtein(base, legit_base)
                max_len = max(len(base), len(legit_base))

                if 0 < dist <= 2 and max_len >= 4:
                    similarity = 1.0 - (dist / max_len)
                    if similarity >= 0.7:
                        return (brand, similarity)

        return None

    @staticmethod
    def _levenshtein(s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return BrandSpoofDetector._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)

        prev_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row

        return prev_row[-1]

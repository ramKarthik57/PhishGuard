"""
PhishGuard - Phishing Simulation Mode
Generates realistic phishing test samples for security awareness training.
Three difficulty levels: easy (obvious), medium (crafted), hard (sophisticated).
"""

import random
import logging
from typing import Dict, List
from dataclasses import dataclass

logger = logging.getLogger("phishguard.simulator")


@dataclass
class PhishSample:
    """A generated phishing test sample."""
    url: str
    email_subject: str
    email_body: str
    difficulty: str
    attack_type: str
    expected_risk: str           # expected detection level

    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "email_subject": self.email_subject,
            "email_body": self.email_body,
            "difficulty": self.difficulty,
            "attack_type": self.attack_type,
            "expected_risk": self.expected_risk,
        }


class PhishingSimulator:
    """Generate realistic phishing samples for testing and training."""

    # ── Template pools ───────────────────────────────

    _BRANDS = ["PayPal", "Microsoft", "Apple", "Netflix", "Amazon", "Bank of America"]

    _EASY_URLS = [
        "http://{ip}/login/verify-account.html",
        "http://free-{brand}-gift.xyz/claim?id={rand}",
        "http://{brand}-security-alert.top/update-now",
        "http://{ip}/@user/password-reset/{rand}",
    ]

    _MEDIUM_URLS = [
        "http://secure-{brand_lower}.account-verify.club/signin?ref={rand}",
        "http://{sub}.{sub}.{brand_lower}-support.icu/billing/confirm",
        "http://login.{brand_lower}-portal.click/auth/token={rand}",
        "http://{brand_lower}.service-update.buzz/credential/{rand}",
    ]

    _HARD_URLS = [
        "https://{brand_lower}-com.secure-auth.net/login?session={rand}&redirect=true",
        "https://support.{brand_lower}.com-verify.org/account/confirm-identity",
        "https://{brand_lower}.com-account.review/secure/2fa?token={rand}",
        "https://auth.{brand_lower}-services.co/oauth/callback?code={rand}",
    ]

    _EASY_EMAILS = {
        "subject": [
            "URGENT: Your {brand} account has been compromised!!!",
            "WARNING - Verify your {brand} account NOW",
            "You won a free {brand} gift card! Click here!",
        ],
        "body": [
            "Dear User,\n\nYour {brand} account will be SUSPENDED in 24 hours. "
            "Click the link below immediately to verify your identity:\n\n{url}\n\n"
            "If you don't act now, you will lose access permanently!\n\nThe {brand} Team",

            "Dear valued customer,\n\nWe detected unauthorized activity on your account. "
            "Click here to secure it: {url}\n\nYou must act within 2 hours or your "
            "credit card will be charged $499.99.\n\nSincerely, {brand} Security",
        ],
    }

    _MEDIUM_EMAILS = {
        "subject": [
            "Action Required: Verify your {brand} account",
            "Your {brand} subscription payment failed",
            "{brand} Security Alert - Unusual sign-in activity",
        ],
        "body": [
            "Hello,\n\nWe noticed unusual activity on your {brand} account from a new device. "
            "For your security, please verify your identity:\n\n{url}\n\n"
            "If this wasn't you, please secure your account immediately.\n\nBest regards,\n"
            "{brand} Account Security",

            "Dear Customer,\n\nYour recent payment for {brand} subscription could not be processed. "
            "Please update your billing information to avoid service interruption:\n\n{url}\n\n"
            "Thank you for your prompt attention.\n\n{brand} Billing Department",
        ],
    }

    _HARD_EMAILS = {
        "subject": [
            "Re: Your recent {brand} order #ORD-{rand}",
            "FW: {brand} Two-Factor Authentication Update",
            "Your {brand} account security review is complete",
        ],
        "body": [
            "Hi,\n\nFollowing our recent security review, we've implemented enhanced "
            "two-factor authentication across all {brand} accounts. To ensure uninterrupted "
            "access, please complete the verification process at your earliest convenience:\n\n"
            "{url}\n\nThis update is part of our ongoing commitment to protecting your data "
            "in compliance with GDPR and SOC 2 Type II standards.\n\nWarm regards,\n"
            "Sarah Mitchell\nSenior Account Security Analyst\n{brand} Trust & Safety",

            "Hello,\n\nWe noticed a sign-in to your {brand} account from a new location "
            "(San Jose, CA). If this was you, no action is needed.\n\n"
            "If you don't recognize this activity, review your account security settings:\n\n"
            "{url}\n\nFor reference, this notification was generated per your security "
            "preferences (ID: {rand}).\n\nThe {brand} Identity Team",
        ],
    }

    _ATTACK_TYPES = {
        "easy":   ["credential_harvest", "fake_giveaway", "account_suspension"],
        "medium": ["billing_fraud", "session_hijack", "fake_security_alert"],
        "hard":   ["spear_phishing", "oauth_abuse", "brand_impersonation"],
    }

    # ── Generation ───────────────────────────────────

    def generate(self, difficulty: str = "medium", count: int = 3) -> List[PhishSample]:
        difficulty = difficulty.lower()
        if difficulty not in ("easy", "medium", "hard"):
            difficulty = "medium"
        count = min(count, 10)

        samples = []
        for _ in range(count):
            samples.append(self._generate_one(difficulty))
        return samples

    def _generate_one(self, difficulty: str) -> PhishSample:
        brand = random.choice(self._BRANDS)
        brand_lower = brand.lower().replace(" ", "")

        helpers = {
            "brand": brand,
            "brand_lower": brand_lower,
            "ip": ".".join(str(random.randint(1, 254)) for _ in range(4)),
            "sub": self._rand_str(random.randint(3, 7)),
            "rand": self._rand_hex(random.randint(8, 16)),
        }

        # Select templates by difficulty
        if difficulty == "easy":
            url_templates = self._EASY_URLS
            email_pool = self._EASY_EMAILS
            expected_risk = "HIGH"
        elif difficulty == "hard":
            url_templates = self._HARD_URLS
            email_pool = self._HARD_EMAILS
            expected_risk = "MEDIUM"
        else:
            url_templates = self._MEDIUM_URLS
            email_pool = self._MEDIUM_EMAILS
            expected_risk = "HIGH"

        url = random.choice(url_templates).format(**helpers)
        subject = random.choice(email_pool["subject"]).format(**helpers)
        body = random.choice(email_pool["body"]).format(url=url, **helpers)
        attack = random.choice(self._ATTACK_TYPES[difficulty])

        return PhishSample(
            url=url,
            email_subject=subject,
            email_body=body,
            difficulty=difficulty,
            attack_type=attack,
            expected_risk=expected_risk,
        )

    @staticmethod
    def _rand_str(length: int) -> str:
        return "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=length))

    @staticmethod
    def _rand_hex(length: int) -> str:
        return "".join(random.choices("0123456789abcdef", k=length))

"""
PhishGuard - Interactive Phishing Training Mode
Generates quiz challenges mixing safe and phishing URLs.
Users guess, then receive the correct answer with detailed explanations.
"""

import random
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("phishguard.training")


@dataclass
class QuizChallenge:
    """A single training quiz challenge."""
    challenge_id: int
    url: str
    email_subject: Optional[str]
    email_body: Optional[str]
    correct_answer: str            # "safe" | "phishing"
    difficulty: str                # easy | medium | hard
    hint: str

    def to_dict(self) -> Dict:
        return {
            "challenge_id": self.challenge_id,
            "url": self.url,
            "email_subject": self.email_subject,
            "email_body": self.email_body,
            "difficulty": self.difficulty,
            "hint": self.hint,
        }


@dataclass
class QuizResult:
    """Evaluation of a user's guess."""
    challenge_id: int
    user_answer: str
    correct_answer: str
    is_correct: bool
    explanation: str
    indicators: List[str]
    risk_score: int
    risk_level: str

    def to_dict(self) -> Dict:
        return {
            "challenge_id": self.challenge_id,
            "user_answer": self.user_answer,
            "correct_answer": self.correct_answer,
            "is_correct": self.is_correct,
            "explanation": self.explanation,
            "indicators": self.indicators,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
        }


# ── Challenge Templates ─────────────────────────────

_SAFE_URLS = [
    {"url": "https://www.google.com/search?q=cybersecurity+best+practices",
     "subject": None, "body": None,
     "explanation": "This is a legitimate Google search URL using HTTPS on the official google.com domain.",
     "indicators": ["Official google.com domain", "Uses HTTPS encryption", "Standard search query parameters"]},

    {"url": "https://github.com/user/awesome-python",
     "subject": None, "body": None,
     "explanation": "This is a legitimate GitHub repository URL on the official github.com domain.",
     "indicators": ["Official github.com domain", "Uses HTTPS", "Standard repository URL structure"]},

    {"url": "https://docs.microsoft.com/en-us/azure/security/",
     "subject": "Your Azure subscription renewal", "body": "Hi Team,\n\nYour Azure subscription has been renewed successfully for the next billing cycle. No action is required.\n\nYou can review your billing details at https://portal.azure.com\n\nThank you,\nAzure Billing Team",
     "explanation": "This is a legitimate Microsoft docs URL and the email uses proper personalization with no urgency tactics.",
     "indicators": ["Official microsoft.com subdomain", "HTTPS", "No urgency language", "Professional tone"]},

    {"url": "https://www.python.org/downloads/release/python-3120/",
     "subject": None, "body": None,
     "explanation": "This is the official Python download page on python.org.",
     "indicators": ["Official python.org domain", "HTTPS", "Standard download path"]},

    {"url": "https://stackoverflow.com/questions/12345/how-to-use-python-requests",
     "subject": None, "body": None,
     "explanation": "This is a standard StackOverflow question page on the official domain.",
     "indicators": ["Official stackoverflow.com domain", "HTTPS", "Standard question ID pattern"]},

    {"url": "https://linkedin.com/in/john-doe-security",
     "subject": "New connection request", "body": "Hi,\n\nJane Smith wants to connect with you on LinkedIn.\n\nView profile: https://linkedin.com/in/jane-smith\n\nLinkedIn Notifications",
     "explanation": "Legitimate LinkedIn profile URL and standard connection notification.",
     "indicators": ["Official linkedin.com domain", "HTTPS", "Standard profile path", "No requests for credentials"]},
]

_PHISHING_EASY = [
    {"url": "http://192.168.1.100/paypal/login",
     "subject": "Your PayPal account has been limited", "body": "Dear User,\n\nYour PayPal account has been LIMITED due to suspicious activity. Click the link below IMMEDIATELY to restore access:\n\nhttp://192.168.1.100/paypal/login\n\nIf you do not act within 24 hours, your account will be permanently SUSPENDED.\n\nPayPal Security",
     "explanation": "This is a phishing attack using an IP address instead of a domain, impersonating PayPal with urgent language and threats.",
     "indicators": ["IP address instead of domain name", "Impersonates PayPal", "Missing HTTPS", "Urgency and threats", "Generic greeting 'Dear User'"]},

    {"url": "http://free-iphone-giveaway.xyz/claim-now?id=829371",
     "subject": "YOU WON! Claim your FREE iPhone 16!", "body": "Congratulations!!!\n\nYou have been selected as the WINNER of our iPhone 16 giveaway! Click here NOW to claim your prize:\n\nhttp://free-iphone-giveaway.xyz/claim-now\n\nOffer expires in 1 hour!!!",
     "explanation": "Classic giveaway scam using suspicious .xyz TLD, excessive urgency, and too-good-to-be-true promises.",
     "indicators": ["Suspicious .xyz TLD", "Too-good-to-be-true offer", "Extreme urgency", "No HTTPS", "Excessive punctuation"]},
]

_PHISHING_MEDIUM = [
    {"url": "http://secure-paypal-verification.click/account/login?ref=user2847",
     "subject": "Action Required: Verify your PayPal account", "body": "Hello,\n\nWe noticed unusual activity on your PayPal account from a new device. For your security, please verify your identity:\n\nhttp://secure-paypal-verification.click/account/login?ref=user2847\n\nIf this wasn't you, please secure your account immediately.\n\nBest regards,\nPayPal Account Security",
     "explanation": "Brand impersonation using 'paypal' keyword in a fake domain with a suspicious .click TLD. The real PayPal URL would be paypal.com.",
     "indicators": ["Contains 'paypal' but NOT on paypal.com", "Suspicious .click TLD", "Hyphens mimicking official subdomain", "No HTTPS", "Social engineering language"]},

    {"url": "http://login.microsoft-365-portal.club/oauth/signin",
     "subject": "Microsoft 365: Password expires in 24 hours", "body": "Dear User,\n\nYour Microsoft 365 password will expire in 24 hours. To continue using your account, please update your password now:\n\nhttp://login.microsoft-365-portal.club/oauth/signin\n\nMicrosoft Support Team",
     "explanation": "Fake Microsoft login page using 'microsoft' keyword in a non-Microsoft domain with .club TLD.",
     "indicators": ["Contains 'microsoft' but NOT on microsoft.com", "Suspicious .club TLD", "Excessive hyphens", "Password expiry urgency", "No HTTPS"]},
]

_PHISHING_HARD = [
    {"url": "https://paypa1.com/signin?token=a8f3c2d1e5",
     "subject": "Re: Your recent PayPal transaction #PP-7829463", "body": "Hi,\n\nWe noticed a charge of $849.99 to an unknown merchant. If you did not authorize this transaction, please review your account:\n\nhttps://paypa1.com/signin?token=a8f3c2d1e5\n\nFor your reference, this notification was generated per your security preferences (ID: PP-7829463).\n\nBest,\nPayPal Trust & Safety",
     "explanation": "Sophisticated homoglyph attack: 'paypa1.com' uses the number '1' instead of letter 'l'. The email uses specific transaction IDs and professional tone to appear legitimate.",
     "indicators": ["Homoglyph attack: paypa1 vs paypal (1 vs l)", "Specific dollar amount creates panic", "Professional tone with fake transaction ID", "Uses HTTPS to appear trustworthy"]},

    {"url": "https://apple.com-id-verify.net/account/security",
     "subject": "Your Apple ID was used to sign in on a new device", "body": "Dear Customer,\n\nYour Apple ID (j***@gmail.com) was used to sign in to iCloud via a web browser.\n\nDate: April 3, 2026\nLocation: San Jose, CA\nBrowser: Chrome on Windows\n\nIf this was you, no action is needed. If you don't recognize this activity:\n\nhttps://apple.com-id-verify.net/account/security\n\nApple Support",
     "explanation": "Combo-squatting: domain 'apple.com-id-verify.net' makes it look like apple.com but the actual domain is 'com-id-verify.net'. The email includes realistic details like partial email masking and location data.",
     "indicators": ["Actual domain is com-id-verify.net, NOT apple.com", "Partial email masking creates false credibility", "Realistic device and location details", "Uses HTTPS to appear legitimate"]},
]


class TrainingQuizEngine:
    """Generates and evaluates phishing awareness training quizzes."""

    def __init__(self):
        self._challenges: Dict[int, Dict] = {}
        self._counter = 0
        self._session_scores: Dict[str, Dict] = {}

    def generate_quiz(self, difficulty: str = "mixed", count: int = 5) -> List[QuizChallenge]:
        """Generate a quiz with a mix of safe and phishing challenges."""
        count = min(count, 10)
        challenges = []

        if difficulty == "mixed":
            # Mix of safe and phishing at various difficulties
            safe_count = max(1, count // 3)
            phish_count = count - safe_count
            pool = []
            pool += [(s, "safe", "easy") for s in random.sample(_SAFE_URLS, min(safe_count, len(_SAFE_URLS)))]
            phish_pool = _PHISHING_EASY + _PHISHING_MEDIUM + _PHISHING_HARD
            pool += [(p, "phishing", "medium") for p in random.sample(phish_pool, min(phish_count, len(phish_pool)))]
            random.shuffle(pool)
        elif difficulty == "easy":
            safe = random.sample(_SAFE_URLS, min(2, len(_SAFE_URLS)))
            phish = random.sample(_PHISHING_EASY, min(count - 2, len(_PHISHING_EASY)))
            pool = [(s, "safe", "easy") for s in safe] + [(p, "phishing", "easy") for p in phish]
            random.shuffle(pool)
        elif difficulty == "hard":
            safe = random.sample(_SAFE_URLS, min(1, len(_SAFE_URLS)))
            phish = random.sample(_PHISHING_HARD, min(count - 1, len(_PHISHING_HARD)))
            pool = [(s, "safe", "hard") for s in safe] + [(p, "phishing", "hard") for p in phish]
            random.shuffle(pool)
        else:
            safe = random.sample(_SAFE_URLS, min(2, len(_SAFE_URLS)))
            phish = random.sample(_PHISHING_MEDIUM, min(count - 2, len(_PHISHING_MEDIUM)))
            pool = [(s, "safe", "medium") for s in safe] + [(p, "phishing", "medium") for p in phish]
            random.shuffle(pool)

        for item, answer, diff in pool:
            self._counter += 1
            cid = self._counter

            # Generate contextual hint
            if answer == "safe":
                hint = "Look at the domain carefully. Is it an official, well-known website?"
            else:
                hint = "Check for: unusual domains, missing HTTPS, urgency language, or brand mimicking."

            ch = QuizChallenge(
                challenge_id=cid,
                url=item["url"],
                email_subject=item.get("subject"),
                email_body=item.get("body"),
                correct_answer=answer,
                difficulty=diff,
                hint=hint,
            )
            # Store full data for evaluation
            self._challenges[cid] = {**item, "correct_answer": answer, "difficulty": diff}
            challenges.append(ch)

        return challenges

    def evaluate(self, challenge_id: int, user_answer: str) -> Optional[QuizResult]:
        """Evaluate a user's guess and return detailed feedback."""
        data = self._challenges.get(challenge_id)
        if not data:
            return None

        correct = data["correct_answer"]
        is_correct = user_answer.lower().strip() == correct

        if correct == "safe":
            risk_score = 0
            risk_level = "LOW"
        elif data["difficulty"] == "easy":
            risk_score = 90
            risk_level = "HIGH"
        elif data["difficulty"] == "hard":
            risk_score = 65
            risk_level = "HIGH"
        else:
            risk_score = 78
            risk_level = "HIGH"

        return QuizResult(
            challenge_id=challenge_id,
            user_answer=user_answer.lower().strip(),
            correct_answer=correct,
            is_correct=is_correct,
            explanation=data.get("explanation", ""),
            indicators=data.get("indicators", []),
            risk_score=risk_score,
            risk_level=risk_level,
        )

    def get_session_score(self, session_id: str) -> Dict:
        return self._session_scores.get(session_id, {"correct": 0, "total": 0, "streak": 0})

    def update_session_score(self, session_id: str, is_correct: bool) -> Dict:
        if session_id not in self._session_scores:
            self._session_scores[session_id] = {"correct": 0, "total": 0, "streak": 0, "best_streak": 0}

        s = self._session_scores[session_id]
        s["total"] += 1
        if is_correct:
            s["correct"] += 1
            s["streak"] += 1
            s["best_streak"] = max(s["best_streak"], s["streak"])
        else:
            s["streak"] = 0

        s["accuracy"] = round(s["correct"] / s["total"] * 100, 1) if s["total"] > 0 else 0
        return s

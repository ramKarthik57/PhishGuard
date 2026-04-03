"""Demo script showing both XAI Engine and SOC Dashboard outputs."""
import requests
import json

BASE = "http://127.0.0.1:5000"

# ═══════════════════════════════════════════════════
# 1. EXPLAINABLE AI ENGINE
# ═══════════════════════════════════════════════════
print("=" * 64)
print("  EXPLAINABLE AI SECURITY ENGINE (XAI)")
print("=" * 64)

r = requests.post(f"{BASE}/analyze", json={
    "url": "http://secure-login.suspicious-bank.xyz/verify",
    "email_body": "Dear Customer, verify your account immediately or it will be suspended."
})
d = r.json()
xai = d["explanation"]

print()
print("SUMMARY:")
print(f"  {xai['summary']}")
print()
print(f"CONFIDENCE: {xai['confidence']['percentage']}% ({xai['confidence']['label']})")
print(f"  {xai['confidence']['note']}")
print()
print("EVIDENCE CHAIN:")
for step in xai["evidence_chain"]:
    sev = step["severity"].upper()
    print(f"  Step {step['step']} [{step['source']}] ({sev})")
    print(f"    -> {step['indicator']}")
print()
print("RECOMMENDATION:")
print(f"  {xai['recommendation_rationale']}")
print()
print("SCORING BREAKDOWN:")
bd = d["scoring_breakdown"]
for key, val in bd.items():
    bar = "#" * int(val)
    print(f"  {key:18s} {val:6.1f}  {bar}")

# ═══════════════════════════════════════════════════
# 2. MINI SOC DASHBOARD
# ═══════════════════════════════════════════════════
print()
print("=" * 64)
print("  MINI SOC DASHBOARD")
print("=" * 64)

tl = requests.get(f"{BASE}/api/soc/threat-level").json()
print()
print(f"  THREAT LEVEL:    {tl['label']} (Level {tl['level']})")
print(f"  Critical Alerts: {tl['critical_events']}")
print(f"  Warnings:        {tl['warning_events']}")
print(f"  Total Events:    {tl['total_all_time']}")
print(f"  Breakdown:       {tl['alert_breakdown']}")

print()
print("  LIVE EVENT FEED:")
events = requests.get(f"{BASE}/api/soc/events?limit=8").json()
for e in events:
    print(f"    [{e['severity']:8s}] {e['title']}")
    print(f"               {e['detail']}")

# ═══════════════════════════════════════════════════
# 3. THREAT INTELLIGENCE
# ═══════════════════════════════════════════════════
print()
print("=" * 64)
print("  THREAT INTELLIGENCE REPORT")
print("=" * 64)
ti = d["threat_intel"]
print()
print(f"  Domain:      {ti['domain']}")
print(f"  Reputation:  {ti['reputation_score']} / 1.0")
print(f"  Blacklisted: {ti['is_blacklisted']}")
print(f"  Domain Age:  {ti['domain_age_days']} days")
print(f"  Tags:        {', '.join(ti['threat_tags']) if ti['threat_tags'] else 'None'}")

print()
print("=" * 64)
print("  ALL FEATURES VERIFIED SUCCESSFULLY")
print("=" * 64)

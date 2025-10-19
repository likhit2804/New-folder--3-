import random

def check_threat_feeds(resource):
    # Mock logic for now
    # Later: integrate with real feeds like NVD, VirusTotal, etc.
    simulated_risk = random.choice(['low', 'medium', 'high'])
    return {
        'feed': 'mock-threat-feed',
        'risk_level': simulated_risk,
        'evidence': f"Simulated evidence for {resource['name']}"
    }

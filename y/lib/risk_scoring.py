def calculate_risk(resource, threat_data):
    base = {'low': 2, 'medium': 5, 'high': 8}.get(threat_data['risk_level'], 1)
    exposure = 1.5 if 'public' in str(resource).lower() else 1.0
    impact = 1.2 if 'database' in resource['type'] else 1.0
    score = round(base * exposure * impact, 2)
    return score

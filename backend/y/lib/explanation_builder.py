def build_explanation(resource, threat_data, risk_score):
    return {
        'resource_name': resource['name'],
        'resource_type': resource['type'],
        'risk_score': risk_score,
        'threat_feed': threat_data['feed'],
        'evidence': threat_data['evidence'],
        'calculation_log': f"Base: {threat_data['risk_level']}, Exposure: {'public' if 'public' in str(resource).lower() else 'private'}",
    }

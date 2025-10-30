def calculate_risk(resource, confirmed_findings_list):
    """
    Calculates a final risk score based on the list of confirmed findings.
    """
    if not confirmed_findings_list:
        return "LOW"

    # Define the priority of each risk level
    risk_priority = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
    highest_risk = 0
    
    # Loop through all findings to find the highest risk level
    for finding in confirmed_findings_list:
        # risk_level is set by the adapter or correlation_engine
        level = finding.get('risk_level', 'LOW').upper()
        risk_val = risk_priority.get(level, 1)
        if risk_val > highest_risk:
            highest_risk = risk_val

    # Return the string corresponding to the highest risk found
    if highest_risk == 4:
        return "CRITICAL"
    if highest_risk == 3:
        return "HIGH"
    if highest_risk == 2:
        return "MEDIUM"
    
    return "LOW"
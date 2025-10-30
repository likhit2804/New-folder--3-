def build_explanation(resource, confirmed_findings_list, final_risk_score):
    """
    Builds a single "explanation object" for the resource,
    summarizing all confirmed findings from the list.
    """
    
    # This is the main object that will be in the final 'results_json'
    explanation = {
        # 'name' and 'type' might not exist on all resources, 
        # use .get() for safety
        "resource_id": resource.get('name', 'unknown_resource'),
        "resource_type": resource.get('type', 'unknown_type'),
        "risk_score": final_risk_score,
        "details": f"Found {len(confirmed_findings_list)} correlated threat(s).",
        "findings": [], # A list to hold all individual findings
        "threat_source": "CorrelationEngine"
    }

    # Add details from each confirmed finding to the list
    for finding in confirmed_findings_list:
        explanation['findings'].append({
            "feed": finding.get('feed', 'unknown'),
            "risk_level": finding.get('risk_level', 'LOW'),
            "evidence": finding.get('evidence', 'N/A')
        })

    # Set a more descriptive top-level detail if the risk is high
    if final_risk_score == "CRITICAL" or final_risk_score == "HIGH":
        if explanation['findings']:
            highest_finding = explanation['findings'][0]
            # Use .get() for safety, as 'evidence' might not always exist
            details = highest_finding.get('evidence', 'No evidence detail.')
            explanation['details'] = f"High-risk threat detected: {details}"
        else:
            explanation['details'] = "High-risk threat detected, but finding list was empty."
            
    return explanation
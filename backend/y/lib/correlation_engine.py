import json

def correlate_threats(parsed_resource, threat_data_list):
    """
    Applies contextual confirmation logic to raw threat data against
    a specific parsed IaC resource.
    
    This is the "Correlation Engine" described in Phase II, Step 2.
    It reduces false positives by confirming context.
    
    NOTE: 'threat_data_list' is the list of finding dicts from threat_adapters.
    """
    confirmed_findings = []
    
    # We assume 'is_public' is a boolean flag set by the parser
    # based on CIDRs like '0.0.0.0/0' or security group rules.
    is_publicly_accessible = parsed_resource.get('is_public', False)
            
    # Loop through all findings from the threat adapters
    for threat in threat_data_list:
        
        # ---
        # Correlation Example 1: Blocklisted IPs
        # ---
        if threat.get('feed') == 'abuseipdb':
            # CONTEXT CHECK: Is the resource public?
            if is_publicly_accessible:
                # If the resource is public AND we found a bad IP, it's a confirmed finding
                threat['details'] = f"Resource {parsed_resource.get('resource_id')} is publicly exposed AND is associated with a blocklisted IP."
                threat['risk_level'] = 'HIGH' # Escalate risk due to context
                confirmed_findings.append(threat)
            else:
                # Not public, but a bad IP is still medium risk
                threat['risk_level'] = 'MEDIUM'
                threat['details'] = f"Resource {parsed_resource.get('resource_id')} is internal but associated with a blocklisted IP."
                confirmed_findings.append(threat)

        # ---
        # Correlation Example 2: Vulnerable AMI (Placeholder from plan)
        # ---
        elif threat.get('feed') == 'nvd': # Assuming you add an 'nvd' feed
            if is_publicly_accessible:
                threat['details'] = f"Resource {parsed_resource.get('resource_id')} uses a vulnerable AMI AND is publicly accessible."
                threat['risk_level'] = 'CRITICAL'
                confirmed_findings.append(threat)
            else:
                threat['details'] = f"Resource {parsed_resource.get('resource_id')} uses a vulnerable AMI but is internal."
                threat['risk_level'] = 'MEDIUM'
                confirmed_findings.append(threat)
        
        # ---
        # Fallback: If no specific correlation logic, just add the threat
        # ---
        else:
            confirmed_findings.append(threat)

    return confirmed_findings
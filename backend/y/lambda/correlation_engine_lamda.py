import json

def correlate_threats(parsed_resource, threat_data):
    """
    Applies contextual confirmation logic to raw threat data against
    a specific parsed IaC resource.
    
    This is the "Correlation Engine" described in Phase II, Step 2[cite: 251].
    It reduces false positives by confirming context[cite: 254, 255].
    """
    confirmed_findings = []
    
    # We assume 'is_public' is a boolean flag set by the parser [cite: 229, 233]
    # based on CIDRs like '0.0.0.0/0' or security group rules.
    is_publicly_accessible = parsed_resource.get('is_public', False)
            
    # ---
    # Correlation Example 1: Blocklisted IPs 
    # ---
    if 'ip_blocklist' in threat_data and threat_data['ip_blocklist']:
        resource_cidrs = parsed_resource.get('cidr_blocks', [])
        resource_ports = parsed_resource.get('exposed_ports', [])
        
        # CONTEXT CHECK: Is the resource public?
        if is_publicly_accessible:
            for bad_ip_data in threat_data['ip_blocklist']:
                # This is a simple example. A real implementation would
                # check for overlapping CIDR ranges.
                if bad_ip_data.get('ip') in resource_cidrs:
                    finding = {
                        'type': 'EXPOSED_BLOCKLISTED_IP',
                        'resource_id': parsed_resource.get('resource_id'),
                        'details': f"Resource {parsed_resource.get('resource_id')} is publicly exposed on ports {resource_ports} and its allowed CIDRs include a known malicious IP: {bad_ip_data.get('ip')}",
                        'threat_source': bad_ip_data.get('source'),
                        'raw_evidence': bad_ip_data
                    }
                    confirmed_findings.append(finding)

    # ---
    # Correlation Example 2: Vulnerable AMI 
    # ---
    if 'cve_details' in threat_data and threat_data['cve_details']:
        
        # CONTEXT CHECK: Is the resource public?
        if is_publicly_accessible:
            # If the resource is public, *all* its CVEs are contextually significant
            for cve in threat_data['cve_details']:
                finding = {
                    'type': 'PUBLIC_VULNERABLE_AMI',
                    'resource_id': parsed_resource.get('resource_id'),
                    'details': f"Resource {parsed_resource.get('resource_id')} uses AMI {parsed_resource.get('ami_id')} which has known vulnerability {cve.get('id')} and is publicly accessible.",
                    'threat_source': 'NVD', # Or wherever cve_details came from
                    'raw_evidence': cve,
                    'base_score': cve.get('cvss_score', 7.0) # Pass score to risk_scoring
                }
                confirmed_findings.append(finding)
        else:
            # Resource is not public. We might still care about CRITICAL CVEs,
            # but the context is different.
            for cve in threat_data['cve_details']:
                if cve.get('cvss_score', 0) >= 9.0:
                     finding = {
                        'type': 'INTERNAL_VULNERABLE_AMI',
                        'resource_id': parsed_resource.get('resource_id'),
                        'details': f"Resource {parsed_resource.get('resource_id')} uses AMI {parsed_resource.get('ami_id')} with CRITICAL vulnerability {cve.get('id')}. Resource is internal, but this warrants review.",
                        'threat_source': 'NVD',
                        'raw_evidence': cve,
                        'base_score': cve.get('cvss_score', 9.0)
                    }
                     confirmed_findings.append(finding)

    # Add more correlation logic here for other resource types or threats...

    return confirmed_findings
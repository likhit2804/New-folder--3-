import os
import json
import time
import boto3
import requests # Make sure 'requests' is in backend/y/requirements.txt
import traceback # For detailed error logging in API calls
import ipaddress # For IP address validation and filtering

# --- Cache Setup ---
# Get the cache table name from environment variable, default to None if not set
DYNAMODB_CACHE_TABLE_NAME = os.environ.get('CACHE_TABLE_NAME')
CACHE_TTL_SECONDS = 3600 # Cache items for 1 hour

dynamodb = boto3.resource('dynamodb')
cache_table = None # Initialize as None

# Only try to connect if the table name is explicitly provided via environment variable
if DYNAMODB_CACHE_TABLE_NAME:
    try:
        print(f"DEBUG: Attempting to connect to cache table: {DYNAMODB_CACHE_TABLE_NAME}")
        cache_table = dynamodb.Table(DYNAMODB_CACHE_TABLE_NAME)
        cache_table.load() # Check if table exists/is accessible
        print(f"DEBUG: Successfully connected to cache table: {DYNAMODB_CACHE_TABLE_NAME}")
    except Exception as e:
        print(f"Warning: Could not connect to cache table '{DYNAMODB_CACHE_TABLE_NAME}'. Caching disabled. Error: {e}")
        cache_table = None
else:
    print("DEBUG: CACHE_TABLE_NAME environment variable not set. Caching disabled.")


def get_cached_threat(cache_key):
    """Retrieves threat data from DynamoDB cache if available and not expired."""
    if not cache_table:
        print("DEBUG: Cache is disabled, skipping cache get.")
        return None
    try:
        print(f"DEBUG: Cache GET attempt for key: {cache_key}")
        response = cache_table.get_item(Key={'cache_key': cache_key})
        item = response.get('Item')
        if item:
            expires_at = item.get('expires_at', 0)
            if expires_at > time.time():
                print(f"DEBUG: Cache HIT for key: {cache_key}")
                # Ensure data is loaded correctly from the stored JSON string
                return json.loads(item.get('data', '{}'))
            else:
                print(f"DEBUG: Cache EXPIRED for key: {cache_key}")
        else:
            print(f"DEBUG: Cache MISS for key: {cache_key}")
    except Exception as e:
        print(f"Error reading from cache for key {cache_key}: {e}")
    return None

def set_cached_threat(cache_key, data):
    """Stores threat data into DynamoDB cache with a TTL."""
    if not cache_table:
        print("DEBUG: Cache is disabled, skipping cache set.")
        return
    try:
        expires_at = int(time.time() + CACHE_TTL_SECONDS)
        print(f"DEBUG: Cache SET attempt for key: {cache_key} with TTL: {CACHE_TTL_SECONDS}s")
        # Ensure data is stored as a JSON string
        item_data_str = json.dumps(data)
        cache_table.put_item(
            Item={
                'cache_key': cache_key,
                'data': item_data_str,
                'expires_at': expires_at
            }
        )
        print(f"DEBUG: Cache SET successful for key: {cache_key}")
    except Exception as e:
        print(f"Error writing to cache for key {cache_key}: {e}")
        # Optionally log the data that failed to cache (be mindful of size/sensitivity)
        # print(f"DEBUG: Failed cache data: {item_data_str}")


# --- Helper Function for IP Extraction ---
def _extract_ips_recursive(data):
    """Helper to find potential public IPv4/IPv6 addresses recursively in nested data."""
    ips = set()
    if isinstance(data, str):
        try:
            # Check if it looks like an IP or CIDR before parsing
            if '.' in data or ':' in data:
                ip_part = data.split('/')[0] # Get the IP part from potential CIDR
                ip_obj = ipaddress.ip_address(ip_part)
                # Filter out private, loopback, link-local, multicast, unspecified
                if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified):
                    ips.add(str(ip_obj))
        except ValueError:
            pass # Not a valid IP address string
    elif isinstance(data, list):
        for item in data:
            ips.update(_extract_ips_recursive(item))
    elif isinstance(data, dict):
        for key, value in data.items():
             # Avoid searching keys themselves, focus on values
             ips.update(_extract_ips_recursive(value))
    return ips

# --- Threat Feed Functions ---

def check_nvd(resource_type):
    """Checks the NVD API for high/critical CVEs related to a resource type."""
    if not resource_type:
        print("WARN: No resource_type provided for NVD check.")
        return None

    cache_key = f"nvd_{resource_type.lower()}" # Use lowercase for consistency
    cached_data = get_cached_threat(cache_key)
    if cached_data:
        return cached_data

    print(f"DEBUG: Checking NVD API for resource type: {resource_type}")

    NVD_API_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_API_KEY = "" # Get API key from environment variables

    headers = {'Accept': 'application/json'}
    if NVD_API_KEY:
        print("DEBUG: Using NVD API Key.")
        headers['apiKey'] = NVD_API_KEY
    else:
        print("INFO: NVD_API_KEY environment variable not set. Proceeding without API key (rate limits may apply).")

    # Search for the resource type, limit results, focus on High/Critical
    params = {'keywordSearch': resource_type, 'resultsPerPage': 5, 'cvssV3Severity': 'HIGH,CRITICAL'}

    result = None
    response = None # Initialize response to None
    try:
        print(f"DEBUG: Calling NVD API: GET {NVD_API_ENDPOINT} with params {params}")
        response = requests.get(NVD_API_ENDPOINT, headers=headers, params=params, timeout=20) # 20 second timeout
        print(f"DEBUG: NVD API response status code: {response.status_code}")
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        data = response.json()
        print(f"DEBUG: NVD API response data (structure): Keys={list(data.keys())}, TotalResults={data.get('totalResults')}")
        vulnerabilities = data.get('vulnerabilities', [])
        total_results = data.get('totalResults', 0)

        if vulnerabilities:
            count = len(vulnerabilities)
            highest_cvss_v3_score = 0.0
            highest_severity = 'NONE' # Start with lowest severity

            for vuln in vulnerabilities:
                cve_item = vuln.get('cve', {})
                metrics = cve_item.get('metrics', {})
                # Prioritize CVSS v3.1, then v3.0
                cvss_metrics_v31 = metrics.get('cvssMetricV31', [])
                cvss_metrics_v30 = metrics.get('cvssMetricV30', [])
                cvss_data_list = cvss_metrics_v31 or cvss_metrics_v30

                if cvss_data_list:
                    # NVD API returns a list, usually with one item per version
                    metric_data = cvss_data_list[0].get('cvssData', {})
                    score = metric_data.get('baseScore', 0.0)
                    severity = metric_data.get('baseSeverity', 'NONE').upper() # Ensure uppercase

                    # Track the highest score and severity found
                    if score > highest_cvss_v3_score:
                        highest_cvss_v3_score = score
                        highest_severity = severity

            # Map NVD severity to our internal risk levels
            risk = highest_severity.lower()
            if risk == 'critical':
                risk = 'high'
            elif risk not in ['low', 'medium', 'high']:
                risk = 'low' # Default to low if severity is NONE or unknown

            evidence = f"Found {total_results} CVEs ({count} high/critical in first page) related to '{resource_type}' in NVD. Highest Severity: {highest_severity} (Score: {highest_cvss_v3_score})."
            result = {'feed': 'nvd', 'risk_level': risk, 'evidence': evidence}
        else:
            result = {'feed': 'nvd', 'risk_level': 'low', 'evidence': f"No significant CVEs found for keyword '{resource_type}' in NVD."}

        print(f"DEBUG: NVD check result: {json.dumps(result)}")

    except requests.exceptions.Timeout:
        print(f"ERROR: NVD API request timed out for {resource_type}")
        result = {'feed': 'nvd', 'risk_level': 'low', 'evidence': 'API Timeout'}
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Error calling NVD API for {resource_type}: {e}")
        error_details = f'API Error: {e}'
        # Log response text if available for non-timeout errors
        if response is not None:
             error_details += f" | Status: {response.status_code} | Response: {response.text[:500]}" # Log first 500 chars
             print(f"DEBUG: NVD API error response text: {response.text[:500]}")
        result = {'feed': 'nvd', 'risk_level': 'low', 'evidence': error_details}
    except json.JSONDecodeError as e:
        print(f"ERROR: Failed to decode JSON response from NVD API for {resource_type}: {e}")
        response_text = response.text[:500] if response else "No response object"
        print(f"DEBUG: NVD API raw response text: {response_text}")
        result = {'feed': 'nvd', 'risk_level': 'low', 'evidence': f'API JSON Decode Error: {response_text}'}
    except Exception as e: # Catch any other unexpected errors
        print(f"ERROR: Unexpected error during NVD check for {resource_type}: {e}\n{traceback.format_exc()}")
        result = {'feed': 'nvd', 'risk_level': 'low', 'evidence': f'Unexpected Error: {e}'}

    # Cache the result, whether successful or an error indicator
    if result:
        set_cached_threat(cache_key, result)

    return result


def check_abuseipdb(resource):
    """Checks IPs found in the resource against the AbuseIPDB API."""
    unique_ips = set()
    resource_name = resource.get('name', 'unknown_resource')
    resource_type = resource.get('type', 'unknown_type')
    try:
        print(f"DEBUG: Starting IP extraction for resource: {resource_name} ({resource_type})")
        # Search within the 'change' or 'values' part of the resource data
        search_data = resource.get('change', {}) or resource.get('values', {})
        unique_ips = _extract_ips_recursive(search_data)
    except Exception as e:
        print(f"ERROR: Failed during IP extraction for resource {resource_name}: {e}\n{traceback.format_exc()}")

    print(f"DEBUG: Found unique public IPs to check in resource {resource_name}: {list(unique_ips)}")
    if not unique_ips:
        print(f"DEBUG: No public IPs found in {resource_name} to check with AbuseIPDB.")
        return None # Skip if no relevant IPs found

    all_ip_results = []
    highest_risk_level = 'low'
    highest_evidence = ""
    risk_priority = {'low': 1, 'medium': 2, 'high': 3} # Define risk level priorities

    ABUSEIPDB_API_KEY = "" # Get API key from environment variables
    if not ABUSEIPDB_API_KEY:
        print("INFO: ABUSEIPDB_API_KEY environment variable not set. Skipping AbuseIPDB check.")
        return None # Exit the function early if no key

    print("DEBUG: Using AbuseIPDB API Key.")
    ABUSEIPDB_API_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}

    for ip_address in unique_ips:
        cache_key = f"abuseipdb_{ip_address}"
        cached_data = get_cached_threat(cache_key)
        if cached_data:
            result = cached_data
        else:
            print(f"DEBUG: Checking AbuseIPDB API for IP: {ip_address}")
            params = {'ipAddress': ip_address, 'maxAgeInDays': '90', 'verbose': ''} # Add verbose for more context if needed
            result = None
            response = None # Initialize response to None
            try:
                print(f"DEBUG: Calling AbuseIPDB API: GET {ABUSEIPDB_API_ENDPOINT} for IP {ip_address}")
                response = requests.get(ABUSEIPDB_API_ENDPOINT, headers=headers, params=params, timeout=15) # 15 second timeout
                print(f"DEBUG: AbuseIPDB API response status code for {ip_address}: {response.status_code}")
                response.raise_for_status() # Raise HTTPError for bad responses

                data_wrapper = response.json()
                data = data_wrapper.get('data', {}) # Response data is nested under 'data' key
                print(f"DEBUG: AbuseIPDB API response data for {ip_address}: {json.dumps(data)}")

                abuse_score = data.get('abuseConfidenceScore', 0)
                risk = 'low'
                if abuse_score >= 80: risk = 'high'
                elif abuse_score >= 40: risk = 'medium'

                evidence = f"IP {ip_address} (in {resource_name}) has AbuseIPDB score: {abuse_score}."
                if data.get('totalReports', 0) > 0:
                    evidence += f" Total reports: {data['totalReports']}."
                    # Optionally add more details if needed, e.g., last reported date
                    # if data.get('lastReportedAt'):
                    #    evidence += f" Last reported: {data['lastReportedAt']}."

                result = {'feed': 'abuseipdb', 'risk_level': risk, 'evidence': evidence}
                print(f"DEBUG: AbuseIPDB check result for {ip_address}: {json.dumps(result)}")

            except requests.exceptions.Timeout:
                print(f"ERROR: AbuseIPDB API request timed out for {ip_address}")
                result = {'feed': 'abuseipdb', 'risk_level': 'low', 'evidence': f'API Timeout for {ip_address}'}
            except requests.exceptions.RequestException as e:
                print(f"ERROR: Error calling AbuseIPDB API for {ip_address}: {e}")
                error_details = f'API Error for {ip_address}: {e}'
                if response is not None:
                     error_details += f" | Status: {response.status_code} | Response: {response.text[:500]}"
                     print(f"DEBUG: AbuseIPDB API error response text: {response.text[:500]}")
                result = {'feed': 'abuseipdb', 'risk_level': 'low', 'evidence': error_details}
            except json.JSONDecodeError as e:
                print(f"ERROR: Failed to decode JSON response from AbuseIPDB API for {ip_address}: {e}")
                response_text = response.text[:500] if response else "No response object"
                print(f"DEBUG: AbuseIPDB API raw response text: {response_text}")
                result = {'feed': 'abuseipdb', 'risk_level': 'low', 'evidence': f'API JSON Decode Error for {ip_address}: {response_text}'}
            except Exception as e: # Catch any other unexpected errors
                print(f"ERROR: Unexpected error during AbuseIPDB check for {ip_address}: {e}\n{traceback.format_exc()}")
                result = {'feed': 'abuseipdb', 'risk_level': 'low', 'evidence': f'Unexpected Error for {ip_address}: {e}'}

            # Cache the result for this specific IP
            if result:
                set_cached_threat(cache_key, result)

        # Process the result for this IP (whether cached or fresh)
        if result:
            all_ip_results.append(result)
            current_priority = risk_priority.get(result.get('risk_level'), 0)
            highest_priority = risk_priority.get(highest_risk_level, 0)
            # Update highest risk level and evidence if current IP is riskier
            if current_priority > highest_priority:
                highest_risk_level = result['risk_level']
                highest_evidence = result['evidence'] # Store the evidence of the highest risk IP

    if not all_ip_results:
        print(f"DEBUG: No results obtained from AbuseIPDB for IPs in {resource_name}.")
        return None # No results obtained, possibly due to errors for all IPs

    # Construct the final result based on the highest risk found among all IPs checked
    final_result = {
        'feed': 'abuseipdb',
        'risk_level': highest_risk_level,
        'evidence': highest_evidence or f"Checked {len(unique_ips)} IPs in {resource_name}, none found with significant risk score (>40)."
    }
    print(f"DEBUG: Final aggregated AbuseIPDB result for resource {resource_name}: {json.dumps(final_result)}")
    return final_result


# --- Main Adapter Function ---

def check_threat_feeds(resource):
    """
    Checks a given IaC resource against configured threat intelligence feeds.

    Args:
        resource (dict): A dictionary representing the parsed IaC resource.
                         Expected keys: 'type', 'name', 'change'/'values'.

    Returns:
        dict: A dictionary containing the highest risk finding, including
              'feed', 'risk_level', and 'evidence'. Returns a default low-risk
              finding if no threats are identified.
    """
    resource_name = resource.get('name', 'unknown_resource')
    resource_type = resource.get('type', 'unknown_type')
    print(f"DEBUG: Entering check_threat_feeds for resource: {resource_name} ({resource_type})")

    threats = []
    default_risk = {
        'feed': 'internal-assessment',
        'risk_level': 'low',
        'evidence': f"No specific threats identified for {resource_name} ({resource_type}) in configured feeds."
    }

    # --- Call specific feed checkers ---
    # Wrap each checker in a try-except to prevent one failure from stopping others
    try:
        nvd_threat = check_nvd(resource_type)
        if nvd_threat:
            print(f"DEBUG: NVD check returned: {json.dumps(nvd_threat)}")
            threats.append(nvd_threat)
    except Exception as e:
        print(f"ERROR: Uncaught exception during NVD check: {e}\n{traceback.format_exc()}")
        threats.append({'feed': 'nvd', 'risk_level': 'low', 'evidence': f'Error during check: {e}'})

    try:
        abuse_threat = check_abuseipdb(resource)
        if abuse_threat:
            print(f"DEBUG: AbuseIPDB check returned: {json.dumps(abuse_threat)}")
            threats.append(abuse_threat)
    except Exception as e:
        print(f"ERROR: Uncaught exception during AbuseIPDB check: {e}\n{traceback.format_exc()}")
        threats.append({'feed': 'abuseipdb', 'risk_level': 'low', 'evidence': f'Error during check: {e}'})

    # --- Add calls to more checkers here in similar try-except blocks ---
    # Example:
    # try:
    #     another_threat = check_another_api(resource)
    #     if another_threat:
    #         threats.append(another_threat)
    # except Exception as e:
    #     print(f"ERROR: Uncaught exception during AnotherAPI check: {e}\n{traceback.format_exc()}")
    #     threats.append({'feed': 'another_api', 'risk_level': 'low', 'evidence': f'Error during check: {e}'})


    if not threats:
        print("DEBUG: No threats found from any feed.")
        return default_risk

    # --- Determine the highest risk ---
    highest_threat = default_risk # Start with default
    risk_priority = {'low': 1, 'medium': 2, 'high': 3}
    highest_priority_found = 0

    for threat in threats:
        current_priority = risk_priority.get(threat.get('risk_level', 'low'), 0)
        if current_priority > highest_priority_found:
            highest_threat = threat
            highest_priority_found = current_priority

    print(f"DEBUG: Highest threat determined after evaluating {len(threats)} results: {json.dumps(highest_threat)}")

    # --- Combine Evidence (Optional Refinement for multiple findings) ---
    if len(threats) > 1:
         # Sort threats by risk (descending) to show most important first
        threats.sort(key=lambda t: risk_priority.get(t.get('risk_level'), 0), reverse=True)
        # Create a combined evidence string
        combined_evidence = "; ".join([f"[{t.get('feed', 'unknown')} ({t.get('risk_level','?')})]: {t.get('evidence', 'N/A')}" for t in threats])
        # Update the evidence of the highest threat object to include all findings
        highest_threat['evidence'] = f"Highest risk found: {highest_threat.get('risk_level', '?')}. All Findings: {combined_evidence}"
        # Make sure the feed reflects the source of the highest risk, but maybe add note about others
        highest_threat['feed'] = f"{highest_threat.get('feed', 'unknown')} (+{len(threats)-1} other sources)"
        print(f"DEBUG: Combined evidence for multiple threats: {highest_threat['evidence']}")


    print(f"DEBUG: Returning final threat data for {resource_name}: {json.dumps(highest_threat)}")
    return highest_threat
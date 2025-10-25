import os
import json
import time
import traceback
import ipaddress
import requests
import shodan
import concurrent.futures

import boto3

# --- Config / env keys ---
OTX_API_KEY ="9b032a104ead9b762b6e6a718cc7f52f8f570b8ba1bc240d91954c0bd71f255c"
oss_API="9175e58c73b24cbaeb9a5ab83ac538c0d64ad877"
PHISHTANK_API_KEY ="http://checkurl.phishtank.com/checkurl/"
SHODAN_API_KEY ="5860982614fbc026afec4c4f2eb5ec10be21c1eb706be904a6a83d485abb59fb4eed8e1dc9bf3e77"
ABUSEIPDB_API_KEY ="5860982614fbc026afec4c4f2eb5ec10be21c1eb706be904a6a83d485abb59fb4eed8e1dc9bf3e77"
DYNAMODB_CACHE_TABLE_NAME = os.environ.get("CACHE_TABLE_NAME")
CACHE_TTL_SECONDS = 3600
HEALTH_STATUS_KEY = "_HEALTH_STATUS_" # Key for storing health data

# --- DynamoDB cache setup ---
dynamodb = boto3.resource('dynamodb')
cache_table = None
if DYNAMODB_CACHE_TABLE_NAME:
    try:
        cache_table = dynamodb.Table(DYNAMODB_CACHE_TABLE_NAME)
        cache_table.load()
    except Exception as e:
        print(f"Warning: Cache table not accessible: {e}")
        cache_table = None

def get_cached_threat(cache_key):
    if not cache_table:
        return None
    try:
        response = cache_table.get_item(Key={'cache_key': cache_key})
        item = response.get('Item')
        if item and item.get('expires_at', 0) > time.time():
            return json.loads(item.get('data', '{}'))
    except Exception as e:
        print(f"Error reading cache: {e}")
    return None

def set_cached_threat(cache_key, data):
    if not cache_table:
        return
    try:
        expires_at = int(time.time() + CACHE_TTL_SECONDS)
        cache_table.put_item(
            Item={
                'cache_key': cache_key,
                'data': json.dumps(data),
                'expires_at': expires_at
            }
        )
    except Exception as e:
        print(f"Error writing cache: {e}")

# ✨ --- ADDED ---
def get_feed_health():
    """
    Reads the health status blob from the cache, written by the HealthCheck Lambda.
    """
    if not cache_table:
        print("Warning: Cannot check feed health, cache table not configured.")
        return {} # Assume all healthy if cache is down
    
    try:
        response = cache_table.get_item(Key={'cache_key': HEALTH_STATUS_KEY})
        item = response.get('Item')
        if item:
            # Return a simple dict: {'shodan': 'HEALTHY', 'abuseipdb': 'DEGRADED'}
            data = json.loads(item.get('data', '{}'))
            status_dict = {feed: details.get('status', 'DEGRADED') for feed, details in data.items()}
            return status_dict
    except Exception as e:
        print(f"Error reading health status from cache: {e}")
    
    return {} # Default to healthy if status item is missing or expired
# --- END ADDED ---

# --- utility to extract IPs from nested structures ---
def _extract_ips_recursive(data):
    ips = set()
    if isinstance(data, str):
        try:
            # strip CIDRs or ports
            ip_part = data.split('/')[0].split(':')[0]
            ip_obj = ipaddress.ip_address(ip_part)
            if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified):
                ips.add(str(ip_obj))
        except Exception:
            pass
    elif isinstance(data, list):
        for item in data:
            ips.update(_extract_ips_recursive(item))
    elif isinstance(data, dict):
        for value in data.values():
            ips.update(_extract_ips_recursive(value))
    return ips

# --- Shodan ---
def check_shodan(resource):
    cache_key = f"shodan_{resource.get('type','unknown')}_{resource.get('name','')}"
    cached = get_cached_threat(cache_key)
    if cached:
        return cached

    if not SHODAN_API_KEY:
        return {'feed': 'shodan', 'risk_level': 'low', 'evidence': 'SHODAN_API_KEY not set; skipped'}

    api = shodan.Shodan(SHODAN_API_KEY)
    resource_type = resource.get('type', '')
    ips = _extract_ips_recursive(resource) or {resource.get('ip')} if resource.get('ip') else set()

    evidence_items = []
    highest_risk = 'low'
    try:
        # If we have specific IPs, query host info
        for ip in ips:
            try:
                host = api.host(ip)
                ports = host.get('ports', [])
                products = []
                for s in host.get('data', []):
                    prod = s.get('product') or s.get('banner') or ''
                    products.append(f"{s.get('port')}:{prod}")
                evidence_items.append(f"{ip} ports={ports} products_sample={products[:3]}")
                if ports:
                    highest_risk = 'medium' if highest_risk != 'high' else highest_risk
            except shodan.exception.APIError as e:
                # host lookups may fail; try a general search fallback
                try:
                    res = api.search(resource_type or ip, limit=3)
                    matches = res.get('matches', [])
                    if matches:
                        for m in matches:
                            evidence_items.append(f"{m.get('ip_str')}:{m.get('port')} ({m.get('org','')})")
                        highest_risk = 'medium'
                except Exception:
                    pass
        # If no ips or minimal findings, try a general search by resource type/name
        if not evidence_items:
            q = resource_type or resource.get('name')
            if q:
                try:
                    res = api.search(q, limit=5)
                    matches = res.get('matches', [])
                    if matches:
                        for m in matches:
                            evidence_items.append(f"{m.get('ip_str')}:{m.get('port')} ({m.get('org','')})")
                        highest_risk = 'medium'
                except Exception:
                    pass

        if evidence_items:
            result = {'feed': 'shodan', 'risk_level': highest_risk, 'evidence': "; ".join(evidence_items)}
        else:
            result = {'feed': 'shodan', 'risk_level': 'low', 'evidence': 'No Shodan results'}

    except Exception as e:
        print("Shodan error:", e)
        traceback.print_exc()
        result = {'feed': 'shodan', 'risk_level': 'low', 'evidence': f"Shodan error: {e}"}

    set_cached_threat(cache_key, result)
    return result

# --- AlienVault OTX ---
def check_alienvault(resource):
    cache_key = f"alienvault_{resource.get('type','unknown')}_{resource.get('name','')}"
    cached = get_cached_threat(cache_key)
    if cached:
        return cached

    if not OTX_API_KEY:
        return {'feed': 'alienvault', 'risk_level': 'low', 'evidence': 'OTX_API_KEY not set; skipped'}

    base = "https://otx.alienvault.com/api/v1"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    ips = _extract_ips_recursive(resource)

    evidence = []
    highest_risk = 'low'
    try:
        # Query indicator/host for each IP
        for ip in ips:
            url = f"{base}/indicators/IPv4/{ip}/general"
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                data = r.json()
                pulses = data.get('pulse_info', {}).get('pulses', [])
                if pulses:
                    evidence.append(f"{ip} pulses={len(pulses)} sample:{pulses[0].get('name') if pulses else ''}")
                    highest_risk = 'medium' if highest_risk != 'high' else highest_risk
            else:
                # non-200 is okay: include message
                evidence.append(f"{ip} OTX status={r.status_code}")
        # If no ips, try searching by domain/name if provided
        if not evidence and resource.get('name'):
            name = resource['name']
            url = f"{base}/indicators/domain/{name}/general"
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                data = r.json()
                pulses = data.get('pulse_info', {}).get('pulses', [])
                if pulses:
                    evidence.append(f"{name} pulses={len(pulses)} sample:{pulses[0].get('name')}")
                    highest_risk = 'medium'
    except Exception as e:
        print("AlienVault error:", e)
        traceback.print_exc()
        result = {'feed': 'alienvault', 'risk_level': 'low', 'evidence': f"AlienVault error: {e}"}
        set_cached_threat(cache_key, result)
        return result

    if evidence:
        result = {'feed': 'alienvault', 'risk_level': highest_risk, 'evidence': "; ".join(evidence)}
    else:
        result = {'feed': 'alienvault', 'risk_level': 'low', 'evidence': 'No OTX findings'}
    set_cached_threat(cache_key, result)
    return result

# --- PhishTank ---
def check_phishtank(resource):
    cache_key = f"phishtank_{resource.get('type','unknown')}_{resource.get('name','')}"
    cached = get_cached_threat(cache_key)
    if cached:
        return cached

    base_lookup = "https://checkurl.phishtank.com/checkurl/"
    evidence = []
    highest_risk = 'low'

    try:
        def _extract_urls(o):
            urls = set()
            if isinstance(o, str):
                if o.startswith("http://") or o.startswith("https://"):
                    urls.add(o)
            elif isinstance(o, list):
                for i in o:
                    urls.update(_extract_urls(i))
            elif isinstance(o, dict):
                for v in o.values():
                    urls.update(_extract_urls(v))
            return urls

        urls = _extract_urls(resource)
        for url in urls:
            try:
                r = requests.post(base_lookup, data={"url": url}, timeout=10)
                text = r.text.lower()
                if "in_database" in text and ("true" in text or "true" in text.split("in_database")[-1][:50]):
                    evidence.append(f"{url} found in PhishTank database")
                    highest_risk = 'high'
                elif r.status_code == 200 and "phishing" in text:
                    evidence.append(f"{url} possibly listed on PhishTank (raw response)")
                    highest_risk = max_risk(highest_risk, 'medium')
                else:
                    evidence.append(f"{url} not found on PhishTank")
            except Exception as e:
                evidence.append(f"{url} PhishTank lookup error: {e}")
    except Exception as e:
        print("PhishTank error:", e)
        traceback.print_exc()
        result = {'feed': 'phishtank', 'risk_level': 'low', 'evidence': f"PhishTank error: {e}"}
        set_cached_threat(cache_key, result)
        return result

    if evidence:
        result = {'feed': 'phishtank', 'risk_level': highest_risk, 'evidence': "; ".join(evidence)}
    else:
        result = {'feed': 'phishtank', 'risk_level': 'low', 'evidence': 'No PhishTank findings'}
    set_cached_threat(cache_key, result)
    return result

def max_risk(a, b):
    order = {'low': 1, 'medium': 2, 'high': 3}
    return a if order[a] >= order[b] else b

# --- AbuseIPDB ---
def check_abuseipdb(resource):
    cache_key = f"abuseipdb_{resource.get('type','unknown')}_{resource.get('name','')}"
    cached = get_cached_threat(cache_key)
    if cached:
        return cached

    if not ABUSEIPDB_API_KEY:
        return {'feed': 'abuseipdb', 'risk_level': 'low', 'evidence': 'ABUSEIPDB_API_KEY not set; skipped'}

    ips = _extract_ips_recursive(resource)
    if not ips:
        return {'feed': 'abuseipdb', 'risk_level': 'low', 'evidence': 'No IPs to check'}

    base = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    evidence = []
    highest_risk = 'low'
    try:
        for ip in ips:
            params = {"ipAddress": ip, "maxAgeInDays": 90}
            r = requests.get(base, headers=headers, params=params, timeout=10)
            if r.status_code == 200:
                data = r.json().get('data', {})
                abuse_confidence = data.get('abuseConfidenceScore', 0)
                reports = data.get('totalReports', 0)
                evidence.append(f"{ip} abuse_score={abuse_confidence} reports={reports}")
                if abuse_confidence >= 75 or reports > 10:
                    highest_risk = max_risk(highest_risk, 'high')
                elif abuse_confidence >= 30:
                    highest_risk = max_risk(highest_risk, 'medium')
            else:
                evidence.append(f"{ip} AbuseIPDB status={r.status_code}")
    except Exception as e:
        print("AbuseIPDB error:", e)
        traceback.print_exc()
        result = {'feed': 'abuseipdb', 'risk_level': 'low', 'evidence': f"AbuseIPDB error: {e}"}
        set_cached_threat(cache_key, result)
        return result

    result = {'feed': 'abuseipdb', 'risk_level': highest_risk, 'evidence': "; ".join(evidence) if evidence else 'No AbuseIPDB findings'}
    set_cached_threat(cache_key, result)
    return result


# --- Main parallel runner / aggregator (MODIFIED) ---
def check_threat_feeds(resource, feeds=None, max_workers=8, timeout=30):
    """
    resource: dict with fields like 'name', 'type', possibly nested fields that contain IPs/URLs
    feeds: list of feed ids to run, e.g. ['shodan','alienvault','phishtank','abuseipdb','osint'] or None for all
    
    ✨ --- MODIFIED ---
    Returns a tuple: (highest_threat_dict, skipped_feeds_list)
    --- END MODIFIED ---
    """
    if feeds is None:
        feeds = ['shodan', 'alienvault', 'phishtank', 'abuseipdb'] # Removed 'osint' as it's not a feed

    feed_map = {
        'shodan': check_shodan,
        'alienvault': check_alienvault,
        'phishtank': check_phishtank,
        'abuseipdb': check_abuseipdb
    }

    # ✨ --- ADDED ---
    # Get the health status of all feeds
    feed_health = get_feed_health()
    skipped_feeds = []
    # --- END ADDED ---

    tasks = []
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_feed = {}
        for f in feeds:
            func = feed_map.get(f)
            if not func:
                continue
            
            # ✨ --- ADDED ---
            # Graceful Degradation Logic
            if feed_health.get(f) == 'DEGRADED':
                print(f"Skipping feed {f} as it is marked DEGRADED.")
                skipped_feeds.append(f)
                continue
            # --- END ADDED ---
                
            future = executor.submit(func, resource)
            future_to_feed[future] = f

        # collect with timeout
        for future in concurrent.futures.as_completed(future_to_feed.keys(), timeout=timeout):
            feed_name = future_to_feed.get(future)
            try:
                r = future.result()
                if r:
                    results.append(r)
            except Exception as e:
                print(f"Feed {feed_name} failed: {e}")
                traceback.print_exc()
                results.append({'feed': feed_name, 'risk_level': 'low', 'evidence': f'Error: {e}'})
                # ✨ --- ADDED ---
                # If a feed fails, it was skipped
                if feed_name not in skipped_feeds:
                    skipped_feeds.append(feed_name) 
                # --- END ADDED ---

    # If no results, return internal low
    if not results:
        return {'feed': 'internal-assessment', 'risk_level': 'low', 'evidence': f"No threats identified for {resource.get('name','unknown')}"}, skipped_feeds

    # Determine highest risk across feeds
    risk_priority = {'low': 1, 'medium': 2, 'high': 3}
    highest_threat = {'feed': 'internal-assessment', 'risk_level': 'low', 'evidence': f"No threats identified for {resource.get('name','unknown')}"}
    for t in results:
        if risk_priority.get(t.get('risk_level', 'low'), 0) > risk_priority.get(highest_threat.get('risk_level', 'low'), 0):
            highest_threat = t

    # Combine evidence when multiple feeds
    if len(results) > 1:
        combined_evidence = "; ".join([f"[{t.get('feed')} ({t.get('risk_level')})]: {t.get('evidence')}" for t in results])
        highest_threat['evidence'] = f"Highest risk: {highest_threat.get('risk_level')}. All findings: {combined_evidence}"
        highest_threat['feed'] = f"{highest_threat.get('feed')} (+{len(results)-1} other sources)"

    # ✨ --- MODIFIED ---
    return highest_threat, skipped_feeds
    # --- END MODIFIED ---

# --- Example usage ---
if __name__ == "__main__":
    sample = {
        "name": "example.com",
        "type": "domain",
        "ip": "8.8.8.8",
        "urls": ["http://example.com/login", "https://malicious.example.test"]
    }
    out, skipped = check_threat_feeds(sample)
    print(json.dumps(out, indent=2))
    print(f"Skipped feeds: {skipped}")
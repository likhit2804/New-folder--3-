import json
import os
import requests
import shodan
import time
import boto3
import concurrent.futures

# --- Config / env keys ---
# These are read from the environment of the HealthCheck Lambda
OTX_API_KEY = os.environ.get("OTX_API_KEY", "9b032a104ead9b762b6e6a718cc7f52f8f570b8ba1bc240d91954c0bd71f255c")
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "5860982614fbc026afec4c4f2eb5ec10be21c1eb706be904a6a83d485abb59fb4eed8e1dc9bf3e77")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "5860982614fbc026afec4c4f2eb5ec10be21c1eb706be904a6a83d485abb59fb4eed8e1dc9bf3e77")

DYNAMODB_CACHE_TABLE_NAME = os.environ.get("CACHE_TABLE_NAME")
HEALTH_STATUS_KEY = "_HEALTH_STATUS_"
CACHE_TTL_SECONDS = 3600 # Store health status for 1 hour

# --- DynamoDB cache setup ---
dynamodb = boto3.resource('dynamodb')
cache_table = None
if DYNAMODB_CACHE_TABLE_NAME:
    try:
        cache_table = dynamodb.Table(DYNAMODB_CACHE_TABLE_NAME)
    except Exception as e:
        print(f"Error: Could not load cache table: {e}")
        cache_table = None

# --- Ping Functions ---

def ping_shodan():
    if not SHODAN_API_KEY:
        return 'DEGRADED', 'SHODAN_API_KEY not set'
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        api.info() # A simple, lightweight call
        return 'HEALTHY', ''
    except Exception as e:
        return 'DEGRADED', str(e)

def ping_alienvault():
    if not OTX_API_KEY:
        return 'DEGRADED', 'OTX_API_KEY not set'
    try:
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        # Ping a known, stable indicator
        r = requests.get("https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general", headers=headers, timeout=10)
        r.raise_for_status()
        return 'HEALTHY', ''
    except Exception as e:
        return 'DEGRADED', str(e)

def ping_phishtank():
    try:
        # A simple checkurl POST is the best synthetic check
        r = requests.post("https://checkurl.phishtank.com/checkurl/", data={"url": "http://example.com"}, timeout=10)
        r.raise_for_status()
        if "in_database" in r.text:
             return 'HEALTHY', ''
        return 'DEGRADED', 'Unexpected response from PhishTank'
    except Exception as e:
        return 'DEGRADED', str(e)

def ping_abuseipdb():
    if not ABUSEIPDB_API_KEY:
        return 'DEGRADED', 'ABUSEIPDB_API_KEY not set'
    try:
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": "1.1.1.1", "maxAgeInDays": 1} # Check a known-good IP
        r = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=10)
        r.raise_for_status()
        if "data" in r.json():
            return 'HEALTHY', ''
        return 'DEGRADED', 'Invalid response from AbuseIPDB'
    except Exception as e:
        return 'DEGRADED', str(e)

# --- Main Handler ---

def lambda_handler(event, context):
    if not cache_table:
        print("Error: Cache table is not configured. Cannot store health status.")
        return
        
    feeds_to_check = {
        'shodan': ping_shodan,
        'alienvault': ping_alienvault,
        'phishtank': ping_phishtank,
        'abuseipdb': ping_abuseipdb
    }
    
    health_status = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        future_to_feed = {executor.submit(func): feed for feed, func in feeds_to_check.items()}
        
        for future in concurrent.futures.as_completed(future_to_feed):
            feed_name = future_to_feed[future]
            try:
                status, error_msg = future.result()
                health_status[feed_name] = {
                    'status': status,
                    'message': error_msg,
                    'timestamp': int(time.time())
                }
            except Exception as e:
                health_status[feed_name] = {
                    'status': 'DEGRADED',
                    'message': f"Health check function failed: {e}",
                    'timestamp': int(time.time())
                }

    # Save the combined health status to the cache table
    try:
        expires_at = int(time.time() + CACHE_TTL_SECONDS)
        cache_table.put_item(
            Item={
                'cache_key': HEALTH_STATUS_KEY,
                'data': json.dumps(health_status),
                'expires_at': expires_at
            }
        )
        print(f"Successfully updated health status: {health_status}")
        return {"statusCode": 200, "body": json.dumps(health_status)}
        
    except Exception as e:
        print(f"Error writing health status to cache: {e}")
        return {"statusCode": 500, "body": "Failed to write health status"}
import boto3
import os
import time
import requests # Make sure 'requests' is in your requirements.txt for this lambda

# This is the new table you need to create
STATUS_TABLE_NAME = os.environ.get('STATUS_TABLE_NAME', 'ThreatFeedStatus-3')
dynamodb = boto3.resource('dynamodb')
status_table = dynamodb.Table(STATUS_TABLE_NAME)

# Define the feeds to check
# Add the actual lightweight endpoints you want to check here
FEEDS_TO_CHECK = {
    "NVD": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-1010218", # Example check
    "AbuseIPDB": "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8" # Example check (requires auth header)
}

# AbuseIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY') # Uncomment if needed

def lambda_handler(event, context):
    print("Running threat feed health checks...")
    
    for feed_name, endpoint in FEEDS_TO_CHECK.items():
        status = "DEGRADED" # Assume degraded until proven healthy
        try:
            # ---
            # NOTE: Add any required headers (like API keys) here
            # headers = {}
            # if feed_name == "AbuseIPDB":
            #     headers = {'Key': AbuseIPDB_API_KEY, 'Accept': 'application/json'}
            #
            # r = requests.get(endpoint, timeout=10, headers=headers)
            # ---
            
            # For this example, we'll just use a simple GET
            r = requests.get(endpoint, timeout=10)

            # Check for a successful (but not rate-limited) response
            if r.status_code == 200:
                status = "HEALTHY"
            else:
                print(f"Feed {feed_name} returned non-200 status: {r.status_code}")
                
        except requests.exceptions.RequestException as e:
            # Timeout, connection error, etc.
            print(f"Feed {feed_name} check failed with error: {e}")
        
        # ---
        # Step 2: Persist the status to DynamoDB [cite: 87]
        # ---
        try:
            status_table.put_item(
                Item={
                    'feed_name': feed_name,
                    'status': status,
                    'last_updated_timestamp': int(time.time())
                }
            )
            print(f"Updated status for {feed_name}: {status}")
        except Exception as dbe:
            print(f"Failed to write status for {feed_name} to DynamoDB: {dbe}")

    return {"status": "complete"}
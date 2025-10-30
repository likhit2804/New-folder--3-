import json
import boto3
import os
import time
from lib.parser import parse_iac_plan
from lib.threat_adapters import check_threat_feeds
from lib.correlation_engine import correlate_threats
from lib.risk_scoring import calculate_risk
from lib.explanation_builder import build_explanation

dynamodb = boto3.resource('dynamodb')

# Main results table
TABLE_NAME = os.environ.get('TABLE_NAME', 'TaIacScanResults-3')
table = dynamodb.Table(TABLE_NAME)

# New status table (must match the one in health_check_lambda)
STATUS_TABLE_NAME = os.environ.get('STATUS_TABLE_NAME', 'ThreatFeedStatus-3')
status_table = dynamodb.Table(STATUS_TABLE_NAME)


def get_feed_health_status():
    """
    Reads the health status of all feeds from the status table.
    This is the "Feed Status Check" from Phase III, Step 1[cite: 61].
    """
    feed_status = {}
    try:
        # Scan the table (it will be small)
        response = status_table.scan()
        items = response.get('Items', [])
        
        # Convert list to a simple map, e.g., {"NVD": "HEALTHY", "AbuseIPDB": "DEGRADED"}
        for item in items:
            feed_status[item['feed_name']] = item.get('status', 'DEGRADED')
            
        print(f"Loaded feed health status: {feed_status}")
        
    except Exception as e:
        # If we can't read the status table, we fail open
        # (i.e., assume all are HEALTHY) to not block scans.
        print(f"Error reading feed status table, assuming HEALTHY: {e}")
        return {} # Return empty map, logic in adapter will default to "HEALTHY"
        
    return feed_status


def lambda_handler(event, context):
    
    # ---
    # Step 0: Get current feed health status [cite: 62]
    # ---
    feed_status_map = get_feed_health_status()
    
    for record in event['Records']:
        scan_id = None
        try:
            message = json.loads(record['body'])
            iac_data = message.get('iac_plan', {})
            scan_id = message.get('scan_id')

            if not scan_id:
                print("Error: Message missing scan_id. Cannot process.")
                continue # Skip this record

            # Step 1: Parse IaC (Phase I)
            parsed_resources = parse_iac_plan(iac_data)

            all_findings = []
            all_skipped_feeds = set()
            
            for res in parsed_resources:
                # ---
                # Step 2: Check threat feeds (Phase II, Step 1)
                # Pass the status map to the adapters [cite: 64]
                # ---
                threat_data, skipped = check_threat_feeds(res, feed_status_map)
                all_skipped_feeds.update(skipped)
                
                # Step 3: Correlate threats (Phase II, Step 2)
                confirmed_findings = correlate_threats(res, threat_data)

                if not confirmed_findings:
                    continue

                # Step 4: Calculate risk (Phase II, Step 3)
                risk_score = calculate_risk(res, confirmed_findings)
                
                # Step 5: Build explanation (Phase I, Step 3)
                explanation = build_explanation(res, confirmed_findings, risk_score)
                
                all_findings.append(explanation)

            # Step 6: Update DynamoDB item to COMPLETED
            # The 'skipped_feeds' attribute will now contain feeds that were
            # skipped due to degradation, fulfilling Phase III, Step 1[cite: 65].
            table.update_item(
                Key={'scan_id': scan_id},
                UpdateExpression="SET #st = :s, #ts = :t, #res = :r, #skip = :sk",
                ExpressionAttributeNames={
                    '#st': 'status',
                    '#ts': 'timestamp',
                    '#res': 'results_json',
                    '#skip': 'skipped_feeds'
                },
                ExpressionAttributeValues={
                    ':s': 'COMPLETED',
                    't': int(time.time()),
                    ':r': json.dumps(all_findings),
                    ':sk': list(all_skipped_feeds)
                }
            )
            print(f"Scan {scan_id} COMPLETED.")

        except Exception as e:
            print(f"Error processing message for scan_id {scan_id}: {e}")
            if scan_id:
                try:
                    table.update_item(
                        Key={'scan_id': scan_id},
                        UpdateExpression="SET #st = :s, #msg = :m",
                        ExpressionAttributeNames={
                            '#st': 'status',
                            '#msg': 'error_message'
                        },
                        ExpressionAttributeValues={
                            ':s': 'FAILED',
                            ':m': str(e)
                        }
                    )
                except Exception as dbe:
                    print(f"Failed to update status to FAILED for {scan_id}: {dbe}")
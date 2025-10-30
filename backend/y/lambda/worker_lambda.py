import json
import boto3
import os
import time
from lib.parser import parse_iac_plan
# ✨ --- CORRECTED IMPORTS ---
from lib.threat_adapters import check_threat_feeds, get_feed_health_from_cache
from lib.correlation_engine import correlate_threats
# --- END CORRECTIONS ---
from lib.risk_scoring import calculate_risk
from lib.explanation_builder import build_explanation

dynamodb = boto3.resource('dynamodb')
TABLE_NAME = os.environ.get('TABLE_NAME')
table = dynamodb.Table(TABLE_NAME)

def lambda_handler(event, context):
    
    # --- ✨ CORRECTED: Get health status from the right place ---
    # This reads from TaThreatIntelCache-5, as defined in threat_adapters.py
    feed_status_map = get_feed_health_from_cache()
    print(f"Loaded feed health status: {feed_status_map}")
    
    for record in event['Records']:
        scan_id = None
        try:
            message = json.loads(record['body'])
            iac_data = message.get('iac_plan', {})
            scan_id = message.get('scan_id')

            if not scan_id:
                print("Error: Message missing scan_id. Cannot process.")
                continue 

            # Step 1: Parse IaC
            parsed_resources = parse_iac_plan(iac_data)

            all_findings = []
            all_skipped_feeds = set()
            
            for res in parsed_resources:
                # Step 2: Check threat feeds
                # ✨ --- CORRECTED: Pass the feed_status_map ---
                threat_data, skipped = check_threat_feeds(res, feed_status_map)
                all_skipped_feeds.update(skipped)
                
                # Step 3: Correlate threats
                confirmed_findings = correlate_threats(res, threat_data)

                if not confirmed_findings:
                    continue

                # Step 4: Calculate risk
                risk_score = calculate_risk(res, confirmed_findings)
                
                # Step 5: Build explanation
                explanation = build_explanation(res, confirmed_findings, risk_score)
                
                all_findings.append(explanation)

            # Step 6: Update DynamoDB item to COMPLETED
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
                    ':t': int(time.time()),
                    ':r': json.dumps(all_findings),
                    ':sk': list(all_skipped_feeds)
                }
            )
            print(f"Scan {scan_id} COMPLETED.")

        except Exception as e:
            print(f"Error processing message for scan_id {scan_id}: {e}")
            # If an error occurs, update the status to FAILED
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
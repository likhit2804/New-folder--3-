import json
import boto3
import os
import time
from lib.parser import parse_iac_plan
from lib.threat_adapters import check_threat_feeds
from lib.risk_scoring import calculate_risk
from lib.explanation_builder import build_explanation

dynamodb = boto3.resource('dynamodb')
TABLE_NAME = os.environ.get('TABLE_NAME', 'TaIacScanResults-3') # Changed env var name
table = dynamodb.Table(TABLE_NAME)

def lambda_handler(event, context):
    for record in event['Records']:
        scan_id = None
        try:
            message = json.loads(record['body'])
            iac_data = message.get('iac_plan', {})
            scan_id = message.get('scan_id')

            if not scan_id:
                print("Error: Message missing scan_id. Cannot process.")
                continue # Skip this record

            # Step 1: Parse IaC
            parsed_resources = parse_iac_plan(iac_data)

            findings = []
            all_skipped_feeds = set()
            
            for res in parsed_resources:
                # Step 2: Check threat feeds (Now returns 2 values)
                threat_data, skipped = check_threat_feeds(res)
                all_skipped_feeds.update(skipped)
                
                # Step 3: Calculate risk
                risk_score = calculate_risk(res, threat_data)
                
                # Step 4: Build explanation
                explanation = build_explanation(res, threat_data, risk_score)
                
                findings.append(explanation)

            # Step 5: Update DynamoDB item to COMPLETED
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
                    ':r': json.dumps(findings),
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
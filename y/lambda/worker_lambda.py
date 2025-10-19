import json
import boto3
import os
from lib.parser import parse_iac_plan
from lib.threat_adapters import check_threat_feeds
from lib.risk_scoring import calculate_risk
from lib.explanation_builder import build_explanation

dynamodb = boto3.resource('dynamodb')
TABLE_NAME = os.environ.get('DYNAMODB_TABLE', 'TaIacScanResults')
table = dynamodb.Table(TABLE_NAME)

def lambda_handler(event, context):
    for record in event['Records']:
        try:
            message = json.loads(record['body'])
            iac_data = message.get('iac_plan', {})

            # Step 1: Parse IaC
            parsed_resources = parse_iac_plan(iac_data)

            findings = []
            for res in parsed_resources:
                # Step 2: Check threat feeds
                threat_data = check_threat_feeds(res)
                
                # Step 3: Calculate risk
                risk_score = calculate_risk(res, threat_data)
                
                # Step 4: Build explanation
                explanation = build_explanation(res, threat_data, risk_score)
                
                findings.append(explanation)

            # Step 5: Save to DynamoDB
            table.put_item(Item={
                'scan_id': message.get('scan_id', 'unknown'),
                'timestamp': context.aws_request_id,
                'results_json': json.dumps(findings)
            })

        except Exception as e:
            print(f"Error processing message: {e}")

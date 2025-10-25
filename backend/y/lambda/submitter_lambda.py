import json
import boto3
import os
import uuid
import time

sqs = boto3.client('sqs')
dynamodb = boto3.resource('dynamodb') # <-- ADDED

# Set from environment
QUEUE_URL = os.environ.get('QUEUE_URL')
TABLE_NAME = os.environ.get('TABLE_NAME') # <-- ADDED
table = dynamodb.Table(TABLE_NAME) # <-- ADDED

def lambda_handler(event, context):
    try:
        # Parse incoming request
        body = json.loads(event.get('body', '{}'))

        # Basic validation
        if 'iac_plan' not in body:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Missing IaC plan data'})
            }
            
        # ✨ --- MODIFIED ---
        # Get scan_id from body or generate a new one
        scan_id = body.get('scan_id', f'api-scan-{uuid.uuid4()}')
        body['scan_id'] = scan_id # Ensure scan_id is in the message
        
        # 1. Create PENDING item in DynamoDB
        try:
            table.put_item(Item={
                'scan_id': scan_id,
                'status': 'PENDING',
                'timestamp': int(time.time()),
                'results_json': json.dumps([]),
                'skipped_feeds': []
            })
        except Exception as e:
            print(f"DynamoDB put_item error: {e}")
            return {
                'statusCode': 500,
                'body': json.dumps({'error': f'Failed to create scan item: {e}'})
            }

        # 2. Send to SQS
        response = sqs.send_message(
            QueueUrl=QUEUE_URL,
            MessageBody=json.dumps(body) # Pass the full body with scan_id
        )

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Scan request submitted successfully',
                'scan_id': scan_id, # Return the scan_id to the client
                'sqsMessageId': response['MessageId']
            })
        }
        # --- END MODIFIED ---

    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
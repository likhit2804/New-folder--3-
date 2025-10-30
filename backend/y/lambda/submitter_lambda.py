import json
import boto3
import os
import uuid
import time
from decimal import Decimal  # <-- IMPORT THIS

sqs = boto3.client('sqs')
dynamodb = boto3.resource('dynamodb')

# Set from environment
QUEUE_URL = os.environ.get('QUEUE_URL')
TABLE_NAME = os.environ.get('TABLE_NAME')
table = dynamodb.Table(TABLE_NAME)

# --- ✨ NEW HELPER CLASS ---
# This class teaches json.dumps how to handle Decimal objects from DynamoDB
class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            # Convert Decimal to int if it's a whole number, else float
            if obj % 1 == 0:
                return int(obj)
            else:
                return float(obj)
        # Let the base class default method raise the TypeError
        return super(DecimalEncoder, self).default(obj)
# --- END NEW CLASS ---


def lambda_handler(event, context):
    # This function must handle two routes: POST /scans and GET /scans/{scan_id}
    
    # --- ✨ MODIFIED: ADDED ROUTING ---
    http_method = event.get('httpMethod')
    
    # === ROUTE 1: POST /scans (Submit a new scan) ===
    if http_method == 'POST':
        try:
            body = json.loads(event.get('body', '{}'))
            
            iac_plan = body.get('iac_plan')
            if not iac_plan:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'message': 'iac_plan (JSON) is required in the body'})
                }

            # Use provided scan_id or generate a new one
            scan_id = body.get('scan_id', f"api-{str(uuid.uuid4())}")

            # 1. Create PENDING entry in DynamoDB
            table.put_item(
                Item={
                    'scan_id': scan_id,
                    'status': 'PENDING',
                    'timestamp': int(time.time()),
                    'results_json': '[]', # Use '[]' as a string, not json.dumps
                    'skipped_feeds': []
                }
            )

            # 2. Send message to SQS
            # We only send the scan_id and the plan to SQS to keep the message small
            sqs_message = json.dumps({
                'scan_id': scan_id,
                'iac_plan': iac_plan 
            })
            
            sqs_response = sqs.send_message(
                QueueUrl=QUEUE_URL,
                MessageBody=sqs_message
            )

            # 3. Return success to the user
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Scan request submitted successfully',
                    'scan_id': scan_id,
                    'sqsMessageId': sqs_response.get('MessageId')
                })
            }
        except Exception as e:
            print(f"[POST Error] {e}")
            return {'statusCode': 500, 'body': json.dumps(f"Error submitting: {str(e)}")}
    
    # === ROUTE 2: GET /scans/{scan_id} (Check scan status) ===
    elif http_method == 'GET':
        try:
            # Get the scan_id from the URL path
            scan_id = event.get('pathParameters', {}).get('scan_id')
            if not scan_id:
                return {'statusCode': 400, 'body': json.dumps({'message': 'Missing scan_id in path'})}

            response = table.get_item(
                Key={'scan_id': scan_id}
            )
            
            item = response.get('Item')
            
            if item:
                # This is the fix for the 500 Internal Server Error
                return {
                    'statusCode': 200,
                    # --- ✨ MODIFIED LINE ---
                    # Use the new DecimalEncoder class to handle DynamoDB's Decimal numbers
                    'body': json.dumps(item, cls=DecimalEncoder)
                }
            else:
                return {
                    'statusCode': 404,
                    'body': json.dumps({'message': 'Scan not found'})
                }
        except Exception as e:
            print(f"[GET Error] {e}")
            return {'statusCode': 500, 'body': json.dumps(f"Error fetching status: {str(e)}")}
    # --- END ROUTING ---
            
    return {
        'statusCode': 400,
        'body': json.dumps({'message': 'Unsupported method'})
    }
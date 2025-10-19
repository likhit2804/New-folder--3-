import json
import boto3
import os

sqs = boto3.client('sqs')

# Set your queue URL here
QUEUE_URL = os.environ.get('QUEUE_URL', 'https://sqs.us-east-1.amazonaws.com/106731597972/TaIacScanQueue')

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

        # Send to SQS
        response = sqs.send_message(
            QueueUrl=QUEUE_URL,
            MessageBody=json.dumps(body)
        )

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Scan request submitted successfully',
                'sqsMessageId': response['MessageId']
            })
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

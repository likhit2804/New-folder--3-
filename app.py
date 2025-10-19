from aws_cdk import (
    RemovalPolicy,
    aws_s3_assets,
    Stack,
    aws_lambda as _lambda,
    aws_sqs as sqs,
    aws_dynamodb as dynamodb,
    aws_iam as iam,
    aws_apigateway as apigateway,
)
from constructs import Construct


class TaIacInfraStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # 1️⃣ DynamoDB Table
        table = dynamodb.Table(
            self, "TaIacScanResultsO",
            table_name="TaIacScanResultsO",
            partition_key={"name": "scan_id", "type": dynamodb.AttributeType.STRING},
            removal_policy=RemovalPolicy.DESTROY  # delete on teardown (dev only)
        )

        # 2️⃣ SQS Queue
        queue = sqs.Queue(
            self, "TaIacScanQueueO",
            queue_name="TaIacScanQueueO"
        )

        # 3️⃣ Submitter Lambda
        submitter_lambda = _lambda.Function(
            self, "SubmitterLambdaO",
            function_name="TaIacSubmitterO",
            runtime=_lambda.Runtime.PYTHON_3_11,
            handler="submitter_lambda.lambda_handler",
            code=_lambda.Code.from_asset(
                "y",
                bundling={
                    "image": _lambda.Runtime.PYTHON_3_11.bundling_image,
                     "command": ["bash", "-c", "pip install -r requirements.txt -t /asset-output && cp -r . /asset-output"],},
            ),
            environment={
                "QUEUE_URL": queue.queue_url
            }
        )

        # 4️⃣ Worker Lambda
        worker_lambda = _lambda.Function(
            self, "WorkerLambdaO",
            function_name="TaIacWorkerO",
            runtime=_lambda.Runtime.PYTHON_3_11,
            handler="worker_lambda.lambda_handler",
            code=_lambda.Code.from_asset(
                "y",
                bundling={
                    "image": _lambda.Runtime.PYTHON_3_11.bundling_image,
                    "command": ["bash", "-c", "pip install -r requirements.txt -t /asset-output && cp -r . /asset-output"],},
            ),
            environment={
                "TABLE_NAME": table.table_name
            }
        )

        # 5️⃣ Give Lambdas permissions
        queue.grant_send_messages(submitter_lambda)
        queue.grant_consume_messages(worker_lambda)
        table.grant_write_data(worker_lambda)

        # 6️⃣ Connect SQS to Worker Lambda
        worker_lambda.add_event_source_mapping(
            "SQSTriggerO",
            event_source_arn=queue.queue_arn,
            batch_size=1
        )

        # 7️⃣ API Gateway to trigger Submitter Lambda
        api = apigateway.LambdaRestApi(
            self, "TaIacAPIO",
            handler=submitter_lambda,
            proxy=False
        )

        scans = api.root.add_resource("scan")
        scans.add_method("POST")  # POST /scan
import aws_cdk as cdk
app = cdk.App()
stack = TaIacInfraStack(app, "TaIacInfraStack")
app.synth()